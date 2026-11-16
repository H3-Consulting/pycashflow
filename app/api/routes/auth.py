"""API v1 authentication routes."""

import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta, timezone
from threading import Lock

from flask import current_app, request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import check_password_hash, generate_password_hash

from app import limiter, db
from app.models import PasskeyCredential, User, UserToken
from app.auth import _DUMMY_HASH, _passkey_enabled
from app.password_setup import consume_password_setup_token
from app.totp_utils import decrypt_totp_secret, verify_totp, verify_and_consume_backup_code
from app.subscription import enforce_user_access
from app.oauth.tokens import revoke_all_user_grants

from app.api import api
from app.api.auth_utils import (
    api_login_required,
    create_token_for_user,
    delete_token,
    get_api_user,
    hash_token,
)
from app.api.errors import unauthorized, validation_error, forbidden
from app.api.responses import api_ok
from app.api.serializers import serialize_user


logger = logging.getLogger(__name__)


try:
    from webauthn import (
        generate_authentication_options,
        verify_authentication_response,
        options_to_json,
    )
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
    from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
    from webauthn.helpers.structs import (
        PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    )
    _WEBAUTHN_AVAILABLE = True
except Exception:  # pragma: no cover - webauthn is an optional dependency
    _WEBAUTHN_AVAILABLE = False
    generate_authentication_options = None
    verify_authentication_response = None
    options_to_json = None
    base64url_to_bytes = None
    bytes_to_base64url = None
    PublicKeyCredentialDescriptor = None
    UserVerificationRequirement = None


_PASSKEY_CHALLENGE_MAX_AGE_SECONDS = 300
_CONSUMED_PASSKEY_CHALLENGES: dict[str, datetime] = {}
_CONSUMED_PASSKEY_CHALLENGES_LOCK = Lock()


_TWOFA_CHALLENGE_MAX_AGE_SECONDS = 300
_CONSUMED_TWOFA_CHALLENGES: dict[str, datetime] = {}
_CONSUMED_TWOFA_CHALLENGES_LOCK = Lock()


def _challenge_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="api-login-2fa")


def _purge_expired_consumed_challenges(now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    expired = [
        token
        for token, expires_at in _CONSUMED_TWOFA_CHALLENGES.items()
        if expires_at <= now
    ]
    for token in expired:
        _CONSUMED_TWOFA_CHALLENGES.pop(token, None)


def _is_twofa_challenge_consumed(challenge: str) -> bool:
    with _CONSUMED_TWOFA_CHALLENGES_LOCK:
        _purge_expired_consumed_challenges()
        return challenge in _CONSUMED_TWOFA_CHALLENGES


def _try_mark_twofa_challenge_consumed(challenge: str) -> bool:
    now = datetime.now(timezone.utc)
    with _CONSUMED_TWOFA_CHALLENGES_LOCK:
        _purge_expired_consumed_challenges(now)
        if challenge in _CONSUMED_TWOFA_CHALLENGES:
            return False
        _CONSUMED_TWOFA_CHALLENGES[challenge] = now + timedelta(
            seconds=_TWOFA_CHALLENGE_MAX_AGE_SECONDS
        )
        return True


def _build_twofa_challenge(user: User) -> str:
    payload = {
        "uid": user.id,
        "email": user.email,
        "nonce": hash_token(f"{user.id}:{datetime.now(timezone.utc).isoformat()}"),
    }
    return _challenge_serializer().dumps(payload)


def _verify_twofa_challenge(challenge: str) -> User | None:
    if _is_twofa_challenge_consumed(challenge):
        return None

    try:
        payload = _challenge_serializer().loads(
            challenge,
            max_age=_TWOFA_CHALLENGE_MAX_AGE_SECONDS,
        )
    except (BadSignature, SignatureExpired):
        return None

    user_id = payload.get("uid")
    if not isinstance(user_id, int):
        return None
    return db.session.get(User, user_id)


def _validate_new_password(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if password.lower() == password or password.upper() == password:
        return "Password must include uppercase and lowercase letters"
    if not any(ch.isdigit() for ch in password):
        return "Password must include at least one number"
    return None


@api.route("/auth/login", methods=["POST"])
@limiter.limit("10 per minute", exempt_when=lambda: current_app.testing)
def api_login():
    body = request.get_json(silent=True) or {}

    errors: dict = {}
    if not body.get("email", "").strip():
        errors["email"] = "Email is required"
    if not body.get("password", ""):
        errors["password"] = "Password is required"
    if errors:
        return validation_error(errors)

    email = body["email"].strip().lower()
    password = body["password"]

    user = User.query.filter_by(email=email).first()

    candidate_hash = user.password if user else _DUMMY_HASH
    password_ok = check_password_hash(candidate_hash, password)

    if not password_ok or user is None or not enforce_user_access(user):
        return unauthorized("Invalid credentials or account is not active")

    if user.twofa_enabled:
        return api_ok({
            "twofa_required": True,
            "challenge": _build_twofa_challenge(user),
            "user": serialize_user(user),
        })

    raw_token, _record = create_token_for_user(user)

    return api_ok({
        "token": raw_token,
        "user": serialize_user(user),
    })


@api.route("/auth/login/2fa", methods=["POST"])
@limiter.limit("10 per minute", exempt_when=lambda: current_app.testing)
def api_login_2fa():
    body = request.get_json(silent=True) or {}
    errors: dict = {}
    challenge_raw = body.get("challenge")
    challenge = challenge_raw.strip() if isinstance(challenge_raw, str) else ""
    if not challenge:
        errors["challenge"] = "Challenge is required"
    code_raw = body.get("code")
    code = code_raw.strip() if isinstance(code_raw, str) else ""
    if not code:
        errors["code"] = "Code is required"
    if errors:
        return validation_error(errors)

    user = _verify_twofa_challenge(challenge)
    if user is None or not enforce_user_access(user) or not user.twofa_enabled:
        return unauthorized("Invalid or expired 2FA challenge")

    submitted = code
    twofa_ok = False

    try:
        secret = decrypt_totp_secret(user.twofa_secret) if user.twofa_secret else ""
    except Exception:
        secret = ""

    if secret:
        twofa_ok = verify_totp(secret, submitted)

    if not twofa_ok:
        twofa_ok = verify_and_consume_backup_code(user, submitted)

    if not twofa_ok:
        return unauthorized("Invalid verification code")

    if not _try_mark_twofa_challenge_consumed(challenge):
        return unauthorized("Invalid or expired 2FA challenge")
    raw_token, _record = create_token_for_user(user)
    return api_ok({"token": raw_token, "user": serialize_user(user)})


@api.route("/auth/refresh", methods=["POST"])
@api_login_required(require_bearer=True)
def api_refresh_token():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return unauthorized("Bearer token required for refresh")

    raw_token = auth_header[7:].strip()
    if not raw_token:
        return unauthorized("Bearer token required for refresh")

    delete_token(raw_token)
    new_raw_token, _record = create_token_for_user(get_api_user())
    return api_ok({"token": new_raw_token, "user": serialize_user(get_api_user())})


@api.route("/auth/logout", methods=["POST"])
@api_login_required(require_bearer=True)
def api_logout():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_token = auth_header[7:].strip()
        delete_token(raw_token)

    return api_ok({"message": "Logged out"})


@api.route("/auth/password", methods=["PUT"])
@api_login_required(require_bearer=True)
def api_change_password():
    user = get_api_user()
    if not user.admin:
        return forbidden("Guest users cannot change account passwords")

    body = request.get_json(silent=True) or {}
    errors: dict = {}
    if not body.get("current_password", ""):
        errors["current_password"] = "Current password is required"
    if not body.get("new_password", ""):
        errors["new_password"] = "New password is required"
    if body.get("new_password", "") and len(body["new_password"]) < 8:
        errors["new_password"] = "New password must be at least 8 characters"
    if errors:
        return validation_error(errors)

    if not check_password_hash(user.password, body["current_password"]):
        return unauthorized("Current password is incorrect")

    user.password = generate_password_hash(body["new_password"], method="scrypt")
    UserToken.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    revoke_all_user_grants(user.id, "password_changed", commit=False)
    db.session.commit()
    return api_ok({"message": "Password updated"})


@api.route("/auth/me", methods=["GET"])
@api_login_required
def api_me():
    return api_ok(serialize_user(get_api_user()))


@api.route("/auth/complete-password-setup", methods=["POST"])
def api_complete_password_setup():
    body = request.get_json(silent=True) or {}
    token_raw = body.get("token")
    token = token_raw.strip() if isinstance(token_raw, str) else ""
    password_raw = body.get("password")
    new_password = password_raw if isinstance(password_raw, str) else ""

    errors: dict = {}
    if token_raw is not None and not isinstance(token_raw, str):
        errors["token"] = "Token must be a string"
    elif not token:
        errors["token"] = "Token is required"
    if password_raw is not None and not isinstance(password_raw, str):
        errors["password"] = "Password must be a string"
    elif not new_password:
        errors["password"] = "Password is required"
    else:
        password_error = _validate_new_password(new_password)
        if password_error:
            errors["password"] = password_error
    if errors:
        return validation_error(errors)

    user = consume_password_setup_token(token)
    if user is None:
        return unauthorized("Invalid or expired password setup token")

    user.password = generate_password_hash(new_password, method="scrypt")
    user.is_active = True
    revoke_all_user_grants(user.id, "password_reset", commit=False)
    db.session.commit()
    return api_ok({"message": "Password setup complete"})


def _api_passkey_enabled() -> bool:
    return bool(_WEBAUTHN_AVAILABLE and _passkey_enabled())


def _passkey_challenge_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="api-login-passkey")


def _purge_expired_consumed_passkey_challenges(now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    expired = [
        token
        for token, expires_at in _CONSUMED_PASSKEY_CHALLENGES.items()
        if expires_at <= now
    ]
    for token in expired:
        _CONSUMED_PASSKEY_CHALLENGES.pop(token, None)


def _is_passkey_challenge_consumed(challenge_token: str) -> bool:
    with _CONSUMED_PASSKEY_CHALLENGES_LOCK:
        _purge_expired_consumed_passkey_challenges()
        return challenge_token in _CONSUMED_PASSKEY_CHALLENGES


def _try_mark_passkey_challenge_consumed(challenge_token: str) -> bool:
    now = datetime.now(timezone.utc)
    with _CONSUMED_PASSKEY_CHALLENGES_LOCK:
        _purge_expired_consumed_passkey_challenges(now)
        if challenge_token in _CONSUMED_PASSKEY_CHALLENGES:
            return False
        _CONSUMED_PASSKEY_CHALLENGES[challenge_token] = now + timedelta(
            seconds=_PASSKEY_CHALLENGE_MAX_AGE_SECONDS
        )
        return True


def _build_passkey_challenge_token(email: str, challenge_b64url: str) -> str:
    # The payload is identical in shape for real and ineligible emails so a
    # caller cannot distinguish the two by decoding the (signed, not encrypted)
    # token. /auth/passkey/verify re-resolves the user by email and still
    # requires a matching stored credential, so ineligible emails fail there.
    payload = {
        "email": email,
        "challenge": challenge_b64url,
        "nonce": hash_token(f"{email}:{datetime.now(timezone.utc).isoformat()}"),
    }
    return _passkey_challenge_serializer().dumps(payload)


def _decode_passkey_challenge_token(challenge_token: str) -> dict | None:
    try:
        payload = _passkey_challenge_serializer().loads(
            challenge_token,
            max_age=_PASSKEY_CHALLENGE_MAX_AGE_SECONDS,
        )
    except (BadSignature, SignatureExpired):
        return None

    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("email"), str)
        or not isinstance(payload.get("challenge"), str)
    ):
        return None
    return payload


def _derive_decoy_credential_id(email: str) -> str:
    # HMAC with SECRET_KEY so the decoy id is unpredictable to callers but
    # stable across retries for the same email, matching the shape of a real
    # PasskeyCredential.credential_id (base64url of 32 bytes).
    digest = hmac.new(
        current_app.config["SECRET_KEY"].encode("utf-8"),
        f"passkey-decoy:{email}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return bytes_to_base64url(digest)


@api.route("/auth/passkey/options", methods=["POST"])
@limiter.limit("10 per minute", exempt_when=lambda: current_app.testing)
def api_passkey_login_options():
    if not _api_passkey_enabled():
        return unauthorized("Passkey authentication is not enabled")

    body = request.get_json(silent=True) or {}
    email_raw = body.get("email")
    email = email_raw.strip().lower() if isinstance(email_raw, str) else ""

    errors: dict = {}
    if not email:
        errors["email"] = "Email is required"
    if errors:
        return validation_error(errors)

    user = User.query.filter_by(email=email).first()
    eligible = (
        user is not None
        and enforce_user_access(user)
        and bool(user.passkey_credentials)
    )

    # Always return a success-shaped response so an unauthenticated caller
    # cannot enumerate which emails have passkey-enabled accounts. For
    # ineligible emails we fill allow_credentials with a deterministic decoy
    # descriptor so the response shape matches a real user with a single
    # passkey (the common case), and issue a challenge_token whose payload
    # is structurally identical to a real one. Verification naturally fails
    # at /auth/passkey/verify because no stored credential matches.
    if eligible:
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
            for c in user.passkey_credentials
        ]
    else:
        allow_credentials = [
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(_derive_decoy_credential_id(email))
            )
        ]

    options = generate_authentication_options(
        rp_id=current_app.config["PASSKEY_RP_ID"],
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge_b64url = bytes_to_base64url(options.challenge)
    challenge_token = _build_passkey_challenge_token(email, challenge_b64url)

    return api_ok({
        "challenge_token": challenge_token,
        "options": json.loads(options_to_json(options)),
    })


@api.route("/auth/passkey/verify", methods=["POST"])
@limiter.limit("10 per minute", exempt_when=lambda: current_app.testing)
def api_passkey_login_verify():
    if not _api_passkey_enabled():
        return unauthorized("Passkey authentication is not enabled")

    body = request.get_json(silent=True) or {}

    errors: dict = {}
    challenge_token_raw = body.get("challenge_token")
    challenge_token = (
        challenge_token_raw.strip() if isinstance(challenge_token_raw, str) else ""
    )
    if not challenge_token:
        errors["challenge_token"] = "Challenge token is required"
    credential = body.get("credential")
    if not isinstance(credential, dict) or not credential.get("id"):
        errors["credential"] = "Credential is required"
    if errors:
        return validation_error(errors)

    payload = _decode_passkey_challenge_token(challenge_token)
    if payload is None or _is_passkey_challenge_consumed(challenge_token):
        return unauthorized("Invalid or expired passkey challenge")

    # Mirror the eligibility check used by /auth/passkey/options and return a
    # single generic error for every post-decode failure mode. Otherwise an
    # attacker holding a decoy challenge_token for email X can distinguish
    # "active account without passkeys" (previously "Passkey not recognized")
    # from "unknown/inactive email" (previously "Invalid or expired passkey
    # challenge"), reintroducing account enumeration at /verify.
    user = User.query.filter_by(email=payload["email"]).first()
    eligible = (
        user is not None
        and enforce_user_access(user)
        and bool(user.passkey_credentials)
    )
    if not eligible:
        return unauthorized("Invalid or expired passkey challenge")

    raw_credential_id = credential.get("id")
    stored_credential = PasskeyCredential.query.filter_by(
        credential_id=raw_credential_id,
        user_id=user.id,
    ).first()
    if stored_credential is None:
        return unauthorized("Invalid or expired passkey challenge")

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(payload["challenge"]),
            expected_origin=current_app.config["PASSKEY_ORIGIN"],
            expected_rp_id=current_app.config["PASSKEY_RP_ID"],
            credential_public_key=base64url_to_bytes(stored_credential.public_key),
            credential_current_sign_count=stored_credential.sign_count,
            require_user_verification=True,
        )
    except Exception as exc:
        logger.warning("API passkey login verification failed: %s", exc)
        return unauthorized("Invalid or expired passkey challenge")

    if not _try_mark_passkey_challenge_consumed(challenge_token):
        return unauthorized("Invalid or expired passkey challenge")

    stored_credential.sign_count = verification.new_sign_count
    stored_credential.last_used_at = datetime.now(timezone.utc)
    db.session.commit()

    raw_token, _record = create_token_for_user(user)
    return api_ok({
        "token": raw_token,
        "user": serialize_user(user),
    })
