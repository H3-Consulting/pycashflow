from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify, current_app
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, Settings, PasskeyCredential, TextSettings
from app import db, limiter
from .getemail import send_new_user_notification, send_password_setup_email
from .password_setup import consume_password_setup_token, create_password_setup_link
from .totp_utils import verify_totp, decrypt_totp_secret, verify_and_consume_backup_code
from .subscription import enforce_user_access
import logging
from datetime import datetime, timezone
from functools import wraps
import json
from urllib.parse import urlparse

try:
    from webauthn import (
        generate_registration_options,
        verify_registration_response,
        generate_authentication_options,
        verify_authentication_response,
        options_to_json,
    )
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
    from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
    from webauthn.helpers.structs import (
        PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
    )
    _WEBAUTHN_AVAILABLE = True
except Exception:  # pragma: no cover - safe fallback when dependency is missing
    _WEBAUTHN_AVAILABLE = False
    generate_registration_options = None
    verify_registration_response = None
    generate_authentication_options = None
    verify_authentication_response = None
    options_to_json = None
    base64url_to_bytes = None
    bytes_to_base64url = None
    PublicKeyCredentialDescriptor = None
    UserVerificationRequirement = None
    AuthenticatorSelectionCriteria = None
    ResidentKeyRequirement = None

logger = logging.getLogger(__name__)

# Pre-computed hash used to perform a constant-time dummy check when the
# submitted email doesn't match any user, preventing username enumeration
# via response-time differences.
_DUMMY_HASH = generate_password_hash('__dummy__', method='scrypt')

auth = Blueprint('auth', __name__)


PASSKEY_CHALLENGE_TTL_SECONDS = 300


def _validate_new_password(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if password.lower() == password or password.upper() == password:
        return "Password must include uppercase and lowercase letters"
    if not any(ch.isdigit() for ch in password):
        return "Password must include at least one number"
    return None


def _passkey_enabled() -> bool:
    return bool(
        _WEBAUTHN_AVAILABLE
        and current_app.config.get("PASSKEY_RP_ID")
        and current_app.config.get("PASSKEY_RP_NAME")
        and current_app.config.get("PASSKEY_ORIGIN")
    )


def _external_signup_url() -> str | None:
    setting = TextSettings.query.filter_by(name='external_signup_url').first()
    if not setting or not setting.value:
        return None

    candidate = setting.value.strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return None
    return candidate


def _safe_next_path(raw_next: str | None) -> str | None:
    """Return ``raw_next`` if it is a safe relative path on this host.

    Rejects absolute URLs, scheme/netloc redirects, and anything outside
    a leading "/" path. The full path + query string is preserved so flows
    like Plaid's OAuth return (``/settings?oauth_state_id=...``) survive a
    detour through ``/login``.
    """
    if not raw_next:
        return None
    if not isinstance(raw_next, str):
        return None
    if not raw_next.startswith('/') or raw_next.startswith('//'):
        return None
    parsed = urlparse(raw_next)
    if parsed.scheme or parsed.netloc:
        return None
    return raw_next


@auth.route('/login')
def login():
    raw_next = request.args.get('next')
    next_url = _safe_next_path(raw_next)
    # Stash the safe next path in the session so it survives login methods
    # that don't carry hidden form fields — e.g. the Passkey button, which
    # navigates directly to /passkey_login. When this GET has no ``next``
    # query param at all (the typical failed-attempt retry path, since
    # ``login_post`` redirects back to ``/login`` without it), fall back to
    # any value already stashed so the original destination is preserved
    # across retries. But if a ``next`` was explicitly supplied and is
    # invalid/unsafe, drop the stale stash so a prior flow's destination
    # can't bleed into this one.
    if next_url:
        session['post_login_next'] = next_url
    elif raw_next is None:
        next_url = _safe_next_path(session.get('post_login_next'))
    else:
        session.pop('post_login_next', None)
    return render_template(
        'login.html',
        passkey_enabled=_passkey_enabled(),
        external_signup_url=_external_signup_url(),
        next_url=next_url,
    )


@auth.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html')

    email = (request.form.get('email') or '').strip().lower()
    success_message = (
        "If an account exists for that email, a password reset link has been sent."
    )
    if not email:
        flash("Email address is required")
        return render_template('forgot_password.html')

    user = User.query.filter_by(email=email).first()
    if user is not None:
        try:
            setup_url, expires_minutes = create_password_setup_link(user)
            sent = send_password_setup_email(
                user_name=user.name or user.email.split('@')[0],
                user_email=user.email,
                setup_url=setup_url,
                expires_minutes=expires_minutes,
            )
            if not sent:
                logger.warning("Password reset email could not be sent for user_id=%s", user.id)
        except RuntimeError:
            logger.exception("Forgot-password flow unavailable; FRONTEND_BASE_URL missing")
            flash("Password reset is currently unavailable. Please contact support.")
            return render_template('forgot_password.html')

    flash(success_message, 'success')
    return redirect(url_for('auth.login'))


@auth.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login_post():
    # login code goes here
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # Always run the hash comparison to prevent username enumeration via timing.
    # When no user is found we compare against a dummy hash so the response time
    # is indistinguishable from a wrong-password attempt for a real user.
    if user:
        password_ok = check_password_hash(user.password, password)
    else:
        check_password_hash(_DUMMY_HASH, password)
        password_ok = False

    if not password_ok:
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))

    # check if the user account is active and subscription-valid
    if not enforce_user_access(user):
        flash('Your account is pending approval. Please contact an administrator.')
        return redirect(url_for('auth.login'))

    # Preserve a safe ``next`` URL across the (optional) 2FA step so flows
    # like the Plaid OAuth redirect can land back on ``/settings?...``.
    next_url = _safe_next_path(request.form.get('next') or request.args.get('next'))
    if next_url:
        session['post_login_next'] = next_url
    else:
        session.pop('post_login_next', None)

    # If 2FA is enabled, redirect to TOTP verification step
    if user.twofa_enabled:
        session['twofa_pending_user_id'] = user.id
        session['twofa_remember'] = remember
        return redirect(url_for('auth.login_2fa'))

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    session['name'] = user.name
    session['email'] = user.email

    next_target = _safe_next_path(session.pop('post_login_next', None))
    if next_target:
        return redirect(next_target)
    return redirect(url_for('main.index'))


@auth.route('/login/2fa', methods=['GET'])
def login_2fa():
    if 'twofa_pending_user_id' not in session:
        return redirect(url_for('auth.login'))
    return render_template('2fa_verify.html')


@auth.route('/login/2fa', methods=['POST'])
@limiter.limit("10 per minute")
def login_2fa_post():
    pending_id = session.get('twofa_pending_user_id')
    if not pending_id:
        flash('Session expired. Please log in again.')
        return redirect(url_for('auth.login'))

    user = User.query.get(pending_id)
    if not user:
        session.pop('twofa_pending_user_id', None)
        session.pop('twofa_remember', None)
        flash('User not found. Please log in again.')
        return redirect(url_for('auth.login'))

    code = request.form.get('code', '').strip()
    use_backup = request.form.get('use_backup')

    verified = False

    if use_backup:
        # Attempt backup code verification
        verified = verify_and_consume_backup_code(user, code)
        if not verified:
            flash('Invalid or already-used backup code.')
            return redirect(url_for('auth.login_2fa'))
    else:
        # Attempt TOTP verification
        if user.twofa_secret:
            plain_secret = decrypt_totp_secret(user.twofa_secret)
            verified = verify_totp(plain_secret, code)
        if not verified:
            flash('Invalid or expired verification code.')
            return redirect(url_for('auth.login_2fa'))

    # Verification passed – complete login
    remember = session.pop('twofa_remember', False)
    session.pop('twofa_pending_user_id', None)

    login_user(user, remember=remember)
    session['name'] = user.name
    session['email'] = user.email

    next_target = _safe_next_path(session.pop('post_login_next', None))
    if next_target:
        return redirect(next_target)
    return redirect(url_for('main.index'))


@auth.route('/signup')
def signup():
    external_signup_url = _external_signup_url()
    if external_signup_url:
        return redirect(external_signup_url)

    try:
        setting = Settings.query.filter_by(name='signup').first()
        if setting and setting.value == 1:
            return render_template('login.html')
    except Exception as exc:
        logger.debug("Settings table not available: %s", exc)

    return render_template('signup.html')


@auth.route('/signup', methods=['POST'])
@limiter.limit("5 per minute")
def signup_post():
    external_signup_url = _external_signup_url()
    if external_signup_url:
        return redirect(external_signup_url)

    # Disabling sign-ups must block account creation, not just hide the form.
    setting = Settings.query.filter_by(name='signup').first()
    if setting and setting.value:
        flash('Sign-ups are currently disabled')
        return redirect(url_for('auth.login'))

    # code to validate and add user to database goes here
    email = (request.form.get('email') or '').strip().lower()
    name = request.form.get('name')
    password = request.form.get('password')

    if not email or not password:
        flash('Email and password are required')
        return redirect(url_for('auth.signup'))

    user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))

    # Signup never auto-elevates anyone to global admin regardless of whether an
    # admin already exists.  The bootstrap env-var path in __init__.py is the sole
    # mechanism for creating the first global admin account.
    admin = True
    is_global_admin = False
    is_active = False

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(
        email=email,
        name=name,
        password=generate_password_hash(password, method='scrypt'),
        admin=admin,
        is_global_admin=is_global_admin,
        is_active=is_active
    )

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    # Send notification to global admin if this is not the first user
    # (first user becomes global admin, so no need to notify themselves)
    if not is_global_admin:
        try:
            send_new_user_notification(name, email)
        except Exception as exc:
            # Don't fail registration if email notification fails
            logger.warning("Failed to send new user notification for %s: %s", email, exc)

    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('main.index'))


@auth.route('/auth/set-password/<token>', methods=['GET', 'POST'])
def set_password(token: str):
    setup_token = (token or "").strip()
    if not setup_token:
        flash("Invalid or expired password setup token")
        return redirect(url_for('auth.login'))

    if request.method == 'GET':
        return render_template("set_password.html", token=setup_token)

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not password:
        flash("Password is required")
        return render_template("set_password.html", token=setup_token)
    if password != confirm_password:
        flash("Passwords do not match")
        return render_template("set_password.html", token=setup_token)

    password_error = _validate_new_password(password)
    if password_error:
        flash(password_error)
        return render_template("set_password.html", token=setup_token)

    user = consume_password_setup_token(setup_token)
    if user is None:
        flash("Invalid or expired password setup token")
        return render_template("set_password.html", token=setup_token)

    user.password = generate_password_hash(password, method="scrypt")
    user.is_active = True
    db.session.commit()
    flash(
        "Password successfully set! You can sign in here or on the iOS app.",
        "success",
    )
    return redirect(url_for("auth.login"))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.admin:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('main.index'))
    return decorated_function


def global_admin_required(f):
    """
    Decorator for routes that require global admin access.
    Only users with is_global_admin=True can access.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if current_user.is_global_admin:
            return f(*args, **kwargs)
        else:
            flash('Global admin access required')
            return redirect(url_for('main.index'))
    return decorated_function


def account_owner_required(f):
    """
    Decorator for routes that require account owner access.
    Guest users (those with account_owner_id set) cannot access.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if current_user.owner_user_id is not None or current_user.account_owner_id is not None:
            flash('Account owner access required')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


@auth.route('/passkey_login')
def login_passkey():
    if not _passkey_enabled():
        flash('Passkey authentication is not enabled.')
        return redirect(url_for('auth.login'))
    raw_next = request.args.get('next')
    next_url = _safe_next_path(raw_next)
    if next_url:
        session['post_login_next'] = next_url
    elif raw_next is not None:
        # ``next`` was supplied but unsafe — clear any stale stash so a
        # prior flow's destination can't carry over.
        session.pop('post_login_next', None)
    # If no ``next`` is provided at all (e.g. the user clicked the "Sign In
    # with Passkey" link from ``/login?next=/settings``, which doesn't
    # forward the query param), leave any previously stashed value alone
    # so the original post-login destination survives.
    return render_template('passkey_login.html')


@auth.route('/passkey_login/options', methods=['POST'])
@limiter.limit("10 per minute")
def passkey_login_options():
    if not _passkey_enabled():
        return jsonify({"error": "Passkey authentication is not enabled."}), 400

    payload = request.get_json(silent=True) or {}
    email = (payload.get('email') or '').strip().lower()
    if not email:
        return jsonify({"error": "Unable to start passkey login."}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not enforce_user_access(user) or not user.passkey_credentials:
        return jsonify({"error": "Unable to start passkey login."}), 400

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
        for c in user.passkey_credentials
    ]
    options = generate_authentication_options(
        rp_id=current_app.config["PASSKEY_RP_ID"],
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    session["passkey_login_challenge"] = bytes_to_base64url(options.challenge)
    session["passkey_login_user_id"] = user.id
    session["passkey_login_expires_at"] = int(datetime.now(timezone.utc).timestamp()) + PASSKEY_CHALLENGE_TTL_SECONDS

    return jsonify(json.loads(options_to_json(options)))


@auth.route('/passkey_login/verify', methods=['POST'])
@limiter.limit("10 per minute")
def login_passkey_post():
    if not _passkey_enabled():
        flash('Passkey authentication is not enabled.')
        return redirect(url_for('auth.login'))

    challenge = session.get("passkey_login_challenge")
    user_id = session.get("passkey_login_user_id")
    expires_at = session.get("passkey_login_expires_at", 0)
    if not challenge or not user_id or int(datetime.now(timezone.utc).timestamp()) > int(expires_at):
        flash("Passkey authentication session expired. Please try again.")
        return redirect(url_for('auth.login_passkey'))

    credential = request.get_json(silent=True) or {}
    raw_id = credential.get("id")
    if not raw_id:
        flash("Invalid passkey response.")
        return redirect(url_for('auth.login_passkey'))

    user = User.query.get(user_id)
    stored_credential = PasskeyCredential.query.filter_by(credential_id=raw_id, user_id=user_id).first()
    if not user or not stored_credential:
        flash("Passkey not recognized for this account.")
        return redirect(url_for('auth.login_passkey'))

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_origin=current_app.config["PASSKEY_ORIGIN"],
            expected_rp_id=current_app.config["PASSKEY_RP_ID"],
            credential_public_key=base64url_to_bytes(stored_credential.public_key),
            credential_current_sign_count=stored_credential.sign_count,
            require_user_verification=True,
        )
    except Exception as exc:
        logger.warning("Passkey login verification failed: %s", exc)
        flash("Passkey verification failed. Please try again.")
        return redirect(url_for('auth.login'))

    if not enforce_user_access(user):
        flash('Your account is pending approval. Please contact an administrator.')
        return redirect(url_for('auth.login'))

    stored_credential.sign_count = verification.new_sign_count
    stored_credential.last_used_at = datetime.now(timezone.utc)
    db.session.commit()
    session.pop("passkey_login_challenge", None)
    session.pop("passkey_login_user_id", None)
    session.pop("passkey_login_expires_at", None)

    login_user(user, remember=True)
    session['name'] = user.name
    session['email'] = user.email

    next_target = _safe_next_path(session.pop('post_login_next', None))
    if next_target:
        return redirect(next_target)
    return redirect(url_for('main.index'))


@auth.route('/passkeys')
@login_required
def manage_passkeys():
    if not _passkey_enabled():
        flash('Passkey authentication is not enabled.')
        return redirect(url_for('main.settings'))
    return render_template('passkey_manage.html', credentials=current_user.passkey_credentials)


@auth.route('/passkeys/register/options', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def passkey_register_options():
    if not _passkey_enabled():
        return jsonify({"error": "Passkey authentication is not enabled."}), 400

    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
        for c in current_user.passkey_credentials
    ]
    options = generate_registration_options(
        rp_id=current_app.config["PASSKEY_RP_ID"],
        rp_name=current_app.config["PASSKEY_RP_NAME"],
        user_id=str(current_user.id).encode("utf-8"),
        user_name=current_user.email,
        user_display_name=current_user.name or current_user.email,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    session["passkey_register_challenge"] = bytes_to_base64url(options.challenge)
    session["passkey_register_expires_at"] = int(datetime.now(timezone.utc).timestamp()) + PASSKEY_CHALLENGE_TTL_SECONDS
    return jsonify(json.loads(options_to_json(options)))


@auth.route('/passkeys/register/verify', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def passkey_register_verify():
    if not _passkey_enabled():
        return jsonify({"error": "Passkey authentication is not enabled."}), 400

    challenge = session.get("passkey_register_challenge")
    expires_at = session.get("passkey_register_expires_at", 0)
    if not challenge or int(datetime.now(timezone.utc).timestamp()) > int(expires_at):
        return jsonify({"error": "Passkey registration session expired."}), 400

    credential = request.get_json(silent=True) or {}
    label = (credential.pop("label", "") or "").strip()[:120] or None
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_origin=current_app.config["PASSKEY_ORIGIN"],
            expected_rp_id=current_app.config["PASSKEY_RP_ID"],
            require_user_verification=True,
        )
    except Exception as exc:
        logger.warning("Passkey registration verification failed: %s", exc)
        return jsonify({"error": "Passkey registration verification failed."}), 400

    credential_id = bytes_to_base64url(verification.credential_id)
    existing = PasskeyCredential.query.filter_by(credential_id=credential_id).first()
    if existing:
        return jsonify({"error": "This passkey is already registered."}), 400

    new_credential = PasskeyCredential(
        user_id=current_user.id,
        credential_id=credential_id,
        public_key=bytes_to_base64url(verification.credential_public_key),
        sign_count=verification.sign_count,
        transports=None,
        label=label,
        last_used_at=datetime.now(timezone.utc),
    )
    db.session.add(new_credential)
    db.session.commit()
    session.pop("passkey_register_challenge", None)
    session.pop("passkey_register_expires_at", None)
    return jsonify({"ok": True})


@auth.route('/passkeys/<int:credential_id>/delete', methods=['POST'])
@login_required
def delete_passkey(credential_id: int):
    credential = PasskeyCredential.query.filter_by(id=credential_id, user_id=current_user.id).first()
    if not credential:
        flash('Passkey not found.')
        return redirect(url_for('auth.manage_passkeys'))
    db.session.delete(credential)
    db.session.commit()
    flash('Passkey removed.')
    return redirect(url_for('auth.manage_passkeys'))
