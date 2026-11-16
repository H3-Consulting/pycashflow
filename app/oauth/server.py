"""Authlib-based OAuth 2.1 authorization server for MCP clients.

Authlib supplies the protocol machinery (RFC 6749 grants and errors, RFC 7636
PKCE, RFC 7009 revocation, RFC 7591 registration, RFC 9207 ``iss``). This
module layers PyCashFlow policy on top through Authlib's subclass hooks:

* PKCE is mandatory for every client and only ``S256`` is accepted.
* ``redirect_uri`` must always be sent and must exactly match a registered URI
  (loopback URIs match on any port per RFC 8252).
* RFC 8707: the ``resource`` must be this server's MCP endpoint; it is bound to
  the code and every token, and checked again at the token endpoint.
* Authorization codes expire after 5 minutes and are claimed atomically; a
  replayed code revokes everything issued from it.
* Refresh tokens rotate on every use and are claimed atomically; re-use of a
  rotated refresh token outside a short retry grace revokes the whole grant.
* Tokens are opaque, prefixed and stored only as SHA-256 hashes.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import InvalidGrantError, InvalidRequestError, InvalidScopeError, OAuth2Error
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant, RefreshTokenGrant
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint, InvalidClientMetadataError, InvalidRedirectURIError
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc9207 import IssuerParameter
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from app import db
from app.models import OAuthAuthorizationCode, OAuthClient, OAuthGrant, OAuthToken, User
from app.subscription import enforce_user_access

from . import audit, cimd
from .scopes import IGNORED_SCOPES, SCOPE_DESCRIPTIONS, join_scope, split_scope
from .security import (
    ACCESS_TOKEN_PREFIX,
    CLIENT_SECRET_PREFIX,
    CODE_PREFIX,
    REFRESH_TOKEN_PREFIX,
    RedirectPolicy,
    constant_time_equals,
    new_secret,
    normalize_resource,
    sha256_hex,
)
from .tokens import (
    REFRESH_REUSE_GRACE, collect_garbage, grant_is_live, revoke_grant, revoke_grant_by_id, utcnow,
)

logger = logging.getLogger(__name__)

TOKEN_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"]


class InvalidTargetError(OAuth2Error):
    """RFC 8707 ``invalid_target``: the requested resource is not served here."""

    error = "invalid_target"


# ── Model adapters (Authlib's mixin interfaces over our rows) ───────────────


class ClientAdapter:
    def __init__(self, row: OAuthClient, policy: RedirectPolicy):
        self.row = row
        self.policy = policy
        self.client_id = row.client_id
        self.client_name = row.client_name
        self.registration_type = row.registration_type
        self.redirect_uris = json.loads(row.redirect_uris or "[]")
        self.grant_types = json.loads(row.grant_types or "[]")
        self.token_endpoint_auth_method = row.token_endpoint_auth_method

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        # OAuth 2.1 / MCP: clients must always send redirect_uri explicitly.
        return None

    def get_allowed_scope(self, scope):
        requested = [s for s in split_scope(scope) if s not in IGNORED_SCOPES]
        if not requested:
            return join_scope(SCOPE_DESCRIPTIONS)
        if any(s not in SCOPE_DESCRIPTIONS for s in requested):
            return None
        return join_scope(requested)

    def check_redirect_uri(self, redirect_uri):
        # Re-check the live server policy too, so tightening the allowlist
        # takes effect for clients registered earlier.
        if self.policy.check_registration(redirect_uri) is not None:
            return False
        return any(RedirectPolicy.matches(reg, redirect_uri) for reg in self.redirect_uris)

    def check_client_secret(self, client_secret):
        if not self.row.client_secret_hash or not isinstance(client_secret, str):
            return False
        return constant_time_equals(sha256_hex(client_secret), self.row.client_secret_hash)

    def check_endpoint_auth_method(self, method, endpoint):
        return method == self.token_endpoint_auth_method

    def check_response_type(self, response_type):
        return response_type == "code"

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types


class CodeAdapter:
    def __init__(self, row: OAuthAuthorizationCode):
        self.row = row
        self.code_challenge = row.code_challenge
        self.code_challenge_method = row.code_challenge_method

    def get_redirect_uri(self):
        return self.row.redirect_uri

    def get_scope(self):
        return self.row.scope


class TokenAdapter:
    def __init__(self, row: OAuthToken, kind: str):
        self.row = row
        self.kind = kind  # "access_token" or "refresh_token"

    def check_client(self, client):
        return client is not None and client.get_client_id() == self.row.client_id

    def get_scope(self):
        return self.row.scope

    def get_expires_in(self):
        return int((self.row.access_expires_at - utcnow()).total_seconds())

    def is_expired(self):
        return self.row.access_expires_at <= utcnow()

    def is_revoked(self):
        return self.row.access_revoked_at is not None

    def get_user(self):
        return db.session.get(User, self.row.user_id)

    def get_client(self):  # pragma: no cover - not used by our grants
        return None


# ── PKCE: mandatory, S256 only ───────────────────────────────────────────────


class StrictCodeChallenge(CodeChallenge):
    DEFAULT_CODE_CHALLENGE_METHOD = "S256"
    SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]

    def validate_code_challenge(self, grant, redirect_uri):
        data = grant.request.payload.data
        if not data.get("code_challenge"):
            raise InvalidRequestError("code_challenge is required (PKCE)")
        if data.get("code_challenge_method") != "S256":
            raise InvalidRequestError("code_challenge_method must be S256")
        super().validate_code_challenge(grant, redirect_uri)

    def validate_code_verifier(self, grant, result):
        if not grant.request.form.get("code_verifier"):
            raise InvalidRequestError("Missing 'code_verifier'")
        super().validate_code_verifier(grant, result)


# ── Grants ───────────────────────────────────────────────────────────────────


def _resource_param(request) -> list[str]:
    return request.payload.datalist.get("resource", [])


class PCFAuthorizationCodeGrant(AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = TOKEN_AUTH_METHODS

    def validate_authorization_request(self):
        redirect_uri = super().validate_authorization_request()
        config = self.server.config
        values = _resource_param(self.request)
        if len(values) > 1:
            raise InvalidTargetError("Only one resource may be requested", redirect_uri=redirect_uri)
        if values:
            if normalize_resource(values[0]) != normalize_resource(config.resource):
                raise InvalidTargetError(
                    "The requested resource is not served by this authorization server",
                    redirect_uri=redirect_uri,
                )
        self.request.pcf_resource = config.resource
        prompt = self.request.payload.data.get("prompt")
        if prompt and "none" in prompt.split():
            # Consent is always interactive here; silent authorization is refused.
            raise _ConsentRequiredError(redirect_uri=redirect_uri)
        return redirect_uri

    def generate_authorization_code(self):
        return new_secret(CODE_PREFIX)

    def save_authorization_code(self, code, request):
        config = self.server.config
        granted = getattr(request, "pcf_granted_scope", None) or request.scope
        db.session.add(OAuthAuthorizationCode(
            code_hash=sha256_hex(code),
            client_id=request.client.get_client_id(),
            user_id=request.user.id,
            redirect_uri=request.payload.redirect_uri,
            scope=granted,
            resource=getattr(request, "pcf_resource", config.resource),
            code_challenge=request.payload.data.get("code_challenge"),
            code_challenge_method="S256",
            expires_at=utcnow() + timedelta(seconds=config.code_ttl),
        ))
        db.session.commit()

    def query_authorization_code(self, code, client):
        if not isinstance(code, str) or not code.startswith(CODE_PREFIX):
            return None
        row = OAuthAuthorizationCode.query.filter_by(code_hash=sha256_hex(code)).first()
        if row is None or row.client_id != client.get_client_id():
            return None
        now = utcnow()
        # Atomic single-use claim: only one redemption can flip used_at.
        claimed = db.session.execute(
            update(OAuthAuthorizationCode)
            .where(OAuthAuthorizationCode.id == row.id, OAuthAuthorizationCode.used_at.is_(None))
            .values(used_at=now)
        ).rowcount
        db.session.commit()
        if claimed != 1:
            db.session.refresh(row)
            revoke_grant_by_id(row.grant_id, "code_replay")
            audit.record_event(
                action="oauth.code_replay", outcome="denied", user_id=row.user_id,
                client_id=row.client_id, grant_id=row.grant_id, error_code="invalid_grant",
            )
            return None
        if row.expires_at <= now:
            return None
        return CodeAdapter(row)

    def validate_token_request(self):
        super().validate_token_request()
        values = _resource_param(self.request)
        if len(values) > 1:
            raise InvalidTargetError("Only one resource may be requested")
        bound = self.request.authorization_code.row.resource
        if values and normalize_resource(values[0]) != normalize_resource(bound):
            raise InvalidTargetError("resource does not match the authorization request")

    def delete_authorization_code(self, authorization_code):
        # Codes are claimed (not deleted) so replays can be detected.
        return None

    def authenticate_user(self, authorization_code):
        user = db.session.get(User, authorization_code.row.user_id)
        if user is None or not enforce_user_access(user):
            return None
        return user


class _ConsentRequiredError(OAuth2Error):
    error = "consent_required"
    description = "Interactive consent is required"


class PCFRefreshTokenGrant(RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = TOKEN_AUTH_METHODS
    INCLUDE_NEW_REFRESH_TOKEN = True

    def validate_token_request(self):
        client = self._validate_request_client()
        self.request.client = client
        token = self._validate_request_token(client)
        self._validate_token_scope(token)
        values = _resource_param(self.request)
        if len(values) > 1 or (
            values and normalize_resource(values[0]) != normalize_resource(token.row.resource)
        ):
            raise InvalidTargetError("resource does not match the original grant")
        # Atomic rotation claim: exactly one request can consume this token.
        claimed = db.session.execute(
            update(OAuthToken)
            .where(OAuthToken.id == token.row.id, OAuthToken.refresh_revoked_at.is_(None))
            .values(refresh_revoked_at=utcnow(), refresh_revoked_reason="rotated")
        ).rowcount
        db.session.commit()
        if claimed != 1:
            raise InvalidGrantError()
        self.request.refresh_token = token

    def authenticate_refresh_token(self, refresh_token):
        if not isinstance(refresh_token, str) or not refresh_token.startswith(REFRESH_TOKEN_PREFIX):
            return None
        row = OAuthToken.query.filter_by(refresh_token_hash=sha256_hex(refresh_token)).first()
        if row is None:
            return None
        now = utcnow()
        grant = db.session.get(OAuthGrant, row.grant_id)
        if row.refresh_revoked_at is not None:
            if (
                row.refresh_revoked_reason == "rotated"
                and now - row.refresh_revoked_at > REFRESH_REUSE_GRACE
                and grant is not None
                and grant.revoked_at is None
            ):
                # A rotated refresh token was replayed: assume theft.
                revoke_grant(grant, "refresh_replay")
                audit.record_event(
                    action="oauth.refresh_replay", outcome="denied", user_id=row.user_id,
                    client_id=row.client_id, grant_id=grant.id, error_code="invalid_grant",
                )
            return None
        if row.refresh_expires_at is None or row.refresh_expires_at <= now:
            return None
        if not grant_is_live(grant, now):
            return None
        user = db.session.get(User, row.user_id)
        if user is None or not enforce_user_access(user):
            return None
        return TokenAdapter(row, "refresh_token")

    def authenticate_user(self, refresh_token):
        return refresh_token.get_user()

    def revoke_old_credential(self, refresh_token):
        # Already revoked atomically during validation.
        return None


# ── Endpoints ────────────────────────────────────────────────────────────────


class PCFRevocationEndpoint(RevocationEndpoint):
    CLIENT_AUTH_METHODS = TOKEN_AUTH_METHODS

    def query_token(self, token_string, token_type_hint):
        if not isinstance(token_string, str):
            return None
        digest = sha256_hex(token_string)
        if token_string.startswith(ACCESS_TOKEN_PREFIX):
            row = OAuthToken.query.filter_by(access_token_hash=digest).first()
            return TokenAdapter(row, "access_token") if row else None
        if token_string.startswith(REFRESH_TOKEN_PREFIX):
            row = OAuthToken.query.filter_by(refresh_token_hash=digest).first()
            return TokenAdapter(row, "refresh_token") if row else None
        return None

    def revoke_token(self, token, request):
        row = token.row
        if token.kind == "refresh_token":
            grant = db.session.get(OAuthGrant, row.grant_id)
            if grant is not None:
                revoke_grant(grant, "client_revoked")
        else:
            row.access_revoked_at = row.access_revoked_at or utcnow()
            db.session.commit()
        audit.record_event(
            action="oauth.token_revoked", outcome="success", user_id=row.user_id,
            client_id=row.client_id, grant_id=row.grant_id, resource_type=token.kind,
        )


class PCFClientRegistrationEndpoint(ClientRegistrationEndpoint):
    """RFC 7591 open registration constrained by the redirect allowlist."""

    def authenticate_token(self, request):
        # Open registration is what MCP clients require; abuse is contained by
        # rate limits, the redirect allowlist, client GC and mandatory consent.
        return {"open_registration": True}

    def get_server_metadata(self):
        return authorization_server_metadata(self.server.config)

    def resolve_public_key(self, request):  # pragma: no cover - software statements unsupported
        return None

    def generate_client_id(self, request):
        return new_secret("pcf_dcr_", 24)

    def generate_client_info(self, request):
        info = super().generate_client_info(request)
        method = (request.payload.data or {}).get("token_endpoint_auth_method", "client_secret_basic")
        if method == "none":
            info.pop("client_secret", None)
            info.pop("client_secret_expires_at", None)
        else:
            info["client_secret"] = new_secret(CLIENT_SECRET_PREFIX)
        return info

    def save_client(self, client_info, client_metadata, request):
        config = self.server.config
        policy = self.server.redirect_policy
        redirect_uris = client_metadata.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris or len(redirect_uris) > 20:
            raise InvalidRedirectURIError("Provide between 1 and 20 redirect_uris")
        for uri in redirect_uris:
            reason = policy.check_registration(uri)
            if reason:
                raise InvalidRedirectURIError(reason)
        grant_types = client_metadata.get("grant_types") or ["authorization_code"]
        if "authorization_code" not in grant_types or set(grant_types) - {"authorization_code", "refresh_token"}:
            raise InvalidClientMetadataError("grant_types must be authorization_code [+ refresh_token]")
        response_types = client_metadata.get("response_types") or ["code"]
        if response_types != ["code"]:
            raise InvalidClientMetadataError("response_types must be ['code']")
        method = client_metadata.get("token_endpoint_auth_method", "client_secret_basic")
        if method not in TOKEN_AUTH_METHODS:
            raise InvalidClientMetadataError("Unsupported token_endpoint_auth_method")
        name = client_metadata.get("client_name")
        if name is not None and not isinstance(name, str):
            raise InvalidClientMetadataError("client_name must be a string")
        name = cimd._clean_display(name or "")[:200] or "Unnamed application"
        client_uri = client_metadata.get("client_uri")
        if client_uri is not None and not (isinstance(client_uri, str) and client_uri.startswith("https://")):
            client_uri = None
        if OAuthClient.query.filter_by(registration_type="dcr").count() >= config.max_dcr_clients:
            # Under pressure, reclaim registrations that never completed an
            # authorization within the last hour before refusing new ones.
            collect_garbage(max_dcr_idle=timedelta(hours=1))
            if OAuthClient.query.filter_by(registration_type="dcr").count() >= config.max_dcr_clients:
                raise InvalidClientMetadataError("Client registration is temporarily unavailable")
        secret = client_info.get("client_secret")
        row = OAuthClient(
            client_id=client_info["client_id"],
            registration_type="dcr",
            client_secret_hash=sha256_hex(secret) if secret else None,
            client_name=name,
            client_uri=client_uri[:512] if client_uri else None,
            redirect_uris=json.dumps(redirect_uris),
            grant_types=json.dumps(list(dict.fromkeys(grant_types))),
            response_types=json.dumps(["code"]),
            scope=join_scope(s for s in split_scope(client_metadata.get("scope")) if s in SCOPE_DESCRIPTIONS) or None,
            token_endpoint_auth_method=method,
        )
        db.session.add(row)
        db.session.commit()
        audit.record_event(action="oauth.client_registered", outcome="success", client_id=row.client_id)
        return row


# ── Server ───────────────────────────────────────────────────────────────────


class PCFIssuerParameter(IssuerParameter):
    def __init__(self, issuer: str):
        self.issuer = issuer

    def get_issuer(self):
        return self.issuer


class PyCashFlowAuthorizationServer(AuthorizationServer):
    def __init__(self, app, config):
        self.config = config
        self.redirect_policy = RedirectPolicy(config.allowed_redirect_uris, config.allow_loopback_redirects)
        super().__init__(app, query_client=self._query_client, save_token=self._save_token)
        self.scopes_supported = list(config.scopes)
        self.register_token_generator("default", self._generate_token)

    def load_config(self, app_config):
        # Token generation is handled by _generate_token; skip Authlib's
        # OAUTH2_* config-driven generator setup.
        self._error_uris = None

    def validate_requested_scope(self, scope):
        requested = [s for s in split_scope(scope) if s not in IGNORED_SCOPES]
        if any(s not in SCOPE_DESCRIPTIONS for s in requested):
            raise InvalidScopeError()

    def _query_client(self, client_id):
        if not isinstance(client_id, str) or not client_id or len(client_id) > 512:
            return None
        if cimd.is_cimd_client_id(client_id):
            if not self.config.cimd_enabled:
                return None
            try:
                row = cimd.resolve_cimd_client(client_id, self.config, self.redirect_policy, OAuthClient, db)
            except cimd.CimdError as exc:
                logger.info("Rejected client metadata document: %s", exc)
                return None
            except IntegrityError:
                db.session.rollback()
                row = OAuthClient.query.filter_by(client_id=client_id, registration_type="cimd").first()
            return ClientAdapter(row, self.redirect_policy) if row is not None and row.is_active else None
        row = OAuthClient.query.filter_by(client_id=client_id, registration_type="dcr").first()
        if row is None or not row.is_active or not self.config.dcr_enabled:
            return None
        return ClientAdapter(row, self.redirect_policy)

    def _generate_token(self, grant_type, client, user=None, scope=None, expires_in=None,
                        include_refresh_token=True):
        token = {
            "token_type": "Bearer",
            "access_token": new_secret(ACCESS_TOKEN_PREFIX),
            "expires_in": self.config.access_token_ttl,
            "scope": scope or "",
        }
        if include_refresh_token:
            token["refresh_token"] = new_secret(REFRESH_TOKEN_PREFIX, 48)
        return token

    def _save_token(self, token, request):
        now = utcnow()
        client = request.client
        if request.payload.grant_type == "authorization_code":
            code_row = request.authorization_code.row
            grant = OAuthGrant(
                user_id=request.user.id,
                client_id=client.get_client_id(),
                client_name=client.client_name,
                scope=code_row.scope,
                resource=code_row.resource,
                expires_at=(now + timedelta(seconds=self.config.grant_max_age)) if self.config.grant_max_age else None,
                last_used_at=now,
            )
            db.session.add(grant)
            db.session.flush()
            code_row.grant_id = grant.id
            resource = code_row.resource
            action = "oauth.grant_created"
        else:
            old = request.refresh_token.row
            grant = db.session.get(OAuthGrant, old.grant_id)
            resource = old.resource
            action = "oauth.token_refreshed"
        refresh_expiry = None
        if token.get("refresh_token"):
            refresh_expiry = now + timedelta(seconds=self.config.refresh_token_ttl)
            if grant.expires_at is not None:
                refresh_expiry = min(refresh_expiry, grant.expires_at)
        db.session.add(OAuthToken(
            grant_id=grant.id,
            user_id=request.user.id,
            client_id=client.get_client_id(),
            scope=token.get("scope") or grant.scope,
            resource=resource,
            access_token_hash=sha256_hex(token["access_token"]),
            refresh_token_hash=sha256_hex(token["refresh_token"]) if token.get("refresh_token") else None,
            issued_at=now,
            access_expires_at=now + timedelta(seconds=self.config.access_token_ttl),
            refresh_expires_at=refresh_expiry,
        ))
        db.session.commit()
        audit.record_event(
            action=action, outcome="success", user_id=request.user.id,
            client_id=client.get_client_id(), grant_id=grant.id,
        )


def authorization_server_metadata(config) -> dict:
    """RFC 8414 metadata (with RFC 9207 and CIMD extensions)."""
    issuer = config.issuer
    metadata = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "scopes_supported": list(config.scopes),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": list(TOKEN_AUTH_METHODS),
        "revocation_endpoint_auth_methods_supported": list(TOKEN_AUTH_METHODS),
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
        "client_id_metadata_document_supported": bool(config.cimd_enabled),
        "service_documentation": f"{issuer}/settings/connected-apps",
    }
    if config.dcr_enabled:
        metadata["registration_endpoint"] = f"{issuer}/oauth/register"
    return metadata


def protected_resource_metadata(config) -> dict:
    """RFC 9728 metadata for the MCP endpoint."""
    return {
        "resource": config.resource,
        "authorization_servers": [config.issuer],
        "scopes_supported": list(config.scopes),
        "bearer_methods_supported": ["header"],
        "resource_name": "PyCashFlow",
    }


def create_authorization_server(app, config) -> PyCashFlowAuthorizationServer:
    server = PyCashFlowAuthorizationServer(app, config)
    server.register_grant(PCFAuthorizationCodeGrant, [StrictCodeChallenge(required=True)])
    server.register_grant(PCFRefreshTokenGrant)
    server.register_endpoint(PCFRevocationEndpoint)
    if config.dcr_enabled:
        server.register_endpoint(PCFClientRegistrationEndpoint)
    server.register_extension(PCFIssuerParameter(config.issuer))
    return server
