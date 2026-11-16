"""Flask routes for the OAuth authorization server and connected-apps page."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from urllib.parse import urlsplit

from authlib.common.urls import add_params_to_uri
from authlib.oauth2.rfc6749 import OAuth2Error
from flask import (
    Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app import db, limiter
from app.models import OAuthAuditEvent, OAuthClient, OAuthGrant
from app.services.access import can_write_financial_data, is_guest

from . import audit
from .scopes import SCOPE_DESCRIPTIONS, WRITE_SCOPES, join_scope, split_scope
from .security import is_loopback_redirect
from .server import authorization_server_metadata, protected_resource_metadata
from .tokens import collect_garbage, grant_is_live, revoke_grant, utcnow

logger = logging.getLogger(__name__)

oauth_bp = Blueprint("oauth", __name__)

CONSENT_TICKET_MAX_AGE = 600
_GC_INTERVAL_SECONDS = 600
_gc_lock = threading.Lock()
_last_gc = 0.0

_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, MCP-Protocol-Version",
    "Access-Control-Max-Age": "600",
}


def _server():
    return current_app.extensions["pycashflow_oauth_server"]


def _config():
    return current_app.extensions["pycashflow_oauth_config"]


def _with_cors(response):
    # Only cookie-less, public endpoints get CORS (metadata, token, register,
    # revoke) so browser-based MCP clients such as MCP Inspector work. The
    # authorization/consent page never does.
    for key, value in _CORS_HEADERS.items():
        response.headers[key] = value
    return response


def _json_metadata(payload: dict):
    response = jsonify(payload)
    response.headers["Cache-Control"] = "public, max-age=3600"
    return _with_cors(response)


def _maybe_collect_garbage() -> None:
    global _last_gc
    now = time.monotonic()
    if now - _last_gc < _GC_INTERVAL_SECONDS or not _gc_lock.acquire(blocking=False):
        return
    try:
        _last_gc = now
        collect_garbage()
    except Exception:  # pragma: no cover - housekeeping must not fail requests
        db.session.rollback()
        logger.exception("OAuth garbage collection failed")
    finally:
        _gc_lock.release()


# ── Discovery ────────────────────────────────────────────────────────────────


@oauth_bp.route("/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"])
@limiter.exempt
def authorization_server_metadata_view():
    if request.method == "OPTIONS":
        return _with_cors(current_app.response_class(status=204))
    return _json_metadata(authorization_server_metadata(_config()))


@oauth_bp.route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
@oauth_bp.route("/.well-known/oauth-protected-resource/mcp", methods=["GET", "OPTIONS"])
@limiter.exempt
def protected_resource_metadata_view():
    if request.method == "OPTIONS":
        return _with_cors(current_app.response_class(status=204))
    return _json_metadata(protected_resource_metadata(_config()))


@oauth_bp.route("/.well-known/openai-apps-challenge", methods=["GET"])
@limiter.exempt
def openai_apps_challenge():
    """Serve the OpenAI plugin portal's domain-verification token, if set."""
    token = current_app.config.get("OPENAI_APPS_CHALLENGE_TOKEN") or ""
    if not token or len(token) > 512 or not token.isprintable():
        abort(404)
    return current_app.response_class(token, mimetype="text/plain")


# ── Registration, token, revocation (machine endpoints, CSRF-exempt) ─────────


def _oauth_json_error(error: str, description: str, status: int = 400):
    response = jsonify({"error": error, "error_description": description})
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return _with_cors(response)


@oauth_bp.route("/oauth/register", methods=["POST", "OPTIONS"])
@limiter.limit("20 per hour;100 per day", methods=["POST"])
def register_client():
    if request.method == "OPTIONS":
        return _with_cors(current_app.response_class(status=204))
    if not _config().dcr_enabled:
        return _oauth_json_error("access_denied", "Dynamic client registration is disabled", 403)
    if (request.content_length or 0) > 16 * 1024:
        return _oauth_json_error("invalid_client_metadata", "Registration request is too large", 413)
    if not request.is_json or not isinstance(request.get_json(silent=True), dict):
        return _oauth_json_error("invalid_client_metadata", "Registration body must be a JSON object")
    _maybe_collect_garbage()
    response = _server().create_endpoint_response("client_registration")
    response.headers["Cache-Control"] = "no-store"
    return _with_cors(response)


@oauth_bp.route("/oauth/token", methods=["POST", "OPTIONS"])
@limiter.limit("60 per minute", methods=["POST"])
def issue_token():
    if request.method == "OPTIONS":
        return _with_cors(current_app.response_class(status=204))
    response = _server().create_token_response()
    _maybe_collect_garbage()  # throttled housekeeping; clients refresh hourly
    return _with_cors(response)


@oauth_bp.route("/oauth/revoke", methods=["POST", "OPTIONS"])
@limiter.limit("60 per minute", methods=["POST"])
def revoke_token():
    if request.method == "OPTIONS":
        return _with_cors(current_app.response_class(status=204))
    return _with_cors(_server().create_endpoint_response("revocation"))


# ── Authorization + consent ─────────────────────────────────────────────────


def _ticket_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="pycashflow-oauth-consent")


def _request_fingerprint(grant) -> str:
    data = grant.request.payload.data
    parts = [
        grant.client.get_client_id(),
        data.get("redirect_uri") or "",
        data.get("code_challenge") or "",
        grant.request.scope or "",
        getattr(grant.request, "pcf_resource", "") or "",
        data.get("state") or "",
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _issue_ticket(user_id: int, grant) -> str:
    return _ticket_serializer().dumps({"u": user_id, "f": _request_fingerprint(grant)})


def _ticket_valid(ticket: str | None, user_id: int, grant) -> bool:
    if not ticket:
        return False
    try:
        payload = _ticket_serializer().loads(ticket, max_age=CONSENT_TICKET_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return False
    return payload.get("u") == user_id and payload.get("f") == _request_fingerprint(grant)


def _render_authorize_error(message: str, status: int = 400):
    return render_template("oauth_error.html", message=message), status


def _error_redirect(error: OAuth2Error):
    """Return a redirect for errors whose redirect URI was already validated."""
    params = [("error", error.error)]
    if error.description:
        params.append(("error_description", error.description))
    state = request.values.get("state")
    if state:
        params.append(("state", state))
    params.append(("iss", _config().issuer))
    return redirect(add_params_to_uri(error.redirect_uri, params), code=302)


def _client_identity(client) -> dict:
    if client.registration_type == "cimd":
        host = urlsplit(client.get_client_id()).hostname or ""
        return {"verified_host": host, "self_registered": False}
    return {"verified_host": None, "self_registered": True}


def _scope_choices(scopes: list[str], user) -> tuple[list[dict], list[str]]:
    writable = can_write_financial_data(user)
    choices, withheld = [], []
    for scope in scopes:
        if scope in WRITE_SCOPES and not writable:
            withheld.append(scope)
            continue
        title, detail = SCOPE_DESCRIPTIONS[scope]
        choices.append({"scope": scope, "title": title, "detail": detail, "write": scope in WRITE_SCOPES})
    return choices, withheld


@oauth_bp.route("/oauth/authorize", methods=["GET", "POST"])
@limiter.limit("30 per minute", methods=["POST"])
def authorize():
    if not current_user.is_authenticated:
        if request.method == "POST":
            return _render_authorize_error("Your session expired. Start the connection again from your app.", 401)
        # Reuse the normal sign-in (password, 2FA, passkey); it returns here.
        return redirect(url_for("auth.login", next=request.full_path))

    user = current_user._get_current_object()
    server = _server()
    try:
        grant = server.get_consent_grant(end_user=user)
    except OAuth2Error as error:
        if error.redirect_uri:
            return _error_redirect(error)
        logger.info("Rejected authorization request: %s", error.error)
        return _render_authorize_error(
            "This connection request is not valid. Return to your app and try connecting again."
        )

    client = grant.client
    redirect_uri = grant.request.payload.redirect_uri
    requested = split_scope(grant.request.scope)
    choices, withheld = _scope_choices(requested, user)
    context = {
        "client_name": client.client_name or "Unnamed application",
        "identity": _client_identity(client),
        "redirect_host": urlsplit(redirect_uri).hostname,
        "loopback": is_loopback_redirect(redirect_uri),
        "choices": choices,
        "withheld": [SCOPE_DESCRIPTIONS[s][0] for s in withheld],
        "is_guest": is_guest(user),
        "account_email": user.email,
    }

    if request.method == "GET":
        if not choices:
            return _error_redirect_from_denial(grant, user, "No requested permission is available to this account")
        return render_template("oauth_consent.html", ticket=_issue_ticket(user.id, grant), **context)

    if not _ticket_valid(request.form.get("consent_ticket"), user.id, grant):
        return _render_authorize_error(
            "This approval page expired or did not match the request. Start the connection again from your app."
        )

    if request.form.get("decision") != "approve":
        audit.record_event(action="oauth.consent_denied", outcome="denied", user_id=user.id,
                           client_id=client.get_client_id())
        return server.create_authorization_response(grant=grant, grant_user=None)

    chosen = set(request.form.getlist("grant_scope"))
    granted = [c["scope"] for c in choices if c["scope"] in chosen]
    if not granted:
        flash("Select at least one permission to continue, or choose Deny.")
        return render_template("oauth_consent.html", ticket=_issue_ticket(user.id, grant), **context), 400

    grant.request.pcf_granted_scope = join_scope(granted)
    audit.record_event(action="oauth.consent_approved", outcome="success", user_id=user.id,
                       client_id=client.get_client_id())
    return server.create_authorization_response(grant=grant, grant_user=user)


def _error_redirect_from_denial(grant, user, description: str):
    audit.record_event(action="oauth.consent_denied", outcome="denied", user_id=user.id,
                       client_id=grant.client.get_client_id(), error_code="no_permissions")
    error = OAuth2Error(description=description, redirect_uri=grant.request.payload.redirect_uri)
    error.error = "access_denied"
    return _error_redirect(error)


# ── Connected applications (user-facing management) ─────────────────────────


@oauth_bp.route("/settings/connected-apps", methods=["GET"])
@login_required
def connected_apps():
    now = utcnow()
    grants = (
        OAuthGrant.query.filter_by(user_id=current_user.id, revoked_at=None)
        .order_by(OAuthGrant.created_at.desc())
        .all()
    )
    live = [g for g in grants if grant_is_live(g, now)]
    clients = {
        c.client_id: c for c in OAuthClient.query.filter(
            OAuthClient.client_id.in_([g.client_id for g in live] or [""])
        ).all()
    }
    rows = []
    for grant in live:
        client = clients.get(grant.client_id)
        verified_host = (
            urlsplit(grant.client_id).hostname if client is not None and client.registration_type == "cimd" else None
        )
        rows.append({
            "id": grant.id,
            "client_name": grant.client_name or "Unnamed application",
            "verified_host": verified_host,
            "scopes": [SCOPE_DESCRIPTIONS[s][0] for s in split_scope(grant.scope) if s in SCOPE_DESCRIPTIONS],
            "created_at": grant.created_at,
            "last_used_at": grant.last_used_at,
            "expires_at": grant.expires_at,
        })
    events = (
        OAuthAuditEvent.query.filter_by(user_id=current_user.id)
        .order_by(OAuthAuditEvent.created_at.desc(), OAuthAuditEvent.id.desc())
        .limit(25)
        .all()
    )
    names = {g.client_id: (g.client_name or "Unnamed application") for g in grants}
    return render_template("connected_apps.html", grants=rows, events=events, client_names=names)


@oauth_bp.route("/settings/connected-apps/<int:grant_id>/revoke", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def revoke_connected_app(grant_id: int):
    grant = OAuthGrant.query.filter_by(id=grant_id, user_id=current_user.id).first()
    if grant is None:
        abort(404)
    revoke_grant(grant, "user_revoked")
    audit.record_event(action="oauth.grant_revoked", outcome="success", user_id=current_user.id,
                       client_id=grant.client_id, grant_id=grant.id)
    flash(f"Disconnected {grant.client_name or 'the application'}.", "success")
    return redirect(url_for("oauth.connected_apps"))


def exempt_machine_endpoints(csrf) -> None:
    """Exempt cookie-less OAuth endpoints from Flask-WTF CSRF protection."""
    for view in (register_client, issue_token, revoke_token):
        csrf.exempt(view)


__all__ = ["oauth_bp", "exempt_machine_endpoints"]
