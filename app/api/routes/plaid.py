"""API endpoints for the Plaid Balance integration.

Endpoints:
- GET    /api/v1/plaid/status            – is Plaid configured, and is the
                                           current user connected?
- POST   /api/v1/plaid/link-token        – create a Plaid Link token
- POST   /api/v1/plaid/exchange-token    – exchange public_token + metadata
- POST   /api/v1/plaid/remove            – disconnect the current user's account
- DELETE /api/v1/plaid/remove            – same as POST /remove
- POST   /api/v1/plaid/update-balance    – manual balance refresh trigger
- POST   /api/v1/plaid/realtime-balance  – paid /accounts/balance/get refresh
                                           (rate-limited to once per 24h)

All endpoints require login and operate strictly on the authenticated user.
None of them return access tokens, encrypted tokens, or raw Plaid payloads.
"""

from flask import jsonify, request

from app import limiter
from app.api import api
from app.api.auth_utils import api_login_required, get_api_user
from app.api.errors import api_error, forbidden
from app.api.responses import api_ok, api_no_content
from app.models import User
from app.plaid_service import (
    PlaidServiceError,
    create_link_token_for_user,
    exchange_public_token_for_user,
    get_plaid_connection_status,
    log_plaid_link_exit_for_user,
    realtime_update_plaid_balance_for_user,
    remove_plaid_connection_for_user,
    update_plaid_balance_for_user,
)


def _balance_owner_user():
    """Return the user object whose balance is the source of truth."""
    user = get_api_user()
    effective_id = user.owner_user_id or user.account_owner_id or user.id
    if effective_id == user.id:
        return user
    return User.query.get(effective_id)


def _service_error(exc: PlaidServiceError):
    return api_error(exc.user_message, exc.code, exc.status)


def _forbid_guest_writes():
    user = get_api_user()
    if not user.admin:
        return forbidden("Guest users are read-only")
    return None


@api.route("/plaid/status", methods=["GET"])
@api_login_required
def api_plaid_status():
    user = get_api_user()
    return api_ok(get_plaid_connection_status(user))


@api.route("/plaid/link-token", methods=["POST"])
@api_login_required
@limiter.limit("10 per hour")
def api_plaid_link_token():
    user = get_api_user()
    try:
        token = create_link_token_for_user(user)
    except PlaidServiceError as exc:
        return _service_error(exc)
    return api_ok({"link_token": token})


@api.route("/plaid/exchange-token", methods=["POST"])
@api_login_required(require_bearer=True)
@limiter.limit("10 per hour")
def api_plaid_exchange_token():
    if (resp := _forbid_guest_writes()) is not None:
        return resp
    user = get_api_user()
    body = request.get_json(silent=True) or {}
    public_token = body.get("public_token")
    metadata = body.get("metadata") or {}
    try:
        exchange_public_token_for_user(user, public_token, metadata)
    except PlaidServiceError as exc:
        return _service_error(exc)
    return api_ok(get_plaid_connection_status(user))


@api.route("/plaid/link-exit", methods=["POST"])
@api_login_required
@limiter.limit("60 per hour")
def api_plaid_link_exit():
    """Record a client-side Plaid Link exit for server-side diagnostics.

    Plaid Link surfaces OAuth handoff failures (common for real banks in
    production) only in the browser. This endpoint accepts a small,
    whitelisted subset of those fields and writes them to the server log.
    """
    user = get_api_user()
    body = request.get_json(silent=True) or {}
    log_plaid_link_exit_for_user(user, body)
    return api_no_content()


@api.route("/plaid/remove", methods=["POST", "DELETE"])
@api_login_required(require_bearer=True)
@limiter.limit("10 per hour")
def api_plaid_remove():
    if (resp := _forbid_guest_writes()) is not None:
        return resp
    user = get_api_user()
    remove_plaid_connection_for_user(user)
    return api_no_content()


@api.route("/plaid/update-balance", methods=["POST"])
@api_login_required(require_bearer=True)
@limiter.limit("240 per hour")
def api_plaid_update_balance():
    if (resp := _forbid_guest_writes()) is not None:
        return resp
    user = get_api_user()
    try:
        result = update_plaid_balance_for_user(user)
    except Exception:
        return api_error(
            "Could not refresh balance from Plaid.",
            "plaid_error",
            502,
        )
    return api_ok(result)


def _cooldown_error_response(result: dict):
    """Build the 429 envelope for a cooldown-blocked realtime refresh.

    Uses the standard ``{error, code, status}`` envelope so existing clients
    can decode it, plus extra top-level fields (``retry_after_seconds``,
    ``next_available_refresh_at``) and a ``Retry-After`` header so the UI
    can disable the button until the window opens.
    """
    retry_after = int(result.get("retry_after_seconds") or 0)
    body = {
        "error": "Live balance refresh is available once every 24 hours.",
        "code": "plaid_realtime_cooldown",
        "status": 429,
        "retry_after_seconds": retry_after,
        "last_realtime_balance_at": result.get("last_realtime_balance_at"),
        "next_available_refresh_at": result.get("next_available_refresh_at"),
    }
    response = jsonify(body)
    response.status_code = 429
    if retry_after > 0:
        response.headers["Retry-After"] = str(retry_after)
    return response


@api.route("/plaid/realtime-balance", methods=["POST"])
@api_login_required(require_bearer=True)
@limiter.limit("60 per hour")
def api_plaid_realtime_balance():
    """Force-refresh today's balance via Plaid's billed /accounts/balance/get.

    Server-enforced: at most one attempted refresh per connection every 24
    hours. The cooldown timestamp is claimed before the Plaid call so a
    failed-but-billed call still consumes the window and rapid double-clicks
    cannot trigger duplicate paid calls.

    Callers that hit the cooldown receive HTTP 429 with ``retry_after_seconds``
    plus ``next_available_refresh_at`` so the UI can disable the button.
    """
    if (resp := _forbid_guest_writes()) is not None:
        return resp

    owner = _balance_owner_user()

    try:
        result = realtime_update_plaid_balance_for_user(owner)
    except Exception:
        return api_error(
            "Could not refresh balance from Plaid.",
            "plaid_error",
            502,
        )

    status = result.get("status")
    reason = result.get("reason")

    if status == "skipped" and reason == "no_connection":
        return api_error(
            "Connect a Plaid account before using live balance refresh.",
            "plaid_no_connection",
            400,
        )

    if status == "skipped" and reason == "not_configured":
        return api_error(
            "Live balance refresh is unavailable right now.",
            "plaid_not_configured",
            400,
        )

    if reason == "reconnect_required":
        # Expired or revoked bank consent; the cooldown was not consumed
        # when this was already known before calling Plaid.
        return api_error(
            "Your bank connection has expired or access was revoked. "
            "Reconnect it from Settings on the web.",
            "plaid_reconnect_required",
            409,
        )

    if status == "rate_limited":
        return _cooldown_error_response(result)

    if status == "skipped" and reason == "no_balance_value":
        # Plaid was called and billed, but returned no usable balance value.
        # Surface a successful 200 response so the client can show a friendly
        # message; the cooldown is already recorded so the next call is
        # blocked for 24 hours.
        return api_ok(
            {
                "success": False,
                "message": "Plaid did not return a balance for this account.",
                "balance": None,
                "balance_source": None,
                "refreshed_at": result.get("refreshed_at"),
                "next_available_refresh_at": result.get("next_available_refresh_at"),
            }
        )

    if status == "error":
        return api_error(
            "Could not refresh balance from Plaid.",
            "plaid_error",
            502,
        )

    # status == "ok"
    return api_ok(
        {
            "success": True,
            "message": "Live balance refreshed.",
            "balance": result.get("amount"),
            "balance_source": result.get("source"),
            "refreshed_at": result.get("refreshed_at"),
            "next_available_refresh_at": result.get("next_available_refresh_at"),
        }
    )
