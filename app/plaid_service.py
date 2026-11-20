"""Plaid Balance integration service layer.

Encapsulates all Plaid SDK interactions so routes/templates never call Plaid
directly. Stores only the minimum connection metadata required to call
/accounts/balance/get for a single depository account per user.

This module never returns Plaid secrets, access tokens, or raw Plaid response
payloads to callers, and it never logs them either.
"""

from __future__ import annotations

import logging
import re
from datetime import date, datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from flask import current_app, g
from sqlalchemy import desc, or_
from sqlalchemy.exc import IntegrityError

from app import db
from app.crypto_utils import encrypt_password, decrypt_password
from app.models import Balance, Email, PlaidConnection, User

logger = logging.getLogger(__name__)


# Plaid Link products that are valid for create_link_token; "balance" is not.
_INVALID_LINK_PRODUCTS = {"balance"}

# Only depository cash accounts are appropriate for cash-flow forecasting.
_ALLOWED_ACCOUNT_TYPES = {"depository"}
_ALLOWED_ACCOUNT_SUBTYPES = {
    "checking",
    "savings",
    "cash management",
    "money market",
    "ebt",
    "hsa",
    "paypal",
    "prepaid",
}

_BALANCE_SOURCE_AVAILABLE = "plaid_available_balance"
_BALANCE_SOURCE_CURRENT_FALLBACK = "plaid_current_balance_fallback"
_BALANCE_SOURCE_REALTIME_AVAILABLE = "plaid_realtime_available_balance"
_BALANCE_SOURCE_REALTIME_CURRENT_FALLBACK = "plaid_realtime_current_balance_fallback"

# Plaid charges per /accounts/balance/get call, so the manual real-time
# refresh is rate-limited to once every 24 hours per connection.
REALTIME_BALANCE_COOLDOWN_SECONDS = 24 * 60 * 60

# How long after a real-time /accounts/balance/get refresh the cached
# /accounts/get auto-sync is skipped. Plaid does not guarantee that the
# cached path immediately reflects the freshly-refreshed value, so the
# auto-sync triggered by the next dashboard load could otherwise overwrite
# the live balance with stale data.
REALTIME_BALANCE_PROTECTION_SECONDS = 5 * 60

# Plaid Item error codes that only the user can fix by going back through
# Plaid Link: expired or revoked consent (e.g. a Chase connection reaching
# the 6- or 12-month limit the consumer picked returns ITEM_LOGIN_REQUIRED),
# changed or locked bank credentials, or no usable accounts left. Generic
# API failures and outages are deliberately not in this set.
_RECONNECT_ERROR_CODES = frozenset(
    {
        "ITEM_LOGIN_REQUIRED",
        "USER_PERMISSION_REVOKED",
        "USER_ACCOUNT_REVOKED",
        "ACCESS_NOT_GRANTED",
        "ITEM_LOCKED",
        "PASSWORD_RESET_REQUIRED",
        "USER_SETUP_REQUIRED",
        "NO_ACCOUNTS",
        "ITEM_NOT_FOUND",
    }
)

RECONNECT_REQUIRED_STATUS = "reconnect_required"
_RECONNECT_REQUIRED_MESSAGE = (
    "The bank connection has expired or access was revoked. "
    "Remove it and connect it again."
)

# Warn this many days before Plaid's consent_expiration_time.
CONSENT_EXPIRY_WARNING_DAYS = 14


class PlaidServiceError(Exception):
    """Raised for any Plaid-related failure surfaced to a route.

    The ``user_message`` is safe to show to end users (no Plaid secrets,
    no raw payloads, no tokens). ``code`` is a stable slug for callers.
    """

    def __init__(self, user_message: str, code: str = "plaid_error", status: int = 400):
        super().__init__(user_message)
        self.user_message = user_message
        self.code = code
        self.status = status


# ── Configuration ────────────────────────────────────────────────────────────


def _config(key: str) -> str:
    return (current_app.config.get(key) or "").strip()


def plaid_is_configured() -> bool:
    """Return True only when all required Plaid config values are present.

    Does NOT make any network call. Required values:
    PLAID_CLIENT_ID, PLAID_SECRET, PLAID_ENV, PLAID_PRODUCTS.
    """
    if not current_app:
        return False
    return all(_config(k) for k in ("PLAID_CLIENT_ID", "PLAID_SECRET", "PLAID_ENV", "PLAID_PRODUCTS"))


def get_configured_products() -> list[str]:
    raw = _config("PLAID_PRODUCTS")
    products = [p.strip().lower() for p in raw.split(",") if p.strip()]
    return [p for p in products if p not in _INVALID_LINK_PRODUCTS]


def get_configured_country_codes() -> list[str]:
    raw = _config("PLAID_COUNTRY_CODES") or "US"
    return [c.strip().upper() for c in raw.split(",") if c.strip()]


# ── Plaid SDK helpers ────────────────────────────────────────────────────────


def _plaid_environment_host():
    """Map PLAID_ENV string to the SDK's environment host constant."""
    from plaid.configuration import Environment

    env = _config("PLAID_ENV").lower()
    if env == "production":
        return Environment.Production
    if env in ("development", "dev"):
        # Plaid SDK v39 removed the dedicated Development host; fall back to
        # Sandbox for unrecognized values so we never hit Production unintentionally.
        return getattr(Environment, "Development", Environment.Sandbox)
    return Environment.Sandbox


def _plaid_client():
    """Build an authenticated Plaid API client from current config."""
    from plaid.api import plaid_api
    from plaid.api_client import ApiClient
    from plaid.configuration import Configuration

    config = Configuration(
        host=_plaid_environment_host(),
        api_key={
            "clientId": _config("PLAID_CLIENT_ID"),
            "secret": _config("PLAID_SECRET"),
        },
    )
    return plaid_api.PlaidApi(ApiClient(config))


def _plaid_request_id(api_exception) -> str | None:
    """Extract Plaid request_id from an ApiException body for safe logging."""
    info = _plaid_error_info(api_exception)
    return info.get("request_id")


def _plaid_error_info(api_exception) -> dict:
    """Extract safe diagnostic fields from a Plaid ApiException body.

    Returns a dict with any of ``request_id``, ``error_type``, ``error_code``,
    ``error_message`` that were present. These fields are documented as the
    error envelope Plaid returns and never contain secrets or access tokens,
    so they are safe to write to application logs.
    """
    info: dict = {}
    try:
        body = getattr(api_exception, "body", None)
        if not body:
            return info
        import json as _json

        data = _json.loads(body) if isinstance(body, (str, bytes)) else body
        if not isinstance(data, dict):
            return info
        for key in ("request_id", "error_type", "error_code", "error_message"):
            val = data.get(key)
            if val:
                info[key] = str(val)
    except Exception:  # noqa: BLE001 - never let logging break the flow
        return info
    return info


# ── Connection lookup ────────────────────────────────────────────────────────


def get_active_connection(user) -> PlaidConnection | None:
    if not user or not getattr(user, "id", None):
        return None
    return (
        PlaidConnection.query.filter_by(user_id=user.id, is_active=True)
        .order_by(desc(PlaidConnection.id))
        .first()
    )


# ── Connection health (expiring / expired consent) ───────────────────────────


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_reconnect_error_code(code) -> bool:
    if not code or not isinstance(code, str):
        return False
    return code.strip().upper() in _RECONNECT_ERROR_CODES


def _mark_reconnect_required(conn: PlaidConnection) -> None:
    """Flag ``conn`` as needing the user to reconnect (keeps the first time)."""
    if conn.reconnect_required_at is None:
        conn.reconnect_required_at = _utcnow_naive()


def connection_needs_reconnect(
    conn: PlaidConnection | None, now: Optional[datetime] = None
) -> bool:
    """True when Plaid can no longer read this connection without the user.

    Either a sync saw a reconnect-only Item error, or Plaid's consent
    expiration time has already passed.
    """
    if conn is None:
        return False
    if conn.reconnect_required_at is not None:
        return True
    expires = conn.consent_expiration_time
    return expires is not None and expires <= (now or _utcnow_naive())


def connection_consent_expires_soon(
    conn: PlaidConnection | None, now: Optional[datetime] = None
) -> bool:
    """True when consent ends within ``CONSENT_EXPIRY_WARNING_DAYS``."""
    if conn is None or conn.consent_expiration_time is None:
        return False
    now = now or _utcnow_naive()
    window_end = now + timedelta(days=CONSENT_EXPIRY_WARNING_DAYS)
    return now < conn.consent_expiration_time <= window_end


def _apply_item_health(conn: PlaidConnection, item_response) -> bool:
    """Update ``conn`` from a /item/get response after /accounts/get worked.

    Records ``item.consent_expiration_time`` (null means none scheduled) and
    sets or clears the reconnect flag from ``item.error``. When /item/get
    failed (``item_response`` is None) nothing changes: /accounts/get can
    return cached data for an Item that needs the user, so its success alone
    does not prove the connection recovered.
    Returns True when anything on ``conn`` changed.
    """
    item = _nested_get(item_response, "item")
    if item is None:
        return False

    changed = False
    item_error_code = _nested_get(item, "error", "error_code")
    if _is_reconnect_error_code(item_error_code):
        if conn.reconnect_required_at is None:
            _mark_reconnect_required(conn)
            changed = True
    elif conn.reconnect_required_at is not None:
        conn.reconnect_required_at = None
        changed = True

    expires = _normalize_naive_utc(_nested_get(item, "consent_expiration_time"))
    if expires is not None:
        expires = expires.replace(microsecond=0)
    if expires != conn.consent_expiration_time:
        conn.consent_expiration_time = expires
        changed = True

    return changed


def get_plaid_connection_alert(user) -> dict | None:
    """Return the dashboard warning for ``user``'s Plaid connection, if any.

    ``kind`` is ``"reconnect_required"`` or ``"expires_soon"``. Never raises:
    the dashboard must render even if this lookup fails.
    """
    try:
        if user is None or not plaid_is_configured():
            return None
        conn = get_active_connection(user)
        if conn is None:
            return None
        now = _utcnow_naive()
        if connection_needs_reconnect(conn, now):
            kind = RECONNECT_REQUIRED_STATUS
        elif connection_consent_expires_soon(conn, now):
            kind = "expires_soon"
        else:
            return None
        return {
            "kind": kind,
            "institution_name": conn.institution_name,
            "consent_expiration_time": conn.consent_expiration_time,
        }
    except Exception:
        logger.exception("Could not build Plaid connection alert")
        return None


def get_plaid_connection_status(user) -> dict:
    """Return a safe, JSON-friendly status payload for the settings UI."""
    configured = plaid_is_configured()
    payload: dict = {"configured": configured, "connected": False, "connection": None}
    if not configured:
        return payload

    conn = get_active_connection(user)
    if conn is None:
        return payload

    now = _utcnow_naive()
    payload["connected"] = True
    payload["connection"] = {
        "institution_name": conn.institution_name,
        "account_name": conn.account_name,
        "account_mask": conn.account_mask,
        "account_type": conn.account_type,
        "account_subtype": conn.account_subtype,
        "iso_currency_code": conn.iso_currency_code,
        "last_balance_sync_at": (
            conn.last_balance_sync_at.replace(microsecond=0).isoformat() + "Z"
            if conn.last_balance_sync_at
            else None
        ),
        "last_sync_status": conn.last_sync_status,
        "last_sync_error": conn.last_sync_error,
        "last_realtime_balance_at": _iso_utc(conn.last_realtime_balance_at),
        "last_realtime_refresh_status": conn.last_realtime_refresh_status,
        "last_realtime_refresh_error": conn.last_realtime_refresh_error,
        "realtime_refresh_retry_after_seconds": _seconds_until_realtime_refresh(conn),
        "next_available_refresh_at": _iso_utc(_next_available_refresh_at(conn)),
        "consent_expiration_time": _iso_utc(conn.consent_expiration_time),
        "consent_expires_soon": connection_consent_expires_soon(conn, now),
        "reconnect_required": connection_needs_reconnect(conn, now),
    }
    return payload


# ── Link token ───────────────────────────────────────────────────────────────


def create_link_token_for_user(user) -> str:
    """Build a Plaid Link token for the current user. Returns the link_token."""
    if not plaid_is_configured():
        raise PlaidServiceError(
            "Plaid is not configured. Set PLAID_CLIENT_ID, PLAID_SECRET, "
            "PLAID_ENV, and PLAID_PRODUCTS.",
            code="plaid_not_configured",
            status=400,
        )

    from plaid.exceptions import ApiException
    from plaid.model.country_code import CountryCode
    from plaid.model.link_token_create_request import LinkTokenCreateRequest
    from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
    from plaid.model.products import Products

    products = [Products(p) for p in get_configured_products()]
    if not products:
        raise PlaidServiceError(
            "Plaid is not configured with a valid PLAID_PRODUCTS value.",
            code="plaid_not_configured",
            status=400,
        )
    country_codes = [CountryCode(c) for c in get_configured_country_codes()]

    request_kwargs = dict(
        user=LinkTokenCreateRequestUser(client_user_id=str(user.id)),
        client_name="PyCashFlow",
        products=products,
        country_codes=country_codes,
        language="en",
    )
    redirect_uri = _config("PLAID_REDIRECT_URI")
    if redirect_uri:
        # Plaid rejects redirect_uri values that include a query string or
        # fragment ("redirect_uri cannot include query"). The dashboard-
        # registered URI is the bare path; OAuth-return params are appended
        # by Plaid on the way back, not configured here.
        parts = urlsplit(redirect_uri)
        request_kwargs["redirect_uri"] = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, "", "")
        )

    try:
        client = _plaid_client()
        response = client.link_token_create(LinkTokenCreateRequest(**request_kwargs))
    except ApiException as exc:
        info = _plaid_error_info(exc)
        logger.warning(
            "Plaid link_token_create failed for user %s "
            "(request_id=%s, error_type=%s, error_code=%s, error_message=%s, "
            "env=%s, products=%s, country_codes=%s, redirect_uri_set=%s)",
            user.id,
            info.get("request_id"),
            info.get("error_type"),
            info.get("error_code"),
            info.get("error_message"),
            _config("PLAID_ENV"),
            ",".join(get_configured_products()),
            ",".join(get_configured_country_codes()),
            bool(_config("PLAID_REDIRECT_URI")),
        )
        raise PlaidServiceError(
            "Could not start Plaid Link. Please try again later.",
            code="plaid_link_failed",
            status=502,
        ) from None
    except Exception:
        logger.exception("Unexpected error creating Plaid link token for user %s", user.id)
        raise PlaidServiceError(
            "Could not start Plaid Link. Please try again later.",
            code="plaid_link_failed",
            status=502,
        ) from None

    return response.link_token


# ── Link client-side event logging ───────────────────────────────────────────


# Whitelisted fields we accept from the client. Plaid documents these as the
# onExit error envelope and metadata; none of them carry credentials, access
# tokens, or balances, so it is safe to write them to server logs.
_LINK_EVENT_ERROR_FIELDS = (
    "error_type",
    "error_code",
    "error_message",
    "display_message",
)
_LINK_EVENT_METADATA_FIELDS = (
    "status",
    "link_session_id",
    "request_id",
    "institution_name",
)


# Strip ASCII control characters (incl. CR/LF) so a client-supplied value
# cannot inject forged log lines when interpolated into a single-line warning.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _scrub_log_value(val: str) -> str:
    return _CONTROL_CHARS_RE.sub(" ", val)[:255]


def _sanitize_link_event_payload(payload: dict) -> dict:
    """Pick only whitelisted, short string fields from a client-supplied payload."""
    safe: dict = {}
    if not isinstance(payload, dict):
        return safe
    err = payload.get("error")
    if isinstance(err, dict):
        for key in _LINK_EVENT_ERROR_FIELDS:
            val = err.get(key)
            if isinstance(val, str) and val:
                safe[key] = _scrub_log_value(val)
    meta = payload.get("metadata")
    if isinstance(meta, dict):
        for key in _LINK_EVENT_METADATA_FIELDS:
            val = meta.get(key)
            if isinstance(val, str) and val:
                safe["metadata_" + key] = _scrub_log_value(val)
    return safe


def log_plaid_link_exit_for_user(user, payload: dict) -> None:
    """Log client-reported Plaid Link exit diagnostics for a user.

    Plaid Link reports failures (especially OAuth handoff problems for real
    banks in production) entirely client-side; the server otherwise sees no
    error. This bridges that gap by accepting a whitelisted subset of the
    onExit ``err`` + ``metadata`` fields and emitting them to the server log.
    """
    safe = _sanitize_link_event_payload(payload or {})
    if not safe:
        logger.warning(
            "Plaid Link exited with no recoverable diagnostics for user %s "
            "(env=%s, products=%s, country_codes=%s, redirect_uri_set=%s)",
            getattr(user, "id", None),
            _config("PLAID_ENV"),
            ",".join(get_configured_products()),
            ",".join(get_configured_country_codes()),
            bool(_config("PLAID_REDIRECT_URI")),
        )
        return
    logger.warning(
        "Plaid Link exit reported by user %s: %s "
        "(env=%s, products=%s, country_codes=%s, redirect_uri_set=%s)",
        getattr(user, "id", None),
        ", ".join("%s=%s" % (k, v) for k, v in safe.items()),
        _config("PLAID_ENV"),
        ",".join(get_configured_products()),
        ",".join(get_configured_country_codes()),
        bool(_config("PLAID_REDIRECT_URI")),
    )


# ── Public token exchange ────────────────────────────────────────────────────


def _pick_single_account_from_metadata(metadata: dict) -> dict | None:
    """Return the single Plaid-Link-selected account, or None if ambiguous."""
    accounts = metadata.get("accounts") if isinstance(metadata, dict) else None
    if not isinstance(accounts, list) or not accounts:
        return None
    if len(accounts) == 1:
        return accounts[0]
    return None


def _validate_account_type(account: dict) -> None:
    acct_type = (account.get("type") or "").lower()
    subtype = (account.get("subtype") or "").lower()
    if acct_type not in _ALLOWED_ACCOUNT_TYPES:
        raise PlaidServiceError(
            "Only depository (checking/savings) accounts are supported.",
            code="plaid_unsupported_account_type",
            status=422,
        )
    if subtype and subtype not in _ALLOWED_ACCOUNT_SUBTYPES:
        raise PlaidServiceError(
            "Only checking/savings depository subtypes are supported.",
            code="plaid_unsupported_account_subtype",
            status=422,
        )


def exchange_public_token_for_user(user, public_token: str, metadata: dict) -> PlaidConnection:
    """Exchange a Link public_token and persist minimal connection metadata."""
    if not plaid_is_configured():
        raise PlaidServiceError(
            "Plaid is not configured.",
            code="plaid_not_configured",
            status=400,
        )

    if not public_token or not isinstance(public_token, str):
        raise PlaidServiceError(
            "Missing Plaid public_token.",
            code="validation_error",
            status=422,
        )

    if get_active_connection(user) is not None:
        raise PlaidServiceError(
            "A Plaid account is already connected. Remove it before connecting a new one.",
            code="plaid_already_connected",
            status=409,
        )

    metadata = metadata if isinstance(metadata, dict) else {}
    selected = _pick_single_account_from_metadata(metadata)
    if selected is None:
        raise PlaidServiceError(
            "Please select a single Plaid account, or enable Plaid Account Select "
            "for a single account in your Plaid dashboard.",
            code="plaid_select_one_account",
            status=422,
        )

    _validate_account_type(selected)

    account_id_raw = selected.get("id")
    account_id = account_id_raw.strip() if isinstance(account_id_raw, str) else ""
    if not account_id:
        raise PlaidServiceError(
            "Plaid did not return an account id for the selected account.",
            code="plaid_missing_account_id",
            status=422,
        )

    from plaid.exceptions import ApiException
    from plaid.model.item_public_token_exchange_request import (
        ItemPublicTokenExchangeRequest,
    )

    try:
        client = _plaid_client()
        exchange = client.item_public_token_exchange(
            ItemPublicTokenExchangeRequest(public_token=public_token)
        )
    except ApiException as exc:
        info = _plaid_error_info(exc)
        logger.warning(
            "Plaid public_token exchange failed for user %s "
            "(request_id=%s, error_type=%s, error_code=%s, error_message=%s)",
            user.id,
            info.get("request_id"),
            info.get("error_type"),
            info.get("error_code"),
            info.get("error_message"),
        )
        raise PlaidServiceError(
            "Could not finalize Plaid connection. Please try again.",
            code="plaid_exchange_failed",
            status=502,
        ) from None
    except Exception:
        logger.exception("Unexpected error exchanging Plaid public token for user %s", user.id)
        raise PlaidServiceError(
            "Could not finalize Plaid connection. Please try again.",
            code="plaid_exchange_failed",
            status=502,
        ) from None

    access_token = exchange.access_token
    item_id = exchange.item_id

    institution = metadata.get("institution") if isinstance(metadata, dict) else None
    institution_id = institution.get("institution_id") if isinstance(institution, dict) else None
    institution_name = institution.get("name") if isinstance(institution, dict) else None

    encrypted = encrypt_password(access_token)
    conn = PlaidConnection(
        user_id=user.id,
        encrypted_access_token=encrypted,
        plaid_item_id=str(item_id),
        plaid_account_id=account_id,
        institution_id=str(institution_id) if institution_id else None,
        institution_name=str(institution_name) if institution_name else None,
        account_name=(selected.get("name") or None),
        account_mask=(selected.get("mask") or None),
        account_type=(selected.get("type") or None),
        account_subtype=(selected.get("subtype") or None),
        iso_currency_code=(selected.get("iso_currency_code") or None),
        is_active=True,
        # Carry the user-level cooldown timestamp into the new connection so
        # delete-and-re-add cannot bypass the 24-hour real-time refresh limit.
        last_realtime_balance_at=getattr(user, "last_plaid_realtime_balance_at", None),
    )
    db.session.add(conn)
    db.session.commit()
    return conn


# ── Remove connection ────────────────────────────────────────────────────────


def _detach_plaid_item(conn: PlaidConnection) -> None:
    """Best-effort call to Plaid's /item/remove for ``conn``. Never raises.

    Calling /item/remove ends the Plaid Transactions subscription for the
    underlying Item; skipping this step means Plaid keeps billing us for the
    Item even after the local record is gone.
    """
    if not plaid_is_configured():
        return

    from plaid.exceptions import ApiException
    from plaid.model.item_remove_request import ItemRemoveRequest

    try:
        access_token = decrypt_password(conn.encrypted_access_token)
        client = _plaid_client()
        client.item_remove(ItemRemoveRequest(access_token=access_token))
    except ApiException as exc:
        info = _plaid_error_info(exc)
        logger.warning(
            "Plaid item_remove failed for user %s connection %s "
            "(request_id=%s, error_type=%s, error_code=%s, error_message=%s); "
            "deleting local record anyway",
            conn.user_id,
            conn.id,
            info.get("request_id"),
            info.get("error_type"),
            info.get("error_code"),
            info.get("error_message"),
        )
    except Exception:
        logger.exception(
            "Unexpected error calling Plaid item_remove for user %s connection %s; "
            "deleting local record anyway",
            conn.user_id,
            conn.id,
        )


def _preserve_realtime_cooldown(conn: PlaidConnection) -> None:
    """Copy the connection's real-time refresh cooldown timestamp onto its user.

    The PlaidConnection row is about to be deleted; persisting
    ``last_realtime_balance_at`` on the user prevents a delete-and-re-add
    cycle from resetting the 24-hour /accounts/balance/get rate limit.

    Keeps the newest of the user-level and connection-level timestamps:
    bulk deletes may iterate multiple connections per user (and SQL row
    order is not guaranteed), so a blind overwrite could move the
    cooldown backward and let a reconnect bypass the rate limit.
    """
    if conn.last_realtime_balance_at is None:
        return
    user = getattr(conn, "user", None)
    if user is None:
        user = User.query.get(conn.user_id)
    if user is None:
        return
    existing = user.last_plaid_realtime_balance_at
    if existing is None or conn.last_realtime_balance_at > existing:
        user.last_plaid_realtime_balance_at = conn.last_realtime_balance_at


def remove_plaid_connection_for_user(user) -> bool:
    """Remove the active Plaid connection for ``user``. Returns True if removed."""
    conn = get_active_connection(user)
    if conn is None:
        return False

    _detach_plaid_item(conn)
    _preserve_realtime_cooldown(conn)
    db.session.delete(conn)
    db.session.commit()
    return True


def remove_plaid_connections_for_user_ids(user_ids, *, commit: bool = False) -> int:
    """Remove every PlaidConnection owned by the given user IDs.

    For each row, best-effort calls Plaid's /item/remove (so we stop being
    billed for the Item's Transactions subscription) and then deletes the
    local record. Returns the number of rows removed. Caller is responsible
    for committing the session unless ``commit=True``.
    """
    if not user_ids:
        return 0

    connections = (
        PlaidConnection.query.filter(PlaidConnection.user_id.in_(list(user_ids))).all()
    )
    for conn in connections:
        _detach_plaid_item(conn)
        _preserve_realtime_cooldown(conn)
        db.session.delete(conn)

    if commit and connections:
        db.session.commit()

    return len(connections)


# ── Balance update ───────────────────────────────────────────────────────────


def _today_date() -> date:
    return datetime.today().date()


def _normalize_naive_utc(value):
    """Coerce an ISO datetime string or aware/naive datetime to naive UTC.

    Plaid freshness fields are ISO 8601 strings (per SDK version, sometimes
    parsed ``datetime`` objects). Internal
    timestamps like ``last_realtime_balance_at`` are naive UTC, so cast
    both sides to the same form before comparing.
    """
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _nested_get(obj, *path):
    """Return a nested value from SDK model objects or dictionaries.

    Plaid SDK responses are model objects in production, while tests and some
    SDK versions may expose dict-like shapes. Keep this helper intentionally
    small so freshness resolution can support both without storing raw payloads.
    """
    current = obj
    for key in path:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(key)
        else:
            current = getattr(current, key, None)
    return current


def _transactions_last_successful_update(item_response):
    """Return Plaid Item Transactions freshness, when present.

    Plaid exposes the Transactions product's cached-data freshness on
    ``status.transactions.last_successful_update`` from /item/get. Older
    mocks and SDK-shaped fixtures may have placed ``status`` under ``item``,
    so keep that as a compatibility fallback after checking the production
    shape first.
    """
    return (
        _nested_get(
            item_response,
            "status",
            "transactions",
            "last_successful_update",
        )
        or _nested_get(
            item_response,
            "item",
            "status",
            "transactions",
            "last_successful_update",
        )
    )


def _newest_email_balance_datetime(user_id: int) -> Optional[datetime]:
    """Return the most recent email balance timestamp for *user_id*, or None.

    Multiple Email configs per user are allowed by the schema; the newest
    ``balance_email_datetime`` across them wins so the freshest email-derived
    balance drives the cached-Plaid comparison.
    """
    row = (
        db.session.query(Email.balance_email_datetime)
        .filter(
            Email.user_id == user_id,
            Email.balance_email_datetime.isnot(None),
        )
        .order_by(desc(Email.balance_email_datetime))
        .first()
    )
    return row[0] if row else None


def _upsert_today_balance(user_id: int, amount: float) -> Balance:
    today = _today_date()
    existing = (
        Balance.query.filter_by(user_id=user_id, date=today)
        .order_by(desc(Balance.id))
        .first()
    )
    if existing is not None:
        existing.amount = amount
        return existing
    # Flush inside a SAVEPOINT so a concurrent insert for the same
    # (user_id, date) surfaces as IntegrityError here without discarding
    # any other dirty state on the outer transaction.
    row = Balance(user_id=user_id, amount=amount, date=today)
    db.session.add(row)
    savepoint = db.session.begin_nested()
    try:
        db.session.flush()
        savepoint.commit()
        return row
    except IntegrityError:
        savepoint.rollback()
        existing = Balance.query.filter_by(user_id=user_id, date=today).first()
        if existing is None:
            raise
        existing.amount = amount
        return existing


def _record_sync_status(conn: PlaidConnection, status: str, error: Optional[str]) -> None:
    conn.last_balance_sync_at = datetime.now(timezone.utc).replace(tzinfo=None)
    conn.last_sync_status = status[:64] if status else None
    conn.last_sync_error = error[:255] if error else None


def update_plaid_balance_for_user(user) -> dict:
    """Refresh today's PyCashFlow balance from the connected Plaid account.

    Safe to call from the dashboard path: never raises on Plaid/configuration
    errors. Returns a small status dict useful for tests/optional API responses.
    """
    if user is None or not getattr(user, "id", None):
        return {"status": "skipped", "reason": "no_user"}

    if not plaid_is_configured():
        return {"status": "skipped", "reason": "not_configured"}

    # Avoid duplicate Plaid calls within a single request.
    cache = getattr(g, "_plaid_update_cache", None)
    if cache is None:
        cache = {}
        try:
            g._plaid_update_cache = cache
        except RuntimeError:
            cache = None  # outside request context
    if cache is not None and user.id in cache:
        return cache[user.id]

    conn = get_active_connection(user)
    if conn is None:
        result = {"status": "skipped", "reason": "no_connection"}
        if cache is not None:
            cache[user.id] = result
        return result

    # Don't clobber a freshly-written real-time balance with a possibly-stale
    # /accounts/get cached value. Plaid does not guarantee that calling
    # /accounts/get immediately after /accounts/balance/get returns the new
    # value, so skip the auto-sync briefly after a real-time refresh.
    if conn.last_realtime_balance_at is not None:
        age = (
            datetime.now(timezone.utc).replace(tzinfo=None)
            - conn.last_realtime_balance_at
        ).total_seconds()
        if age < REALTIME_BALANCE_PROTECTION_SECONDS:
            result = {"status": "skipped", "reason": "realtime_recent"}
            if cache is not None:
                cache[user.id] = result
            return result

    from plaid.exceptions import ApiException
    from plaid.model.accounts_get_request import AccountsGetRequest
    from plaid.model.accounts_get_request_options import AccountsGetRequestOptions
    from plaid.model.item_get_request import ItemGetRequest

    try:
        access_token = decrypt_password(conn.encrypted_access_token)
    except Exception:
        logger.warning("Could not decrypt Plaid access token for user %s", user.id)
        _record_sync_status(conn, "decrypt_failed", "Stored Plaid token could not be read.")
        db.session.commit()
        result = {"status": "error", "reason": "decrypt_failed"}
        if cache is not None:
            cache[user.id] = result
        return result

    # Use /accounts/get rather than /accounts/balance/get: the latter requires
    # the "balance" product authorization, while /accounts/get is included
    # with "transactions" and returns the same available/current balance
    # fields (refreshed as part of regular transaction sync).
    try:
        client = _plaid_client()
        request = AccountsGetRequest(
            access_token=access_token,
            options=AccountsGetRequestOptions(account_ids=[conn.plaid_account_id]),
        )
        response = client.accounts_get(request)
    except ApiException as exc:
        info = _plaid_error_info(exc)
        logger.warning(
            "Plaid accounts_get failed for user %s "
            "(request_id=%s, error_type=%s, error_code=%s, error_message=%s)",
            user.id,
            info.get("request_id"),
            info.get("error_type"),
            info.get("error_code"),
            info.get("error_message"),
        )
        if _is_reconnect_error_code(info.get("error_code")):
            _mark_reconnect_required(conn)
            _record_sync_status(
                conn, RECONNECT_REQUIRED_STATUS, _RECONNECT_REQUIRED_MESSAGE
            )
            reason = RECONNECT_REQUIRED_STATUS
        else:
            _record_sync_status(conn, "plaid_api_error", "Plaid balance request failed.")
            reason = "plaid_api_error"
        db.session.commit()
        result = {"status": "error", "reason": reason}
        if cache is not None:
            cache[user.id] = result
        return result
    except Exception:
        logger.exception("Unexpected error calling Plaid accounts API for user %s", user.id)
        _record_sync_status(conn, "unexpected_error", "Unexpected Plaid error.")
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        result = {"status": "error", "reason": "unexpected_error"}
        if cache is not None:
            cache[user.id] = result
        return result

    item_response = None
    try:
        item_response = client.item_get(ItemGetRequest(access_token=access_token))
    except ApiException as exc:
        info = _plaid_error_info(exc)
        logger.warning(
            "Plaid item_get failed while resolving cached balance freshness for "
            "user %s (request_id=%s, error_type=%s, error_code=%s, "
            "error_message=%s); falling back to account balance freshness",
            user.id,
            info.get("request_id"),
            info.get("error_type"),
            info.get("error_code"),
            info.get("error_message"),
        )
    except Exception:
        logger.exception(
            "Unexpected Plaid item_get error while resolving cached balance "
            "freshness for user %s; falling back to account balance freshness",
            user.id,
        )

    # /accounts/get worked, so record the consent expiration and reconnect
    # state now: the skip branches below return without committing.
    if _apply_item_health(conn, item_response):
        db.session.commit()

    # Pull the matching account from the response.
    target = None
    try:
        accounts = list(response.accounts or [])
    except Exception:
        accounts = []
    for acct in accounts:
        if str(getattr(acct, "account_id", "")) == conn.plaid_account_id:
            target = acct
            break

    if target is None:
        _record_sync_status(
            conn,
            "account_not_found",
            "Connected Plaid account was not in the balance response.",
        )
        db.session.commit()
        result = {"status": "error", "reason": "account_not_found"}
        if cache is not None:
            cache[user.id] = result
        return result

    balances = getattr(target, "balances", None)
    available = getattr(balances, "available", None) if balances is not None else None
    current = getattr(balances, "current", None) if balances is not None else None
    balance_cache_updated_at = (
        getattr(balances, "last_updated_datetime", None)
        if balances is not None
        else None
    )
    transactions_cache_updated_at = _transactions_last_successful_update(item_response)

    # Defense in depth: resolve Plaid cached freshness by preferring the
    # Transactions product timestamp from /item/get
    # (status.transactions.last_successful_update), then falling back to
    # the account balance timestamp from /accounts/get
    # (balances.last_updated_datetime). If neither is present, freshness stays
    # unknown and the manual/email guards below preserve the local balance.
    normalized_transactions_updated_at = _normalize_naive_utc(
        transactions_cache_updated_at
    )
    normalized_balance_updated_at = _normalize_naive_utc(balance_cache_updated_at)
    normalized_cache_updated_at = (
        normalized_transactions_updated_at or normalized_balance_updated_at
    )
    if (
        conn.last_realtime_balance_at is not None
        and normalized_cache_updated_at is not None
        and normalized_cache_updated_at < conn.last_realtime_balance_at
    ):
        result = {"status": "skipped", "reason": "cache_older_than_realtime"}
        if cache is not None:
            cache[user.id] = result
        return result

    # Don't overwrite a manually-entered balance with a possibly-stale Plaid
    # cached value. If the user keyed in a balance more recently than Plaid's
    # cached freshness (or Plaid did not report its freshness at all), the
    # manual value is authoritative regardless of which calendar day either
    # falls on. This sits alongside the email and real-time refresh checks;
    # the cached update may only proceed when all of them allow it.
    manual_balance_dt = _normalize_naive_utc(
        getattr(user, "last_manual_balance_entry_at", None)
    )
    if manual_balance_dt is not None and (
        normalized_cache_updated_at is None
        or normalized_cache_updated_at < manual_balance_dt
    ):
        logger.info(
            "Plaid cached /accounts/get sync skipped for user %s: "
            "manual balance entry is newer than Plaid cached freshness",
            user.id,
        )
        result = {
            "status": "skipped",
            "reason": "skipped_cached_plaid_update_manual_newer",
        }
        if cache is not None:
            cache[user.id] = result
        return result

    # Don't overwrite an email-derived balance with a possibly-stale Plaid
    # cached value. If the resolved Plaid cached freshness is older than (or
    # unknown relative to) the most recent balance email we've processed, the
    # email value is authoritative regardless of which calendar day either
    # falls on.
    email_balance_dt = _newest_email_balance_datetime(user.id)
    if email_balance_dt is not None and (
        normalized_cache_updated_at is None
        or normalized_cache_updated_at < email_balance_dt
    ):
        logger.info(
            "Plaid cached /accounts/get sync skipped for user %s: "
            "email balance is newer than Plaid cached freshness",
            user.id,
        )
        result = {
            "status": "skipped",
            "reason": "skipped_cached_plaid_update_email_newer",
        }
        if cache is not None:
            cache[user.id] = result
        return result

    if available is not None:
        balance_value = float(available)
        source = _BALANCE_SOURCE_AVAILABLE
    elif current is not None:
        balance_value = float(current)
        source = _BALANCE_SOURCE_CURRENT_FALLBACK
    else:
        _record_sync_status(
            conn,
            "no_balance_value",
            "Plaid did not return available or current balance.",
        )
        db.session.commit()
        result = {"status": "skipped", "reason": "no_balance_value"}
        if cache is not None:
            cache[user.id] = result
        return result

    _upsert_today_balance(user.id, balance_value)
    _record_sync_status(conn, source, None)
    db.session.commit()
    result = {"status": "ok", "source": source}
    if cache is not None:
        cache[user.id] = result
    return result


def safe_update_plaid_balance_for_user(user) -> None:
    """Wrapper that never raises — for use from dashboard request paths."""
    try:
        update_plaid_balance_for_user(user)
    except Exception:
        logger.exception("Plaid balance update failed for user %s", getattr(user, "id", None))
        try:
            db.session.rollback()
        except Exception:
            pass


def record_manual_balance_entry(user) -> None:
    """Stamp *user*'s last manual balance entry time (naive UTC).

    Call from the web/API manual balance entry paths after validation
    succeeds and the balance write is staged to commit. The cached
    /accounts/get sync compares this against Plaid's cached freshness so a
    stale cached balance cannot immediately overwrite a newer manual entry.
    Does not commit — the caller commits it alongside the balance write.
    """
    if user is None or not getattr(user, "id", None):
        return
    user.last_manual_balance_entry_at = datetime.now(timezone.utc).replace(tzinfo=None)


# ── Real-time balance refresh (/accounts/balance/get) ────────────────────────


def _iso_utc(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.replace(microsecond=0).isoformat() + "Z"


def _seconds_until_realtime_refresh(conn: PlaidConnection) -> int:
    """Return seconds remaining before the next real-time refresh is allowed.

    Zero means a refresh is allowed now. Treat any value > 0 as rate-limited.
    """
    last = conn.last_realtime_balance_at
    if last is None:
        return 0
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    elapsed = (now - last).total_seconds()
    remaining = REALTIME_BALANCE_COOLDOWN_SECONDS - int(elapsed)
    return max(remaining, 0)


def _next_available_refresh_at(conn: PlaidConnection) -> Optional[datetime]:
    if conn.last_realtime_balance_at is None:
        return None
    return conn.last_realtime_balance_at + timedelta(
        seconds=REALTIME_BALANCE_COOLDOWN_SECONDS
    )


def _record_realtime_status(
    conn: PlaidConnection, status: str, error: Optional[str]
) -> None:
    """Write the dedicated real-time refresh status/error columns.

    Kept separate from ``_record_sync_status`` so a failed paid call cannot
    overwrite the unrelated status of the automatic /accounts/get sync.
    """
    conn.last_realtime_refresh_status = status[:64] if status else None
    conn.last_realtime_refresh_error = error[:255] if error else None


def _claim_realtime_refresh_slot(conn_id: int) -> bool:
    """Atomically reserve the next 24-hour real-time refresh window.

    Updates ``last_realtime_balance_at`` to *now* only when the previous
    value is null or older than the cooldown. Returns True if this caller
    won the race and may now call Plaid; False if another caller is already
    inside (or has just consumed) the window. The pre-call write ensures
    that even a failed-but-billed Plaid call consumes the cooldown.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(seconds=REALTIME_BALANCE_COOLDOWN_SECONDS)
    updated = (
        db.session.query(PlaidConnection)
        .filter(
            PlaidConnection.id == conn_id,
            or_(
                PlaidConnection.last_realtime_balance_at.is_(None),
                PlaidConnection.last_realtime_balance_at <= cutoff,
            ),
        )
        .update(
            {PlaidConnection.last_realtime_balance_at: now},
            synchronize_session=False,
        )
    )
    db.session.commit()
    return updated == 1


def realtime_update_plaid_balance_for_user(user) -> dict:
    """Force-refresh today's balance from Plaid's /accounts/balance/get endpoint.

    Plaid charges per call for this product, so callers are rate-limited to
    one *attempted* refresh every ``REALTIME_BALANCE_COOLDOWN_SECONDS`` per
    connection. The cooldown timestamp is reserved with an atomic conditional
    UPDATE before the Plaid call is made — that way a failed-but-billed call
    still consumes the window, and rapid double-clicks cannot trigger
    duplicate paid calls.

    Returns a status dict; never returns Plaid secrets or raw payloads.
    """
    if user is None or not getattr(user, "id", None):
        return {"status": "skipped", "reason": "no_user"}

    if not plaid_is_configured():
        return {"status": "skipped", "reason": "not_configured"}

    conn = get_active_connection(user)
    if conn is None:
        return {"status": "skipped", "reason": "no_connection"}

    # A connection Plaid already said needs the user (or whose consent has
    # expired) cannot succeed, so don't spend the 24-hour window on it.
    if connection_needs_reconnect(conn):
        return {"status": "skipped", "reason": RECONNECT_REQUIRED_STATUS}

    # Atomic pre-call cooldown claim: succeeds only when the previous
    # refresh was >= 24 hours ago (or never).
    if not _claim_realtime_refresh_slot(conn.id):
        # Reload to see the existing timestamp written by whoever owns the slot.
        db.session.refresh(conn)
        return {
            "status": "rate_limited",
            "reason": "cooldown_active",
            "retry_after_seconds": _seconds_until_realtime_refresh(conn),
            "last_realtime_balance_at": _iso_utc(conn.last_realtime_balance_at),
            "next_available_refresh_at": _iso_utc(_next_available_refresh_at(conn)),
        }

    # Slot reserved — refresh local state so we see the new timestamp.
    db.session.refresh(conn)
    refreshed_at = conn.last_realtime_balance_at

    from plaid.exceptions import ApiException
    from plaid.model.accounts_balance_get_request import AccountsBalanceGetRequest
    from plaid.model.accounts_balance_get_request_options import (
        AccountsBalanceGetRequestOptions,
    )

    try:
        access_token = decrypt_password(conn.encrypted_access_token)
    except Exception:
        logger.warning(
            "Could not decrypt Plaid access token for user %s (realtime refresh)",
            user.id,
        )
        _record_realtime_status(
            conn, "decrypt_failed", "Stored Plaid token could not be read."
        )
        db.session.commit()
        return {
            "status": "error",
            "reason": "decrypt_failed",
            "refreshed_at": _iso_utc(refreshed_at),
            "next_available_refresh_at": _iso_utc(_next_available_refresh_at(conn)),
        }

    try:
        client = _plaid_client()
        request = AccountsBalanceGetRequest(
            access_token=access_token,
            options=AccountsBalanceGetRequestOptions(
                account_ids=[conn.plaid_account_id]
            ),
        )
        response = client.accounts_balance_get(request)
    except ApiException as exc:
        info = _plaid_error_info(exc)
        logger.warning(
            "Plaid accounts_balance_get failed for user %s "
            "(request_id=%s, error_type=%s, error_code=%s, error_message=%s)",
            user.id,
            info.get("request_id"),
            info.get("error_type"),
            info.get("error_code"),
            info.get("error_message"),
        )
        if _is_reconnect_error_code(info.get("error_code")):
            _mark_reconnect_required(conn)
            _record_realtime_status(
                conn, RECONNECT_REQUIRED_STATUS, _RECONNECT_REQUIRED_MESSAGE
            )
            reason = RECONNECT_REQUIRED_STATUS
        else:
            _record_realtime_status(
                conn,
                "plaid_realtime_api_error",
                "Plaid real-time balance request failed.",
            )
            reason = "plaid_api_error"
        db.session.commit()
        return {
            "status": "error",
            "reason": reason,
            "refreshed_at": _iso_utc(refreshed_at),
            "next_available_refresh_at": _iso_utc(_next_available_refresh_at(conn)),
        }
    except Exception:
        logger.exception(
            "Unexpected error calling Plaid /accounts/balance/get for user %s", user.id
        )
        _record_realtime_status(
            conn, "plaid_realtime_unexpected_error", "Unexpected Plaid error."
        )
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        return {
            "status": "error",
            "reason": "unexpected_error",
            "refreshed_at": _iso_utc(refreshed_at),
            "next_available_refresh_at": _iso_utc(_next_available_refresh_at(conn)),
        }

    target = None
    try:
        accounts = list(response.accounts or [])
    except Exception:
        accounts = []
    for acct in accounts:
        if str(getattr(acct, "account_id", "")) == conn.plaid_account_id:
            target = acct
            break

    if target is None:
        _record_realtime_status(
            conn,
            "account_not_found",
            "Connected Plaid account was not in the balance response.",
        )
        db.session.commit()
        return {
            "status": "error",
            "reason": "account_not_found",
            "refreshed_at": _iso_utc(refreshed_at),
            "next_available_refresh_at": _iso_utc(_next_available_refresh_at(conn)),
        }

    balances = getattr(target, "balances", None)
    available = getattr(balances, "available", None) if balances is not None else None
    current = getattr(balances, "current", None) if balances is not None else None

    if available is not None:
        balance_value = float(available)
        source = _BALANCE_SOURCE_REALTIME_AVAILABLE
    elif current is not None:
        balance_value = float(current)
        source = _BALANCE_SOURCE_REALTIME_CURRENT_FALLBACK
    else:
        _record_realtime_status(
            conn,
            "no_balance_value",
            "Plaid did not return available or current balance.",
        )
        db.session.commit()
        return {
            "status": "skipped",
            "reason": "no_balance_value",
            "refreshed_at": _iso_utc(refreshed_at),
            "next_available_refresh_at": _iso_utc(_next_available_refresh_at(conn)),
        }

    _upsert_today_balance(user.id, balance_value)
    _record_realtime_status(conn, source, None)
    db.session.commit()
    return {
        "status": "ok",
        "source": source,
        "amount": balance_value,
        "refreshed_at": _iso_utc(refreshed_at),
        "next_available_refresh_at": _iso_utc(_next_available_refresh_at(conn)),
    }
