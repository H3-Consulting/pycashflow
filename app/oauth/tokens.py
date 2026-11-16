"""OAuth token lifecycle: verification (resource server side), revocation, GC."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, update

from app import db
from app.models import (
    McpIdempotencyKey,
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthGrant,
    OAuthToken,
    User,
)
from app.subscription import enforce_user_access

from .scopes import split_scope
from .security import ACCESS_TOKEN_PREFIX, normalize_resource, sha256_hex

logger = logging.getLogger(__name__)

# A rotated refresh token presented again within this window is answered with
# invalid_grant but does not revoke the grant (tolerates client retries after
# a lost response). Later re-use is treated as theft and revokes the grant.
REFRESH_REUSE_GRACE = timedelta(seconds=30)
LAST_USED_WRITE_INTERVAL = timedelta(minutes=5)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass(frozen=True)
class Principal:
    """The authenticated caller of an MCP request, derived server-side only."""

    user_id: int
    effective_user_id: int
    client_id: str
    client_name: str | None
    grant_id: int
    token_id: int
    scopes: frozenset = field(default_factory=frozenset)
    is_guest: bool = False
    can_write: bool = False

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


def grant_is_live(grant: OAuthGrant | None, now: datetime | None = None) -> bool:
    now = now or utcnow()
    if grant is None or grant.revoked_at is not None:
        return False
    return grant.expires_at is None or grant.expires_at > now


def verify_access_token(raw_token: str, expected_resource: str) -> Principal | None:
    """Validate an MCP bearer token; return the principal or ``None``.

    Checks, in order: token format, hash lookup, access revocation and expiry,
    audience (RFC 8707 resource), grant liveness, client still active, and the
    user's current account/subscription status (``enforce_user_access``).
    Only OAuth access tokens are accepted — REST/iOS tokens never match.
    """
    from app.services.access import can_write_financial_data, effective_user_id, is_guest

    if not isinstance(raw_token, str) or not raw_token.startswith(ACCESS_TOKEN_PREFIX):
        return None
    if len(raw_token) > 200:
        return None
    now = utcnow()
    row = OAuthToken.query.filter_by(access_token_hash=sha256_hex(raw_token)).first()
    if row is None or row.access_revoked_at is not None or row.access_expires_at <= now:
        return None
    if normalize_resource(row.resource) != normalize_resource(expected_resource):
        logger.warning("Rejected OAuth token issued for a different resource (token_id=%s)", row.id)
        return None
    grant = db.session.get(OAuthGrant, row.grant_id)
    if not grant_is_live(grant, now):
        return None
    client = OAuthClient.query.filter_by(client_id=row.client_id).first()
    if client is None or not client.is_active:
        return None
    user = db.session.get(User, row.user_id)
    if user is None or not enforce_user_access(user):
        return None
    if grant.last_used_at is None or now - grant.last_used_at > LAST_USED_WRITE_INTERVAL:
        grant.last_used_at = now
        db.session.commit()
    return Principal(
        user_id=user.id,
        effective_user_id=effective_user_id(user),
        client_id=row.client_id,
        client_name=grant.client_name,
        grant_id=grant.id,
        token_id=row.id,
        scopes=frozenset(split_scope(row.scope)),
        is_guest=is_guest(user),
        can_write=can_write_financial_data(user),
    )


def revoke_grant(grant: OAuthGrant, reason: str, *, commit: bool = True) -> None:
    """Revoke a grant and every token issued under it."""
    now = utcnow()
    if grant.revoked_at is None:
        grant.revoked_at = now
        grant.revoked_reason = reason[:40]
    db.session.execute(
        update(OAuthToken)
        .where(OAuthToken.grant_id == grant.id, OAuthToken.access_revoked_at.is_(None))
        .values(access_revoked_at=now)
    )
    db.session.execute(
        update(OAuthToken)
        .where(OAuthToken.grant_id == grant.id, OAuthToken.refresh_revoked_at.is_(None))
        .values(refresh_revoked_at=now, refresh_revoked_reason="grant_revoked")
    )
    if commit:
        db.session.commit()


def revoke_grant_by_id(grant_id: int | None, reason: str) -> None:
    if grant_id is None:
        return
    grant = db.session.get(OAuthGrant, grant_id)
    if grant is not None:
        revoke_grant(grant, reason)


def revoke_all_user_grants(user_id: int, reason: str, *, commit: bool = True) -> int:
    """Revoke every live OAuth grant for a user (e.g. after a password change)."""
    grants = OAuthGrant.query.filter_by(user_id=user_id, revoked_at=None).all()
    for grant in grants:
        revoke_grant(grant, reason, commit=False)
    if commit:
        db.session.commit()
    return len(grants)


def collect_garbage(max_dcr_idle: timedelta = timedelta(days=7)) -> None:
    """Delete expired codes/tokens/idempotency keys and unused DCR clients."""
    now = utcnow()
    # Expired codes can no longer be redeemed, so replay tracking is moot.
    OAuthAuthorizationCode.query.filter(
        OAuthAuthorizationCode.expires_at < now - timedelta(days=1),
    ).delete(synchronize_session=False)
    McpIdempotencyKey.query.filter(
        McpIdempotencyKey.created_at < now - timedelta(days=1)
    ).delete(synchronize_session=False)
    stale_cutoff = now - timedelta(days=30)
    dead_tokens = OAuthToken.query.filter(
        OAuthToken.access_expires_at < stale_cutoff,
        or_(OAuthToken.refresh_expires_at.is_(None), OAuthToken.refresh_expires_at < stale_cutoff,
            OAuthToken.refresh_revoked_at.isnot(None)),
    )
    dead_tokens.delete(synchronize_session=False)
    # DCR clients that never completed an authorization within the idle window.
    used_client_ids = db.session.query(OAuthGrant.client_id).distinct()
    pending_code_client_ids = db.session.query(OAuthAuthorizationCode.client_id).distinct()
    OAuthClient.query.filter(
        OAuthClient.registration_type == "dcr",
        OAuthClient.created_at < now - max_dcr_idle,
        ~OAuthClient.client_id.in_(used_client_ids),
        ~OAuthClient.client_id.in_(pending_code_client_ids),
    ).delete(synchronize_session=False)
    db.session.commit()
