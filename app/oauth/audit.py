"""Audit trail for OAuth grant lifecycle events and MCP mutations.

Events record *who* (user, OAuth client, grant), *what* (action, resource type
and id), the outcome and a correlation id — never tokens, secrets, record
names or amounts. Every event is also emitted as a structured log line.
Audit writes use their own short transaction and never raise into callers.
"""

from __future__ import annotations

import logging
import uuid

from app import db
from app.models import OAuthAuditEvent

logger = logging.getLogger("pycashflow.audit")


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def record_event(
    *,
    action: str,
    outcome: str,
    user_id: int | None = None,
    client_id: str | None = None,
    grant_id: int | None = None,
    resource_type: str | None = None,
    resource_id=None,
    error_code: str | None = None,
    correlation_id: str | None = None,
) -> None:
    resource_id_text = str(resource_id)[:64] if resource_id is not None else None
    logger.info(
        "audit action=%s outcome=%s user_id=%s client_id=%s grant_id=%s "
        "resource_type=%s resource_id=%s error_code=%s correlation_id=%s",
        action, outcome, user_id, client_id, grant_id,
        resource_type, resource_id_text, error_code, correlation_id,
    )
    try:
        db.session.add(OAuthAuditEvent(
            action=action[:64],
            outcome=outcome[:16],
            user_id=user_id,
            client_id=(client_id or None) and client_id[:512],
            grant_id=grant_id,
            resource_type=resource_type,
            resource_id=resource_id_text,
            error_code=(error_code or None) and error_code[:40],
            correlation_id=correlation_id,
        ))
        db.session.commit()
    except Exception:  # pragma: no cover - audit must never break the request
        db.session.rollback()
        logger.exception("Failed to persist audit event action=%s", action)
