"""Execution runtime shared by every MCP tool.

Each tool call goes through :meth:`ToolRunner.run`, which:

1. reads the :class:`~app.oauth.tokens.Principal` that the HTTP auth
   middleware attached to the request (never anything from tool arguments),
2. enforces the tool's OAuth scopes and, for writes, the guest read-only rule,
3. runs the synchronous business logic in a bounded worker thread inside a
   fresh Flask app context (own DB session, rolled back on any failure),
4. applies idempotency-key replay protection for write tools,
5. records an audit event for every write attempt, and
6. returns either typed ``structuredContent`` or a structured error.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from contextlib import nullcontext
from typing import Callable

import anyio
from mcp_types import CallToolResult, TextContent
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError

from app import db
from app.models import McpIdempotencyKey
from app.oauth import audit
from app.oauth.tokens import Principal
from app.services.errors import Conflict, ServiceError

logger = logging.getLogger(__name__)

IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")

_ACCOUNT_LOCKS: dict[int, threading.Lock] = {}
_ACCOUNT_LOCKS_GUARD = threading.Lock()


def account_write_lock(account_id: int) -> threading.Lock:
    """Per-account lock serialising MCP writes inside one worker process.

    PostgreSQL deployments additionally rely on row locks (FOR UPDATE); with
    SQLite those are no-ops, so this closes check-then-insert races (e.g.
    duplicate holds/skips) for the default single-worker container.
    """
    with _ACCOUNT_LOCKS_GUARD:
        lock = _ACCOUNT_LOCKS.get(account_id)
        if lock is None:
            lock = _ACCOUNT_LOCKS[account_id] = threading.Lock()
        return lock


class AuthContextMissing(RuntimeError):
    """The request reached a tool without an authenticated principal."""


def principal_from_context(ctx) -> Principal:
    request = getattr(ctx.request_context, "request", None)
    principal = getattr(getattr(request, "state", None), "pcf_principal", None) if request else None
    if not isinstance(principal, Principal):
        raise AuthContextMissing("No authenticated principal on this request")
    return principal


def _json_text(payload: dict) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=False, default=str)


def success(model: BaseModel) -> CallToolResult:
    data = model.model_dump(mode="json")
    return CallToolResult(content=[TextContent(type="text", text=_json_text(data))], structured_content=data)


def error_result(code: str, message: str, *, details: dict | None = None,
                 correlation_id: str | None = None, meta: dict | None = None) -> CallToolResult:
    # correlation_id is recorded in the audit log only: hosts ask servers not
    # to return trace/request identifiers in tool results.
    body = {"error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details
    return CallToolResult(
        content=[TextContent(type="text", text=_json_text(body))],
        structured_content=body,
        is_error=True,
        meta=meta,
    )


class ToolRunner:
    def __init__(self, flask_app, config, *, max_threads: int = 8):
        self.flask_app = flask_app
        self.config = config
        self._limiter = anyio.CapacityLimiter(max_threads)

    def insufficient_scope(self, missing: list[str], correlation_id: str) -> CallToolResult:
        scope = " ".join(missing)
        description = f"This connection is missing permission: {scope}. Reconnect PyCashFlow and approve it."
        challenge = (
            f'Bearer resource_metadata="{self.config.resource_metadata_url}", '
            f'error="insufficient_scope", scope="{scope}", error_description="{description}"'
        )
        return error_result(
            "insufficient_scope",
            description,
            details={"required_scopes": missing},
            correlation_id=correlation_id,
            meta={"mcp/www_authenticate": [challenge]},
        )

    async def run(
        self,
        ctx,
        *,
        tool: str,
        scopes: list[str],
        fn: Callable[[Principal, str], BaseModel],
        write: bool = False,
        resource_type: str | None = None,
        idempotency_key: str | None = None,
        idempotency_payload: dict | None = None,
    ) -> CallToolResult:
        principal = principal_from_context(ctx)
        correlation_id = audit.new_correlation_id()
        missing = [s for s in scopes if not principal.has_scope(s)]
        if missing:
            if write:
                await self._audit_async(principal, tool, resource_type, None, "denied", "insufficient_scope", correlation_id)
            return self.insufficient_scope(missing, correlation_id)
        if write and not principal.can_write:
            await self._audit_async(principal, tool, resource_type, None, "denied", "forbidden", correlation_id)
            return error_result(
                "forbidden",
                "This PyCashFlow account is view-only (guest), so it cannot change financial data.",
                correlation_id=correlation_id,
            )
        if idempotency_key is not None and not IDEMPOTENCY_KEY_PATTERN.match(idempotency_key):
            return error_result(
                "validation_error",
                "idempotency_key must be 8-128 characters of letters, digits, '.', '_', ':' or '-'",
                details={"fields": {"idempotency_key": "invalid format"}},
                correlation_id=correlation_id,
            )

        def work():
            lock = account_write_lock(principal.effective_user_id) if write else nullcontext()
            with lock, self.flask_app.app_context():
                try:
                    if write and idempotency_key:
                        model, replayed = self._run_idempotent(
                            principal, tool, idempotency_key, idempotency_payload or {},
                            lambda: fn(principal, correlation_id),
                        )
                    else:
                        model, replayed = fn(principal, correlation_id), False
                    if write:
                        audit.record_event(
                            action=f"mcp.{tool}", outcome="success", user_id=principal.user_id,
                            client_id=principal.client_id, grant_id=principal.grant_id,
                            resource_type=resource_type, resource_id=_resource_id(model),
                            correlation_id=correlation_id,
                        )
                    return success(model) if not replayed else model
                except ServiceError as exc:
                    db.session.rollback()
                    if write:
                        audit.record_event(
                            action=f"mcp.{tool}", outcome="error", user_id=principal.user_id,
                            client_id=principal.client_id, grant_id=principal.grant_id,
                            resource_type=resource_type, error_code=exc.code,
                            correlation_id=correlation_id,
                        )
                    return error_result(exc.code, exc.message, details=exc.details or None,
                                        correlation_id=correlation_id)
                except Exception:
                    db.session.rollback()
                    logger.exception("MCP tool %s failed (correlation_id=%s)", tool, correlation_id)
                    if write:
                        audit.record_event(
                            action=f"mcp.{tool}", outcome="error", user_id=principal.user_id,
                            client_id=principal.client_id, grant_id=principal.grant_id,
                            resource_type=resource_type, error_code="internal_error",
                            correlation_id=correlation_id,
                        )
                    return error_result(
                        "internal_error",
                        "PyCashFlow could not complete this request. Re-read the affected records "
                        "before retrying.",
                        correlation_id=correlation_id,
                    )

        return await anyio.to_thread.run_sync(work, limiter=self._limiter)

    # ── Idempotency ────────────────────────────────────────────────────────

    def _run_idempotent(self, principal: Principal, tool: str, key: str, payload: dict, call):
        request_hash = hashlib.sha256(
            json.dumps({"tool": tool, "args": payload}, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        scope = {"user_id": principal.user_id, "client_id": principal.client_id, "idempotency_key": key}
        existing = McpIdempotencyKey.query.filter_by(**scope).first()
        if existing is not None:
            return self._replay(existing, tool, request_hash), True
        row = McpIdempotencyKey(tool_name=tool, request_hash=request_hash, **scope)
        db.session.add(row)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            existing = McpIdempotencyKey.query.filter_by(**scope).first()
            if existing is None:  # pragma: no cover - deleted between attempts
                raise Conflict("Retry the request")
            return self._replay(existing, tool, request_hash), True
        try:
            model = call()
        except Exception:
            db.session.rollback()
            McpIdempotencyKey.query.filter_by(id=row.id).delete()
            db.session.commit()
            raise
        data = model.model_dump(mode="json")
        stored = dict(data)
        if "replayed" in stored:
            stored["replayed"] = True
        row = db.session.get(McpIdempotencyKey, row.id)
        row.response_json = json.dumps(stored, default=str)
        db.session.commit()
        return model, False

    @staticmethod
    def _replay(existing: McpIdempotencyKey, tool: str, request_hash: str) -> CallToolResult:
        if existing.tool_name != tool or existing.request_hash != request_hash:
            raise Conflict("This idempotency_key was already used for a different request")
        if not existing.response_json:
            raise Conflict("A request with this idempotency_key is still in progress; retry shortly")
        data = json.loads(existing.response_json)
        return CallToolResult(content=[TextContent(type="text", text=_json_text(data))], structured_content=data)

    async def _audit_async(self, principal, tool, resource_type, resource_id, outcome, error_code, correlation_id):
        def _write():
            with self.flask_app.app_context():
                audit.record_event(
                    action=f"mcp.{tool}", outcome=outcome, user_id=principal.user_id,
                    client_id=principal.client_id, grant_id=principal.grant_id,
                    resource_type=resource_type, resource_id=resource_id,
                    error_code=error_code, correlation_id=correlation_id,
                )

        await anyio.to_thread.run_sync(_write, limiter=self._limiter)


def _resource_id(model) -> str | None:
    for attr in ("item", "hold", "skip"):
        obj = getattr(model, attr, None)
        if obj is not None and getattr(obj, "id", None) is not None:
            return str(obj.id)
    for attr in ("deleted", "removed"):
        obj = getattr(model, attr, None)
        if isinstance(obj, dict) and obj.get("id") is not None:
            return str(obj["id"])
    return None


__all__ = ["ToolRunner", "principal_from_context", "success", "error_result", "account_write_lock"]
