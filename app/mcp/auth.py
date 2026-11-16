"""HTTP-level bearer authentication and rate limiting for the MCP endpoint.

Every request to ``/mcp`` must carry ``Authorization: Bearer <OAuth access
token>``. The token is validated server-side (format, hash lookup, expiry,
revocation, audience = this MCP resource, live grant, active client, current
account/subscription status). The resulting
:class:`~app.oauth.tokens.Principal` is attached to the ASGI scope state; tools
read the user, effective account and scopes only from there.

Unauthenticated or invalid requests get ``401`` with a ``WWW-Authenticate``
challenge that points to the protected-resource metadata, as required by the
MCP authorization spec and by ChatGPT/Claude to start sign-in.
"""

from __future__ import annotations

import json
import logging

import anyio

from app.oauth.scopes import ALL_SCOPES
from app.oauth.tokens import verify_access_token

logger = logging.getLogger(__name__)


def _build_rate_limiter(flask_app, config):
    spec = (config.mcp_rate_limit or "").strip()
    if not spec:
        return None, []
    from limits import parse_many
    from limits.storage import storage_from_string
    from limits.strategies import MovingWindowRateLimiter

    storage = storage_from_string(flask_app.config.get("RATELIMIT_STORAGE_URI") or "memory://")
    return MovingWindowRateLimiter(storage), parse_many(spec)


class McpAuthMiddleware:
    def __init__(self, app, flask_app, config):
        self.app = app
        self.flask_app = flask_app
        self.config = config
        self._rate_limiter, self._limits = _build_rate_limiter(flask_app, config)
        self._verify_limiter = anyio.CapacityLimiter(8)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        token = _bearer_token(scope)
        if token is None:
            await self._challenge(send, 401, "invalid_token", "Authentication required")
            return
        principal, limited = await anyio.to_thread.run_sync(self._authenticate, token,
                                                            limiter=self._verify_limiter)
        if principal is None:
            await self._challenge(send, 401, "invalid_token", "The access token is invalid, expired or revoked")
            return
        if limited:
            await _send_json(send, 429, {"error": "rate_limited",
                                         "error_description": "Too many requests; slow down and retry"},
                             extra_headers=[(b"retry-after", b"60")])
            return
        scope.setdefault("state", {})["pcf_principal"] = principal
        await self.app(scope, receive, send)

    def _authenticate(self, token: str):
        with self.flask_app.app_context():
            try:
                principal = verify_access_token(token, self.config.resource)
            except Exception:  # pragma: no cover - fail closed on unexpected errors
                logger.exception("MCP token verification failed")
                from app import db
                db.session.rollback()
                return None, False
        if principal is None:
            return None, False
        return principal, self._rate_limited(principal)

    def _rate_limited(self, principal) -> bool:
        from app import limiter as flask_limiter

        if self._rate_limiter is None or not flask_limiter.enabled:
            return False
        key = f"mcp:{principal.user_id}:{principal.client_id}"
        for item in self._limits:
            if not self._rate_limiter.hit(item, key):
                return True
        return False

    async def _challenge(self, send, status: int, error: str, description: str):
        challenge = (
            f'Bearer resource_metadata="{self.config.resource_metadata_url}", '
            f'scope="{" ".join(ALL_SCOPES)}", error="{error}", error_description="{description}"'
        )
        await _send_json(send, status, {"error": error, "error_description": description},
                         extra_headers=[(b"www-authenticate", challenge.encode("latin-1"))])


def _bearer_token(scope) -> str | None:
    for name, value in scope.get("headers") or []:
        if name.lower() == b"authorization":
            text = value.decode("latin-1")
            if text[:7].lower() == "bearer ":
                token = text[7:].strip()
                return token or None
            return None
    return None


async def _send_json(send, status: int, body: dict, extra_headers=()):
    payload = json.dumps(body).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(payload)).encode()),
        (b"cache-control", b"no-store"),
        *extra_headers,
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})
