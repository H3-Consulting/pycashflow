"""Shared constants and helpers for OAuth + MCP integration tests."""

import asyncio
import base64
import hashlib
import html
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlencode, urlsplit

from app.models import Schedule

BASE = "http://localhost"
RESOURCE = f"{BASE}/mcp"
CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
CHATGPT_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
ALL_SCOPES = (
    "projections:read schedules:read schedules:write scenarios:read scenarios:write "
    "holds:read holds:write skips:read skips:write"
)


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def pkce_pair():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class OAuthHelper:
    """Drives the real authorization-code flow through the Flask test client."""

    def __init__(self, flask_app, login_as):
        self.app = flask_app
        self.login_as = login_as
        self.anon = flask_app.test_client()

    def register(self, redirect_uris=(CLAUDE_REDIRECT,), auth_method="none",
                 grant_types=("authorization_code", "refresh_token"), name="Claude", **extra):
        body = {
            "client_name": name,
            "redirect_uris": list(redirect_uris),
            "grant_types": list(grant_types),
            "response_types": ["code"],
            "token_endpoint_auth_method": auth_method,
            **extra,
        }
        resp = self.anon.post("/oauth/register", json=body)
        assert resp.status_code == 201, resp.get_data(as_text=True)
        return resp.get_json()

    def authorize_params(self, client_id, *, redirect_uri=CLAUDE_REDIRECT, scope=ALL_SCOPES,
                         challenge=None, state="state-123", resource=RESOURCE, **extra):
        params = {
            "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
            "scope": scope, "state": state, "code_challenge": challenge,
            "code_challenge_method": "S256", "resource": resource,
        }
        params.update(extra)
        return {k: v for k, v in params.items() if v is not None}

    @staticmethod
    def url(params):
        return "/oauth/authorize?" + urlencode(params)

    @staticmethod
    def ticket(html):
        match = re.search(r'name="consent_ticket" value="([^"]+)"', html)
        assert match, "consent page did not render a ticket"
        return match.group(1)

    def approve(self, user_client, params, scopes=None, decision="approve"):
        """GET the consent page then POST the decision; return the redirect response."""
        url = self.url(params)
        page = user_client.get(url)
        assert page.status_code == 200, page.get_data(as_text=True)[:500]
        chosen = scopes if scopes is not None else params.get("scope", ALL_SCOPES).split()
        return user_client.post(url, data={
            "consent_ticket": self.ticket(page.get_data(as_text=True)),
            "decision": decision,
            "grant_scope": chosen,
        })

    @staticmethod
    def redirect_location(resp):
        """Where the response sends the browser back to the client.

        GET-time errors are plain 302s. After the Allow/Deny POST the server
        answers with a continue page (form-action CSP would block a
        cross-origin 302), whose Continue link carries the same URL.
        """
        if resp.status_code == 302:
            return resp.headers["Location"]
        body = resp.get_data(as_text=True)
        assert resp.status_code == 200 and "Location" not in resp.headers, body[:500]
        match = re.search(r'id="oauth-continue" href="([^"]+)"', body)
        assert match, "continue page has no Continue link"
        return html.unescape(match.group(1))

    @classmethod
    def redirect_params(cls, resp):
        query = parse_qs(urlsplit(cls.redirect_location(resp)).query)
        return {k: v[0] for k, v in query.items()}

    def exchange(self, client_id, code, verifier, *, redirect_uri=CLAUDE_REDIRECT, resource=RESOURCE, **extra):
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "client_id": client_id, "code_verifier": verifier}
        if resource:
            data["resource"] = resource
        data.update(extra)
        return self.anon.post("/oauth/token", data=data)

    def refresh(self, client_id, refresh_token, **extra):
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id}
        data.update(extra)
        return self.anon.post("/oauth/token", data=data)

    def connect(self, user_id, scopes=ALL_SCOPES, *, client=None, approve_scopes=None):
        """Run the whole flow for *user_id*; return (client_info, token_response)."""
        client = client or self.register()
        verifier, challenge = pkce_pair()
        params = self.authorize_params(client["client_id"], scope=scopes, challenge=challenge,
                                       redirect_uri=client["redirect_uris"][0])
        resp = self.approve(self.login_as(user_id), params, scopes=approve_scopes)
        code = self.redirect_params(resp)["code"]
        token = self.exchange(client["client_id"], code, verifier, redirect_uri=client["redirect_uris"][0])
        assert token.status_code == 200, token.get_data(as_text=True)
        return client, token.get_json()


def schedule_id(user_id, name):
    return Schedule.query.filter_by(user_id=user_id, name=name).first().id


class McpClient:
    """Synchronous facade over the SDK client talking to the real ASGI app."""

    def __init__(self, flask_app):
        self.flask_app = flask_app

    async def _session_calls(self, token, calls, raw_requests):
        import httpx2 as httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        from app.asgi import create_asgi_app

        asgi = create_asgi_app(self.flask_app)
        results = []
        async with asgi.mcp_server.session_manager.run():
            transport = httpx.ASGITransport(app=asgi)
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=headers) as http:
                for method, kwargs in raw_requests:
                    results.append(await http.request(method, **kwargs))
                if calls:
                    async with streamable_http_client(RESOURCE, http_client=http) as streams:
                        async with ClientSession(streams[0], streams[1]) as session:
                            await session.initialize()
                            for name, args in calls:
                                if name == "__list_tools__":
                                    results.append(await session.list_tools())
                                else:
                                    results.append(await session.call_tool(name, args))
        return results

    def call(self, token, name, args=None):
        return asyncio.run(self._session_calls(token, [(name, args or {})], []))[0]

    def calls(self, token, calls):
        return asyncio.run(self._session_calls(token, calls, []))

    def list_tools(self, token):
        return asyncio.run(self._session_calls(token, [("__list_tools__", None)], []))[0]

    def http(self, token, method="POST", path="/mcp", **kwargs):
        kwargs.setdefault("headers", {})
        kwargs["headers"].setdefault("Accept", "application/json, text/event-stream")
        if token:
            kwargs["headers"].setdefault("Authorization", f"Bearer {token}")
        return asyncio.run(self._session_calls(None, [], [(method, {"url": path, **kwargs})]))[0]


def error_code(result):
    assert result.is_error, f"expected an error, got {result.structured_content}"
    sc = result.structured_content
    if sc and "error" in sc:
        return sc["error"]["code"]
    return "schema_error"


def initialize_body(req_id=1):
    return {"jsonrpc": "2.0", "id": req_id, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "1"}}}
