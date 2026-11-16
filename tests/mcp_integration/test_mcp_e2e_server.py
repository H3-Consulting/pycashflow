"""End-to-end test against a real gunicorn ASGI server process.

Boots ``gunicorn --worker-class asgi 'app.asgi:create_asgi_app()'`` exactly as
entry.sh does with MCP enabled, on a fresh SQLite file migrated with the
real Alembic migrations, with CSRF and rate limiting enabled. It then:

1. completes the OAuth flow like a browser + MCP client would (DCR, login
   form with CSRF, consent form with CSRF, PKCE code exchange),
2. drives the MCP server over real Streamable HTTP with the official SDK client,
3. verifies the existing web UI and REST/iOS API on the same server.
"""

import asyncio
import html
import os
import re
import socket
import subprocess
import sys
import time
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from mcp_integration.mcp_helpers import pkce_pair

ROOT = Path(__file__).resolve().parents[2]
ADMIN_EMAIL = "e2e-admin@example.com"
ADMIN_PASSWORD = "E2e-Test-Passw0rd"

pytestmark = pytest.mark.skipif(
    sys.platform.startswith("win"), reason="gunicorn does not run on Windows"
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    pytest.importorskip("gunicorn")
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    db_path = tmp_path_factory.mktemp("e2e") / "e2e.sqlite"
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite:///{db_path}",
        "SECRET_KEY": "e2e-secret-key-0123456789abcdef0123",
        "APP_SECRET": "e2e-app-secret-0123456789abcdef0123",
        "SESSION_COOKIE_SECURE": "false",
        "TRUSTED_PROXY_COUNT": "0",
        "MCP_ENABLED": "true",
        "MCP_PUBLIC_BASE_URL": base,
        "BOOTSTRAP_ADMIN_EMAIL": ADMIN_EMAIL,
        "BOOTSTRAP_ADMIN_PASSWORD": ADMIN_PASSWORD,
        "PYTHONPATH": str(ROOT),
        "GUNICORN_THREADS": "4",
    }
    env.pop("TEST_DATABASE_URL", None)
    migrate = subprocess.run(
        [sys.executable, "-m", "flask", "--app", "app", "db", "upgrade"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=180,
    )
    assert migrate.returncode == 0, migrate.stderr[-2000:]
    log_path = db_path.parent / "gunicorn.log"
    log_file = open(log_path, "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "gunicorn", "--bind", f"127.0.0.1:{port}", "--workers", "1",
         "--worker-class", "asgi", "--asgi-lifespan", "on", "--timeout", "60",
         "app.asgi:create_asgi_app()"],
        # A file, not a pipe: an unread pipe could fill and stall the server.
        cwd=ROOT, env=env, stdout=log_file, stderr=subprocess.STDOUT,
    )
    import httpx2 as httpx

    # Generous deadline: CI runners and a fully loaded test run can make the
    # first import of pandas/plotly/the MCP SDK slow.
    deadline = time.time() + 180
    while time.time() < deadline:
        if proc.poll() is not None:
            pytest.fail("gunicorn exited early:\n" + log_path.read_text()[-4000:])
        try:
            if httpx.get(f"{base}/healthz", timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    else:
        proc.terminate()
        pytest.fail("gunicorn did not become healthy:\n" + log_path.read_text()[-4000:])
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:  # pragma: no cover
        proc.kill()
    log_file.close()


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "page has no CSRF token"
    return match.group(1)


def test_end_to_end_oauth_mcp_web_and_rest(live_server):
    import httpx2 as httpx

    base = live_server
    resource = f"{base}/mcp"
    browser = httpx.Client(base_url=base, follow_redirects=False, timeout=30)

    # Discovery as an MCP client sees it.
    challenge = browser.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                             headers={"Accept": "application/json, text/event-stream"})
    assert challenge.status_code == 401
    assert f'resource_metadata="{base}/.well-known/oauth-protected-resource/mcp"' in \
        challenge.headers["www-authenticate"]
    prm = browser.get("/.well-known/oauth-protected-resource/mcp").json()
    assert prm["resource"] == resource and prm["authorization_servers"] == [base]
    asm = browser.get("/.well-known/oauth-authorization-server").json()
    assert asm["issuer"] == base

    # Dynamic client registration (loopback redirect, like Claude Code).
    reg = browser.post("/oauth/register", json={
        "client_name": "E2E Client", "redirect_uris": ["http://127.0.0.1/callback"],
        "grant_types": ["authorization_code", "refresh_token"], "token_endpoint_auth_method": "none"})
    assert reg.status_code == 201
    client_id = reg.json()["client_id"]

    verifier, code_challenge = pkce_pair()
    redirect_uri = "http://127.0.0.1:43210/callback"
    authorize = "/oauth/authorize?" + urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "scope": "projections:read schedules:read schedules:write", "state": "e2e-state",
        "code_challenge": code_challenge, "code_challenge_method": "S256", "resource": resource})

    # Not signed in: bounced to the normal login page, which returns here.
    first = browser.get(authorize)
    assert first.status_code == 302 and first.headers["location"].startswith("/login?next=")
    login_page = browser.get(first.headers["location"])
    login = browser.post("/login", data={
        "csrf_token": _csrf(login_page.text), "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD,
        "next": authorize})
    assert login.status_code == 302 and login.headers["location"] == authorize

    consent = browser.get(authorize)
    assert consent.status_code == 200 and "E2E Client" in consent.text
    ticket = re.search(r'name="consent_ticket" value="([^"]+)"', consent.text).group(1)
    # Without the CSRF token the approval is refused.
    assert browser.post(authorize, data={"consent_ticket": ticket, "decision": "approve",
                                         "grant_scope": ["projections:read"]}).status_code == 400
    approved = browser.post(authorize, data={
        "csrf_token": _csrf(consent.text), "consent_ticket": ticket, "decision": "approve",
        "grant_scope": ["projections:read", "schedules:read", "schedules:write"]})
    # A continue page, not a 302: the consent form's CSP (form-action 'self')
    # would make a browser drop a cross-origin redirect after the POST.
    assert approved.status_code == 200 and "location" not in approved.headers
    assert "form-action 'self'" in (approved.headers.get("content-security-policy")
                                    or approved.headers.get("content-security-policy-report-only") or "")
    continue_url = html.unescape(re.search(r'id="oauth-continue" href="([^"]+)"', approved.text).group(1))
    callback = urlsplit(continue_url)
    params = {k: v[0] for k, v in parse_qs(callback.query).items()}
    assert f"{callback.scheme}://{callback.netloc}{callback.path}" == redirect_uri
    assert params["state"] == "e2e-state" and params["iss"] == base

    token = httpx.post(f"{base}/oauth/token", data={
        "grant_type": "authorization_code", "code": params["code"], "redirect_uri": redirect_uri,
        "client_id": client_id, "code_verifier": verifier, "resource": resource}).json()
    assert token["access_token"].startswith("pcf_at_")

    # Real Streamable HTTP with the official SDK client.
    async def mcp_session():
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        start = (date.today() + timedelta(days=6)).isoformat()
        async with httpx.AsyncClient(headers={"Authorization": f"Bearer {token['access_token']}"},
                                     timeout=30) as http:
            async with streamable_http_client(resource, http_client=http) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    init = await session.initialize()
                    tools = await session.list_tools()
                    created = await session.call_tool("create_schedule", {
                        "name": "E2E Rent", "amount": "1200.00", "type": "Expense",
                        "frequency": "Monthly", "start_date": start})
                    summary = await session.call_tool("get_projection_summary", {})
                    denied = await session.call_tool("create_hold", {"schedule_id": 1})
                    return init, tools, created, summary, denied

    init, tools, created, summary, denied = asyncio.run(mcp_session())
    assert init.server_info.name == "pycashflow"
    assert len(tools.tools) == 20
    assert not created.is_error and created.structured_content["item"]["name"] == "E2E Rent"
    assert not summary.is_error and summary.structured_content["major_outflows"][0]["name"] == "E2E Rent"
    assert denied.is_error and denied.structured_content["error"]["code"] == "insufficient_scope"

    # Refresh rotation over HTTP.
    refreshed = httpx.post(f"{base}/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": token["refresh_token"], "client_id": client_id})
    assert refreshed.status_code == 200 and refreshed.json()["refresh_token"] != token["refresh_token"]

    # Existing web UI still works on the same server (session from the login).
    dashboard = browser.get("/")
    assert dashboard.status_code == 200 and "plotly" in dashboard.text.lower()
    assert "Connected apps" in browser.get("/settings").text
    apps = browser.get("/settings/connected-apps")
    assert apps.status_code == 200 and "E2E Client" in apps.text

    # Existing REST/iOS API still works and sees the MCP-created schedule.
    rest_login = httpx.post(f"{base}/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert rest_login.status_code == 200
    rest_headers = {"Authorization": f"Bearer {rest_login.json()['data']['token']}"}
    schedules = httpx.get(f"{base}/api/v1/schedules", headers=rest_headers).json()["data"]
    assert any(s["name"] == "E2E Rent" for s in schedules)
    assert httpx.get(f"{base}/api/v1/dashboard", headers=rest_headers).status_code == 200
    # Token types stay separate across the two APIs.
    assert httpx.get(f"{base}/api/v1/dashboard",
                     headers={"Authorization": f"Bearer {refreshed.json()['access_token']}"}).status_code == 401
    ios_at_mcp = httpx.post(resource, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                            headers={**rest_headers, "Accept": "application/json, text/event-stream"})
    assert ios_at_mcp.status_code == 401
