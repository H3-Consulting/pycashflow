"""MCP endpoint authentication, transport security and protocol behaviour."""

import asyncio
from datetime import timedelta

import pytest

from app import db as _db
from app.api.auth_utils import create_token_for_user
from app.models import OAuthClient, OAuthGrant, Subscription, User

from mcp_integration.mcp_helpers import ALL_SCOPES, BASE, RESOURCE, initialize_body, utcnow

PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


class TestAuthentication:
    def test_missing_token_gets_resource_metadata_challenge(self, mcp):
        resp = mcp.http(None, json=initialize_body())
        assert resp.status_code == 401
        challenge = resp.headers["www-authenticate"]
        assert challenge.startswith("Bearer ")
        assert f'resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"' in challenge
        assert 'scope="projections:read' in challenge
        assert resp.json()["error"] == "invalid_token"

    @pytest.mark.parametrize("method", ["GET", "DELETE", "OPTIONS", "HEAD", "PUT"])
    def test_every_method_requires_auth(self, mcp, method):
        assert mcp.http(None, method=method).status_code == 401

    def test_trailing_slash_path_requires_auth(self, mcp):
        assert mcp.http(None, path="/mcp/", json=PING).status_code == 401

    @pytest.mark.parametrize("header", ["Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "bearer pcf_at_nope",
                                        "Token pcf_at_x"])
    def test_malformed_authorization_headers(self, mcp, header):
        assert mcp.http(None, json=PING, headers={"Authorization": header}).status_code == 401

    def test_valid_token_initializes(self, mcp, make_user, issue_token):
        token = issue_token(make_user())
        resp = mcp.http(token, json=initialize_body())
        assert resp.status_code == 200
        assert resp.json()["result"]["serverInfo"]["name"] == "pycashflow"

    def test_token_in_query_string_is_ignored(self, mcp, make_user, issue_token):
        token = issue_token(make_user())
        assert mcp.http(None, path=f"/mcp?access_token={token}", json=PING).status_code == 401

    def test_ios_api_token_rejected_at_mcp(self, mcp, make_user, app_ctx):
        raw, _ = create_token_for_user(_db.session.get(User, make_user()))
        assert mcp.http(raw, json=PING).status_code == 401

    def test_oauth_token_rejected_by_rest_api(self, client, make_user, issue_token):
        token = issue_token(make_user())
        resp = client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_expired_token(self, mcp, make_user, issue_token):
        token = issue_token(make_user(), expires_in=-1)
        assert mcp.http(token, json=PING).status_code == 401

    def test_token_for_other_resource(self, mcp, make_user, issue_token):
        token = issue_token(make_user(), resource="https://other.example/mcp")
        assert mcp.http(token, json=PING).status_code == 401

    def test_revoked_grant(self, mcp, make_user, issue_token, app_ctx):
        uid = make_user()
        token = issue_token(uid)
        grant = OAuthGrant.query.filter_by(user_id=uid).first()
        grant.revoked_at = utcnow()
        _db.session.commit()
        assert mcp.http(token, json=PING).status_code == 401

    def test_expired_grant(self, mcp, make_user, issue_token):
        token = issue_token(make_user(), grant_expires_at=utcnow() - timedelta(seconds=1))
        assert mcp.http(token, json=PING).status_code == 401

    def test_disabled_client(self, mcp, make_user, issue_token, app_ctx):
        token = issue_token(make_user(), client_id="pcf_dcr_disabled_client")
        OAuthClient.query.filter_by(client_id="pcf_dcr_disabled_client").first().is_active = False
        _db.session.commit()
        assert mcp.http(token, json=PING).status_code == 401

    def test_deactivated_user(self, mcp, make_user, issue_token, app_ctx):
        uid = make_user()
        token = issue_token(uid)
        _db.session.get(User, uid).is_active = False
        _db.session.commit()
        assert mcp.http(token, json=PING).status_code == 401

    def test_deleted_user_token_dead(self, mcp, make_user, issue_token, login_as, app_ctx):
        uid = make_user()
        token = issue_token(uid)
        resp = login_as(uid).post("/delete_my_account", data={
            "username": _db.session.get(User, uid).email, "password": "testpass123"})
        assert resp.status_code == 302
        assert _db.session.get(User, uid) is None
        assert mcp.http(token, json=PING).status_code == 401

    def test_expired_subscription_blocks_owner_and_guest(self, mcp, make_user, issue_token, flask_app, app_ctx):
        owner = make_user()
        guest = make_user(admin=False, owner_id=owner)
        _db.session.add(Subscription(user_id=owner, source="stripe", status="expired",
                                     expires_at=utcnow() - timedelta(days=1)))
        _db.session.commit()
        owner_token = issue_token(owner)
        guest_token = issue_token(guest, scopes="projections:read")
        flask_app.config["PAYMENTS_ENABLED"] = True
        try:
            assert mcp.http(owner_token, json=PING).status_code == 401
            assert mcp.http(guest_token, json=PING).status_code == 401
        finally:
            flask_app.config["PAYMENTS_ENABLED"] = False


class TestTransportSecurity:
    def test_foreign_host_header_rejected(self, mcp, make_user, issue_token):
        token = issue_token(make_user())
        resp = mcp.http(token, json=PING, headers={"Host": "evil.example"})
        assert resp.status_code == 421

    def test_foreign_origin_rejected(self, mcp, make_user, issue_token):
        token = issue_token(make_user())
        resp = mcp.http(token, json=PING, headers={"Origin": "https://evil.example"})
        assert resp.status_code == 403

    @pytest.mark.parametrize("origin", ["https://claude.ai", "https://chatgpt.com", BASE])
    def test_known_origins_allowed(self, mcp, make_user, issue_token, origin):
        token = issue_token(make_user())
        assert mcp.http(token, json=PING, headers={"Origin": origin}).status_code == 200

    def test_oversized_body_rejected(self, mcp, make_user, issue_token):
        token = issue_token(make_user())
        big = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "x" * (300 * 1024)}}
        assert mcp.http(token, json=big).status_code == 413

    def test_non_json_post_rejected(self, mcp, make_user, issue_token):
        token = issue_token(make_user())
        resp = mcp.http(token, content=b"hello", headers={"Content-Type": "text/plain"})
        assert resp.status_code in (400, 415)

    def test_stateless_mode_issues_no_session_id(self, mcp, make_user, issue_token):
        token = issue_token(make_user())
        resp = mcp.http(token, json=initialize_body())
        assert "mcp-session-id" not in {k.lower() for k in resp.headers}


class TestRateLimit:
    def test_rate_limit_per_user_and_client(self, flask_app, make_user, issue_token, monkeypatch):
        from dataclasses import replace

        from app import limiter
        from mcp_integration.mcp_helpers import McpClient

        uid = make_user()
        token = issue_token(uid)
        other_token = issue_token(make_user())
        config = flask_app.extensions["pycashflow_oauth_config"]
        monkeypatch.setitem(flask_app.extensions, "pycashflow_oauth_config",
                            replace(config, mcp_rate_limit="3/minute"))
        monkeypatch.setattr(limiter, "enabled", True)
        client = McpClient(flask_app)

        async def burst():
            import httpx2 as httpx

            from app.asgi import create_asgi_app

            asgi = create_asgi_app(flask_app)
            statuses = []
            async with asgi.mcp_server.session_manager.run():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=asgi), base_url=BASE) as http:
                    for tok in [token] * 5 + [other_token]:
                        r = await http.post("/mcp", json=PING, headers={
                            "Authorization": f"Bearer {tok}", "Accept": "application/json, text/event-stream"})
                        statuses.append(r.status_code)
            return statuses

        statuses = asyncio.run(burst())
        assert statuses[:3] == [200, 200, 200]
        assert statuses[3:5] == [429, 429]
        assert statuses[5] == 200  # a different user is unaffected
        assert client  # fixture kept for parity


class TestDiscoveryFromMcpEndpoint:
    def test_challenge_points_to_metadata_that_names_this_server(self, mcp, client):
        challenge = mcp.http(None, json=PING).headers["www-authenticate"]
        url = challenge.split('resource_metadata="', 1)[1].split('"', 1)[0]
        meta = client.get(url.replace(BASE, "")).get_json()
        assert meta["resource"] == RESOURCE
        as_meta = client.get("/.well-known/oauth-authorization-server").get_json()
        assert as_meta["issuer"] == meta["authorization_servers"][0]
        assert set(meta["scopes_supported"]) == set(ALL_SCOPES.split())
