"""Regression tests for findings from the independent security review."""

import socket
import threading
from dataclasses import replace
from datetime import date, timedelta

import pytest

from app import db as _db
from app.api.auth_utils import create_token_for_user
from app.models import (
    Hold, OAuthAuditEvent, OAuthClient, OAuthGrant, OAuthToken, PasskeyCredential, Schedule, User, UserToken,
)
from app.oauth import cimd
from app.oauth.config import DEFAULT_REDIRECT_URIS
from app.oauth.security import RedirectPolicy
from app.services import projections

from mcp_integration.mcp_helpers import ALL_SCOPES, CLAUDE_REDIRECT, error_code, schedule_id, utcnow

PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


class TestGuestRemovalRevokesOAuth:
    def test_remove_guest_deletes_oauth_rows_and_kills_tokens(self, mcp, make_user, login_as, oauth, app_ctx):
        owner = make_user()
        guest = make_user(admin=False, owner_id=owner)
        _client, token = oauth.connect(guest, scopes="projections:read schedules:read")
        _db.session.add(PasskeyCredential(user_id=guest, credential_id=f"cred-{guest}", public_key="pk"))
        _db.session.commit()
        create_token_for_user(_db.session.get(User, guest))
        # The guest also has an audit trail (consent events) referencing it.
        assert OAuthAuditEvent.query.filter_by(user_id=guest).count() > 0

        resp = login_as(owner).post(f"/remove_guest/{guest}")
        assert resp.status_code == 302
        _db.session.expire_all()
        assert _db.session.get(User, guest) is None
        for model in (OAuthGrant, OAuthToken, OAuthAuditEvent, PasskeyCredential, UserToken):
            assert model.query.filter_by(user_id=guest).count() == 0, model.__name__
        assert mcp.http(token["access_token"], json=PING).status_code == 401


class TestScopeLeakage:
    @pytest.mark.parametrize("tool,args,needed", [
        ("create_hold", lambda o: {"schedule_id": schedule_id(o, "Rent")}, "schedules:read"),
        ("create_skip", lambda o: {"schedule_id": schedule_id(o, "Rent")}, "schedules:read"),
        ("create_skip", lambda o: {"schedule_id": schedule_id(o, "Rent")}, "projections:read"),
        ("preview_change", lambda o: {"change_type": "create_hold", "schedule_id": schedule_id(o, "Rent")},
         "schedules:read"),
        ("preview_change", lambda o: {"change_type": "create_skip", "schedule_id": schedule_id(o, "Rent")},
         "schedules:read"),
    ])
    def test_schedule_details_need_schedules_read(self, mcp, owner, issue_token, tool, args, needed, app_ctx):
        scopes = " ".join(s for s in ALL_SCOPES.split() if s != needed)
        result = mcp.call(issue_token(owner, scopes=scopes), tool, args(owner))
        assert error_code(result) == "insufficient_scope"
        assert "Rent" not in str(result.structured_content)
        assert Hold.query.filter_by(user_id=owner).count() == 0


class TestPostCommitFailures:
    def test_summary_failure_does_not_misreport_committed_write(self, mcp, owner, issue_token, monkeypatch,
                                                               app_ctx):
        def boom(_user_id):
            raise RuntimeError("projection engine down")

        monkeypatch.setattr(projections, "run_projection", boom)
        result = mcp.call(issue_token(owner), "create_schedule", {
            "name": "Water", "amount": "30.00", "type": "Expense", "frequency": "Monthly",
            "start_date": (date.today() + timedelta(days=9)).isoformat()})
        assert not result.is_error
        assert result.structured_content["projection_after_change"] is None
        assert Schedule.query.filter_by(user_id=owner, name="Water").count() == 1


class TestPathNormalisation:
    def test_trailing_slash_is_served_not_redirected(self, mcp, make_user, issue_token):
        token = issue_token(make_user())
        resp = mcp.http(token, path="/mcp/", json=PING)
        assert resp.status_code == 200 and "location" not in {k.lower() for k in resp.headers}

    def test_trailing_slash_with_foreign_host_still_rejected(self, mcp, make_user, issue_token):
        token = issue_token(make_user())
        resp = mcp.http(token, path="/mcp/", json=PING, headers={"Host": "evil.example"})
        assert resp.status_code == 421 and "location" not in {k.lower() for k in resp.headers}


class TestRedirectAllowlist:
    policy = RedirectPolicy(DEFAULT_REDIRECT_URIS.split(","), allow_loopback=True)

    @pytest.mark.parametrize("uri", [
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://chatgpt.com/connector/oauth/abc_123-XYZ",
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
        "http://localhost/callback", "http://127.0.0.1:33418/callback",
    ])
    def test_published_callbacks_allowed(self, uri):
        assert self.policy.check_registration(uri) is None

    @pytest.mark.parametrize("uri", [
        "https://claude.ai/some/open/redirect", "https://chatgpt.com/",
        "https://chatgpt.com/connector/oauth/", "https://chatgpt.com/connector/oauth/a/b",
        "https://chatgpt.com/connector/oauth/..%2F..%2Fx", "https://chatgpt.com/connector/oauth/a?next=x",
        "https://claude.ai/api/mcp/auth_callback?x=1", "https://claude.ai/api/mcp/auth_callback/",
        "https://claude.ai:8443/api/mcp/auth_callback", "https://CLAUDE.ai/api/mcp/auth_callback",
    ])
    def test_other_paths_on_trusted_hosts_rejected(self, uri):
        assert self.policy.check_registration(uri) is not None

    def test_dcr_rejects_unlisted_path(self, client):
        resp = client.post("/oauth/register", json={
            "redirect_uris": ["https://claude.ai/attacker/path"], "token_endpoint_auth_method": "none"})
        assert resp.status_code == 400


class TestCimdHardening:
    @pytest.mark.parametrize("address", ["64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1", "::7f00:1",
                                         "2002:a9fe:a9fe::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
                                         "::ffff:10.0.0.1"])
    def test_ipv4_embedding_addresses_refused(self, monkeypatch, address):
        monkeypatch.setattr(cimd.socket, "getaddrinfo",
                            lambda *a, **k: [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 443, 0, 0))])
        with pytest.raises(cimd.CimdError):
            cimd.resolve_public_ip("chatgpt.com")

    def test_public_address_allowed(self, monkeypatch):
        monkeypatch.setattr(cimd.socket, "getaddrinfo",
                            lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.18.32.47", 443))])
        assert cimd.resolve_public_ip("chatgpt.com") == "104.18.32.47"

    def test_watchdog_unblocks_a_stalled_read(self):
        left, right = socket.socketpair()
        holder = type("Conn", (), {"sock": left})()
        received = []
        reader = threading.Thread(target=lambda: received.append(left.recv(10)))
        reader.start()
        cimd._abort_connection(holder)
        reader.join(timeout=5)
        assert not reader.is_alive() and received == [b""]
        left.close()
        right.close()


def test_registration_cap_reclaims_abandoned_clients(oauth, flask_app, monkeypatch, app_ctx):
    server = flask_app.extensions["pycashflow_oauth_server"]
    abandoned = oauth.register()
    row = OAuthClient.query.filter_by(client_id=abandoned["client_id"]).first()
    row.created_at = utcnow() - timedelta(hours=2)
    _db.session.commit()
    current = OAuthClient.query.filter_by(registration_type="dcr").count()
    monkeypatch.setattr(server, "config", replace(server.config, max_dcr_clients=current))
    resp = oauth.anon.post("/oauth/register", json={"redirect_uris": [CLAUDE_REDIRECT],
                                                   "token_endpoint_auth_method": "none"})
    assert resp.status_code == 201
    assert OAuthClient.query.filter_by(client_id=abandoned["client_id"]).first() is None
