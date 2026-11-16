"""Regression tests for findings from the independent security review."""

import socket
import threading
from dataclasses import replace
from datetime import date, timedelta
from decimal import Decimal

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

from mcp_integration.mcp_helpers import (
    ALL_SCOPES, CHATGPT_REDIRECT, CLAUDE_REDIRECT, error_code, pkce_pair, schedule_id, utcnow,
)

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


class TestCodexReviewFindings:
    """Codex PR review: stale-start coverage and post-maintenance etags."""

    def _stale_item(self, uid, name, frequency, days_ago, amount="500.00", type_="Expense"):
        start = date.today() - timedelta(days=days_ago)
        row = Schedule(user_id=uid, name=name, amount=amount, type=type_, frequency=frequency,
                       startdate=start, firstdate=start)
        _db.session.add(row)
        _db.session.commit()
        return row.id

    @pytest.mark.parametrize("frequency,days_ago", [("Quarterly", 200), ("Monthly", 190), ("Weekly", 150)])
    def test_long_window_balances_match_cash_flow_totals(self, mcp, make_user, issue_token, app_ctx,
                                                         frequency, days_ago):
        uid = make_user(balance="100000.00")
        self._stale_item(uid, "Stale bill", frequency, days_ago)
        end = (date.today() + timedelta(days=270)).isoformat()
        result = mcp.call(issue_token(uid), "get_cashflow_projection", {"end_date": end}).structured_content
        stats = result["baseline"]["stats"]
        net = Decimal(result["baseline_cash_flow"]["net"])
        assert Decimal(stats["ending_balance"]) - Decimal(stats["start_balance"]) == net
        complete = result["projection_complete_through"]
        assert complete is not None
        assert result["window"]["end_date"] == min(end, complete)
        if date.today().weekday() < 5:
            # Maintenance advanced the stale date, so the full window is covered.
            assert result["window"]["end_date"] == end

    def test_settled_projection_is_stable(self, make_user, app_ctx):
        uid = make_user(balance="10.00")
        self._stale_item(uid, "Weekly stale", "Weekly", 400)
        projections.run_projection(uid, settle=True)
        before = projections._maintenance_signature(uid)
        projections.run_projection(uid, settle=True)
        assert projections._maintenance_signature(uid) == before

    def test_rest_projection_stays_single_pass(self, make_user, app_ctx, monkeypatch):
        uid = make_user(balance="10.00")
        calls = []
        real = projections._run_projection_once
        monkeypatch.setattr(projections, "_run_projection_once",
                            lambda user_id: calls.append(user_id) or real(user_id))
        projections.run_projection(uid)
        assert calls == [uid]

    def test_returned_etag_matches_stored_row_after_maintenance(self, mcp, make_user, issue_token, app_ctx):
        uid = make_user(balance="5000.00")
        token = issue_token(uid)
        past = (date.today() - timedelta(days=40)).isoformat()
        created = mcp.call(token, "create_schedule", {
            "name": "Back-dated", "amount": "20.00", "type": "Expense", "frequency": "Monthly",
            "start_date": past}).structured_content
        etag = created["item"]["etag"]
        stored = mcp.call(token, "get_schedule", {"schedule_id": created["item"]["id"]}).structured_content
        assert stored["etag"] == etag
        updated = mcp.call(token, "update_schedule", {"schedule_id": created["item"]["id"], "amount": "25.00",
                                                      "expected_etag": etag})
        assert not updated.is_error, updated.structured_content
        follow_up = mcp.call(token, "update_schedule", {"schedule_id": created["item"]["id"], "amount": "30.00",
                                                        "expected_etag": updated.structured_content["item"]["etag"]})
        assert not follow_up.is_error, follow_up.structured_content


class TestConsentHandoffUnderFormActionCsp:
    """Production enforces the app-wide CSP ``form-action 'self'``.

    Browsers apply form-action to every redirect after a form submission, so a
    cross-origin 302 from the Allow/Deny POST is silently dropped: the user
    clicks Allow and nothing happens (reported on Claude for iOS). The POST
    must answer with a page that navigates to the client instead.
    """

    @staticmethod
    def _decide(oauth, make_user, decision="approve", state="state-123", redirect_uri=CLAUDE_REDIRECT):
        uid = make_user()
        info = oauth.register(redirect_uris=[redirect_uri])
        _v, challenge = pkce_pair()
        params = oauth.authorize_params(info["client_id"], challenge=challenge, state=state,
                                        redirect_uri=redirect_uri)
        return oauth.approve(oauth.login_as(uid), params, decision=decision)

    @staticmethod
    def _csp(resp):
        return (resp.headers.get("Content-Security-Policy")
                or resp.headers.get("Content-Security-Policy-Report-Only") or "")

    @pytest.mark.parametrize("redirect_uri", [CLAUDE_REDIRECT, CHATGPT_REDIRECT])
    def test_allow_answers_with_continue_page_not_cross_origin_redirect(self, oauth, make_user, redirect_uri):
        resp = self._decide(oauth, make_user, redirect_uri=redirect_uri)
        assert resp.status_code == 200 and "Location" not in resp.headers
        target = oauth.redirect_location(resp)
        assert target.startswith(redirect_uri + "?")
        params = oauth.redirect_params(resp)
        assert params["code"].startswith("pcf_ac_") and params["state"] == "state-123"
        body = resp.get_data(as_text=True)
        # Script, meta refresh (no JavaScript) and a link all point at the client.
        assert 'http-equiv="refresh"' in body and "window.location.replace(" in body
        # The CSP is unchanged: still form-action 'self' only.
        assert "form-action 'self';" in self._csp(resp) + ";"
        assert "claude.ai" not in self._csp(resp) and "chatgpt.com" not in self._csp(resp)
        assert resp.headers["Cache-Control"] == "no-store"
        assert resp.headers["Referrer-Policy"] == "no-referrer"

    def test_deny_also_uses_continue_page(self, oauth, make_user):
        resp = self._decide(oauth, make_user, decision="deny")
        assert resp.status_code == 200 and "Location" not in resp.headers
        params = oauth.redirect_params(resp)
        assert params["error"] == "access_denied" and params["state"] == "state-123"

    def test_state_cannot_inject_markup_into_continue_page(self, oauth, make_user):
        state = '"><script>alert(1)</script>'
        resp = self._decide(oauth, make_user, state=state)
        body = resp.get_data(as_text=True)
        assert "<script>alert(1)</script>" not in body
        assert oauth.redirect_params(resp)["state"] == state

    def test_get_time_errors_still_redirect_directly(self, oauth, make_user):
        # No form submission is involved, so form-action does not apply.
        uid = make_user()
        info = oauth.register()
        _v, challenge = pkce_pair()
        params = oauth.authorize_params(info["client_id"], challenge=challenge, scope="nonexistent:scope")
        resp = oauth.login_as(uid).get(oauth.url(params))
        assert resp.status_code == 302 and resp.headers["Location"].startswith(CLAUDE_REDIRECT + "?")
