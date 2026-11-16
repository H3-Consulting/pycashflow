"""OAuth 2.1 authorization server: discovery, registration, authorize/consent, tokens."""

import time
from dataclasses import replace
from urllib.parse import urlencode
from datetime import timedelta

import pyotp
import pytest

from app import db as _db
from app.crypto_utils import encrypt_password
from app.models import OAuthAuthorizationCode, OAuthClient, OAuthGrant, OAuthToken, User
from app.oauth import cimd
from app.oauth.security import RedirectPolicy, normalize_resource
from app.oauth.tokens import REFRESH_REUSE_GRACE

from mcp_integration.mcp_helpers import ALL_SCOPES, BASE, CHATGPT_REDIRECT, CLAUDE_REDIRECT, RESOURCE, pkce_pair, utcnow


# ── Discovery ────────────────────────────────────────────────────────────────


class TestDiscovery:
    def test_authorization_server_metadata(self, client):
        resp = client.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        meta = resp.get_json()
        assert meta["issuer"] == BASE
        assert meta["authorization_endpoint"] == f"{BASE}/oauth/authorize"
        assert meta["token_endpoint"] == f"{BASE}/oauth/token"
        assert meta["registration_endpoint"] == f"{BASE}/oauth/register"
        assert meta["code_challenge_methods_supported"] == ["S256"]
        assert meta["authorization_response_iss_parameter_supported"] is True
        assert meta["client_id_metadata_document_supported"] is True
        assert "none" in meta["token_endpoint_auth_methods_supported"]
        assert meta["grant_types_supported"] == ["authorization_code", "refresh_token"]
        assert "offline_access" not in meta["scopes_supported"]
        assert resp.headers["Access-Control-Allow-Origin"] == "*"

    @pytest.mark.parametrize("path", ["/.well-known/oauth-protected-resource",
                                      "/.well-known/oauth-protected-resource/mcp"])
    def test_protected_resource_metadata(self, client, path):
        meta = client.get(path).get_json()
        assert meta["resource"] == RESOURCE
        assert meta["authorization_servers"] == [BASE]
        assert meta["bearer_methods_supported"] == ["header"]
        assert set(meta["scopes_supported"]) == set(ALL_SCOPES.split())


# ── Dynamic client registration ─────────────────────────────────────────────


class TestRegistration:
    def test_public_client_gets_no_secret(self, oauth, app_ctx):
        info = oauth.register()
        assert info["client_id"].startswith("pcf_dcr_")
        assert "client_secret" not in info
        row = OAuthClient.query.filter_by(client_id=info["client_id"]).first()
        assert row.registration_type == "dcr" and row.client_secret_hash is None

    def test_confidential_client_secret_is_hashed(self, oauth, app_ctx):
        info = oauth.register(auth_method="client_secret_post")
        secret = info["client_secret"]
        row = OAuthClient.query.filter_by(client_id=info["client_id"]).first()
        assert row.client_secret_hash and secret not in row.client_secret_hash
        assert len(row.client_secret_hash) == 64

    @pytest.mark.parametrize("uri", [
        "https://evil.example/callback",
        "http://claude.ai/api/mcp/auth_callback",
        "https://claude.ai/cb#frag",
        "https://user:pw@claude.ai/cb",
        "javascript:alert(1)",
        "custom-scheme://callback",
        "https://claude.ai.evil.example/cb",
    ])
    def test_rejects_disallowed_redirect_uris(self, client, uri):
        resp = client.post("/oauth/register", json={
            "client_name": "x", "redirect_uris": [uri], "token_endpoint_auth_method": "none"})
        assert resp.status_code == 400
        assert resp.get_json()["error"] in {"invalid_redirect_uri", "invalid_client_metadata"}

    def test_accepts_loopback_and_known_hosts(self, oauth):
        info = oauth.register(redirect_uris=["http://127.0.0.1/callback", "http://localhost/callback",
                                             CHATGPT_REDIRECT])
        assert len(info["redirect_uris"]) == 3

    def test_rejects_non_json_and_bad_grants(self, client):
        assert client.post("/oauth/register", data="x").status_code == 400
        resp = client.post("/oauth/register", json={
            "redirect_uris": [CLAUDE_REDIRECT], "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "none"})
        assert resp.status_code == 400

    def test_client_name_control_characters_stripped(self, oauth, app_ctx):
        info = oauth.register(name="Evil‮App\x07")
        row = OAuthClient.query.filter_by(client_id=info["client_id"]).first()
        assert row.client_name == "EvilApp"


# ── Authorization + consent ─────────────────────────────────────────────────


class TestAuthorize:
    def test_unauthenticated_redirects_to_login_with_next(self, oauth):
        client_info = oauth.register()
        _v, challenge = pkce_pair()
        resp = oauth.anon.get(oauth.url(oauth.authorize_params(client_info["client_id"], challenge=challenge)))
        assert resp.status_code == 302
        assert resp.headers["Location"].startswith("/login?next=/oauth/authorize")

    def test_password_login_returns_to_consent(self, oauth, make_user, flask_app, app_ctx):
        uid = make_user()
        email = _db.session.get(User, uid).email
        client_info = oauth.register()
        _v, challenge = pkce_pair()
        url = oauth.url(oauth.authorize_params(client_info["client_id"], challenge=challenge))
        c = flask_app.test_client()
        c.get("/login?" + urlencode({"next": url}))
        resp = c.post("/login", data={"email": email, "password": "testpass123", "next": url})
        assert resp.status_code == 302 and resp.headers["Location"] == url
        page = c.get(url)
        assert page.status_code == 200
        html = page.get_data(as_text=True)
        assert "Claude" in html and "claude.ai" in html and email in html

    def test_totp_login_returns_to_consent(self, oauth, make_user, flask_app, app_ctx):
        secret = pyotp.random_base32()
        uid = make_user(twofa_enabled=True, twofa_secret=encrypt_password(secret))
        email = _db.session.get(User, uid).email
        client_info = oauth.register()
        _v, challenge = pkce_pair()
        url = oauth.url(oauth.authorize_params(client_info["client_id"], challenge=challenge))
        c = flask_app.test_client()
        resp = c.post("/login", data={"email": email, "password": "testpass123", "next": url})
        assert resp.headers["Location"].endswith("/login/2fa")
        resp = c.post("/login/2fa", data={"code": pyotp.TOTP(secret).now()})
        assert resp.status_code == 302 and resp.headers["Location"] == url
        assert c.get(url).status_code == 200

    def test_passkey_login_returns_to_consent(self, oauth, make_user, flask_app, app_ctx, monkeypatch, auth_module):
        from types import SimpleNamespace
        from app.models import PasskeyCredential

        uid = make_user()
        _db.session.add(PasskeyCredential(user_id=uid, credential_id="cred-1", public_key="pk", sign_count=0))
        _db.session.commit()
        monkeypatch.setattr(auth_module, "_WEBAUTHN_AVAILABLE", True)
        monkeypatch.setattr(auth_module, "_passkey_enabled", lambda: True)
        monkeypatch.setattr(auth_module, "base64url_to_bytes", lambda s: s.encode())
        monkeypatch.setattr(auth_module, "verify_authentication_response",
                            lambda **_k: SimpleNamespace(new_sign_count=1))
        client_info = oauth.register()
        _v, challenge = pkce_pair()
        url = oauth.url(oauth.authorize_params(client_info["client_id"], challenge=challenge))
        c = flask_app.test_client()
        # Real flow: /oauth/authorize -> /login?next=<encoded> -> passkey button.
        c.get("/login?" + urlencode({"next": url}))
        c.get("/passkey_login")
        with c.session_transaction() as sess:
            sess["passkey_login_challenge"] = "Y2hhbGxlbmdl"
            sess["passkey_login_user_id"] = uid
            sess["passkey_login_expires_at"] = int(time.time()) + 120
        resp = c.post("/passkey_login/verify", json={"id": "cred-1", "response": {}})
        assert resp.status_code == 302 and resp.headers["Location"] == url

    def test_full_flow_issues_prefixed_scoped_tokens(self, oauth, make_user, app_ctx):
        uid = make_user()
        _client, token = oauth.connect(uid, scopes="projections:read schedules:read")
        assert token["token_type"] == "Bearer"
        assert token["access_token"].startswith("pcf_at_")
        assert token["refresh_token"].startswith("pcf_rt_")
        assert token["expires_in"] == 3600
        assert set(token["scope"].split()) == {"projections:read", "schedules:read"}
        assert OAuthGrant.query.filter_by(user_id=uid).count() == 1

    def test_redirect_carries_state_and_iss(self, oauth, make_user):
        uid = make_user()
        info = oauth.register()
        _v, challenge = pkce_pair()
        resp = oauth.approve(oauth.login_as(uid), oauth.authorize_params(info["client_id"], challenge=challenge))
        params = oauth.redirect_params(resp)
        assert oauth.redirect_location(resp).startswith(CLAUDE_REDIRECT + "?")
        assert params["state"] == "state-123" and params["iss"] == BASE
        assert params["code"].startswith("pcf_ac_")

    def test_consent_can_narrow_scopes(self, oauth, make_user):
        uid = make_user()
        _client, token = oauth.connect(uid, approve_scopes=["projections:read"])
        assert token["scope"] == "projections:read"

    def test_deny_returns_access_denied(self, oauth, make_user):
        uid = make_user()
        info = oauth.register()
        _v, challenge = pkce_pair()
        resp = oauth.approve(oauth.login_as(uid), oauth.authorize_params(info["client_id"], challenge=challenge),
                             decision="deny")
        params = oauth.redirect_params(resp)
        assert params["error"] == "access_denied" and params["state"] == "state-123"
        assert params["iss"] == BASE and "code" not in params

    def test_guest_cannot_grant_write_scopes(self, oauth, make_user):
        owner = make_user()
        guest = make_user(admin=False, owner_id=owner)
        info = oauth.register()
        verifier, challenge = pkce_pair()
        params = oauth.authorize_params(info["client_id"], challenge=challenge)
        page = oauth.login_as(guest).get(oauth.url(params)).get_data(as_text=True)
        assert 'value="schedules:write"' not in page
        assert "view-only" in page
        # Even a forged POST naming write scopes cannot obtain them.
        resp = oauth.approve(oauth.login_as(guest), params, scopes=ALL_SCOPES.split())
        token = oauth.exchange(info["client_id"], oauth.redirect_params(resp)["code"], verifier).get_json()
        assert not any(s.endswith(":write") for s in token["scope"].split())

    def test_unknown_client_renders_error_without_redirect(self, oauth, make_user):
        uid = make_user()
        _v, challenge = pkce_pair()
        resp = oauth.login_as(uid).get(oauth.url(oauth.authorize_params("pcf_dcr_nope", challenge=challenge)))
        assert resp.status_code == 400 and "Location" not in resp.headers

    @pytest.mark.parametrize("redirect", [
        "https://evil.example/cb", CLAUDE_REDIRECT + "/extra", CLAUDE_REDIRECT + "?x=1",
        "https://claude.ai/api/mcp/auth_callback#x", CHATGPT_REDIRECT,
    ])
    def test_unregistered_redirect_never_redirects(self, oauth, make_user, redirect):
        uid = make_user()
        info = oauth.register()
        _v, challenge = pkce_pair()
        resp = oauth.login_as(uid).get(oauth.url(oauth.authorize_params(
            info["client_id"], challenge=challenge, redirect_uri=redirect)))
        assert resp.status_code == 400 and "Location" not in resp.headers

    def test_missing_redirect_uri_is_rejected(self, oauth, make_user):
        uid = make_user()
        info = oauth.register()
        _v, challenge = pkce_pair()
        params = oauth.authorize_params(info["client_id"], challenge=challenge)
        params.pop("redirect_uri")
        resp = oauth.login_as(uid).get(oauth.url(params))
        assert resp.status_code == 400 and "Location" not in resp.headers

    @pytest.mark.parametrize("mutate,error", [
        (lambda p: p.pop("code_challenge"), "invalid_request"),
        (lambda p: p.update(code_challenge_method="plain"), "invalid_request"),
        (lambda p: p.pop("code_challenge_method"), "invalid_request"),
        (lambda p: p.update(code_challenge="short"), "invalid_request"),
        (lambda p: p.update(resource="https://other.example/mcp"), "invalid_target"),
        (lambda p: p.update(scope="projections:read admin:all"), "invalid_scope"),
        (lambda p: p.update(prompt="none"), "consent_required"),
    ])
    def test_invalid_requests_redirect_with_error(self, oauth, make_user, mutate, error):
        uid = make_user()
        info = oauth.register()
        _v, challenge = pkce_pair()
        params = oauth.authorize_params(info["client_id"], challenge=challenge)
        mutate(params)
        resp = oauth.login_as(uid).get(oauth.url(params))
        result = oauth.redirect_params(resp)
        assert result["error"] == error and result["iss"] == BASE and "code" not in result

    def test_resource_is_optional_and_defaults_to_mcp(self, oauth, make_user, app_ctx):
        uid = make_user()
        info = oauth.register()
        verifier, challenge = pkce_pair()
        params = oauth.authorize_params(info["client_id"], challenge=challenge, resource=None)
        code = oauth.redirect_params(oauth.approve(oauth.login_as(uid), params))["code"]
        assert oauth.exchange(info["client_id"], code, verifier, resource=None).status_code == 200
        assert OAuthToken.query.filter_by(user_id=uid).first().resource == RESOURCE

    def test_consent_post_requires_matching_ticket(self, oauth, make_user):
        uid = make_user()
        info = oauth.register()
        _v, challenge = pkce_pair()
        params = oauth.authorize_params(info["client_id"], challenge=challenge)
        c = oauth.login_as(uid)
        resp = c.post(oauth.url(params), data={"decision": "approve", "grant_scope": ["projections:read"]})
        assert resp.status_code == 400
        # A ticket issued for one request cannot approve a different one.
        page = c.get(oauth.url(params)).get_data(as_text=True)
        ticket = oauth.ticket(page)
        _v2, other_challenge = pkce_pair()
        other = oauth.authorize_params(info["client_id"], challenge=other_challenge)
        resp = c.post(oauth.url(other), data={"consent_ticket": ticket, "decision": "approve",
                                               "grant_scope": ["projections:read"]})
        assert resp.status_code == 400
        # Another user cannot reuse my ticket.
        intruder = make_user()
        resp = oauth.login_as(intruder).post(oauth.url(params), data={
            "consent_ticket": ticket, "decision": "approve", "grant_scope": ["projections:read"]})
        assert resp.status_code == 400

    def test_consent_post_requires_csrf_token(self, oauth, make_user, flask_app):
        uid = make_user()
        info = oauth.register()
        _v, challenge = pkce_pair()
        params = oauth.authorize_params(info["client_id"], challenge=challenge)
        c = oauth.login_as(uid)
        ticket = oauth.ticket(c.get(oauth.url(params)).get_data(as_text=True))
        flask_app.config.update(WTF_CSRF_ENABLED=True, WTF_CSRF_CHECK_DEFAULT=True)
        try:
            resp = c.post(oauth.url(params), data={"consent_ticket": ticket, "decision": "approve",
                                                    "grant_scope": ["projections:read"]})
        finally:
            flask_app.config.update(WTF_CSRF_ENABLED=False, WTF_CSRF_CHECK_DEFAULT=False)
        assert resp.status_code == 400
        assert "Location" not in resp.headers

    def test_consent_page_cannot_be_framed(self, oauth, make_user):
        uid = make_user()
        info = oauth.register()
        _v, challenge = pkce_pair()
        resp = oauth.login_as(uid).get(oauth.url(oauth.authorize_params(info["client_id"], challenge=challenge)))
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Cache-Control"] == "no-store"

    def test_inactive_user_is_logged_out_before_consent(self, oauth, make_user):
        uid = make_user(is_active=False)
        info = oauth.register()
        _v, challenge = pkce_pair()
        resp = oauth.login_as(uid).get(oauth.url(oauth.authorize_params(info["client_id"], challenge=challenge)))
        assert resp.status_code == 302 and "/login" in resp.headers["Location"]

    def test_loopback_client_shows_warning_and_matches_any_port(self, oauth, make_user):
        uid = make_user()
        info = oauth.register(redirect_uris=["http://127.0.0.1/callback"])
        verifier, challenge = pkce_pair()
        params = oauth.authorize_params(info["client_id"], challenge=challenge,
                                        redirect_uri="http://127.0.0.1:53111/callback")
        page = oauth.login_as(uid).get(oauth.url(params)).get_data(as_text=True)
        assert "your own computer" in page
        code = oauth.redirect_params(oauth.approve(oauth.login_as(uid), params))["code"]
        resp = oauth.exchange(info["client_id"], code, verifier, redirect_uri="http://127.0.0.1:53111/callback")
        assert resp.status_code == 200


# ── Token endpoint ───────────────────────────────────────────────────────────


def _code(oauth, uid, info=None, **kw):
    info = info or oauth.register()
    verifier, challenge = pkce_pair()
    params = oauth.authorize_params(info["client_id"], challenge=challenge, **kw)
    code = oauth.redirect_params(oauth.approve(oauth.login_as(uid), params))["code"]
    return info, code, verifier


class TestTokenEndpoint:
    def test_wrong_verifier_rejected(self, oauth, make_user):
        info, code, _v = _code(oauth, make_user())
        resp = oauth.exchange(info["client_id"], code, pkce_pair()[0])
        assert resp.status_code == 400 and resp.get_json()["error"] == "invalid_grant"

    def test_missing_verifier_rejected(self, oauth, make_user):
        info, code, _v = _code(oauth, make_user())
        resp = oauth.anon.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": CLAUDE_REDIRECT,
            "client_id": info["client_id"]})
        assert resp.status_code == 400

    def test_code_bound_to_client(self, oauth, make_user):
        info, code, verifier = _code(oauth, make_user())
        other = oauth.register()
        resp = oauth.exchange(other["client_id"], code, verifier)
        assert resp.get_json()["error"] == "invalid_grant"

    def test_redirect_uri_must_match(self, oauth, make_user):
        info = oauth.register(redirect_uris=[CLAUDE_REDIRECT, "https://claude.com/api/mcp/auth_callback"])
        info, code, verifier = _code(oauth, make_user(), info=info)
        resp = oauth.exchange(info["client_id"], code, verifier,
                              redirect_uri="https://claude.com/api/mcp/auth_callback")
        assert resp.get_json()["error"] == "invalid_grant"

    def test_resource_must_match_code(self, oauth, make_user):
        info, code, verifier = _code(oauth, make_user())
        resp = oauth.exchange(info["client_id"], code, verifier, resource="https://other.example/mcp")
        assert resp.get_json()["error"] == "invalid_target"

    def test_expired_code_rejected(self, oauth, make_user, app_ctx):
        info, code, verifier = _code(oauth, make_user())
        row = OAuthAuthorizationCode.query.order_by(OAuthAuthorizationCode.id.desc()).first()
        row.expires_at = utcnow() - timedelta(seconds=1)
        _db.session.commit()
        assert oauth.exchange(info["client_id"], code, verifier).get_json()["error"] == "invalid_grant"

    def test_code_replay_revokes_issued_tokens(self, oauth, make_user, app_ctx, mcp):
        uid = make_user()
        info, code, verifier = _code(oauth, uid)
        first = oauth.exchange(info["client_id"], code, verifier).get_json()
        replay = oauth.exchange(info["client_id"], code, verifier)
        assert replay.get_json()["error"] == "invalid_grant"
        grant = OAuthGrant.query.filter_by(user_id=uid).first()
        _db.session.refresh(grant)
        assert grant.revoked_reason == "code_replay"
        assert mcp.http(first["access_token"], json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401
        assert oauth.refresh(info["client_id"], first["refresh_token"]).get_json()["error"] == "invalid_grant"

    def test_confidential_client_must_authenticate(self, oauth, make_user):
        info = oauth.register(auth_method="client_secret_post")
        _info, code, verifier = _code(oauth, make_user(), info=info)
        assert oauth.exchange(info["client_id"], code, verifier).get_json()["error"] == "invalid_client"
        resp = oauth.exchange(info["client_id"], code, verifier, client_secret="wrong")
        assert resp.get_json()["error"] == "invalid_client"
        resp = oauth.exchange(info["client_id"], code, verifier, client_secret=info["client_secret"])
        assert resp.status_code == 200

    def test_token_endpoint_accepts_only_post_form(self, client):
        assert client.get("/oauth/token").status_code == 405


class TestRefresh:
    def test_rotation_and_reuse_detection(self, oauth, make_user, app_ctx):
        uid = make_user()
        info, token = oauth.connect(uid)
        rotated = oauth.refresh(info["client_id"], token["refresh_token"])
        assert rotated.status_code == 200
        new = rotated.get_json()
        assert new["refresh_token"] != token["refresh_token"]
        assert new["access_token"] != token["access_token"]
        # Immediate re-use (client retry) is refused but does not kill the grant.
        assert oauth.refresh(info["client_id"], token["refresh_token"]).get_json()["error"] == "invalid_grant"
        grant = OAuthGrant.query.filter_by(user_id=uid).first()
        assert grant.revoked_at is None
        # Re-use after the grace window is treated as theft: the grant dies.
        old = OAuthToken.query.filter_by(user_id=uid).order_by(OAuthToken.id.asc()).first()
        old.refresh_revoked_at = utcnow() - REFRESH_REUSE_GRACE - timedelta(seconds=1)
        _db.session.commit()
        assert oauth.refresh(info["client_id"], token["refresh_token"]).get_json()["error"] == "invalid_grant"
        _db.session.expire_all()
        assert _db.session.get(OAuthGrant, grant.id).revoked_reason == "refresh_replay"
        assert oauth.refresh(info["client_id"], new["refresh_token"]).get_json()["error"] == "invalid_grant"

    def test_scope_cannot_be_escalated_on_refresh(self, oauth, make_user):
        uid = make_user()
        info, token = oauth.connect(uid, approve_scopes=["projections:read"])
        resp = oauth.refresh(info["client_id"], token["refresh_token"], scope="projections:read schedules:write")
        assert resp.get_json()["error"] == "invalid_scope"

    def test_scope_can_be_narrowed_on_refresh(self, oauth, make_user):
        info, token = oauth.connect(make_user())
        resp = oauth.refresh(info["client_id"], token["refresh_token"], scope="projections:read")
        assert resp.get_json()["scope"] == "projections:read"

    def test_refresh_token_bound_to_client(self, oauth, make_user):
        info, token = oauth.connect(make_user())
        other = oauth.register()
        assert oauth.refresh(other["client_id"], token["refresh_token"]).get_json()["error"] == "invalid_grant"

    def test_refresh_fails_for_deactivated_user(self, oauth, make_user, app_ctx):
        uid = make_user()
        info, token = oauth.connect(uid)
        _db.session.get(User, uid).is_active = False
        _db.session.commit()
        assert oauth.refresh(info["client_id"], token["refresh_token"]).get_json()["error"] == "invalid_grant"

    def test_refresh_fails_after_grant_expiry(self, oauth, make_user, app_ctx):
        uid = make_user()
        info, token = oauth.connect(uid)
        grant = OAuthGrant.query.filter_by(user_id=uid).first()
        grant.expires_at = utcnow() - timedelta(seconds=1)
        _db.session.commit()
        assert oauth.refresh(info["client_id"], token["refresh_token"]).get_json()["error"] == "invalid_grant"

    def test_garbage_refresh_tokens(self, oauth, make_user):
        info, _token = oauth.connect(make_user())
        for value in ["", "pcf_rt_nope", "pcf_at_x", "x" * 5000]:
            resp = oauth.refresh(info["client_id"], value)
            assert resp.status_code == 400


class TestRevocationAndPasswordChange:
    def test_revoke_access_token(self, oauth, make_user, mcp):
        info, token = oauth.connect(make_user())
        resp = oauth.anon.post("/oauth/revoke", data={"token": token["access_token"], "client_id": info["client_id"]})
        assert resp.status_code == 200
        assert mcp.http(token["access_token"], json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401

    def test_revoke_refresh_token_revokes_grant(self, oauth, make_user, app_ctx):
        uid = make_user()
        info, token = oauth.connect(uid)
        oauth.anon.post("/oauth/revoke", data={"token": token["refresh_token"], "client_id": info["client_id"]})
        assert OAuthGrant.query.filter_by(user_id=uid).first().revoked_reason == "client_revoked"

    def test_revoke_unknown_token_is_200(self, oauth):
        info = oauth.register()
        assert oauth.anon.post("/oauth/revoke", data={"token": "nope", "client_id": info["client_id"]}).status_code == 200

    def test_other_client_cannot_revoke(self, oauth, make_user, app_ctx):
        uid = make_user()
        info, token = oauth.connect(uid)
        other = oauth.register()
        oauth.anon.post("/oauth/revoke", data={"token": token["refresh_token"], "client_id": other["client_id"]})
        assert OAuthGrant.query.filter_by(user_id=uid).first().revoked_at is None

    def test_web_password_change_revokes_grants(self, oauth, make_user, login_as, app_ctx):
        uid = make_user()
        info, token = oauth.connect(uid)
        login_as(uid).post("/changepw", data={"current": "testpass123", "password": "NewPass123",
                                              "password2": "NewPass123"})
        assert oauth.refresh(info["client_id"], token["refresh_token"]).get_json()["error"] == "invalid_grant"
        assert OAuthGrant.query.filter_by(user_id=uid).first().revoked_reason == "password_changed"

    def test_api_password_change_revokes_grants(self, oauth, make_user, client, app_ctx):
        from app.api.auth_utils import create_token_for_user

        uid = make_user()
        _info, _token = oauth.connect(uid)
        raw, _ = create_token_for_user(_db.session.get(User, uid))
        client.put("/api/v1/auth/password", json={"current_password": "testpass123", "new_password": "Another123"},
                   headers={"Authorization": f"Bearer {raw}"})
        assert OAuthGrant.query.filter_by(user_id=uid).first().revoked_at is not None


class TestConnectedApps:
    def test_lists_and_revokes_only_selected_grant(self, oauth, make_user, login_as, app_ctx, mcp, client):
        from app.api.auth_utils import create_token_for_user

        uid = make_user()
        claude_info, claude = oauth.connect(uid)
        chatgpt_info = oauth.register(redirect_uris=[CHATGPT_REDIRECT], name="ChatGPT")
        _c, chatgpt = oauth.connect(uid, client=chatgpt_info)
        ios_token, _ = create_token_for_user(_db.session.get(User, uid))

        page = login_as(uid).get("/settings/connected-apps").get_data(as_text=True)
        assert "Claude" in page and "ChatGPT" in page
        claude_grant = OAuthGrant.query.filter_by(user_id=uid, client_id=claude_info["client_id"]).first()
        resp = login_as(uid).post(f"/settings/connected-apps/{claude_grant.id}/revoke")
        assert resp.status_code == 302

        ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        assert mcp.http(claude["access_token"], json=ping).status_code == 401
        assert mcp.http(chatgpt["access_token"], json=ping).status_code == 200
        assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {ios_token}"}).status_code == 200

    def test_cannot_revoke_another_users_grant(self, oauth, make_user, login_as, app_ctx):
        victim = make_user()
        oauth.connect(victim)
        grant = OAuthGrant.query.filter_by(user_id=victim).first()
        resp = login_as(make_user()).post(f"/settings/connected-apps/{grant.id}/revoke")
        assert resp.status_code == 404
        _db.session.refresh(grant)
        assert grant.revoked_at is None

    def test_settings_page_links_connected_apps(self, make_user, login_as):
        assert "Connected apps" in login_as(make_user()).get("/settings").get_data(as_text=True)


# ── CIMD ────────────────────────────────────────────────────────────────────

CHATGPT_CIMD = "https://chatgpt.com/oauth/client.json"
CLAUDE_CIMD = "https://claude.ai/oauth/mcp-oauth-client-metadata"


def _doc(url, redirect):
    return {"client_id": url, "client_name": "ChatGPT" if "chatgpt" in url else "Claude",
            "redirect_uris": [redirect], "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "token_endpoint_auth_method": "private_key_jwt"}


class TestCimd:
    @pytest.fixture(autouse=True)
    def _fresh_cimd_cache(self, app_ctx):
        # CIMD documents are cached in oauth_clients; start each test cold.
        OAuthClient.query.filter_by(registration_type="cimd").delete()
        _db.session.commit()

    @pytest.fixture()
    def fake_fetch(self, monkeypatch):
        calls = []

        def fetch(url, allowed_hosts):
            calls.append(url)
            redirect = CHATGPT_REDIRECT if "chatgpt" in url else CLAUDE_REDIRECT
            return cimd.FetchedDocument(document=_doc(url, redirect), max_age=300)

        monkeypatch.setattr(cimd, "fetch_document", fetch)
        return calls

    @pytest.mark.parametrize("url,redirect", [(CHATGPT_CIMD, CHATGPT_REDIRECT), (CLAUDE_CIMD, CLAUDE_REDIRECT)])
    def test_cimd_client_full_flow(self, oauth, make_user, fake_fetch, url, redirect):
        uid = make_user()
        verifier, challenge = pkce_pair()
        params = oauth.authorize_params(url, challenge=challenge, redirect_uri=redirect)
        page = oauth.login_as(uid).get(oauth.url(params)).get_data(as_text=True)
        host = "chatgpt.com" if "chatgpt" in url else "claude.ai"
        assert "Application identity published by <strong" in page and host in page
        code = oauth.redirect_params(oauth.approve(oauth.login_as(uid), params))["code"]
        resp = oauth.exchange(url, code, verifier, redirect_uri=redirect)
        assert resp.status_code == 200
        assert fake_fetch.count(url) == 1  # cached between authorize and token

    def test_untrusted_cimd_host_never_fetched(self, oauth, make_user, fake_fetch):
        uid = make_user()
        _v, challenge = pkce_pair()
        params = oauth.authorize_params("https://evil.example/client.json", challenge=challenge)
        resp = oauth.login_as(uid).get(oauth.url(params))
        assert resp.status_code == 400 and not fake_fetch

    def test_document_client_id_mismatch_rejected(self, oauth, make_user, monkeypatch):
        monkeypatch.setattr(cimd, "fetch_document", lambda url, hosts: cimd.FetchedDocument(
            document=_doc("https://chatgpt.com/other.json", CHATGPT_REDIRECT), max_age=300))
        _v, challenge = pkce_pair()
        params = oauth.authorize_params(CHATGPT_CIMD, challenge=challenge, redirect_uri=CHATGPT_REDIRECT)
        assert oauth.login_as(make_user()).get(oauth.url(params)).status_code == 400

    def test_document_redirects_filtered_by_policy(self, oauth, make_user, monkeypatch):
        monkeypatch.setattr(cimd, "fetch_document", lambda url, hosts: cimd.FetchedDocument(
            document=_doc(CHATGPT_CIMD, "https://evil.example/cb"), max_age=300))
        _v, challenge = pkce_pair()
        params = oauth.authorize_params(CHATGPT_CIMD, challenge=challenge, redirect_uri="https://evil.example/cb")
        resp = oauth.login_as(make_user()).get(oauth.url(params))
        assert resp.status_code == 400 and "Location" not in resp.headers

    def test_stale_cache_used_when_refresh_fails(self, oauth, make_user, fake_fetch, monkeypatch, app_ctx):
        uid = make_user()
        _v, challenge = pkce_pair()
        params = oauth.authorize_params(CLAUDE_CIMD, challenge=challenge)
        assert oauth.login_as(uid).get(oauth.url(params)).status_code == 200
        row = OAuthClient.query.filter_by(client_id=CLAUDE_CIMD).first()
        row.metadata_expires_at = utcnow() - timedelta(seconds=1)
        _db.session.commit()

        def failing(url, hosts):
            raise cimd.CimdError("down")

        monkeypatch.setattr(cimd, "fetch_document", failing)
        assert oauth.login_as(uid).get(oauth.url(params)).status_code == 200

    @pytest.mark.parametrize("url", [
        "http://chatgpt.com/oauth/client.json", "https://chatgpt.com:8443/oauth/client.json",
        "https://chatgpt.com", "https://chatgpt.com/", "https://user@chatgpt.com/x.json",
        "https://chatgpt.com/x.json#frag", "https://203.0.113.5/x.json", "https://[::1]/x.json",
        "https://" + "a" * 600 + ".com/x.json",
    ])
    def test_url_validation(self, url):
        with pytest.raises(cimd.CimdError):
            cimd.validate_cimd_url(url, {"chatgpt.com", "*"})

    @pytest.mark.parametrize("address", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1",
                                         "::1", "fd00::1", "::ffff:127.0.0.1", "100.64.0.1", "0.0.0.0"])
    def test_private_addresses_refused(self, monkeypatch, address):
        import socket

        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        monkeypatch.setattr(cimd.socket, "getaddrinfo",
                            lambda *a, **k: [(family, socket.SOCK_STREAM, 6, "", (address, 443))])
        with pytest.raises(cimd.CimdError):
            cimd.resolve_public_ip("chatgpt.com")

    def test_mixed_public_and_private_resolution_refused(self, monkeypatch):
        import socket

        monkeypatch.setattr(cimd.socket, "getaddrinfo", lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.18.32.47", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
        ])
        with pytest.raises(cimd.CimdError):
            cimd.resolve_public_ip("chatgpt.com")

    def test_http_fetch_rejects_untrusted_host_before_dns(self, monkeypatch):
        def boom(*_a, **_k):
            raise AssertionError("DNS must not be queried for untrusted hosts")

        monkeypatch.setattr(cimd.socket, "getaddrinfo", boom)
        with pytest.raises(cimd.CimdError):
            cimd.http_fetch("https://internal.corp/x.json", {"chatgpt.com"})


class TestPolicyHelpers:
    def test_redirect_matching(self):
        assert RedirectPolicy.matches("http://127.0.0.1/callback", "http://127.0.0.1:4000/callback")
        assert RedirectPolicy.matches("http://localhost/callback", "http://localhost:9/callback")
        assert not RedirectPolicy.matches("http://127.0.0.1/callback", "http://127.0.0.1:4000/callback/x")
        assert not RedirectPolicy.matches("http://127.0.0.1/callback", "http://localhost:4000/callback")
        assert not RedirectPolicy.matches(CLAUDE_REDIRECT, CLAUDE_REDIRECT.upper())
        assert not RedirectPolicy.matches("https://claude.ai/cb", "https://claude.ai:444/cb")
        assert not RedirectPolicy.matches(CLAUDE_REDIRECT, None)

    def test_resource_normalisation(self):
        assert normalize_resource("HTTPS://Cash.Example.com:443/mcp/") == "https://cash.example.com/mcp"
        assert normalize_resource("https://x.example/mcp#f") is None
        assert normalize_resource("mcp.example.com") is None
        assert normalize_resource(None) is None


def test_garbage_collection_removes_stale_dcr_clients(oauth, app_ctx):
    from app.oauth.tokens import collect_garbage

    info = oauth.register()
    row = OAuthClient.query.filter_by(client_id=info["client_id"]).first()
    row.created_at = utcnow() - timedelta(days=30)
    _db.session.commit()
    collect_garbage()
    assert OAuthClient.query.filter_by(client_id=info["client_id"]).first() is None


def test_registration_limit(oauth, flask_app, monkeypatch):
    server = flask_app.extensions["pycashflow_oauth_server"]
    monkeypatch.setattr(server, "config", replace(server.config, max_dcr_clients=0))
    resp = oauth.anon.post("/oauth/register", json={"redirect_uris": [CLAUDE_REDIRECT],
                                                   "token_endpoint_auth_method": "none"})
    assert resp.status_code == 400
