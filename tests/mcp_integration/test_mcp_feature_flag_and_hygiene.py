"""MCP_ENABLED feature flag, configuration safety, and secret/log hygiene."""

import asyncio
import logging

import pytest

from app import db as _db
from app.models import OAuthAuthorizationCode, OAuthClient, OAuthToken
from app.oauth.config import OAuthConfigError, validate_base_url

from mcp_integration.mcp_helpers import pkce_pair


def _fresh_app(create_app, monkeypatch, **env):
    for key in ("MCP_ENABLED", "MCP_PUBLIC_BASE_URL", "FRONTEND_BASE_URL"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    app = create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return app


@pytest.mark.mcp_disabled_ok
class TestFeatureFlag:
    def test_disabled_registers_no_oauth_or_mcp_routes(self, create_app, monkeypatch):
        app = _fresh_app(create_app, monkeypatch, MCP_ENABLED="false")
        assert app.config["MCP_ENABLED"] is False
        rules = {r.rule for r in app.url_map.iter_rules()}
        assert not any(r.startswith("/oauth") or "oauth-" in r or "connected-apps" in r for r in rules)
        c = app.test_client()
        assert c.get("/.well-known/oauth-authorization-server").status_code == 404
        assert c.get("/healthz").status_code == 200

    def test_disabled_asgi_entry_serves_flask_only(self, create_app, monkeypatch):
        from a2wsgi import WSGIMiddleware

        from app.asgi import create_asgi_app

        app = _fresh_app(create_app, monkeypatch, MCP_ENABLED="false")
        asgi = create_asgi_app(app)
        assert isinstance(asgi, WSGIMiddleware)

        async def probe():
            import httpx2 as httpx

            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=asgi), base_url="http://localhost") as h:
                return (await h.post("/mcp", json={})).status_code, (await h.get("/healthz")).status_code

        assert asyncio.run(probe()) == (404, 200)

    def test_enabled_without_base_url_fails_closed_but_app_runs(self, create_app, monkeypatch, caplog):
        with caplog.at_level(logging.ERROR):
            app = _fresh_app(create_app, monkeypatch, MCP_ENABLED="true")
        assert app.config["MCP_ENABLED"] is False
        assert "MCP disabled" in caplog.text
        assert app.test_client().get("/healthz").status_code == 200

    def test_settings_page_hides_connected_apps_when_disabled(self, create_app, monkeypatch, make_user):
        app = _fresh_app(create_app, monkeypatch, MCP_ENABLED="false")
        with app.app_context():
            _db.create_all()
        c = app.test_client()
        uid = make_user()
        with c.session_transaction() as sess:
            sess["_user_id"] = str(uid)
        resp = c.get("/settings")
        if resp.status_code == 200:  # same DB as the shared app when using PostgreSQL
            assert "Connected apps" not in resp.get_data(as_text=True)

    @pytest.mark.parametrize("url", ["http://cash.example.com", "https://cash.example.com/app",
                                     "https://cash.example.com?x=1", "ftp://cash.example.com", "",
                                     "https://user:pw@cash.example.com"])
    def test_base_url_validation(self, url):
        with pytest.raises(OAuthConfigError):
            validate_base_url(url)

    @pytest.mark.parametrize("url,expected", [
        ("https://Cash.Example.com/", "https://cash.example.com"),
        ("https://cash.example.com:443", "https://cash.example.com"),
        ("https://cash.example.com:8443", "https://cash.example.com:8443"),
        ("http://localhost:5000", "http://localhost:5000"),
    ])
    def test_base_url_normalisation(self, url, expected):
        assert validate_base_url(url) == expected


class TestSecretHygiene:
    def test_tokens_codes_and_secrets_never_logged_or_stored_raw(self, oauth, make_user, mcp, caplog, app_ctx):
        uid = make_user()
        with caplog.at_level(logging.DEBUG):
            confidential = oauth.register(auth_method="client_secret_post")
            verifier, challenge = pkce_pair()
            params = oauth.authorize_params(confidential["client_id"], challenge=challenge)
            code = oauth.redirect_params(oauth.approve(oauth.login_as(uid), params))["code"]
            token = oauth.exchange(confidential["client_id"], code, verifier,
                                   client_secret=confidential["client_secret"]).get_json()
            refreshed = oauth.refresh(confidential["client_id"], token["refresh_token"],
                                      client_secret=confidential["client_secret"]).get_json()
            mcp.call(refreshed["access_token"], "get_projection_summary")
            mcp.call(refreshed["access_token"], "create_schedule", {
                "name": "Secret test", "amount": "1.00", "type": "Expense", "frequency": "Monthly",
                "start_date": "2099-01-01"})
        secrets = [confidential["client_secret"], code, verifier, token["access_token"], token["refresh_token"],
                   refreshed["access_token"], refreshed["refresh_token"]]
        for value in secrets:
            assert value not in caplog.text
        stored = []
        for model in (OAuthToken, OAuthAuthorizationCode, OAuthClient):
            for row in model.query.all():
                stored.extend(str(getattr(row, c.name)) for c in model.__table__.columns)
        blob = "\n".join(stored)
        for value in secrets:
            assert value not in blob

    def test_audit_rows_hold_no_financial_values(self, mcp, owner, issue_token, app_ctx):
        from app.models import OAuthAuditEvent

        mcp.call(issue_token(owner), "create_schedule", {
            "name": "Very private label", "amount": "12345.67", "type": "Expense", "frequency": "Monthly",
            "start_date": "2099-01-01"})
        rows = OAuthAuditEvent.query.filter_by(user_id=owner).all()
        dumped = " ".join(str(getattr(r, c.name)) for r in rows for c in OAuthAuditEvent.__table__.columns)
        assert "Very private label" not in dumped and "12345.67" not in dumped

    def test_registration_body_size_limited(self, client):
        resp = client.post("/oauth/register", json={"redirect_uris": ["https://claude.ai/x"],
                                                     "client_name": "x" * 20000})
        assert resp.status_code == 413


def test_redaction_filter_scrubs_authlib_debug_output(caplog):
    from app.oauth.security import install_log_redaction

    install_log_redaction()
    grant_logger = logging.getLogger("authlib.oauth2.rfc6749.grants.authorization_code")
    previous = logging.getLogger("authlib").level
    logging.getLogger("authlib").setLevel(logging.DEBUG)  # an operator forcing DEBUG
    try:
        with caplog.at_level(logging.DEBUG, logger="authlib"):
            grant_logger.debug("Issue token %r to %r",
                               {"access_token": "pcf_at_SECRETVALUE123", "refresh_token": "pcf_rt_ALSOSECRET"},
                               "client")
    finally:
        logging.getLogger("authlib").setLevel(previous)
    assert "SECRETVALUE123" not in caplog.text and "ALSOSECRET" not in caplog.text
    assert "pcf_at_[REDACTED]" in caplog.text
