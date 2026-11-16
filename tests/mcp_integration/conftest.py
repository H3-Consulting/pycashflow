"""Fixtures for OAuth + MCP integration tests.

The shared test app (tests/conftest.py) runs with MCP_ENABLED=true and
MCP_PUBLIC_BASE_URL=http://localhost. Every test here exercises the real
Flask routes, the real Authlib server and the real MCP SDK through the same
ASGI composition used in production (``app.asgi.create_asgi_app``).
"""

import secrets
from datetime import date, timedelta

import pytest

from app import db as _db
from app.models import Balance, OAuthClient, OAuthGrant, OAuthToken, Schedule
from app.oauth.security import ACCESS_TOKEN_PREFIX, new_secret, sha256_hex

from mcp_integration.mcp_helpers import ALL_SCOPES, CLAUDE_REDIRECT, RESOURCE, McpClient, OAuthHelper, utcnow


@pytest.fixture(autouse=True)
def _require_mcp(request, flask_app):
    if request.node.get_closest_marker("mcp_disabled_ok"):
        return
    if not flask_app.config.get("MCP_ENABLED"):
        pytest.skip("MCP integration disabled (MCP_ENABLED=false)")

@pytest.fixture()
def oauth(flask_app, login_as):
    return OAuthHelper(flask_app, login_as)



@pytest.fixture()
def issue_token(app_ctx):
    """Create a client + grant + access token directly in the DB (fast path)."""

    def _issue(user_id, scopes=ALL_SCOPES, *, client_id=None, expires_in=3600,
               resource=RESOURCE, grant_expires_at=None):
        client_id = client_id or f"pcf_dcr_test_{secrets.token_hex(6)}"
        if OAuthClient.query.filter_by(client_id=client_id).first() is None:
            _db.session.add(OAuthClient(
                client_id=client_id, registration_type="dcr", client_name="Test client",
                redirect_uris=f'["{CLAUDE_REDIRECT}"]',
                grant_types='["authorization_code", "refresh_token"]',
                response_types='["code"]', token_endpoint_auth_method="none",
            ))
        grant = OAuthGrant(user_id=user_id, client_id=client_id, client_name="Test client",
                           scope=scopes, resource=resource, expires_at=grant_expires_at)
        _db.session.add(grant)
        _db.session.flush()
        raw = new_secret(ACCESS_TOKEN_PREFIX)
        _db.session.add(OAuthToken(
            grant_id=grant.id, user_id=user_id, client_id=client_id, scope=scopes,
            resource=resource, access_token_hash=sha256_hex(raw),
            access_expires_at=utcnow() + timedelta(seconds=expires_in),
        ))
        _db.session.commit()
        return raw

    return _issue



@pytest.fixture()
def owner(make_user):
    """An account owner with a balance and two schedules."""
    uid = make_user(balance="2500.00")
    today = date.today()
    _db.session.add_all([
        Schedule(user_id=uid, name="Rent", amount="1800.00", type="Expense", frequency="Monthly",
                 startdate=today + timedelta(days=5), firstdate=today + timedelta(days=5)),
        Schedule(user_id=uid, name="Pay", amount="2100.00", type="Income", frequency="BiWeekly",
                 startdate=today + timedelta(days=9), firstdate=today + timedelta(days=9)),
    ])
    _db.session.commit()
    return uid

@pytest.fixture()
def mcp(flask_app):
    return McpClient(flask_app)

@pytest.fixture()
def balance_model():
    return Balance
