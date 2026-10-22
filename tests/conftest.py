"""
Pytest configuration for Flask integration tests.

IMPORTANT: This file is imported by pytest BEFORE any test_*.py files.
Other test files (e.g. test_projection_engine.py) install module stubs for
app/db/models so they can unit-test pure business logic without a database.
Those stubs replace sys.modules entries at import time.

By creating and fully initialising the real Flask test app HERE (at conftest
module load time), we capture all real references before any stubs are
installed. The fixtures below then expose those captured objects safely.
"""

import os
import pytest
from datetime import datetime

# ── Test environment — set before the real app is imported ───────────────────
# DATABASE_URL must be set BEFORE create_app() is called: Flask-SQLAlchemy
# reads it when create_app() calls db.init_app(app), creating the engine at
# that point.  Overriding app.config afterwards has no effect on the engine.
# Set TEST_DATABASE_URL to run the suite against a real server (CI uses a
# throwaway PostgreSQL with a plain postgresql:// URL); it must be an empty
# database because the schema is created here and the suite writes to it.
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL") or "sqlite:///:memory:"
os.environ.setdefault("SECRET_KEY", "pytest-secret-key-32chars-minimum!")
os.environ.setdefault("SESSION_COOKIE_SECURE", "false")
os.environ.setdefault("APP_SECRET", "pytest-app-secret-for-crypto-utils-32!")
os.environ.setdefault("PASSKEY_RP_ID", "localhost")
os.environ.setdefault("PASSKEY_RP_NAME", "PyCashFlow Test")
os.environ.setdefault("PASSKEY_ORIGIN", "http://localhost")
os.environ.setdefault("PAYMENTS_ENABLED", "false")

# ── Capture real app references BEFORE stubs are set up ──────────────────────
# conftest.py is loaded before test_*.py files, so all imports here use the
# real modules.  Stubs installed later do NOT affect already-bound names.
from app import create_app as _create_app, db as _db, limiter as _limiter  # noqa: E402
from app.models import (
    User as _User,
    Balance as _Balance,
    Settings as _Settings,
    TextSettings as _TextSettings,
    PasskeyCredential as _PasskeyCredential,
    PasswordSetupToken as _PasswordSetupToken,
    PlaidConnection as _PlaidConnection,
    Email as _Email,
    Schedule as _Schedule,
    Scenario as _Scenario,
    Hold as _Hold,
    Skip as _Skip,
    AISettings as _AISettings,
    GlobalEmailSettings as _GlobalEmailSettings,
)  # noqa: E402
from app import plaid_service as _plaid_service  # noqa: E402
from app import getemail as _getemail  # noqa: E402
from app.password_setup import (  # noqa: E402
    build_password_setup_url as _build_password_setup_url,
    create_password_setup_token as _create_password_setup_token,
)
from app.api.routes import billing as _billing_routes  # noqa: E402
from app import main as _main_module, auth as _auth_module  # noqa: E402
import _helpers  # noqa: F401  – pre-load real cashflow refs before any test-module stubs
from werkzeug.security import generate_password_hash                # noqa: E402
import types  # noqa: E402
import uuid  # noqa: E402

# ── Create the test Flask app eagerly (before stubs) ─────────────────────────
# Calling create_app() here ensures internal blueprint/model imports happen
# with the real modules, so route handlers work correctly in route tests.
_test_app = _create_app()
# Flask-Limiter reads RATELIMIT_ENABLED during init_app() (already run inside
# create_app), so updating config afterwards is not enough; disable the live
# singleton directly so rate limits don't interfere with the test suite.
_limiter.enabled = False
_test_app.config.update(
    {
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "WTF_CSRF_CHECK_DEFAULT": False,
        "RATELIMIT_ENABLED": False,  # mirrored on the limiter singleton below
        "SESSION_COOKIE_SECURE": False,
        "SECRET_KEY": "pytest-secret-key-32chars-minimum!",
    }
)


def _reset_login_user_cache():
    # Tests that hold an ``app_ctx`` open make Flask reuse that app context for
    # test-client requests, so Flask-Login's per-context ``g._login_user``
    # cache would leak the first request's user into later requests made by a
    # *different* client. Production gets a fresh app context per request;
    # mirror that by dropping the cache before any other hook reads it.
    from flask import g

    g.pop("_login_user", None)


_test_app.before_request_funcs.setdefault(None, []).insert(0, _reset_login_user_cache)

# ── Seed the in-memory database once for the whole session ───────────────────
with _test_app.app_context():
    _db.create_all()

    _admin = _User(
        email="admin@test.local",
        password=generate_password_hash("testpass123", method="scrypt"),
        name="Test Admin",
        admin=True,
        is_active=True,
        account_owner_id=None,
        is_global_admin=False,
    )
    _db.session.add(_admin)
    _db.session.commit()
    _ADMIN_USER_ID: int = _admin.id

    # Seed an initial balance so the dashboard route doesn't start from zero
    _db.session.add(
        _Balance(amount="5000.00", date=datetime.today().date(), user_id=_ADMIN_USER_ID)
    )
    _db.session.commit()


# ── Pytest fixtures ───────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def flask_app():
    """Session-scoped real Flask app backed by an in-memory SQLite database."""
    return _test_app


@pytest.fixture(scope="session")
def create_app():
    """Return the real create_app factory captured before any module stubs.

    Tests that need to build fresh app instances (e.g. to exercise ProxyFix
    under different TRUSTED_PROXY_COUNT settings) must use this rather than
    importing ``app`` directly, because other test modules replace
    ``sys.modules['app']`` with a stub at import time.
    """
    return _create_app


@pytest.fixture()
def client(flask_app):
    """Per-test Flask test client (unauthenticated)."""
    return flask_app.test_client()


@pytest.fixture()
def auth_client(flask_app):
    """Per-test Flask test client with an active admin session."""
    c = flask_app.test_client()
    with c.session_transaction() as sess:
        sess["_user_id"] = str(_ADMIN_USER_ID)
        sess["_fresh"] = True
    return c


@pytest.fixture()
def app_ctx(flask_app):
    """Push an application context; useful for tests that query the DB directly."""
    with flask_app.app_context():
        yield _db


@pytest.fixture(scope="session")
def user_model():
    """Return the real User model captured before any module stubs are installed."""
    return _User


@pytest.fixture(scope="session")
def passkey_credential_model():
    """Return the real PasskeyCredential model captured before stubs are installed."""
    return _PasskeyCredential


@pytest.fixture(scope="session")
def password_setup_token_model():
    """Return the real PasswordSetupToken model captured before stubs are installed."""
    return _PasswordSetupToken


@pytest.fixture(scope="session")
def settings_model():
    """Return the real Settings model captured before any module stubs are installed."""
    return _Settings


@pytest.fixture(scope="session")
def text_settings_model():
    """Return the real TextSettings model captured before any module stubs are installed."""
    return _TextSettings


@pytest.fixture(scope="session")
def password_setup_helpers():
    """Return password setup helpers captured before any module stubs are installed."""
    return {
        "build_url": _build_password_setup_url,
        "create_token": _create_password_setup_token,
    }


@pytest.fixture(scope="session")
def billing_routes_module():
    """Return billing routes module captured before any module stubs are installed."""
    return _billing_routes


@pytest.fixture(scope="session")
def plaid_connection_model():
    """Return the real PlaidConnection model captured before stubs are installed."""
    return _PlaidConnection


@pytest.fixture(scope="session")
def plaid_service_module():
    """Return the real plaid_service module captured before stubs are installed."""
    return _plaid_service


@pytest.fixture(autouse=True)
def _reset_plaid_config(flask_app):
    """Ensure Plaid is not configured by default in tests; restore after each test."""
    snapshot = {
        k: flask_app.config.get(k, "")
        for k in (
            "PLAID_CLIENT_ID",
            "PLAID_SECRET",
            "PLAID_ENV",
            "PLAID_PRODUCTS",
            "PLAID_COUNTRY_CODES",
            "PLAID_REDIRECT_URI",
        )
    }
    yield
    flask_app.config.update(snapshot)


# ── Web-route test helpers ───────────────────────────────────────────────────


@pytest.fixture(scope="session")
def web_models():
    """Namespace of real ORM models captured before any module stubs."""
    return types.SimpleNamespace(
        User=_User,
        Balance=_Balance,
        Settings=_Settings,
        TextSettings=_TextSettings,
        PasskeyCredential=_PasskeyCredential,
        PasswordSetupToken=_PasswordSetupToken,
        PlaidConnection=_PlaidConnection,
        Email=_Email,
        Schedule=_Schedule,
        Scenario=_Scenario,
        Hold=_Hold,
        Skip=_Skip,
        AISettings=_AISettings,
        GlobalEmailSettings=_GlobalEmailSettings,
    )


@pytest.fixture(scope="session")
def main_module():
    """Return the real app.main module (web routes) for monkeypatching."""
    return _main_module


@pytest.fixture(scope="session")
def auth_module():
    """Return the real app.auth module (auth routes) for monkeypatching."""
    return _auth_module


@pytest.fixture()
def make_user(app_ctx):
    """Factory that creates an isolated user and returns its id.

    Each call gets a unique email so tests never collide with the shared
    seeded admin (whose flags other modules mutate) or with each other.
    Defaults to an active, non-global account owner with password
    ``testpass123``.
    """

    def _make(
        *,
        email=None,
        password="testpass123",
        name="Web Test User",
        admin=True,
        is_global_admin=False,
        is_active=True,
        owner_id=None,
        balance=None,
        **extra,
    ):
        user = _User(
            email=email or f"web-{uuid.uuid4().hex[:12]}@test.local",
            password=generate_password_hash(password, method="scrypt"),
            name=name,
            admin=admin,
            is_global_admin=is_global_admin,
            is_active=is_active,
            account_owner_id=owner_id,
            owner_user_id=owner_id,
            is_account_owner=owner_id is None,
            **extra,
        )
        app_ctx.session.add(user)
        app_ctx.session.commit()
        if balance is not None:
            app_ctx.session.add(
                _Balance(amount=balance, date=datetime.today().date(), user_id=user.id)
            )
            app_ctx.session.commit()
        return user.id

    return _make


@pytest.fixture()
def login_as(flask_app):
    """Factory returning a test client with a logged-in session for ``user_id``."""

    def _login(user_id):
        c = flask_app.test_client()
        with c.session_transaction() as sess:
            sess["_user_id"] = str(user_id)
            sess["_fresh"] = True
        return c

    return _login


@pytest.fixture()
def fresh(app_ctx):
    """Re-read a row from the database, discarding stale identity-map state."""

    def _fresh(model, pk):
        app_ctx.session.expire_all()
        return app_ctx.session.get(model, pk)

    return _fresh
