from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import current_user, logout_user
import secrets
import os
import logging
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

logger = logging.getLogger(__name__)


# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address, default_limits=[])
csrf = CSRFProtect()


# Content-Security-Policy allowlist, derived from the external resources the
# templates actually load: Bootstrap (cdn.jsdelivr.net), Plotly (cdn.plot.ly),
# jQuery (ajax.googleapis.com), Plaid Link (cdn.plaid.com), Font Awesome
# (cdnjs.cloudflare.com), and Google Fonts (fonts.googleapis.com /
# fonts.gstatic.com). 'unsafe-inline' is retained because the templates rely on
# inline <script> blocks, inline event handlers (onclick/onsubmit/onfocus), and
# inline style="" attributes that nonces cannot cover without a template
# refactor; the host allowlist still prevents loading script/styles from any
# other origin.
_CSP_DIRECTIVES = {
    "default-src": ["'self'"],
    "script-src": [
        "'self'", "'unsafe-inline'",
        "https://cdn.jsdelivr.net", "https://cdn.plot.ly",
        "https://ajax.googleapis.com", "https://cdn.plaid.com",
    ],
    "style-src": [
        "'self'", "'unsafe-inline'",
        "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com",
        "https://fonts.googleapis.com",
    ],
    "font-src": ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
    "img-src": ["'self'", "data:"],
    # connect-src must also cover the CDN origins because the service worker
    # (app/sw.js) re-fetches every cross-origin asset via fetch(); inside a
    # worker those fetches are governed by the worker script's own CSP
    # connect-src, so omitting the CDNs here would block Bootstrap, Font
    # Awesome, Google Fonts, Plotly, and jQuery when CSP is enforced.
    "connect-src": [
        "'self'", "https://*.plaid.com",
        "https://cdn.jsdelivr.net", "https://cdn.plot.ly",
        "https://ajax.googleapis.com", "https://cdnjs.cloudflare.com",
        "https://fonts.googleapis.com", "https://fonts.gstatic.com",
    ],
    "frame-src": ["https://cdn.plaid.com", "https://*.plaid.com"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "object-src": ["'none'"],
}

_CONTENT_SECURITY_POLICY = "; ".join(
    f"{name} {' '.join(values)}" for name, values in _CSP_DIRECTIVES.items()
)


def normalize_database_url(url):
    """Pin driverless PostgreSQL URLs to the psycopg2 driver the app ships.

    Hosts such as DigitalOcean hand out ``postgresql://`` (or the legacy
    ``postgres://``) URLs with no driver. SQLAlchemy 2.1 changed the default
    driver for those from psycopg2 to psycopg 3, which is not installed, so
    the app would fail to start. URLs that already name a driver
    (``postgresql+psycopg://``) and non-PostgreSQL URLs are returned as-is.
    """
    if not url:
        return url
    for prefix in ('postgresql://', 'postgres://'):
        if url.startswith(prefix):
            return 'postgresql+psycopg2://' + url[len(prefix):]
    return url


def create_app():

    app = Flask(__name__, static_url_path='/static')

    # Load environment variables from .env file
    load_dotenv()

    app.config["PASSKEY_RP_ID"] = os.environ.get("PASSKEY_RP_ID", "")
    app.config["PASSKEY_RP_NAME"] = os.environ.get("PASSKEY_RP_NAME", "PyCashFlow")
    app.config["PASSKEY_ORIGIN"] = os.environ.get("PASSKEY_ORIGIN", "")
    app.config["FRONTEND_BASE_URL"] = os.environ.get("FRONTEND_BASE_URL", "").strip()
    app.config["PASSWORD_SETUP_TOKEN_TTL_MINUTES"] = os.environ.get(
        "PASSWORD_SETUP_TOKEN_TTL_MINUTES",
        "60",
    )
    app.config["PAYMENTS_ENABLED"] = os.environ.get("PAYMENTS_ENABLED", "false").lower() == "true"
    app.config["APPSTORE_ALLOW_STUB_VERIFICATION"] = (
        os.environ.get("APPSTORE_ALLOW_STUB_VERIFICATION", "false").lower() == "true"
    )
    app.config["APPLE_ISSUER_ID"] = os.environ.get("APPLE_ISSUER_ID", "")
    app.config["APPLE_KEY_ID"] = os.environ.get("APPLE_KEY_ID", "")
    app.config["APPLE_PRIVATE_KEY"] = os.environ.get("APPLE_PRIVATE_KEY", "")
    app.config["APPLE_PRIVATE_KEY_PATH"] = os.environ.get("APPLE_PRIVATE_KEY_PATH", "")
    app.config["APPLE_BUNDLE_ID"] = os.environ.get("APPLE_BUNDLE_ID", "")
    app.config["APPLE_ENVIRONMENT"] = os.environ.get("APPLE_ENVIRONMENT", "production")

    # Inbound balance-email authentication (app/getemail.py).
    # Balance emails are only ingested when the From address matches the
    # per-user Allowed Sender AND the message passes sender authentication
    # (DKIM/SPF/DMARC). The mailbox provider (Gmail/Outlook/Fastmail/etc.)
    # prepends the outermost Authentication-Results header on arrival, and that
    # is the header we trust. EMAIL_REQUIRE_AUTH_RESULTS may be set to "false"
    # only when a separate trusted ingestion path makes the headers redundant
    # (not recommended).
    app.config["EMAIL_REQUIRE_AUTH_RESULTS"] = (
        os.environ.get("EMAIL_REQUIRE_AUTH_RESULTS", "true").lower() == "true"
    )
    # Some mailboxes (notably custom-domain / self-hosted mail hosts) never
    # stamp an Authentication-Results header, so an otherwise legitimate,
    # DKIM-signed bank alert would be rejected as unauthenticated. When this is
    # enabled (default), such messages fall back to in-app DKIM verification:
    # the message's DKIM-Signature is verified against DNS and the signing
    # domain must align with the Allowed Sender. Set to "false" only in
    # environments without outbound DNS access.
    app.config["EMAIL_VERIFY_DKIM"] = (
        os.environ.get("EMAIL_VERIFY_DKIM", "true").lower() == "true"
    )

    # Plaid Balance integration config (optional feature).
    # Treated as "configured" only when CLIENT_ID, SECRET, ENV, and PRODUCTS
    # are all populated; see app.plaid_service.plaid_is_configured().
    app.config["PLAID_CLIENT_ID"] = os.environ.get("PLAID_CLIENT_ID", "").strip()
    app.config["PLAID_SECRET"] = os.environ.get("PLAID_SECRET", "").strip()
    app.config["PLAID_ENV"] = os.environ.get("PLAID_ENV", "").strip().lower()
    app.config["PLAID_PRODUCTS"] = os.environ.get("PLAID_PRODUCTS", "").strip()
    app.config["PLAID_COUNTRY_CODES"] = os.environ.get("PLAID_COUNTRY_CODES", "US").strip()
    app.config["PLAID_REDIRECT_URI"] = os.environ.get("PLAID_REDIRECT_URI", "").strip()

    basedir = os.path.abspath(os.path.dirname(__file__))

    # Prefer a stable SECRET_KEY from the environment so sessions survive restarts.
    # Fall back to a per-process random value only when no key is configured.
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)

    # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_DATABASE_URI'] = normalize_database_url(
        os.environ.get('DATABASE_URL')
    ) or 'sqlite:///' + os.path.join(basedir, 'data/db.sqlite')

    # Harden session and remember-me cookies.
    # SESSION_COOKIE_SECURE defaults to True; set SESSION_COOKIE_SECURE=false in .env
    # only when running without TLS (e.g. local dev over plain HTTP).
    # Use == 'true' (not != 'false') so that any value other than exactly 'true'
    # keeps cookies secure, preventing accidental exposure from typos like 'False'.
    _secure_cookies = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true'
    app.config['SESSION_COOKIE_SECURE'] = _secure_cookies
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['REMEMBER_COOKIE_SECURE'] = _secure_cookies
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'

    # Reject request bodies larger than 2 MB before any route handler runs,
    # preventing the server from buffering huge uploads into memory.
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB

    # Configure Flask-Limiter storage backend.
    # Defaults to in-memory (single-process only). For multi-process deployments,
    # set RATELIMIT_STORAGE_URI to a Redis URL, e.g. redis://localhost:6379/0
    app.config['RATELIMIT_STORAGE_URI'] = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')

    # Security response headers (applied in _set_security_headers below).
    # The Content-Security-Policy ships in Report-Only mode by default so the
    # Plaid Link bank-connection flow can be verified in a real browser before
    # it is enforced; set CSP_REPORT_ONLY=false to switch CSP to enforcing.
    app.config['SECURITY_HEADERS_ENABLED'] = (
        os.environ.get('SECURITY_HEADERS_ENABLED', 'true').lower() == 'true'
    )
    app.config['CSP_REPORT_ONLY'] = (
        os.environ.get('CSP_REPORT_ONLY', 'true').lower() == 'true'
    )

    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    csrf.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models import User
    from .subscription import enforce_user_access

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

    @app.before_request
    def _enforce_authenticated_access():
        from flask import request
        if not current_user.is_authenticated:
            return None
        if request.path.startswith("/api/"):
            return None
        if enforce_user_access(current_user._get_current_object()):
            return None
        logout_user()
        return login_manager.unauthorized()

    @app.after_request
    def _set_security_headers(response):
        from flask import request
        if not app.config.get('SECURITY_HEADERS_ENABLED', True):
            return response
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        # Only assert HSTS over HTTPS so local plain-HTTP dev isn't pinned to TLS.
        if request.is_secure:
            response.headers.setdefault(
                'Strict-Transport-Security', 'max-age=31536000; includeSubDomains'
            )
        # Keep authenticated HTML out of shared/disk caches. Scoped to text/html
        # so static assets (CSS/JS/icons) stay cacheable for the PWA.
        if response.mimetype == 'text/html':
            response.headers.setdefault('Cache-Control', 'no-store')
        csp_header = (
            'Content-Security-Policy-Report-Only'
            if app.config.get('CSP_REPORT_ONLY', True)
            else 'Content-Security-Policy'
        )
        response.headers.setdefault(csp_header, _CONTENT_SECURITY_POLICY)
        return response

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # API v1 blueprint — CSRF-exempt; uses Bearer token auth
    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix="/api/v1")
    csrf.exempt(api_blueprint)

    # Don't use db.create_all() - use flask db upgrade instead
    # with app.app_context():
    #     db.create_all()

    # Bootstrap global admin from environment variables.
    # Set BOOTSTRAP_ADMIN_EMAIL + BOOTSTRAP_ADMIN_PASSWORD only for initial setup.
    # IMPORTANT: Remove these environment variables after the first admin account
    # has been created to avoid leaving credentials in the process environment.
    _bootstrap_email = os.environ.get('BOOTSTRAP_ADMIN_EMAIL')
    _bootstrap_password = os.environ.get('BOOTSTRAP_ADMIN_PASSWORD')
    if _bootstrap_email and _bootstrap_password:
        with app.app_context():
            try:
                from .models import User
                from werkzeug.security import generate_password_hash
                if not User.query.filter_by(is_global_admin=True).first():
                    if not User.query.filter_by(email=_bootstrap_email).first():
                        bootstrap_user = User(
                            email=_bootstrap_email,
                            name='Admin',
                            password=generate_password_hash(_bootstrap_password, method='scrypt'),
                            admin=True,
                            is_global_admin=True,
                            is_active=True,
                        )
                        db.session.add(bootstrap_user)
                        db.session.commit()
            except Exception as exc:
                # Expected during pre-migration startup when tables don't exist yet.
                logger.debug(
                    "Bootstrap admin creation skipped (%s); tables may not exist yet",
                    type(exc).__name__,
                )

    # When deployed behind a reverse proxy / PaaS ingress, trust that many
    # X-Forwarded-* hops so rate limiting keys on the real client IP rather than
    # the proxy's address. x_proto makes request.is_secure reflect the original
    # HTTPS scheme behind TLS termination; x_host restores the public hostname for
    # absolute URLs (e.g. password-setup links). Set TRUSTED_PROXY_COUNT=0 when
    # clients connect directly (no proxy) so spoofed headers are ignored.
    _proxy_count = int(os.environ.get('TRUSTED_PROXY_COUNT', '1'))
    if _proxy_count > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=_proxy_count,
            x_proto=_proxy_count,
            x_host=_proxy_count,
        )

    return app
