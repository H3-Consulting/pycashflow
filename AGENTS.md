# PyCashFlow — Agent Guide

> For coding agents (Codex, Claude Code, etc.) working on this repository.
> Read this before making any changes.

---

## Project Overview

PyCashFlow is a **personal cash-flow forecasting application** built with
Flask. Users enter recurring income and expense schedules, and the app
projects their running bank balance over a 90-day window. It includes
what-if scenario modeling, a deterministic risk score, AI-powered insights
(via OpenAI), and a recently added REST API for mobile clients.

**Primary audience:** Individuals and households managing personal finances.

**Deployment model:** Self-hosted via Docker (Alpine + Waitress WSGI) or
manual Python install. Single-instance, single-database (SQLite default,
PostgreSQL supported via `DATABASE_URL`).

---

## Repository Structure

```
pycashflow/
├── app/
│   ├── __init__.py            # Flask app factory, extensions, bootstrap
│   ├── auth.py                # Auth blueprint: login, signup, 2FA, passkeys
│   ├── main.py                # Main blueprint: ~40 server-rendered routes
│   ├── models.py              # 11 SQLAlchemy models
│   ├── cashflow.py            # Projection engine (pandas), risk score
│   ├── ai_insights.py         # OpenAI integration
│   ├── crypto_utils.py        # Fernet encryption helpers
│   ├── totp_utils.py          # TOTP 2FA utilities
│   ├── files.py               # CSV import/export
│   ├── getemail.py            # IMAP balance ingestion + notifications
│   ├── api/
│   │   ├── __init__.py        # API v1 blueprint, error handlers
│   │   ├── auth_utils.py      # Bearer token lifecycle, @api_login_required
│   │   ├── errors.py          # Standardized error responses
│   │   ├── responses.py       # Success response helpers
│   │   ├── serializers.py     # ORM → JSON converters
│   │   └── routes/
│   │       ├── auth.py        # POST login/logout, GET me
│   │       └── data.py        # GET dashboard, schedules, projections, etc.
│   ├── data/                  # SQLite database file (runtime)
│   ├── static/                # CSS, icons, PWA assets
│   └── templates/             # Jinja2 HTML templates
├── migrations/
│   └── versions/              # 9 Alembic migration files
├── tests/
│   ├── conftest.py            # Pytest fixtures (in-memory SQLite)
│   ├── _helpers.py            # Test utilities
│   ├── test_api_foundation.py # API auth and response shape tests
│   ├── test_api_data.py       # API data endpoint tests
│   ├── test_routes.py         # Web route tests
│   ├── test_projection_engine.py  # Cashflow math tests
│   ├── test_scenarios.py      # Scenario modeling tests
│   ├── test_cash_risk_score.py    # Risk scoring tests
│   ├── test_imports.py        # CSV import validation tests
│   └── test_passkey_auth.py   # WebAuthn/passkey tests
├── requirements.txt           # 20 Python dependencies
├── pyproject.toml             # Pytest configuration
├── Dockerfile                 # Alpine + Python 3.15 container
├── entry.sh                   # Container entrypoint (migrate + waitress)
├── API_CONVENTIONS.md         # API response/error shape spec
├── AUTH_API.md                # Bearer token auth guide
├── SAMPLE_PAYLOADS.md         # curl examples for all API endpoints
├── API_GAP_REPORT.md          # Mobile API gap analysis
├── CODEX_HANDOFF.md           # First-pass implementation summary
├── MOBILE_API_REFERENCE.md    # Endpoint-by-endpoint API docs
└── INTEGRATION_GAPS.md        # Template/API friction points
```

---

## How to Run

### Prerequisites

- Python 3.11+
- pip

### Install dependencies

```bash
pip install -r requirements.txt
```

### Environment variables

Create a `.env` file or export these:

```bash
# Required
export SECRET_KEY="your-flask-secret-key-32-chars-minimum"
export APP_SECRET="your-fernet-encryption-key-32-chars"

# Optional
export DATABASE_URL="sqlite:///app/data/db.sqlite"  # default
export SESSION_COOKIE_SECURE="false"                 # set true in production
export PASSKEY_RP_ID="localhost"
export PASSKEY_RP_NAME="PyCashFlow"
export PASSKEY_ORIGIN="http://localhost:5000"
export BOOTSTRAP_ADMIN_EMAIL="admin@example.com"     # auto-creates admin on first run
export BOOTSTRAP_ADMIN_PASSWORD="changeme"
```

### Run the app

```bash
flask db upgrade          # apply migrations
python -m waitress --host=0.0.0.0 --port=5000 app:create_app
```

Or use Flask's dev server:

```bash
flask run --debug
```

### Run tests

```bash
pip install -r requirements-dev.txt -c constraints.txt   # adds pytest + pytest-cov
python -m pytest -q
```

Tests use an in-memory SQLite database. No external services required.
All tests should pass (~700). `LegacyAPIWarning` deprecation warnings from
SQLAlchemy are known and non-blocking.

Web-route tests live in `tests/test_web_*.py` alongside `tests/test_routes.py`.
Use the `make_user`, `login_as`, `fresh`, and `web_models` fixtures from
`conftest.py` so each test gets isolated users instead of mutating the shared
seeded admin.

### CI and releases

- `.github/workflows/ci.yml` runs on every PR to `master` (iOS-only changes
  skipped): the test suite on Python 3.11 and 3.15, plus a Docker build and
  `.github/scripts/docker-smoke-test.sh` (boots the image, logs in, loads the
  dashboard).
- `.github/workflows/release.yml` runs when a PR is merged: bumps the version
  from the latest `vX.Y.Z` tag (patch by default; `release:minor` /
  `release:major` labels bump more, `release:skip` publishes nothing), runs the
  tests, builds and smoke-tests the image, pushes `whahn1983/pycashflow:<version>`
  and `:latest`, then creates the `v<version>` tag and GitHub release.
  Requires the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets.

---

## Coding Conventions Observed

### Python style

- No linter config file exists, but code follows PEP 8 with ~88-char lines
- Type hints used sparingly (mostly in API layer, e.g., `-> str | None`)
- Docstrings on public functions use reStructuredText-style (`Args:`, `Returns:`)
- Module-level docstrings describe purpose and endpoint inventory
- `noqa` comments used for intentional import side-effects

### Flask patterns

- App factory pattern (`create_app()` in `app/__init__.py`)
- Three blueprints: `auth`, `main`, `api`
- Extensions initialized in app factory: `db`, `migrate`, `login_manager`, `limiter`, `csrf`
- `get_effective_user_id()` pattern: returns account owner ID for guests, own ID otherwise
  (duplicated in `main.py` and `app/api/routes/data.py`)

### Database

- SQLAlchemy ORM exclusively — no raw SQL
- Alembic migrations via Flask-Migrate
- Composite unique constraints for per-user uniqueness (e.g., `_user_schedule_uc`)
- `Numeric(10,2)` for all monetary amounts
- Dates stored as `Date`, datetimes as `DateTime` (naive, treated as UTC)

### API conventions

- All API endpoints in `app/api/routes/` directory
- Use `@api_login_required` decorator, not Flask-Login's `@login_required`
- Return values via `api_ok()`, `api_list()`, `api_created()`, `api_no_content()`
- Errors via `unauthorized()`, `validation_error()`, `not_found()`, etc.
- Serialization through explicit `serialize_*()` functions — never `__dict__`
- Amounts as decimal strings (`"1500.00"`), dates as ISO 8601 strings
- All endpoint functions prefixed with `api_` (e.g., `api_dashboard`, `api_schedules`)

### Testing patterns

- `conftest.py` creates the real Flask app and seeds test data BEFORE any test
  module can install stubs
- Module-level imports in `conftest.py` capture real objects before stubs
- Unit tests for `cashflow.py` use lightweight stubs (`_helpers.py`) to avoid DB
- Integration tests use `flask_app.test_client()` with session injection for auth
- Bearer token tests create tokens via `create_token_for_user()` inside `app_ctx`

---

## Rules for Backward Compatibility

1. **Never remove or rename existing API fields.** Add new fields alongside
   old ones if the shape needs to change.

2. **Never change the `data`/`meta`/`error` response envelope.** All clients
   depend on this structure.

3. **Never change serialization formats.** Amounts stay as decimal strings.
   Dates stay as ISO 8601. Do not switch to JSON numbers or Unix timestamps.

4. **Keep the `api` blueprint CSRF-exempt.** Mobile clients cannot provide
   CSRF tokens.

5. **Keep Bearer token auth working alongside session auth.** The
   `@api_login_required` decorator must continue to check both.

6. **Do not add required query parameters to existing GET endpoints.** New
   parameters must be optional with sensible defaults.

7. **Do not change the error `code` slugs** (`unauthorized`, `not_found`,
   etc.). Clients key on these for programmatic error handling.

8. **Keep `_effective_user_id()` in data routes.** Guest isolation depends
   on this pattern. All data queries must filter by effective user ID.

9. **New migrations must be additive.** Do not modify or squash existing
   migrations.

10. **Web routes in `main.py` must continue to work.** The API is additive —
    it does not replace the server-rendered app.

---

## API Conventions (Quick Reference)

- **URL prefix:** `/api/v1/`
- **Auth:** `Authorization: Bearer <token>` (preferred) or session cookie
- **Success:** `{ "data": ... }` with 200/201
- **Collection:** `{ "data": [...], "meta": { "total": N } }` with 200
- **Error:** `{ "error": "...", "code": "...", "status": N }` with 4xx/5xx
- **Validation error:** adds `"fields": { "field": "reason" }` to error body
- **Amounts:** `"1500.00"` (2-decimal string, always positive)
- **Dates:** `"2026-04-09"` (ISO 8601)
- **Datetimes:** `"2026-04-09T14:30:00Z"` (UTC, seconds precision)

---

## Important Business Concepts

### Schedules

Recurring financial transactions (income or expense) with a frequency
(Monthly, BiWeekly, Quarterly, Yearly, Weekly, Onetime). The projection
engine expands these into individual dated transactions over a ~13-month
window.

### Scenarios

What-if overlays. Structurally identical to schedules but modeled separately.
The projection engine produces two running-balance series: schedule-only and
schedule+scenario combined.

### Holds

Pausing a schedule item removes it from projections without deleting it.
A hold copies the schedule's `name`, `amount`, and `type` but not its dates.

### Skips

Skipping a single instance of a recurring schedule. A skip records the
`name`, `date`, `amount`, and `type` of the specific occurrence to exclude.
Skipped items still affect the running balance but are hidden from the
upcoming-transactions view (marked with `"(SKIP)"` in the name).

### Balance

A single point-in-time bank balance. Only the latest balance (by date, then
by ID) is used as the starting point for projections.

### Risk Score

A deterministic 0–100 score computed from the 90-day projection:
- Runway days (40% weight)
- Lowest projected balance (25%)
- Days to lowest balance (20%)
- Balance volatility (15%)

Status bands: Safe (80+), Stable (60+), Watch (40+), Risk (20+), Critical (0–19).

### Guest Users

View-only accounts linked to an account owner via `account_owner_id`. They
see the owner's data but cannot modify it. Guest users authenticate with
their own credentials.

---

## Guidance for Future Agents

1. **Prefer incremental changes.** Make one focused change per commit. Do not
   combine unrelated features or refactors.

2. **Read before writing.** Always read the existing file before modifying it.
   Understand the patterns in use — do not introduce competing patterns.

3. **Run tests after every change.** `python -m pytest -q` should pass all
   tests. Do not commit code that breaks existing tests.

4. **Add tests for new endpoints.** Follow the patterns in
   `test_api_foundation.py` and `test_api_data.py`. Test both success paths
   and error cases.

5. **Use the serializer pattern.** New API data must go through
   `serialize_*()` functions in `app/api/serializers.py`. Do not inline
   serialization in route handlers.

6. **Respect the dual-auth pattern.** All new API endpoints must use
   `@api_login_required` and `get_api_user()` / `_effective_user_id()`.

7. **Keep web routes working.** If you need to refactor business logic out of
   `main.py`, ensure the web routes still render correctly.

8. **Check `API_CONVENTIONS.md` before adding endpoints.** Follow the
   documented response shapes, error codes, and serialization rules.

9. **Do not add dependencies without justification.** The app currently has
   20 direct dependencies — keep it lean.

10. **Document new endpoints.** Update `MOBILE_API_REFERENCE.md` and the
    endpoint inventory in `API_CONVENTIONS.md` when adding routes.

---

## iOS App (SwiftUI) Notes

A SwiftUI client now lives under `/ios-app` with this structure:

- `/ios-app/PyCashFlowApp/App`: app entry (`PyCashFlowApp`) and root navigation (`RootView`)
- `/ios-app/PyCashFlowApp/Core/Networking`: HTTP API client and envelope decoding
- `/ios-app/PyCashFlowApp/Core/Auth`: session manager/token state
- `/ios-app/PyCashFlowApp/Core/Models`: API-aligned DTOs
- `/ios-app/PyCashFlowApp/Features/*`: screen modules (`Login`, `Dashboard`, `Accounts`, `Projections`, `Schedules`, `Scenarios`, `Settings`)

### iOS Architecture Conventions

- UI layers should consume only backend API contracts; no embedded cashflow business logic.
- API envelopes must decode from backend `{ data: ... }` / `{ data: [...], meta: ... }` shapes.
- Authentication is Bearer-token based; session state should be centralized in `SessionManager`.
- If UI needs new behavior, add/extend backend API endpoints rather than client-side rule duplication.

---

## Payments & Activation Rules

- `PAYMENTS_ENABLED=true` enforces subscription checks for authenticated non-global-admin users.
- `PAYMENTS_ENABLED=false` bypasses subscription enforcement for self-hosted/manual operation.
- Subscription truth sources:
  - Stripe webhook events (`/api/v1/billing/webhook/stripe`)
  - App Store verification endpoint (`/api/v1/billing/verify-appstore`) using
    App Store Server API JWT auth (`APPLE_ISSUER_ID`, `APPLE_KEY_ID`,
    `APPLE_PRIVATE_KEY`/`APPLE_PRIVATE_KEY_PATH`, optional `APPLE_BUNDLE_ID`,
    and `APPLE_ENVIRONMENT=production|sandbox|auto`)
- Do not trust client-side purchase state for activation.
- Global admins always bypass subscription checks and must remain active.
- Guests inherit effective access from their account owner (`owner_user_id` or legacy `account_owner_id`).
- Expired owner subscriptions disable guest access.
- Payment-created users must never receive plaintext passwords.
- For newly created paid users (Stripe/App Store), generate one-time password
  setup token, store only token hash + expiry + used state, and send setup
  email. Existing users must not receive setup email.
- User-facing password setup links must always use `FRONTEND_BASE_URL` with
  trailing-slash normalization and fixed route `/auth/set-password/<token>`.
