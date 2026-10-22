<img src="./app/static/app_logo_rounded.png" alt="PyCashFlow logo" width="220" />

# PyCashFlow

![Docker Pulls](https://img.shields.io/docker/pulls/whahn1983/pycashflow)
![GitHub License](https://img.shields.io/github/license/whahn1983/pycashflow)

**A comprehensive Python Flask application for cash flow forecasting, transaction management, AI-powered insights, financial planning, and a REST API for mobile integration.**

PyCashFlow is a powerful, multi-user web application designed to help individuals, families, and small-medium businesses manage their finances through intelligent cash flow forecasting, recurring transaction scheduling, and automated balance tracking. With support for up to one year of cash flow projections, interactive visualizations, AI-generated insights via OpenAI, and automatic email-based balance updates, PyCashFlow provides a complete solution for financial planning and management.

<img width="718" height="1063" alt="pycashflow_screenshot" src="https://github.com/user-attachments/assets/11beb340-e326-4280-9dcd-7936d0c0e4c7" />

---

## Table of Contents

- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
  - [Docker Installation (Recommended)](#docker-installation-recommended)
  - [Manual Installation](#manual-installation)
- [Configuration](#configuration)
- [User Roles & Access Control](#user-roles--access-control)
- [Core Capabilities](#core-capabilities)
- [REST API](#rest-api)
  - [Authentication](#authentication-1)
  - [Data Endpoints](#data-endpoints)
  - [Response Format](#response-format)
- [AI Insights](#ai-insights)
  - [Cash Risk Score](#cash-risk-score)
- [Payments & Activation](#payments--activation)
- [Two-Factor Authentication (2FA)](#two-factor-authentication-2fa)
- [Email Integration](#email-integration)
- [Data Management](#data-management)
- [Updates & Maintenance](#updates--maintenance)
- [Professional Support](#professional-support)
- [License](#license)

---

## Key Features

### Cash Flow Forecasting & Visualization
- **12-Month Projections**: Visualize your future cash flow up to one year in advance
- **Interactive Charts**: Plotly-powered interactive visualizations with zoom, pan, and hover details
- **Minimum Balance Warnings**: Automatically identifies potential low balance periods
- **90-Day Transaction Preview**: Detailed view of upcoming transactions with running balance calculations
- **Scenario Modeling**: Create what-if income and expense scenarios alongside your real schedule; the dashboard chart displays a second dashed line showing the projected impact, and the lowest balance card shows the scenario minimum in amber parentheses

### Transaction Management
- **Recurring Schedules**: Support for multiple frequencies:
  - Monthly, Weekly, BiWeekly, Quarterly, Yearly, and One-Time transactions
- **Smart Date Handling**: Automatic business day adjustments for weekends
- **Transaction Holds**: Temporarily pause scheduled transactions without deletion
- **Skip Functionality**: Skip individual future transaction instances
- **Manual Balance Updates**: Set account balance for any specific date
- **Auto-Cleanup**: One-time transactions automatically removed after their date passes

### Multi-User Support
- **Three-Tier Access Control**:
  - **Global Administrator**: System-wide management and user approval
  - **Account Owner**: Full cash flow management plus guest user administration
  - **Guest User**: View-only dashboard access for family members, business partners, or advisors
- **User Activation Workflow**: Global admin approval required for new registrations
- **Multi-Account Isolation**: Complete data separation between account owners

### AI-Powered Cash Flow Insights
- **Dual AI Provider Support**: Uses your OpenAI API key when configured, or a server-managed DigitalOcean GenAI agent fallback when available
- **Provider Routing**: If a DigitalOcean agent is configured and no explicit model is set, refreshes prefer the DigitalOcean provider; otherwise the saved OpenAI key/model is used
- **Typed Insights**: Categorized as **Cash Risk**, **Risk**, **Pattern**, or **Observation** with color-coded badges
- **Cash Risk Score**: Deterministic 0–100 score computed on every refresh — no AI required; always displayed as a mandatory card in the AI Insights section and as an inline indicator on the Lowest Balance card
- **Refresh Cooldown**: AI insights refresh at most once every 2 hours per account; requests inside the window return cached insights
- **Staleness Indicator**: Last-updated timestamp shown so you always know how current the analysis is
- **Secure Key Storage**: Your OpenAI API key is encrypted at rest using the same Fernet/APP_SECRET pattern as email passwords
- **Guest Visibility**: Cached insights are visible to guest users (view-only); only account owners can trigger a refresh

### Automated Balance Updates
- **IMAP Email Integration**: Automatically extract balance information from bank emails
- **Configurable Search**: Customizable subject lines and balance delimiter patterns
- **Scheduled Processing**: Automated cron job checks emails every minute
- **Multi-User Support**: Per-user email configurations and processing
- **Plaid Balance Sync (optional)**: Connect a single bank account via Plaid Link
  and refresh today's balance from `/accounts/balance/get` on dashboard load.
  Only minimal connection metadata (encrypted access token + selected account)
  is stored — no transactions, no raw Plaid payloads, no queried balances.
  See [Plaid Balance Integration](#plaid-balance-integration).

### Modern Authentication
- **Traditional Login**: Email/password authentication with Scrypt password hashing
- **Two-Factor Authentication (2FA)**: TOTP-based 2FA with QR code setup and backup codes
- **Passkey Support**: Modern passwordless authentication via built-in WebAuthn (py_webauthn) support
- **Session Management**: Secure session handling with "remember me" functionality

### REST API (v1)
- **Bearer Token Authentication**: Secure token-based auth for programmatic access
- **Read-Only Data Endpoints**: Access dashboard, schedules, projections, scenarios, and more
- **Mobile-Ready**: JSON responses designed for mobile app integration
- **Guest-Aware**: Automatically resolves guest users to their account owner's data
- **Rate-Limited**: Login endpoint rate-limited to prevent brute-force attacks

### Progressive Web App (PWA)
- **Installable**: Add to home screen on mobile and desktop devices
- **Offline Support**: Service worker caches pages and static assets so previously visited views remain accessible without a network connection
- **Cache Strategies**: Cache-first for static assets, stale-while-revalidate for CDN resources, and network-first with cache fallback for HTML pages
- **Offline Banner**: An automatic banner notifies users when the app is operating in offline mode
- **Secure Cache Handling**: Page cache is cleared on logout so no financial data remains on shared devices
- **Offline Fallback**: A branded offline page is shown when a page has not been previously cached
- **Mobile Optimized**: Responsive design for all screen sizes

---

## Technology Stack

### Backend
- **Flask**: Lightweight Python web framework
- **SQLAlchemy**: SQL toolkit and ORM for database management
- **Flask-Migrate**: Database migration management
- **Gunicorn**: Production-ready WSGI server
- **Flask-Login**: User session management
- **Flask-Limiter**: Rate limiting for API and auth endpoints

### Data Processing
- **Pandas**: Data manipulation and transaction calculations
- **NumPy**: Numerical operations and array processing
- **Python-dateutil**: Advanced date arithmetic and business day logic

### Frontend & Visualization
- **Plotly**: Interactive, responsive charting library
- **Bootstrap**: Responsive UI framework
- **HTML/CSS/JavaScript**: Modern web standards

### Security
- **Werkzeug**: Scrypt password hashing
- **pyotp**: TOTP-based two-factor authentication
- **qrcode**: QR code generation for authenticator app setup
- **webauthn (py_webauthn)**: Passkey authentication (optional)
- **python-dotenv**: Secure environment variable management

### AI
- **OpenAI Python SDK**: OpenAI integration for cash flow insights
- **cryptography (Fernet)**: Encrypted API key storage

### Email & Notifications
- **IMAPLIB**: Email retrieval from mail servers
- **SMTPLIB**: Email sending for notifications
- **Python email library**: MIME message parsing and creation

### Infrastructure
- **Docker**: Containerization for easy deployment
- **Alpine Linux**: Lightweight container base image
- **Cron**: Scheduled task execution
- **SQLite/PostgreSQL**: Flexible database options

---

## Installation

### Docker Installation (Recommended)

Docker provides the simplest and most reliable deployment method for PyCashFlow.

#### Pull the Latest Image

```bash
docker pull whahn1983/pycashflow:latest
```

#### Run the Container

```bash
docker run -d \
  -p 127.0.0.1:5000:5000 \
  -v /mnt/data:/app/app/data \
  -v /mnt/migrations:/app/migrations \
  -e TZ=America/New_York \
  -e ENABLE_CRON=true \
  -v /mnt/.env:/app/app/.env \
  --restart always \
  --pull always \
  --name pycashflow \
  whahn1983/pycashflow:latest
```

#### Volume Explanations

| Volume Mount | Purpose | Required |
|--------------|---------|----------|
| `/mnt/data:/app/app/data` | Persistent database storage | **Yes** |
| `/mnt/migrations:/app/migrations` | Database migration files | Recommended |
| `/mnt/.env:/app/app/.env` | Environment variables (.env settings, passkeys, bootstrap admin, etc.) | Optional |

#### Time Zone Configuration

Set the container's local time zone using the `TZ` environment variable:

```bash
-e TZ=America/New_York
```

If `TZ` is not provided, the container defaults to `UTC`.

#### Access the Application

Once running, access PyCashFlow at `http://localhost:5000`

#### Production WSGI Server (Gunicorn)

Containerized production startup uses Gunicorn (via `/entry.sh`) and keeps startup behavior unchanged: timezone setup, ownership fixes, optional cron startup, and `flask db upgrade` before serving requests.

#### Cron Startup Control

Use `ENABLE_CRON` to control whether container startup launches `crond`:

- `ENABLE_CRON=true` (default): start cron inside the container
- `ENABLE_CRON=false`: skip cron startup
- If unset, startup defaults to `true`

`ENABLE_CRON` can be provided either as a Docker environment variable (`-e ENABLE_CRON=...`) or in your mounted `.env` file at `/app/app/.env`.

For platforms like **DigitalOcean App Platform** where you run scheduled jobs separately, set:

```bash
-e ENABLE_CRON=false
```

Supported Gunicorn environment variables:

- `GUNICORN_WORKERS`: Number of worker processes. If unset, startup chooses:
  - `1` when `RATELIMIT_STORAGE_URI` is unset or uses `memory://` (process-local rate-limit storage)
  - otherwise `2 * CPU + 1`
- `GUNICORN_TIMEOUT`: Worker timeout seconds (default: `120`)

Example:

```bash
-e ENABLE_CRON=false \
-e GUNICORN_WORKERS=4 \
-e GUNICORN_TIMEOUT=180
```

---

### Manual Installation

For advanced users or custom deployments, PyCashFlow can be installed directly on a server.

#### Prerequisites

- Python 3.11 or higher
- pip (Python package manager)
- Git
- WSGI server (Gunicorn or uWSGI)
- (Optional) Reverse proxy (Nginx or Apache)

#### Installation Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/whahn1983/pycashflow.git
   cd pycashflow
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Apply Database Migrations**
   ```bash
   flask db upgrade
   ```

4. **Configure Environment Variables**

   Create a `.env` file in `/app/app/.env` (or copy from `app/.env_example`):
   ```bash
   cp app/.env_example app/.env

   # Required: Encryption key for email passwords, OpenAI API keys, and 2FA secrets
   # Generate with: python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   # WARNING: Changing this value after first run will make all stored encrypted data unreadable.
   APP_SECRET=your_generated_secret_key

   # Required: Protects Flask session cookies. Set a stable value so sessions
   # survive application restarts.
   # Generate with: python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   SECRET_KEY=your_generated_secret_key

   # Optional: Create the initial global admin on first startup instead of relying
   # on the signup form. Remove or leave blank after the account is created.
   BOOTSTRAP_ADMIN_EMAIL=admin@example.com
   BOOTSTRAP_ADMIN_PASSWORD=your_strong_password

   # Optional (required to enable passkeys): For Passkey Authentication (WebAuthn / py_webauthn)
   # rp_id should match your effective domain (e.g., app.example.com)
   PASSKEY_RP_ID=localhost
   PASSKEY_RP_NAME=PyCashFlow
   # Must exactly match scheme + host (+port in local dev), e.g. http://localhost:5000
   PASSKEY_ORIGIN=http://localhost:5000

   # Optional: set to false for local HTTP development only
   SESSION_COOKIE_SECURE=false

   # Optional: subscription enforcement toggle
   # true = enforce active subscription for non-global-admin users
   # false = bypass subscription checks for self-hosted/manual deployments
   PAYMENTS_ENABLED=false

   # Required for payment-created user onboarding links (Stripe/App Store)
   # Example: https://app.example.com
   FRONTEND_BASE_URL=

   # Optional: password setup link expiration in minutes (default: 60)
   PASSWORD_SETUP_TOKEN_TTL_MINUTES=60

   # Optional: Stripe webhook signing secret for webhook validation
   STRIPE_WEBHOOK_SECRET=

   # Optional: local/dev-only App Store stub verification
   APPSTORE_ALLOW_STUB_VERIFICATION=false

   # Optional: configure rate-limit backend (Redis recommended for multi-worker)
   # RATELIMIT_STORAGE_URI=redis://localhost:6379/0

   # Optional: inbound balance-email authentication (app/getemail.py).
   # Balance emails are ingested only when the From address matches the
   # per-user "Allowed Sender" AND the message passes DKIM/SPF/DMARC.
   # Authentication uses your mailbox provider's (Gmail/Outlook/Fastmail/etc.)
   # outermost Authentication-Results header automatically — no configuration
   # needed. If the mailbox does not stamp that header (common on custom-domain
   # or self-hosted mail hosts), the message's DKIM signature is verified
   # in-app against DNS instead, and its signing domain must align with the
   # Allowed Sender. EMAIL_VERIFY_DKIM defaults to true; set to false only in
   # environments without outbound DNS. EMAIL_REQUIRE_AUTH_RESULTS defaults to
   # true; set to false only when a separate trusted ingestion path makes the
   # checks redundant.
   # EMAIL_REQUIRE_AUTH_RESULTS=true
   # EMAIL_VERIFY_DKIM=true

   # Optional: Database URL (defaults to SQLite)
   DATABASE_URL=sqlite:///data/db.sqlite

   # Optional: container/app timezone (defaults to UTC)
   TZ=America/New_York
   ```

5. **Run the Application**

   Using Waitress (included):
   ```bash
   python app.py
   ```

   Or with Gunicorn:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"
   ```

6. **Configure Email Processing (Optional)**

   Set up a cron job to run email balance imports:
   ```bash
   crontab -e
   ```

   Add the following line:
   ```
   */1 * * * * /usr/local/bin/python3 -u /path/to/pycashflow/app/getemail.py >> /path/to/pycashflow/getemail.log 2>&1
   ```

7. **Set Up Reverse Proxy (Recommended)**

   For production deployments, configure Nginx or Apache to proxy requests to the WSGI server on port 5000.

---

## Configuration

### First-Time Setup

1. **Access the Application**: Navigate to `http://your-server:5000`
2. **Create First User**: Sign up with email and password
3. **Activate Global Admin**: The first user is automatically approved and designated as Global Administrator
4. **Configure Email Settings** (Optional):
   - Navigate to Settings → Email Configuration
   - Enter IMAP server details for automatic balance updates
   - Configure search parameters (subject line, balance delimiters)

### User Management

#### As Global Administrator
- Approve or deny new user registrations
- Activate/deactivate user accounts
- Configure system-wide email settings for notifications
- Enable/disable new user signups

#### As Account Owner
- Manage guest users for your account
- Add guest users with view-only dashboard access
- Remove guest users when access is no longer needed

---

## User Roles & Access Control

PyCashFlow implements a three-tier access control system:

### Global Administrator
- **Full System Access**: Manage all users and system settings
- **User Approval**: Activate or deactivate user accounts
- **Email Configuration**: Set up system notification emails
- **Cannot Be Deactivated**: Ensures system always has an administrator

### Account Owner
- **Full Cash Flow Management**: Create, edit, and delete schedules
- **Scenario Modeling**: Build and manage what-if scenarios for financial planning
- **Balance Management**: Manual and automated balance updates
- **Guest User Management**: Create and manage view-only users
- **Data Management**: Import/export transaction schedules
- **AI Insights**: Configure OpenAI API key, select the model version, and refresh cash flow analysis on demand

### Guest User
- **Dashboard Access Only**: View cash flow chart and current balance
- **No Editing Permissions**: Cannot modify schedules or settings
- **Requires Activation**: Must be activated by account owner before access

---

## Core Capabilities

### Cash Flow Calculation Engine

PyCashFlow's sophisticated calculation engine (`/app/cashflow.py`) provides:

- **Multi-Frequency Support**: Handles Monthly, Weekly, BiWeekly, Quarterly, Yearly, and One-Time transactions
- **Business Day Logic**: Automatically adjusts transaction dates for weekends
  - Income transactions: Rolled back to last business day
  - Expense transactions: Advanced to next business day
- **Hold Management**: Temporarily pause scheduled transactions
- **Skip Functionality**: Skip individual future instances without affecting the entire schedule
- **Running Balance Projections**: Calculate balance for every day up to 12 months ahead
- **Automatic Cleanup**: Remove past one-time transactions

### Transaction Scheduling

Create and manage recurring financial events:

- **Flexible Frequencies**: Choose from multiple recurrence patterns
- **Custom Amounts**: Set precise transaction amounts
- **Income vs Expense**: Categorize transactions for accurate projections
- **Hold Until Date**: Temporarily suspend transactions
- **Skip Future Instances**: One-time skips without schedule deletion

### Scenario Modeling

Model hypothetical "what-if" financial situations without affecting your live schedule:

- **Separate Scenario Table**: Create and manage scenarios independently from your real schedules
- **Same Frequency Support**: All six frequencies (Monthly, Weekly, BiWeekly, Quarterly, Yearly, One-Time) work identically to regular schedules, including business day adjustments
- **Dual-Line Chart**: The dashboard chart renders a solid blue line for your current schedule and a dashed amber line for schedules + scenarios, so both projections are visible simultaneously
- **Scenario Minimum Balance**: The Lowest Balance (90 days) card displays the schedule-only minimum alongside the scenario minimum in amber e.g. `$1,200 ($850)`
- **No Auto-Delete**: One-time scenarios that have passed are skipped in projection but never auto-deleted — remove them manually when no longer needed
- **Full CRUD**: Edit and delete scenarios via the Scenarios page; no holds or skips needed since scenarios are purely hypothetical

### Balance Tracking

Multiple methods for keeping your balance current:

- **Manual Entry**: Set balance for any specific date
- **Email Import**: Automatic extraction from bank notification emails
- **Plaid Balance Sync**: Connect a single bank account via Plaid Link and
  refresh today's balance on every dashboard load (see below)
- **Historical Tracking**: View balance history over time

---

## Plaid Balance Integration

PyCashFlow can refresh the current user's balance from a single connected
bank account via [Plaid](https://plaid.com). The feature is **off by default**
and is only enabled when all required environment variables are present.

### Configuration

Add to `.env`:

```bash
PLAID_CLIENT_ID=your-client-id
PLAID_SECRET=your-secret
PLAID_ENV=sandbox            # sandbox | development | production
PLAID_PRODUCTS=auth          # comma-separated; "balance" is NOT valid here
PLAID_COUNTRY_CODES=US
PLAID_REDIRECT_URI=          # required for OAuth institutions (Chase, etc.)
```

### OAuth institutions (Chase, etc.)

Some institutions (e.g. Chase) require Plaid's OAuth redirect flow. For these:

- `PLAID_REDIRECT_URI` must be set to a fully-qualified HTTPS URL pointing
  back to the PyCashFlow web settings page. Any of these forms work:
  - `https://app.example.com/settings`
  - `https://app.example.com/settings?plaid_oauth_return=1`

  Any query string and fragment are stripped before the URL is sent to
  Plaid's `/link/token/create` (Plaid's redirect_uri field does not accept
  query parameters), so the value that actually reaches Plaid is always the
  bare path, e.g. `https://app.example.com/settings`.
- In the [Plaid Dashboard](https://dashboard.plaid.com), allowlist that
  **bare** URL (without any query string). It must be an exact match,
  otherwise Plaid will refuse to redirect OAuth users back.
- On the way back, Plaid appends `oauth_state_id=...` to the URL. The
  settings page must preserve that query parameter long enough for Plaid
  Link to resume — see the next bullet.
- After the bank redirect, the settings page detects the `oauth_state_id`
  query parameter, reopens the Plaid modal automatically, and resumes Plaid
  Link using the original `link_token` (kept in `sessionStorage`/
  `localStorage`) and `window.location.href` as `receivedRedirectUri`. The
  user does not need to click Connect again. The URL is cleaned only after
  the public-token exchange completes (or Plaid Link is exited).
- iOS Plaid setup is intentionally **not** supported in this phase. Users
  must connect Plaid from the web settings page.

Get keys from the [Plaid Dashboard](https://dashboard.plaid.com). The settings
page shows **Plaid setup: configured** once all four required values are set,
or **Plaid setup: not configured** otherwise. Use the least-data Plaid product
appropriate for your account (typically `auth`); **do not** include
`transactions`.

### How the balance update works

- Settings → **Plaid Balance Sync** → **Connect Plaid Account** opens Plaid Link.
- On success, the public token is exchanged for an access token (encrypted at
  rest with `APP_SECRET`) and the selected depository account's metadata is
  stored. Only one active connection per user is allowed; remove it before
  connecting a new one.
- On every dashboard load (web `/` and `GET /api/v1/dashboard`),
  `update_plaid_balance_for_user()` calls Plaid's cached `/accounts/get`:
  - Uses `balances.available` if present.
  - Falls back to `balances.current` if available is `null`.
  - If both are `null`, the existing balance row is **not** overwritten and
    a non-sensitive status is recorded on the connection.
- The existing PyCashFlow `balance` table is the system of record. Today's
  row is upserted (one balance per day per user); no separate Plaid balance
  history is kept.
- Errors are swallowed by the dashboard call site — Plaid problems never
  break dashboard load.

### Protecting newer balances from stale cached Plaid data

`/accounts/get` returns **cached** balance data — Plaid exposes its own
freshness for that cached value via `balances.last_updated_datetime`. A
balance that PyCashFlow already obtained more recently must not be silently
overwritten by an older cached Plaid value the next time the dashboard
loads. On every cached `/accounts/get` sync, PyCashFlow compares Plaid's
stored cached freshness timestamp against three protected freshness
timestamps and skips the cached update if any of them is newer:

1. **Manual balance entry** — `user.last_manual_balance_entry_at`, set
   whenever a user successfully saves a balance through the web form
   (`POST /balance`) or the iOS API (`POST /api/v1/balance`).
2. **Email balance** — the most recent `balance_email_datetime` recorded on
   the user's `email` configuration (captured from the message `Date`
   header).
3. **Real-time refresh** — the connection's `last_realtime_balance_at`,
   written by the user-triggered `/accounts/balance/get` refresh.

The skip rules for each protected timestamp are the same:

- If the protected timestamp is **newer** than Plaid's cached freshness
  timestamp, the cached sync is skipped and the existing balance row is
  left untouched. The skip reasons are
  `skipped_cached_plaid_update_manual_newer`,
  `skipped_cached_plaid_update_email_newer`, and
  `cache_older_than_realtime` respectively.
- If Plaid's cached freshness timestamp is missing/unknown and a protected
  manual/email/real-time timestamp exists, the cached sync is skipped.
- The cached `/accounts/get` upsert proceeds only when Plaid's cached
  freshness is newer than (or equal to) **every** protected timestamp, or
  when no protected timestamp exists at all.

The comparison is purely timestamp-vs-timestamp — it does not consider the
calendar day of either side or the date of the balance row. The balance
row's date is used only as the insert/update key for today's row.

No balance source/source-timestamp columns or provenance tracking are added
— the balance table keeps storing balance values as before.
`last_manual_balance_entry_at` is a freshness timestamp on the `user` table
only; it is **not** the balance row date or the user-selected balance date.
The comparison reuses the existing Plaid freshness field
(`balances.last_updated_datetime`) that already governs the
cached-vs-email and cached-vs-real-time precedence rules.

The manual real-time `/accounts/balance/get` refresh remains user-triggered
and is **not** affected by these skip rules — it may always update today's
balance.

### Scope and non-goals

- **No transaction storage** and no Plaid Transactions product usage.
- **No raw Plaid payloads** are persisted or logged.
- **No background jobs** are added for Plaid in this phase.
- **No iOS changes** are included in this phase.
- Only **depository** (checking/savings/cash-management) accounts are accepted
  to avoid using a credit-card current balance as if it were available cash.

### Manual verification checklist

After deploying changes, verify the Plaid flow end-to-end:

- [ ] Set `PLAID_CLIENT_ID`, `PLAID_SECRET`, `PLAID_ENV`, `PLAID_PRODUCTS`,
  `PLAID_COUNTRY_CODES`, and (for OAuth) `PLAID_REDIRECT_URI`.
- [ ] Add the **bare** `PLAID_REDIRECT_URI` value (path only, no query
  string) to the Plaid Dashboard allowed redirect URIs.
- [ ] Open the web Settings page → **Plaid Balance Sync** card → **Connect
  Plaid Account**.
- [ ] Test a non-OAuth sandbox institution (e.g. "First Platypus Bank")
  and confirm the connection completes inline.
- [ ] Test an OAuth sandbox institution (e.g. Plaid's "OAuth Bank") and
  confirm the browser is redirected to Plaid, then back to PyCashFlow.
- [ ] Confirm the browser lands on `/settings?...&oauth_state_id=...`
  (the `oauth_state_id` query parameter must still be present in the URL
  bar when the page renders).
- [ ] Confirm the Plaid modal re-opens automatically with
  "Completing Plaid connection…".
- [ ] Confirm Link resumes automatically (no second click on Connect).
- [ ] Confirm `onSuccess` fires and the `public_token` is exchanged.
- [ ] Confirm the connected account row appears in the Plaid card.
- [ ] Confirm the URL is cleaned only **after** the connection completes
  (no `oauth_state_id` left over once the card shows the new account).
- [ ] Confirm no access tokens or public tokens appear in the browser
  console or server logs.
- [ ] Confirm no iOS changes are required — iOS Plaid Link is not
  supported in this phase.

### Running the migration

The integration adds a single `plaid_connections` table. The follow-on
email-balance freshness migration adds one nullable
`balance_email_datetime` column on the existing `email` table. The
manual-balance freshness migration
(`f8b1c2d3e4a5_add_last_manual_balance_entry_at_to_user`) adds one nullable
`last_manual_balance_entry_at` column on the existing `user` table — no
other schema changes.

```bash
flask db current
flask db heads
flask db migrate -m "track manual balance entry freshness"   # only during development
flask db upgrade
```

---

## REST API

PyCashFlow provides a RESTful JSON API under `/api/v1/` for programmatic access and mobile app integration. All API routes are CSRF-exempt and require Bearer token authentication.

### Authentication

#### Login

Obtain a bearer token by posting credentials to the login endpoint:

```bash
curl -X POST https://your-server/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "s3cr3t"}'
```

Response:
```json
{
  "data": {
    "token": "<bearer_token>",
    "user": {
      "id": 1,
      "email": "user@example.com",
      "name": "Jane Doe",
      "is_admin": false,
      "is_global_admin": false,
      "twofa_enabled": false,
      "is_guest": false
    }
  }
}
```

> **Note**: Accounts with two-factor authentication (2FA) enabled cannot authenticate via the API at this time.

#### Using the Token

Include the token in the `Authorization` header on all subsequent requests:

```bash
curl https://your-server/api/v1/dashboard \
  -H "Authorization: Bearer <bearer_token>"
```

Tokens are valid for **30 days**. Only the SHA-256 hash of each token is stored; the raw token is returned once at login and cannot be recovered.

#### Logout

Invalidate the current token:

```bash
curl -X POST https://your-server/api/v1/auth/logout \
  -H "Authorization: Bearer <bearer_token>"
```

#### Current User

Retrieve the authenticated user's profile:

```
GET /api/v1/auth/me
```

### Data Endpoints

All data endpoints are read-only (`GET`) and require authentication. Guest users automatically see their account owner's data.

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/dashboard` | Dashboard summary — current balance, risk score, upcoming transactions, and 90-day minimum balance |
| `GET /api/v1/balance` | Current balance snapshot (lightweight, no projection engine) |
| `GET /api/v1/schedules` | All recurring scheduled transactions |
| `GET /api/v1/transactions` | Expanded upcoming transactions for the next 90 days (with holds and skips applied) |
| `GET /api/v1/projections` | Running-balance projection data points for both schedule-only and schedule+scenario series |
| `GET /api/v1/scenarios` | All what-if scenario items |
| `GET /api/v1/holds` | All held (paused) schedule items |
| `GET /api/v1/skips` | All skipped transaction instances |
| `GET /api/v1/risk-score` | Detailed cash-flow risk assessment with full score breakdown |

### Response Format

**Success — single resource:**
```json
{ "data": { ... } }
```

**Success — collection:**
```json
{ "data": [ ... ], "meta": { "total": 5 } }
```

**Error:**
```json
{
  "error": "Human-readable message",
  "code": "machine_slug",
  "status": 401
}
```

**Validation error (422):**
```json
{
  "error": "Validation failed",
  "code": "validation_error",
  "status": 422,
  "fields": { "email": "Email is required" }
}
```

All monetary values are returned as **decimal strings** (e.g. `"1234.56"`) to avoid floating-point precision issues. Dates use **ISO 8601** format (`YYYY-MM-DD`).

---

## AI Insights

PyCashFlow supports two AI provider paths for on-demand cash flow analysis:

- **OpenAI (user-managed):** account owner stores an encrypted OpenAI API key and optional model override.
- **DigitalOcean GenAI Agent (server-managed):** optional fallback driven by server environment variables when available.

### How It Works

1. The account owner can add an OpenAI API key in **Settings → AI Insights** (optional when server-managed DigitalOcean is available)
2. User-provided keys are encrypted using Fernet symmetric encryption (same `APP_SECRET` used for email passwords) before being stored in the database
3. On refresh, provider selection follows this policy:
   - If a DigitalOcean agent is configured **and** the user has not set an explicit model, DigitalOcean is preferred
   - Otherwise, the user-configured OpenAI provider is used
4. Click **Refresh** on the dashboard/API to trigger a provider call only when the cooldown allows it
5. The AI analyzes a 90-day projection of your schedule (not scenarios) including:
   - Current balance
   - Schedule of recurring transactions (name, amount, frequency, type)
   - Lowest projected balance within 90 days
6. Results are cached in the database and displayed as color-coded insight cards
7. Refreshes are limited to one successful provider call per 2-hour window; during cooldown the cached payload is returned
8. Guest users can view cached insights but cannot trigger a refresh

### Cash Risk Score

The Cash Risk Score is a deterministic **0–100 indicator** calculated on every page refresh from your projected cash flow data — no OpenAI API key required. It is always visible as a mandatory card at the top of the AI Insights section and as an inline badge on the Lowest Balance metric card.

#### Score Categories

| Score | Status | Color |
|-------|--------|-------|
| 80–100 | Safe | Green |
| 60–79 | Stable | Blue |
| 40–59 | Watch | Yellow |
| 20–39 | Risk | Orange |
| 0–19 | Critical | Red |

#### How the Score Is Calculated

The score is a weighted composite of four factors derived from your 90-day projection:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Cash Runway** | 40% | `current_balance ÷ avg_daily_expense` — how many days the current balance can cover expenses. ≥90 days = full score; <45 days = risky. |
| **Lowest Projected Balance** | 25% | `lowest_balance ÷ avg_monthly_expense` — how the dip compares to a typical month of spending. |
| **Days Until Lowest Balance** | 20% | How far away the projected balance dip is. ≥30 days = full score; <14 days = high risk. |
| **Volatility** | 15% | `(max_balance − min_balance) ÷ current_balance` — large balance swings increase risk. |

Each factor is scored 0–100 individually, then combined into the final weighted score.

#### What Is Displayed

The mandatory cash risk card always shows:
- The numeric score and status badge in the appropriate status color
- Cash runway in days
- Days until the lowest projected balance, and the projected low amount

When an OpenAI API key is configured and insights are refreshed, the AI also generates a **Cash Risk** explanation insight as its first entry, describing the primary factors behind the score in plain language.

### Insight Types

| Type | Color | Meaning |
|------|-------|---------|
| **Cash Risk** | Indigo | Always-present AI explanation of the cash risk score and its key drivers |
| **Risk** | Red | Potential cash flow shortfalls or timing problems |
| **Pattern** | Blue | Recurring patterns in your transaction schedule |
| **Observation** | Green | General financial observations about your projection |

### Configuration

1. Obtain an API key from [platform.openai.com](https://platform.openai.com)
2. Navigate to **Settings → AI Insights → Configure API Key**
3. Enter your `sk-...` key and save
4. Optionally enter an **OpenAI Model** name (e.g. `gpt-4o`, `gpt-4o-mini`). Leave the field blank to use the default model (`gpt-4o-mini`)
5. Return to the dashboard and click **Refresh** to generate your first analysis

> **Note**: Refresh is on-demand and subject to a 2-hour cooldown. If a refresh is requested before cooldown expires, the API returns cached insights without updating the timestamp.

---

## Payments & Activation

PyCashFlow supports optional subscription enforcement for hosted deployments while remaining friendly to self-hosted installations.

### Runtime Toggle

- `PAYMENTS_ENABLED=true`: Enforces subscription checks for authenticated **non-global-admin** users
- `PAYMENTS_ENABLED=false`: Bypasses subscription checks (recommended default for self-hosted/manual operation)

### Subscription Truth Sources

When payment enforcement is enabled, activation state is driven server-side from:

- Stripe webhook events at `POST /api/v1/billing/webhook/stripe`
- App Store verification at `POST /api/v1/billing/verify-appstore`

Client-side purchase state is **not** trusted as an activation source.

### Password Setup for Payment-Created Users

For users created from payment flows (Stripe/App Store), PyCashFlow sends a one-time password setup link instead of assigning a plaintext password. This flow depends on:

- `FRONTEND_BASE_URL` (required): Base URL used to build setup links
- `PASSWORD_SETUP_TOKEN_TTL_MINUTES` (optional): Link expiration window

Setup links are generated on the fixed frontend route: `/auth/set-password/<token>`.

---

## Two-Factor Authentication (2FA)

PyCashFlow supports TOTP-based two-factor authentication to add an extra layer of security to your account.

### Enabling 2FA

1. Log in and navigate to **Settings → Two-Factor Authentication**
2. Click **Enable 2FA**
3. Scan the displayed QR code with your authenticator app:
   - Google Authenticator
   - Authy
   - Microsoft Authenticator
   - 1Password
   - Bitwarden
   - Any other TOTP-compatible app
4. If you can't scan the QR code, enter the secret key manually into your app
5. Enter the 6-digit code shown in your authenticator app to confirm setup
6. **Save your backup codes** — they are displayed once immediately after activation

### Logging In with 2FA

After entering your email and password, you will be prompted for your 6-digit TOTP code. Open your authenticator app and enter the current code to complete login.

### Backup Codes

When you enable 2FA, PyCashFlow generates **10 single-use backup codes**. Store these in a safe place. If you lose access to your authenticator app, you can use a backup code in place of the TOTP code to log in. Each backup code can only be used once.

### Disabling 2FA

1. Navigate to **Settings → Two-Factor Authentication**
2. Click **Disable 2FA**
3. Confirm with your account password and a current TOTP code (or a backup code)

### Security Details

- TOTP secrets are encrypted at rest using Fernet symmetric encryption (derived from `APP_SECRET`)
- Backup codes are hashed with scrypt before storage and consumed on first use
- A ±30-second clock skew tolerance is applied to TOTP verification
- The 2FA verification endpoint is rate-limited to prevent brute-force attacks

---

## Email Integration

### Automated Balance Updates

PyCashFlow can automatically update your account balance by reading bank notification emails.

#### Configuration Steps

1. Navigate to **Settings → Email Configuration**
2. Enter your email credentials:
   - IMAP server address
   - Email address
   - Password (stored securely)
3. Configure search parameters:
   - Email subject to search for (e.g., "Balance Alert")
   - Balance start delimiter (text before balance)
   - Balance end delimiter (text after balance)
4. Save configuration

#### How It Works

- Cron job runs every minute (Docker) or as configured (manual installation)
- Searches for emails from the past 24 hours matching your subject
- Extracts balance using your configured delimiters
- Updates your account balance automatically
- Processes all users independently (one failure doesn't affect others)

### System Notifications

PyCashFlow sends email notifications for:

- **New User Registrations**: Alerts global admin when someone signs up
- **Account Activation**: Notifies user when their account is approved

---

## Data Management

### Export Schedules

Export your transaction schedules to CSV format:

1. Navigate to **Schedule → Export**
2. Download CSV file with all scheduled transactions
3. Use for backup, analysis, or migration

### Import Schedules

Import schedules from CSV files:

1. Prepare CSV file with columns: `name`, `amount`, `frequency`, `type`, `day`
2. Navigate to **Schedule → Import**
3. Select CSV file and upload
4. Existing schedules are preserved; new entries are added

### Data Portability

All data is stored in SQLite (default) or PostgreSQL database with full export capabilities.

---

## Updates & Maintenance

### Updating Docker Installation

```bash
docker pull whahn1983/pycashflow:latest
docker stop pycashflow
docker rm pycashflow
# Run the docker run command again with your volume mounts
```

Every merged change publishes a new image tagged with its version (for example
`whahn1983/pycashflow:4.5.8`, matching GitHub release `v4.5.8`) and moves
`latest` to it. Pin a version tag instead of `latest` if you want to control
when upgrades happen.

### Updating Manual Installation

```bash
cd /path/to/pycashflow
git pull origin master
flask db upgrade
# Restart your WSGI server
```

### Database Migrations

PyCashFlow uses Flask-Migrate for database schema management:

- Migrations in `migrations/versions/` are source-controlled and are the only
  schema history used by deployments.
- Containers/startup scripts must **never** run `flask db init` or
  `flask db migrate` automatically.
- Startup may run `flask db upgrade` to apply checked-in migrations.
- For model/schema changes during development:
  1. Update models.
  2. Run `flask db migrate -m "<description>"`.
  3. Review the generated migration file in `migrations/versions/`.
  4. Run `flask db upgrade`.
  5. Commit both model changes and migration file to Git.

---

## Professional Support

<p align="center">
  <img src="https://h3consultingpartners.com/h3_full_logo.png" alt="H3 Consulting Partners Logo" width="500">
</p>

### H3 Consulting Partners LLC

For professional installation, configuration, ongoing support, and accelerated development of PyCashFlow, contact **H3 Consulting Partners LLC**.

**Services Offered:**
- Professional installation and deployment
- Custom configuration for your environment
- Integration with existing financial systems
- Feature development and customization
- Ongoing maintenance and support
- Training and documentation

**Contact Information:**
- **Email**: [bill@h3consultingpartners.com](mailto:bill@h3consultingpartners.com)
- **Website**: [https://h3consultingpartners.com](https://h3consultingpartners.com)

H3 Consulting Partners specializes in enterprise deployments, custom feature development, and ongoing support to ensure PyCashFlow meets your organization's specific needs.

---

## Licensing

This repository contains multiple components with separate licenses:

- Backend / Flask server: GNU GPLv3, as provided in the root [LICENSE](LICENSE) file.
- iOS application located in `/ios-app`: licensed separately under [`ios-app/LICENSE`](ios-app/LICENSE) and, when distributed through the Apple App Store, under Apple's Standard End User License Agreement (EULA):
  https://www.apple.com/legal/internet-services/itunes/dev/stdeula/

The root GPLv3 license applies to backend/server components and does not apply to the separately licensed iOS application in `/ios-app`.

---

## Repository

**GitHub**: [https://github.com/whahn1983/pycashflow](https://github.com/whahn1983/pycashflow)

**Docker Hub**: [https://hub.docker.com/r/whahn1983/pycashflow](https://hub.docker.com/r/whahn1983/pycashflow)


---

*PyCashFlow - Professional cash flow management and forecasting for individuals, families, and small-medium businesses.*
