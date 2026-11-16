# PyCashFlow MCP Integration — Phase 1 Architecture Assessment

Status: written before any MCP/OAuth code was added. Facts below were verified by
reading the code at commit `a7e80dd` and running the existing suite
(**710 passed** on SQLite, Python 3.13).

## 1. What actually runs today

| Concern | Verified implementation |
|---|---|
| App factory | `app/__init__.py:create_app()`; extensions `db`, `migrate`, `limiter` (memory:// by default), `csrf` (Flask-WTF, global). `ProxyFix` wraps `app.wsgi_app` when `TRUSTED_PROXY_COUNT>0` (default 1). |
| Process model | **Gunicorn 27, `gthread` worker**, `workers=1` unless a shared rate-limit store is configured, 8 threads, started by `entry.sh` as `appuser` via `su-exec` after `flask db upgrade`. AGENTS.md mentions Waitress; the container does not use it. |
| Health check | `GET /healthz` (Flask, auth-free, side-effect-free). Docker `HEALTHCHECK` calls it. |
| Background work | busybox `crond` runs `app/getemail.py` every minute (balance e-mail ingestion) when `ENABLE_CRON=true`. |
| Database | SQLAlchemy 2.1 / Flask-SQLAlchemy; SQLite by default, PostgreSQL via `DATABASE_URL` (normalised to psycopg2). Migrations are Alembic via Flask-Migrate (25 files). Tests use `db.create_all()`, not migrations. |
| Web auth | `app/auth.py`: password (scrypt) → optional TOTP / backup code step → `login_user`. Passkeys (WebAuthn) via `/passkey_login`. A safe relative `next` path (query string preserved) survives the password, 2FA and passkey legs via `session['post_login_next']`. |
| API auth | `app/api/auth_utils.py`: opaque bearer tokens (`secrets.token_urlsafe(32)`), SHA-256 hash stored in `user_tokens`, 30-day TTL, no scopes, no client binding. `@api_login_required` checks bearer first, then session; write routes use `require_bearer=True` (session fallback only with a valid CSRF header). |
| Access policy | `app/subscription.py:enforce_user_access(user)` — global admins always allowed; with `PAYMENTS_ENABLED=false` it is `user.is_active`; otherwise owner subscription/review flags decide, and guests inherit the owner. The web `before_request` hook and `@api_login_required` both call it. |
| Tenancy | Effective user = `owner_user_id or account_owner_id or id` (duplicated in `main.py:get_effective_user_id` and `api/routes/data.py:_effective_user_id`). Every data query filters by it. |
| Guest writes | REST: `_forbid_guest_writes()` rejects when `user.admin` is falsy. Web: `@admin_required`. Guests are created with `admin=False` (`main.py:add_guest`). |
| Projection engine | `app/cashflow.py:update_cash(balance, schedules, holds, skips, scenarios, commit=True)` → `calc_schedule` + `calc_transactions` (pandas). ~13-month expansion; UI/risk views use a 90-day horizon. |
| REST callers of the engine | `api/routes/data.py:_project_data()` calls `update_cash(..., commit=True)` and caches per request on `flask.g`. Used by `/dashboard`, `/projections`, `/transactions`, `/risk-score`, `POST /skips`. Web `index`, `addskip`, `transactions` also call it with the default `commit=True`. |

## 2. Projection persistence audit (`update_cash(..., commit=True)`)

`calc_schedule()` mutates **only the ORM objects passed in**, and every caller
pre-filters those lists by the effective user id. With `commit=True` it changes:

| Table | Field / action | Trigger |
|---|---|---|
| `schedule` | `firstdate` set | row has no `firstdate` |
| `schedule` | `startdate` advanced by one period (with month-end day correction) | an occurrence date `<= today` **and today is a weekday** |
| `schedule` | **row deleted** | `Onetime` schedule whose `startdate < today` |
| `scenario` | `firstdate` set / `startdate` advanced | same rules as schedules |
| `scenario` | never deleted | past one-time scenarios are only skipped |
| `skip` | **row deleted** | `skip.date < today` |
| `hold`, `balance`, `user` | not touched | — |

It calls `db.session.commit()` three times (after schedules, after scenarios,
after skips). Observations:

1. **Account isolation holds** because the function has no queries of its own;
   isolation depends entirely on callers passing user-filtered lists. Any new
   caller must keep that invariant (the MCP service layer does).
2. **Partial commits are possible**: an exception in the scenario loop leaves the
   schedule advancement committed. Each individual change is valid on its own,
   so the state stays consistent, but the call is not atomic.
3. **Concurrent deletes race**: two simultaneous projections for the same user can
   both try to delete the same expired one-time schedule or skip. The second
   flush matches 0 rows and SQLAlchemy raises `StaleDataError` (500 today).
   Date advancement is deterministic, so concurrent advancement converges.
4. `commit` also commits anything else pending in the session, so callers must
   not stage unrelated changes before projecting.

## 3. Existing-behaviour findings relevant to an external AI access path

| # | Finding | Severity for MCP | Plan |
|---|---|---|---|
| E1 | REST/web amount validation is `float(x)`: accepts `NaN`, `Infinity`, `1e308`, negatives. Non-finite or out-of-range values can corrupt projections or raise DB errors (`Numeric(10,2)` max 99,999,999.99). | High if reused by MCP | Shared validator rejects non-finite/out-of-range values for REST + MCP; MCP additionally requires `> 0`. |
| E2 | REST/web accept any `YYYY-MM-DD` start date; extreme years overflow `relativedelta` during projection (per-account DoS). | Medium | MCP restricts dates to a bounded window. |
| E3 | Guest write gate keys only on `user.admin`. | Low | MCP requires `admin` **and** not-a-guest, and filters write scopes out at consent time. |
| E4 | Hold semantics in code differ from AGENTS.md ("pause"): a hold adds the schedule's amount/type as a one-off transaction **tomorrow** (iOS demo engine does the same). | Docs | MCP tool descriptions describe the real behaviour. |
| E5 | `POST /skips` with `transaction_index` depends on volatile DataFrame indexes. | Medium for AI | MCP uses `schedule_id + occurrence_date` validated against the projection, and asks for clarification when ambiguous. |
| E6 | No duplicate protection for holds/skips. | Medium for AI retries | MCP rejects duplicates and supports idempotency keys. |
| E7 | Concurrent projection `StaleDataError` (above). | Medium | Shared projection service rolls back and retries once. |
| E8 | Web password change does not revoke API tokens. | Low (pre-existing) | Out of scope for iOS tokens; OAuth grants are revoked on any password change. |

## 4. Architecture decisions

1. **Single Flask app stays the system of record.** The OAuth 2.1 authorization
   server (metadata, DCR, CIMD, authorize + consent, token, revoke,
   connected-apps page) is a new Flask blueprint so it reuses Flask-Login,
   Flask-WTF CSRF, Flask-Limiter, templates, and the existing password / TOTP /
   passkey login flow through the existing `next` mechanism.
2. **Authlib** (maintained, RFC-complete) provides the authorization-code,
   refresh-token, PKCE, revocation, DCR and RFC 9207 machinery. PyCashFlow-specific
   policy (S256-only PKCE, resource indicators, CIMD, redirect allowlist,
   refresh rotation with replay detection, consent scope narrowing) is layered on
   through Authlib's documented subclass hooks.
3. **Official MCP Python SDK** (`mcp` 2.x, `MCPServer`, Streamable HTTP,
   `stateless_http=True`, `json_response=True`). Stateless JSON mode keeps no
   per-session server state (no cross-user session leakage) and works with
   multiple gunicorn workers. The SDK is used as a **resource server only**:
   PyCashFlow wraps it with its own bearer authentication (SDK
   `BearerAuthBackend` + audience check) because the SDK's built-in
   `AuthSettings` wiring requires every token to hold *all* required scopes
   and would make read-only connections impossible.
4. **Process model.** `MCP_ENABLED=false` (default): exactly today's gunicorn
   `gthread` WSGI command — zero runtime change. `MCP_ENABLED=true`: the same
   gunicorn binary runs its **native `asgi` worker** (gunicorn ≥ 24) serving
   `app.asgi:application`, a small dispatcher that sends `/mcp` to the MCP SDK
   Starlette app and everything else to Flask through `a2wsgi.WSGIMiddleware`.
   Rollback is a flag flip. No new process manager, container, or service.
5. **Shared service layer** (`app/services/`) owns validation, ownership-scoped
   CRUD, and the projection call (`update_cash(..., commit=True)` with the same
   inputs as REST). REST routes keep their exact responses and delegate
   validation/projection to it; MCP tools call the same functions.
6. **Separate OAuth token store** (`oauth_*` tables, prefixed opaque tokens,
   SHA-256 hashes). OAuth tokens are never accepted by `/api/v1` and iOS tokens
   are never accepted by `/mcp`. Each grant is bound to user + client + resource +
   scopes; revoking one client's grant leaves other clients and iOS untouched.
7. **No Plaid refresh from MCP.** MCP projections use the latest stored balance
   (like `GET /api/v1/projections`) and report its date, so an AI tool call never
   triggers outbound bank-API traffic.

## 5. Platform requirements verified (Nov 2026)

* MCP authorization spec `2026-07-28`: PRM (RFC 9728) MUST; AS metadata (RFC
  8414); CIMD SHOULD, DCR MAY (deprecated); PKCE S256; RFC 8707 `resource` in
  authorize + token requests and audience validation MUST; RFC 9207 `iss` SHOULD;
  refresh-token rotation MUST for public clients; exact redirect matching MUST;
  consent screen MUST show redirect host.
* ChatGPT: CIMD preferred (`client_id` `https://chatgpt.com/oauth/...client.json`),
  DCR fallback; stable redirect `https://chatgpt.com/connector_platform_oauth_redirect`
  requires `authorization_response_iss_parameter_supported: true`; per-tool
  `_meta.securitySchemes`; tool errors may carry `_meta["mcp/www_authenticate"]`.
* Claude: callback `https://claude.ai/api/mcp/auth_callback`; Claude Code uses a
  loopback redirect on any port; CIMD used only when metadata advertises
  `client_id_metadata_document_supported: true` **and** `"none"` in
  `token_endpoint_auth_methods_supported`; 401 must carry `resource_metadata`;
  `invalid_grant` on dead refresh tokens; form-encoded token endpoint; 10 s
  endpoint budget; directory requires `title` + read/destructive annotations.

## 6. Risks identified up front

* gunicorn's `asgi` worker is newer than `gthread`; it is only used when MCP is
  enabled and is covered by the Docker smoke test in both modes.
* Projection reads mutate data (by design). Tools that project are therefore
  annotated `readOnlyHint=false` and disclose the maintenance side effects, which
  means hosts may ask the user to approve them.
* Open client registration (DCR/CIMD) is required by both hosts; risk is
  contained with a redirect-host allowlist, CIMD host allowlist + SSRF controls,
  rate limits, client GC, and mandatory consent showing the redirect host.
