# Testing: local instructions, automated test report, regression results

## Running locally

```bash
pip install -r requirements-dev.txt -c constraints.txt
python -m pytest -q                                   # SQLite, MCP enabled (default in tests)
TEST_DATABASE_URL=postgresql://test:test@localhost:5432/pycashflow_test python -m pytest -q
MCP_ENABLED=false python -m pytest -q                 # default production config; MCP tests skip
python -m pytest -q tests/mcp_integration             # only OAuth/MCP tests
```

- `tests/conftest.py` sets `MCP_ENABLED=true` and
  `MCP_PUBLIC_BASE_URL=http://localhost` for the shared test app (both
  overridable), so the original suite also proves non-interference.
- Concurrency tests that need real row locks run only on PostgreSQL (6 tests,
  skipped on SQLite).
- `tests/mcp_integration/test_mcp_e2e_server.py` starts a real
  `gunicorn --worker-class asgi` process on a free port with a freshly
  migrated SQLite file (needs `gunicorn` installed; ~8 s).
- Docker: `docker build -t pycashflow:local .` then
  `SMOKE_MCP=true .github/scripts/docker-smoke-test.sh pycashflow:local`
  (add `SMOKE_DB=postgres` for PostgreSQL).

### Trying it by hand

```bash
export SECRET_KEY=dev-secret-key-0123456789abcdef0123 APP_SECRET=dev-app-secret-0123456789abcdef
export SESSION_COOKIE_SECURE=false TRUSTED_PROXY_COUNT=0
export MCP_ENABLED=true MCP_PUBLIC_BASE_URL=http://localhost:5000
export BOOTSTRAP_ADMIN_EMAIL=admin@example.com BOOTSTRAP_ADMIN_PASSWORD='Change-me-123'
flask --app app db upgrade
gunicorn --worker-class asgi --asgi-lifespan on -b 127.0.0.1:5000 'app.asgi:create_asgi_app()'
npx @modelcontextprotocol/inspector   # Streamable HTTP → http://localhost:5000/mcp → Auth
```

The Inspector's OAuth flow uses a loopback redirect (allowed by default).
ChatGPT and Claude need a public HTTPS URL (e.g. a staging host).

## Automated test report (executed Nov 16 2026)

| Suite | Tests | What it covers |
|---|---|---|
| Pre-existing suite (21 files) | 710 | Web routes, REST/iOS API, auth, passkeys, billing, Plaid, projection engine, risk score, imports — unchanged |
| `tests/test_services.py` | 73 | Shared validators (REST-compatible and strict), REST NaN/Infinity rejection, persistent projection pipeline (commit=True deletes expired items, own-account only), race retry, upcoming-occurrence labelling equals engine output, CRUD isolation, partial updates, etags, holds/skips |
| `test_oauth_flow.py` | 99 | Discovery; DCR (public/confidential, redirect policy, sanitising); authorize with password, TOTP and passkey login hand-off; consent narrowing, deny, guest scope withholding, ticket binding, CSRF, framing; invalid client/redirect never redirects; PKCE/resource/scope/prompt errors; token endpoint (verifier, client binding, redirect/resource match, expiry, code replay revokes grant, confidential auth); refresh rotation + reuse grace + theft revocation, scope narrowing/escalation, deactivated user, grant expiry; revocation; password change revokes; connected-apps isolation (ChatGPT vs Claude vs iOS); CIMD flows, caching, stale-if-error, URL validation, private-address refusal; GC; client cap |
| `test_mcp_endpoint.py` | 34 | 401 challenge format, all HTTP methods, malformed headers, query-string tokens ignored, iOS token rejected at `/mcp`, OAuth token rejected at `/api/v1`, expired/foreign-audience/revoked/expired-grant/disabled-client/deactivated/deleted users, expired subscription for owner and guest, Host/Origin validation, body limit, stateless (no session id), rate limiting per user+client |
| `test_mcp_tools.py` | 91 | Catalogue and annotations; scope matrix for every tool (24 cases); IDOR on every id-taking tool (13 cases); injected user ids ignored; guests (incl. mis-flagged admin guest) cannot write; schedule CRUD, validation (NaN, negative, decimals, control chars, `(SKIP)`, dates, past one-time), schema violations, prompt-injection names returned as data, partial update, etag conflicts, confirm-required delete, DB failure rollback + audit; scenarios; holds/skips lifecycle and projection effect; previews persist nothing and `apply_with` works; idempotency (replay, conflict, release on failure, per-user scope) |
| `test_mcp_projections.py` | 17 | Every projection tool uses `commit=True`; maintenance persisted; other accounts untouched; changes via REST visible on next MCP call; parity with `/api/v1/projections`, `/dashboard` (min balance, risk score) and `/transactions`; window validation; shortfalls; stale balance notes |
| `test_mcp_concurrency.py` | 7 | Concurrent projections converge; identical creates → one record; concurrent holds → one; same-etag updates → one wins; concurrent deletes → one; concurrent idempotent tool calls; rollback after a failed commit |
| `test_mcp_feature_flag_and_hygiene.py` | 19 | Disabled flag registers no OAuth/MCP routes and ASGI serves Flask only; enabled without base URL fails closed while the app runs; base-URL validation; no secrets in logs or DB; audit rows contain no names/amounts; registration size limit; Authlib redaction; OpenAI domain-verification route |
| `test_mcp_review_regressions.py` | 46 | Regression tests for every independent-review finding (guest removal, scope leakage, post-commit failures, `/mcp/` handling, redirect pinning, CIMD hardening, client-cap reclaim), the Codex PR-review findings (stale-start coverage invariant for quarterly/monthly/weekly items, settled projections, REST stays single-pass, returned etags match the stored row), and the consent hand-off under the enforced `form-action 'self'` CSP (continue page instead of a cross-origin 302, for Allow and Deny, markup-safe, CSP unchanged) |
| `test_mcp_e2e_server.py` | 1 | Real gunicorn ASGI server: discovery, DCR, login form + consent form with CSRF, PKCE exchange, MCP initialize/list/create/summary/insufficient-scope over Streamable HTTP with the official SDK client, refresh rotation, web dashboard/settings/connected apps, REST login/schedules/dashboard, token-type separation |
| `tests/test_chatgpt_package.py` | 5 | ChatGPT package builder: exit status 3 and no ZIP while placeholders remain, dry runs, reproducible ZIP with only manifest/asset/skill files, invalid package exits 1, listing URLs point at the public support/privacy/terms pages |
| **Total** | **1,102** | |

## Regression results

| Environment | Result |
|---|---|
| Python 3.13.18, SQLite, MCP enabled | 1096 passed, 6 skipped (PostgreSQL-only concurrency tests) |
| Python 3.13.18, PostgreSQL 16, MCP enabled | **1102 passed** |
| Python 3.13.18, SQLite, MCP disabled | 802 passed, 300 skipped (MCP tests skip themselves) |
| Python 3.13.18, PostgreSQL 16, MCP disabled | 802 passed, 295 skipped (before the consent hand-off fix) |
| Chromium (Playwright), local server with CSP enforced: login → consent → Allow / Deny / JavaScript off / onward redirect from the callback | callback reached, no CSP violations (before the fix: Allow stayed on the consent page with a `form-action` violation) |
| Python 3.13.18, pre-existing 710 tests only, MCP enabled | **710 passed** |
| Python 3.11.18 (documented minimum), SQLite | 1080 passed, 6 skipped (before the Codex review fixes) |
| Python 3.15.1, inside the built Alpine production image, SQLite | 1080 passed, 6 skipped (before the Codex review fixes) |
| GitHub Actions CI on the PR (3.11/3.15 × SQLite/PostgreSQL, Docker smoke incl. MCP variants) | all green on `eab15ff` and `e0b1287` |
| `chatgpt-package.yml` build step, run locally with and without the demo-URL placeholder | warns and builds nothing / builds the ZIP and writes the run summary |
| Docker smoke test, SQLite, MCP disabled (gthread) | passed (no OAuth metadata exposed) |
| Docker smoke test, SQLite, MCP enabled (ASGI) | passed (ASGI start, discovery, `/mcp` 401 challenge, login, dashboard, settings) |
| Docker smoke test, PostgreSQL 17, MCP disabled | passed |
| Docker smoke test, PostgreSQL 17, MCP enabled | passed |
| Migration `b7c8d9e0f1a2` on SQLite and PostgreSQL 16 | upgrade, `flask db check` clean, downgrade, upgrade |
| pyflakes (new code) | clean |
| bandit (new code) | 0 medium/high; 5 low B105 false positives |
| pip-audit (`requirements.txt`) | no known vulnerabilities |

## Not executed locally (needs external platforms)

- Connecting from ChatGPT (developer mode) and Claude (custom connector /
  Claude Code) against a public HTTPS deployment; real CIMD fetches from
  `chatgpt.com`/`claude.ai` from the server (unit-tested with fakes; the
  documents were fetched from this sandbox to confirm their contents).
- OpenAI portal validation of the plugin ZIP beyond the published JSON Schemas
  (OpenAI-specific `extensions.com.openai` checks run only in the portal), the
  portal tool scan, and domain verification.
- Claude directory portal sync and review.
- Behaviour behind the production reverse proxy (emulated by Host/Origin and
  ProxyFix tests and the Docker smoke test).
