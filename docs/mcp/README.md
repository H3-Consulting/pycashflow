# PyCashFlow MCP integration (ChatGPT and Claude)

One shared Model Context Protocol server lets ChatGPT and Claude read cash-flow
projections and manage schedules, scenarios, holds and skips for a signed-in
PyCashFlow user. It runs inside the existing Flask app and Docker container,
uses the existing database and login (password, TOTP, passkeys), and is
**disabled by default** (`MCP_ENABLED=false`).

## Documents

| Deliverable | Where |
|---|---|
| Phase 1 architecture assessment | [01-ARCHITECTURE_ASSESSMENT.md](01-ARCHITECTURE_ASSESSMENT.md) |
| Architecture & implementation summary, file list | this page |
| MCP tool catalog | [TOOL_CATALOG.md](TOOL_CATALOG.md) |
| OAuth design | [OAUTH_DESIGN.md](OAUTH_DESIGN.md) |
| Database migration, environment variables, deployment, reverse proxy, rollback | [OPERATIONS.md](OPERATIONS.md) |
| Local testing, automated test report, regression results | [TESTING.md](TESTING.md) |
| ChatGPT connection & submission guide | [../../plugins/chatgpt/README.md](../../plugins/chatgpt/README.md) |
| Claude connection & submission guide | [CLAUDE_CONNECTOR.md](CLAUDE_CONNECTOR.md) |
| Threat model, security findings & remediation, residual risks | [SECURITY.md](SECURITY.md) |
| Final report and production-readiness assessment | [FINAL_REPORT.md](FINAL_REPORT.md) |

## Architecture

```
                      HTTPS (existing hostname, existing reverse proxy)
                                      │
                         gunicorn (one container, same image)
              MCP_ENABLED=false: gthread worker → app:create_app()   (unchanged)
              MCP_ENABLED=true:  asgi worker    → app.asgi:create_asgi_app()
                                      │
                         app/asgi.py PathDispatcher
               ┌──────────────────────┴───────────────────────┐
         path == /mcp                                  everything else
               │                                              │
   app/mcp/auth.py McpAuthMiddleware              a2wsgi.WSGIMiddleware
   (bearer → Principal, 401 challenge,            (thread pool, GUNICORN_THREADS)
    per user+client rate limit)                               │
               │                                     Flask app (unchanged routes)
   MCP Python SDK 2.3 Streamable HTTP             ├─ web UI, /api/v1 (iOS), /healthz
   (stateless, JSON responses,                    └─ app/oauth (only if MCP enabled):
    Host/Origin checks, 256 KiB body cap)            metadata, DCR, CIMD, authorize +
               │                                     consent, token, revoke,
   app/mcp/runtime.py ToolRunner                     connected-apps page
   (scopes, guest rule, Flask app context,
    idempotency, audit, structured errors)
               │
   app/services/* (shared with REST)  ──► app/cashflow.update_cash(..., commit=True)
               │
          existing database (SQLite or PostgreSQL) + 6 new oauth_/mcp_ tables
```

Key properties:

- **Same calculation pipeline.** Every projection path (REST, web, MCP) calls
  `update_cash(..., commit=True)` through `app/services/projections.run_projection`
  with inputs filtered by the authenticated account. Previews evaluate the
  engine on detached copies with `commit=False`, after the normal persistent
  run has established the baseline.
- **Identity only from the token.** Tools never accept user/owner/account ids;
  the principal (user, effective account, client, grant, scopes) comes from the
  validated OAuth access token.
- **Separate credentials.** OAuth tokens live in `oauth_tokens`, are prefixed
  (`pcf_at_`, `pcf_rt_`), hashed, bound to client + grant + resource + scopes,
  and are not accepted by `/api/v1`; iOS tokens are not accepted by `/mcp`.
- **No new infrastructure.** No extra container, database, identity provider
  or hosting service; three pinned Python dependencies (`mcp`, `Authlib`,
  `a2wsgi`).

## Implementation summary

| Area | What was built |
|---|---|
| Shared services (`app/services`) | Tenant/write rules, REST-compatible and strict validators, persistent projection pipeline with race retry, analysis helpers, ownership-scoped CRUD with row locks, etags, duplicate detection, validated skip occurrences. REST data routes now delegate to it with unchanged responses. |
| OAuth AS (`app/oauth`) | Authlib server: authorization code + mandatory S256 PKCE, refresh rotation with reuse detection, revocation, DCR, CIMD with SSRF controls, RFC 8707 resource binding, RFC 9207 `iss`, consent with scope narrowing, connected-apps page, audit trail, GC, log redaction. |
| MCP server (`app/mcp`) | 20 tools (6 read-only, 4 projection/preview, 10 write), typed output schemas, per-tool scopes and `securitySchemes`, idempotency keys, structured errors, server instructions. |
| Runtime (`app/asgi.py`, `entry.sh`) | Path dispatcher; gunicorn ASGI worker only when enabled; lifespan starts the SDK session manager. |
| Data | Migration `b7c8d9e0f1a2` adds `oauth_clients`, `oauth_authorization_codes`, `oauth_grants`, `oauth_tokens`, `oauth_audit_events`, `mcp_idempotency_keys`. |
| Tests | 376 new tests (73 service, 303 OAuth/MCP incl. a real gunicorn end-to-end run); Docker smoke tests for MCP on/off on SQLite and PostgreSQL. |

## Files added or modified

Added:

- `app/services/{__init__,access,errors,validation,projections,records}.py`
- `app/oauth/{__init__,config,scopes,security,cimd,server,tokens,audit,routes}.py`
- `app/mcp/{__init__,auth,runtime,schemas,server}.py`,
  `app/mcp/tools/{__init__,common,projections,items,holds_skips,preview}.py`
- `app/asgi.py`
- `app/templates/{oauth_consent,oauth_error,connected_apps}.html`
- `migrations/versions/b7c8d9e0f1a2_add_oauth_and_mcp_tables.py`
- `plugins/chatgpt/{README.md,plugin.json,mcp.json,build_package.py,skills/get-started/SKILL.md,assets/icon.png,assets/logo.png}`
- `.github/workflows/chatgpt-package.yml` (builds the ChatGPT ZIP on merge), `tests/test_chatgpt_package.py`
- `docs/mcp/*.md`
- `tests/test_services.py`, `tests/mcp_integration/*`

Modified:

| File | Change |
|---|---|
| `app/__init__.py` | Reads MCP/OAuth env; registers the OAuth blueprint only when `MCP_ENABLED`; a misconfiguration disables MCP instead of failing startup |
| `app/models.py` | Six new models (additive) |
| `app/api/routes/data.py` | Delegates tenant rule, validation and projection to `app/services` (same responses); rejects NaN/Infinity/out-of-range amounts |
| `app/api/routes/auth.py`, `app/auth.py`, `app/main.py` | Password change/reset revokes OAuth grants; account and guest deletion remove OAuth rows; `remove_guest` now deletes all FK-linked rows |
| `app/templates/settings*.html` | "Connected apps" card when MCP is enabled |
| `entry.sh` | ASGI worker when `MCP_ENABLED=true`; otherwise the unchanged command |
| `requirements.txt` | `Authlib==1.9.6`, `mcp==2.3.0`, `a2wsgi==1.10.10` |
| `.github/scripts/docker-smoke-test.sh`, `.github/workflows/{ci,release}.yml` | MCP-enabled smoke variants |
| `tests/conftest.py` | Test app runs with MCP enabled (override with `MCP_ENABLED=false`) |
| `AGENTS.md`, `README.md` | MCP section and pointers |
