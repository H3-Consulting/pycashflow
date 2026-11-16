# Operations: migration, configuration, deployment, rollback

> Production deployment requires explicit approval. Nothing here has been
> deployed.

## Database migration

Revision `b7c8d9e0f1a2` (down-revision `f8b1c2d3e4a5`, the previous head) is
**additive only**: it creates six tables and indexes and alters nothing.

| Table | Contents | Sensitive data |
|---|---|---|
| `oauth_clients` | DCR registrations and cached CIMD documents | client secret **hash** only |
| `oauth_authorization_codes` | 5-minute codes with PKCE challenge, redirect URI, scope, resource | code **hash** only |
| `oauth_grants` | One row per user approval (connected app): user, client, scopes, resource, last used, expiry, revocation | — |
| `oauth_tokens` | Access/refresh pairs per grant | token **hashes** only |
| `oauth_audit_events` | Grant lifecycle and MCP write audit (ids and outcomes only) | no names/amounts |
| `mcp_idempotency_keys` | Idempotent write replays (24 h) | stored tool result (may contain record names/amounts until GC) |

`entry.sh` already runs `flask db upgrade` on start, so the container applies
it automatically. The migration was verified on SQLite and PostgreSQL 16:
upgrade → `flask db check` ("No new upgrade operations detected") → downgrade
→ upgrade. The tables are unused while MCP is disabled. Downgrade
(`flask db downgrade f8b1c2d3e4a5`) drops only these tables.

## Environment variables

All optional unless MCP is enabled. Set them in the container environment or
`/app/app/.env` like the existing variables.

| Variable | Default | Purpose |
|---|---|---|
| `MCP_ENABLED` | `false` | Master switch. `true` registers the OAuth endpoints and makes `entry.sh` start the ASGI server with `/mcp`. |
| `MCP_PUBLIC_BASE_URL` | falls back to `FRONTEND_BASE_URL` | Public origin, e.g. `https://app.pycashflow.com`. Issuer = this; resource = this + `/mcp`. Must be `https` (http only for localhost), no path/query. If missing or invalid, MCP stays disabled and an error is logged. |
| `MCP_ALLOWED_HOSTS` | public host | Extra `Host` header values accepted on `/mcp` (DNS-rebinding protection), e.g. when a proxy rewrites `Host`. |
| `MCP_ALLOWED_ORIGINS` | public origin, `https://chatgpt.com`, `https://claude.ai`, `https://claude.com` | Extra allowed `Origin` values on `/mcp` (absent Origin is allowed). |
| `MCP_RATE_LIMIT` | `120/minute;2000/hour` | Per user + client on `/mcp`; uses `RATELIMIT_STORAGE_URI`; empty disables. |
| `OAUTH_ALLOWED_REDIRECT_URIS` | ChatGPT + Claude callbacks (see OAUTH_DESIGN.md) | Comma-separated exact URIs; `…/*` admits one path segment. |
| `OAUTH_ALLOW_LOOPBACK_REDIRECTS` | `true` | Allow `http://localhost|127.0.0.1|[::1]` redirects (Claude Code, MCP Inspector). |
| `OAUTH_DCR_ENABLED` | `true` | Dynamic client registration. |
| `OAUTH_CIMD_ENABLED` | `true` | Client ID Metadata Documents (requires outbound HTTPS to the allowed hosts). |
| `OAUTH_CIMD_ALLOWED_HOSTS` | `chatgpt.com,claude.ai,claude.com` | Hosts whose metadata documents may be fetched; `*` = any public host. |
| `OAUTH_ACCESS_TOKEN_TTL_SECONDS` | `3600` | Access-token lifetime (min 60). |
| `OAUTH_REFRESH_TOKEN_TTL_DAYS` | `30` | Sliding refresh-token lifetime. |
| `OAUTH_GRANT_MAX_AGE_DAYS` | `90` | Absolute lifetime of a connection; `0` = no limit. Users reconnect after it. |
| `OAUTH_MAX_DCR_CLIENTS` | `5000` | Cap on dynamically registered clients. |
| `OPENAI_APPS_CHALLENGE_TOKEN` | — | OpenAI portal domain-verification token, served at `/.well-known/openai-apps-challenge`. |

Existing variables that matter: `SECRET_KEY` (signs consent tickets and
sessions; must be stable), `TRUSTED_PROXY_COUNT` (must equal the number of
proxies in front of the app so per-IP limits on `/oauth/*` cannot be spoofed),
`RATELIMIT_STORAGE_URI` (shared limits across workers), `GUNICORN_WORKERS`,
`GUNICORN_THREADS` (Flask thread-pool size under the ASGI worker),
`GUNICORN_TIMEOUT`, `SESSION_COOKIE_SECURE`.

## Runtime and startup

- `MCP_ENABLED=false`: `entry.sh` runs the **unchanged** command
  (`gunicorn --worker-class gthread … 'app:create_app()'`). No OAuth/MCP
  route exists; `/.well-known/oauth-authorization-server` is 404.
- `MCP_ENABLED=true`: `gunicorn --worker-class asgi --asgi-lifespan on …
  'app.asgi:create_asgi_app()'`. Same port 5000, same `appuser`, same
  migrations, cron and `/healthz` (Docker `HEALTHCHECK` unchanged). Flask
  requests run in an `a2wsgi` thread pool of `GUNICORN_THREADS`; MCP tool calls
  run in a bounded worker pool (8) with their own Flask app context. The
  lifespan protocol starts/stops the MCP SDK session manager. The log line
  `Starting Gunicorn (ASGI, MCP enabled)` confirms the mode.
- Stateless MCP: any worker can serve any request; no sticky sessions needed.
  Multi-worker deployments should set `RATELIMIT_STORAGE_URI` (as today).
- Outbound network: only CIMD fetches to the allowlisted hosts (HTTPS 443).
  If egress is blocked, set `OAUTH_CIMD_ENABLED=false` so clients use DCR.

## Reverse proxy

The MCP endpoint is plain HTTPS POST with JSON responses (no SSE streams,
no WebSockets), so no special proxy configuration is needed beyond:

- Route `/mcp`, `/oauth/*` and `/.well-known/*` to the app like every other
  path (no path stripping; the app must be served at the origin root).
- Preserve the `Host` header (or list the rewritten value in
  `MCP_ALLOWED_HOSTS`) and the `Authorization` header.
- Send `X-Forwarded-For`/`X-Forwarded-Proto`/`X-Forwarded-Host` and set
  `TRUSTED_PROXY_COUNT` to the number of proxies.
- Do not cache `/oauth/*`, `/mcp` or `/settings/connected-apps`.
- Allow request bodies of at least 256 KiB on `/mcp` (the app caps there).
- Claude requires the OAuth endpoints to answer within 10 s (refresh 30 s)
  from Anthropic's egress range `160.79.104.0/21`; do not block it with a WAF.

## Deployment procedure (when approved)

1. Merge; CI must pass (tests on 3.11/3.15 × SQLite/PostgreSQL, Docker smoke
   tests including the MCP-enabled variants).
2. Deploy the new image with `MCP_ENABLED` **unset/false** first. Verify the
   migration ran (`flask db current` = `b7c8d9e0f1a2`), `/healthz`, login,
   dashboard, iOS app.
3. Update the privacy policy for AI-assistant connections.
4. Set `MCP_ENABLED=true` and `MCP_PUBLIC_BASE_URL=https://<host>`; restart.
   Check: `GET /.well-known/oauth-protected-resource/mcp` returns
   `"resource": "https://<host>/mcp"`; `POST /mcp` without a token returns
   `401` with `resource_metadata`; logs show the ASGI start line.
5. Connect from Claude (custom connector) and ChatGPT (developer mode) with a
   test account; run the review test prompts; check Settings → Connected apps.
6. Only then proceed to directory submission (separately approved).

## Rollback

| Situation | Action | Effect |
|---|---|---|
| Any MCP/OAuth problem | Set `MCP_ENABLED=false`, restart | Back to the previous `gthread` server and code paths; `/mcp` and `/oauth/*` disappear; existing OAuth tokens are unusable. Web/iOS unaffected. |
| Revoke all AI access immediately | `MCP_ENABLED=false`, or `UPDATE oauth_grants SET revoked_at = now() WHERE revoked_at IS NULL` | All connections must be re-approved later. |
| Revert the release | Redeploy the previous image tag with `MCP_ENABLED=false` | The extra tables are ignored by the old code; no data migration needed. |
| Remove the tables | `flask db downgrade f8b1c2d3e4a5` (after reverting) | Drops only the six new tables. |

Note: the shared service refactor of `/api/v1` data routes and the stricter
amount validation (NaN/Infinity rejected) ship regardless of `MCP_ENABLED`;
rolling those back requires the previous image.
