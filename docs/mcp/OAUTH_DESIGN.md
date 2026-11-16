# OAuth 2.1 design

PyCashFlow is its own authorization server (AS) and resource server (RS) for
MCP clients. No external identity provider is involved: users authenticate
with their existing PyCashFlow credentials through the existing Flask login.

Implementation: `app/oauth/` on Authlib 1.9.6 (grants, PKCE, revocation,
RFC 7591, RFC 9207), with PyCashFlow policy layered on via Authlib's subclass
hooks. Registered only when `MCP_ENABLED=true`.

## Endpoints

| Endpoint | Purpose | Notes |
|---|---|---|
| `GET /.well-known/oauth-protected-resource[/mcp]` | RFC 9728 metadata | `resource=<base>/mcp`, `authorization_servers=[<base>]`, all scopes, `bearer_methods_supported=["header"]`; CORS `*` |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata | S256 only, `authorization_response_iss_parameter_supported: true`, `client_id_metadata_document_supported: true`, `token_endpoint_auth_methods_supported: ["none","client_secret_basic","client_secret_post"]`; CORS `*` |
| `POST /oauth/register` | RFC 7591 DCR | Open registration, 20/h and 100/day per IP, 16 KiB body cap, CSRF-exempt |
| `GET/POST /oauth/authorize` | Authorization + consent | Login via `/login?next=…` (password, TOTP, passkey); consent POST needs CSRF token + signed consent ticket; 30 POST/min |
| `POST /oauth/token` | Code exchange, refresh | Form-encoded, 60/min per IP, `Cache-Control: no-store`, CSRF-exempt |
| `POST /oauth/revoke` | RFC 7009 | Access token → that token; refresh token → whole grant |
| `GET /settings/connected-apps` | User management | Lists live grants and recent activity; per-grant Disconnect (CSRF) |
| `GET /.well-known/openai-apps-challenge` | OpenAI domain verification | Only when `OPENAI_APPS_CHALLENGE_TOKEN` is set |

## Authorization code flow

1. Client discovers PRM from the `401` challenge on `/mcp`, then AS metadata.
2. Client identity:
   - **CIMD** (preferred by ChatGPT and Claude): `client_id` is an HTTPS URL
     (e.g. `https://claude.ai/oauth/mcp-oauth-client-metadata`). Only hosts on
     `OAUTH_CIMD_ALLOWED_HOSTS` (default `chatgpt.com, claude.ai, claude.com`)
     are fetched. All CIMD clients are public clients (`none` + PKCE).
   - **DCR** fallback: random `pcf_dcr_…` id; public (`none`) or confidential
     (secret returned once, stored as SHA-256).
3. `GET /oauth/authorize` validates, in order: client, exact `redirect_uri`
   (required; loopback URIs match on any port), `response_type=code`, scopes
   (unknown → `invalid_scope`; `offline_access` ignored; none → all offered),
   PKCE (`code_challenge` required, method must be `S256`), `resource` (must
   equal `<base>/mcp` if sent; defaults to it), `prompt=none` →
   `consent_required`. Errors with a validated redirect URI are redirected with
   `error`, `state` and `iss`; otherwise an error page is shown — the server
   never redirects to an unvalidated URI.
4. Not signed in → `302 /login?next=<authorize URL>`; the existing login
   preserves `next` through password, TOTP and passkey flows.
5. Consent page shows: client name (and "identity published by <host>" for
   CIMD or "self-registered, unverified" for DCR), the redirect host, a
   warning for loopback clients, the signed-in account, and one checkbox per
   requested permission. Guests never see write scopes.
6. Approve → the POST must carry the CSRF token and a consent ticket
   (itsdangerous, 10 min) bound to the user and a fingerprint of client,
   redirect URI, PKCE challenge, scope, resource and state. Granted scopes =
   requested ∩ checked ∩ allowed-for-user.
7. Code (`pcf_ac_…`, 256-bit) is stored hashed with user, client, redirect
   URI, scopes, resource, PKCE challenge; expires in 5 minutes. Redirect
   carries `code`, `state`, `iss`.
8. `POST /oauth/token`: client authentication per its registered method; code
   is claimed atomically (`UPDATE … WHERE used_at IS NULL`); PKCE verifier
   required for every client; `redirect_uri` and `resource` must match the
   code; user must still pass `enforce_user_access`. A grant row is created and
   tokens issued.

## Tokens

| | Access token | Refresh token |
|---|---|---|
| Format | `pcf_at_` + 256-bit random | `pcf_rt_` + 384-bit random |
| Storage | SHA-256 hash only | SHA-256 hash only |
| Lifetime | 1 h (`OAUTH_ACCESS_TOKEN_TTL_SECONDS`) | 30 days sliding (`OAUTH_REFRESH_TOKEN_TTL_DAYS`), capped by grant max age (90 days, `OAUTH_GRANT_MAX_AGE_DAYS`) |
| Bound to | grant, user, client, scopes, resource | same |

**Refresh rotation:** every refresh claims the presented refresh token
atomically and returns a new pair. A rotated token presented again within
30 s (client retry) gets `invalid_grant`; after that it is treated as theft and
the whole grant is revoked (RFC 9700 §4.14.2). Scope can be narrowed but not
widened on refresh. Dead refresh tokens always yield `invalid_grant` (Claude's
requirement).

**Code replay:** a second redemption of a code returns `invalid_grant` and
revokes the grant created by the first redemption (and all its tokens).

## Resource server checks (`/mcp`)

`app/oauth/tokens.verify_access_token` on every request: `pcf_at_` prefix and
length → hash lookup → not revoked, not expired → `resource` equals this MCP
resource (RFC 8707 audience) → grant live (not revoked/expired) → client
active → user exists and passes `enforce_user_access` (active, subscription,
guest inherits owner). Failure → `401` with
`WWW-Authenticate: Bearer resource_metadata="…", scope="…", error="invalid_token"`.
Scopes are then checked per tool (`insufficient_scope` tool error with an RFC
6750 challenge in `_meta["mcp/www_authenticate"]`).

## Scopes

| Scope | Grants |
|---|---|
| `projections:read` | Projections, summaries, upcoming transactions, previews (with record read scopes). Implies projection maintenance commits. |
| `schedules:read` / `schedules:write` | Read / create, update, delete schedules |
| `scenarios:read` / `scenarios:write` | Read / create, update, delete scenarios |
| `holds:read` / `holds:write` | Read / create (also needs `schedules:read`), remove holds |
| `skips:read` / `skips:write` | Read / create (also needs `schedules:read` + `projections:read`), remove skips |

Guests (view-only accounts) can be granted read scopes only, and writes are
refused at runtime even if a token somehow carries write scopes.

## Client and grant isolation

- One `oauth_grants` row per approval; tokens reference it. Revoking a grant
  (Disconnect, refresh replay, code replay, client revocation of a refresh
  token) revokes only that client's tokens. ChatGPT, Claude and the iOS app are
  independent.
- Tokens are bound to `client_id`; refresh/revocation by another client fail.
- iOS/REST tokens (`user_tokens`) are never accepted at `/mcp`; OAuth tokens
  are never accepted at `/api/v1`.
- Password change (web or API) and password reset revoke all OAuth grants of
  that user. Deleting an account or removing a guest deletes all OAuth rows.

## Redirect-URI policy

Registration (DCR and CIMD documents) and every authorization request must use:

- an exact URI from `OAUTH_ALLOWED_REDIRECT_URIS` — defaults:
  `https://chatgpt.com/connector_platform_oauth_redirect`,
  `https://chatgpt.com/connector/oauth/*` (one `[A-Za-z0-9_-]` segment),
  `https://claude.ai/api/mcp/auth_callback`,
  `https://claude.com/api/mcp/auth_callback`; or
- an `http` loopback URI (`localhost`, `127.0.0.1`, `[::1]`) when
  `OAUTH_ALLOW_LOOPBACK_REDIRECTS=true` (default; Claude Code, MCP Inspector),
  matched port-agnostically (RFC 8252 §7.3).

No fragments, credentials, whitespace or custom schemes. Pinning full callback
paths means an open redirect elsewhere on those hosts cannot leak codes.

## CIMD fetch controls

Host allowlist; `https`, port 443, non-empty path, no credentials/fragment,
≤ 512 chars, no IP literals; DNS resolved once and **every** address must be
public (rejects private, loopback, link-local, CGNAT, reserved, multicast,
IPv4-mapped, NAT64, IPv4-compatible, 6to4, Teredo); connection pinned to the
checked IP with TLS verified against the hostname; no redirects; JSON content
type; ≤ 32 KiB; 5 s per operation and an 8 s watchdog for the whole fetch.
`client_id` in the document must equal the URL exactly; disallowed redirect
URIs are dropped (all dropped → rejected). Cached in `oauth_clients` for
`max-age` within [5 min, 24 h]; a stale copy (< 7 days) is used only if a
refresh fails.

## Housekeeping and abuse controls

- Rate limits (Flask-Limiter, per client IP — set `TRUSTED_PROXY_COUNT`
  correctly so `X-Forwarded-For` cannot be spoofed).
- `OAUTH_MAX_DCR_CLIENTS` (5000): at the cap, DCR clients that never completed
  an authorization within 1 hour are reclaimed before registration is refused.
- GC (≤ every 10 min per worker, from registration and token requests):
  expired codes, long-dead tokens, idempotency keys > 24 h, unused DCR clients
  > 7 days.
- Audit events for consent approve/deny, grant creation, refresh, revocation,
  replay detection and every MCP write (no secrets, names or amounts).
- Authlib log records are redacted (`pcf_at_[REDACTED]`) and Authlib is kept
  at INFO (it logs issued token dicts at DEBUG).
