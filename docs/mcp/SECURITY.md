# Security: threat model, findings and remediation, residual risks

Scope: the new external access path (OAuth AS, MCP server, ASGI composition)
and the existing code it reuses (login, subscription enforcement, tenant
resolution, REST data routes, projection engine). Method: design review,
implementation review, an independent adversarial review by a second agent
(probing the running app), automated tests for every finding, static analysis
(pyflakes, bandit) and dependency audit (pip-audit).

## Assets and trust boundaries

Assets: users' financial records (schedules, scenarios, holds, skips,
balances, projections); credentials (passwords, TOTP secrets, passkeys, OAuth
codes/tokens, client secrets); account integrity (owner/guest relationships,
subscription status).

```
Internet ── ChatGPT / Claude / other MCP clients (untrusted)
   │  OAuth: /.well-known/*, /oauth/register, /oauth/token, /oauth/revoke  (no cookies)
   │  MCP:   /mcp  (Bearer token)
User's browser (trusted user, untrusted network)
   │  /login (password/TOTP/passkey), /oauth/authorize consent (session + CSRF)
PyCashFlow container ── DB (trusted) ── outbound HTTPS only to CIMD hosts
```

The language model is treated as untrusted: tool arguments are validated, the
model cannot choose the account, and stored text is returned as data.

## Threat model (STRIDE summary)

| Threat | Vector | Controls |
|---|---|---|
| Spoofing a client | DCR with a lookalike name; fake CIMD | Consent shows verified host (CIMD) or "self-registered, unverified"; redirect allowlist pinned to exact ChatGPT/Claude callbacks; CIMD host allowlist; consent always required |
| Spoofing a user | Stolen code / token | PKCE S256 for all clients; 5-min single-use codes; code replay revokes grant; tokens hashed, short-lived, audience-bound |
| Tampering | Scope escalation at consent, token or refresh | Granted ⊆ requested ∩ checked ∩ allowed-for-user; signed consent ticket; refresh can only narrow |
| Tampering | Cross-account writes (IDOR) | Every query filtered by token's effective account; ids from other accounts → `not_found` |
| Tampering | Guest write escalation | Write scopes withheld at consent; runtime `can_write` = `admin` and not a guest |
| Repudiation | Disputed AI-initiated change | Audit event per write attempt (user, client, grant, action, resource, outcome, correlation id) + connected-apps activity view |
| Information disclosure | Token/secret leakage | Hashes only; prefixed tokens; no tokens in URLs; Authlib log redaction; no trace ids in tool results |
| Information disclosure | Over-broad responses | Per-tool scopes incl. `schedules:read` wherever schedule data is revealed; bounded windows; no internal ids beyond record ids/etags |
| Denial of service | Registration flooding, CIMD slow-drip, large bodies, tool spam | Per-IP limits, client cap with reclaim, GC; CIMD allowlist + 8 s watchdog + 32 KiB; 256 KiB MCP body cap; per user+client rate limit; bounded worker pools |
| Elevation of privilege | Token confusion between REST and MCP | Separate tables/prefixes; each verifier only accepts its own tokens |
| MCP-specific | Prompt injection via record names | Names validated (no control/format chars), returned as JSON data; server instructions say not to follow stored text; no tool can act across accounts or move money; writes need host approval (destructive annotations) |
| MCP-specific | Confused deputy / token passthrough | The server never calls third-party APIs with the client's token; Plaid is not reachable from MCP |
| MCP-specific | DNS rebinding / foreign Host | SDK transport security: `Host` allowlist, `Origin` allowlist |
| MCP-specific | Session/context leakage | Stateless mode; principal attached per request; each tool call gets its own Flask app context/DB session |
| SSRF | CIMD `client_id` URL | Host allowlist, public-IP check of every resolved address (incl. NAT64/6to4/Teredo/mapped), IP pinning, no redirects |

## Findings and remediation

Severity reflects impact on this deployment. "Verified" means an automated
test reproduces the attack and now passes.

| # | Severity | Finding | Remediation | Status |
|---|---|---|---|---|
| F1 | **High** | Removing a guest (`/remove_guest`) deleted only password-setup tokens. A removed guest's OAuth grants/tokens survived; on SQLite a reused user id could then read another user's data with the old token; on PostgreSQL the FK made guest removal fail (guest kept access). (Found by independent review.) | `remove_guest` deletes every FK-linked row via `_delete_user_owned_rows` (OAuth, API tokens, passkeys, …) | Fixed, verified (`test_remove_guest_deletes_oauth_rows_and_kills_tokens`) |
| F2 | **High** | REST/web amount validation (`float(x)`) accepted `NaN`, `Infinity`, `1e308`, booleans — corrupt projections or DB errors; the same validator would have been reused by MCP. (Pre-existing.) | Shared validator rejects non-finite/out-of-range values (REST messages unchanged otherwise); MCP uses strict positive 2-decimal parsing | Fixed, verified (`TestRestRejectsNonFiniteAmounts`, `TestStrictParsers`) |
| F3 | **High** | Authlib logs the full issued token dict (access + refresh token) at DEBUG; enabling debug logging would leak credentials. | Redaction filter on Authlib loggers + Authlib capped at INFO | Fixed, verified (`test_tokens_codes_and_secrets_never_logged_or_stored_raw`, `test_redaction_filter_scrubs_authlib_debug_output`) |
| F4 | **Medium** | `update_schedule`/`update_scenario` committed before the past-one-time check; the tool reported an error while the row (later auto-deleted by maintenance) was saved — a delete bypassing `confirm`/etag. (Found by tests and review.) | Rule enforced inside `records.update_item`/`create_item` before commit | Fixed, verified (`test_update_to_past_onetime_rejected_and_rolled_back`) |
| F5 | **Medium** | `create_hold` / `create_skip` / `preview_change(create_hold|create_skip)` revealed schedule names, amounts and dates to tokens lacking `schedules:read`; `create_skip` ran projection maintenance without `projections:read`. | Scopes extended (`schedules:read`, `projections:read`) | Fixed, verified (`TestScopeLeakage`) |
| F6 | **Medium** | Redirect allowlist matched whole hosts (any path on chatgpt.com/claude.ai); an open redirect there would leak codes. | Exact callback URIs (+ one-segment ChatGPT pattern) | Fixed, verified (`TestRedirectAllowlist`) |
| F7 | **Medium** | Concurrent projections raced on deleting the same expired row → `StaleDataError` (500). (Pre-existing in REST/web.) | `run_projection` rolls back and retries once (maintenance is deterministic) | Fixed, verified (`test_retries_once_after_concurrent_maintenance_race`, `test_concurrent_projections_converge` on PostgreSQL) |
| F8 | **Medium** | Holds/skips have no uniqueness; concurrent or retried creates could double-apply. | Duplicate detection, row lock on the schedule, per-account write lock, idempotency keys | Fixed, verified (`test_concurrent_holds_on_same_schedule`, idempotency tests) |
| F9 | Low–Medium | DCR flooding could exhaust the client cap and block new connections. | Reclaim never-authorized clients (> 1 h) at the cap; GC; per-IP limits | Mitigated (`test_registration_cap_reclaims_abandoned_clients`); depends on correct `TRUSTED_PROXY_COUNT` |
| F10 | Low | CIMD fetch had only per-operation timeouts (slow-drip) and accepted NAT64/IPv4-compatible addresses. | 8 s watchdog; extra address checks | Fixed, verified (`TestCimdHardening`) |
| F11 | Low | `/mcp/` was answered by an SDK redirect built from the client `Host` header. | Path normalised to `/mcp` before dispatch | Fixed, verified (`TestPathNormalisation`) |
| F12 | Low | A failure computing the post-change summary after a committed write was reported as "no change saved", and deleted the idempotency record. | Summary failures are logged and the write result returned | Fixed, verified (`test_summary_failure_does_not_misreport_committed_write`) |
| F13 | Low | Name containing `(SKIP)` would hide a real schedule from upcoming-transaction lists. (Pre-existing engine quirk.) | Rejected for MCP-created names | Fixed for MCP; REST/web unchanged |
| F14 | Low | Web password change does not revoke iOS API tokens. (Pre-existing.) | OAuth grants are now revoked on password change/reset; iOS behaviour unchanged | Partially addressed (residual R5) |
| F15 | Info | AGENTS.md describes holds as "pausing"; the engine applies a hold as an extra transaction tomorrow. | MCP descriptions document the real behaviour | Documented |
| F16 | Info | Tool results contained correlation ids (OpenAI data-minimisation rule). | Removed from results; kept in audit log | Fixed |
| F17 | Info | `entry.sh` would not have served `/mcp` with MCP enabled. | ASGI command when enabled; smoke test checks it | Fixed, verified in Docker |
| F18 | Medium (availability) | Found in production testing (Claude for iOS): clicking Allow did nothing. The enforced CSP `form-action 'self'` made browsers drop the cross-origin 302 from the consent POST to the client's callback. | The POST answers with a page that navigates to the callback; the CSP is unchanged | Fixed, verified in Chromium with CSP enforced (`TestConsentHandoffUnderFormActionCsp`) |

No critical findings. All high-severity findings are fixed and covered by
tests.

## Checked and found sound

PKCE (S256 mandatory, verifier required for all clients); atomic single-use
codes with replay revocation; atomic refresh rotation with reuse detection;
exact redirect matching (port-agnostic only for loopback); errors never
redirect to unvalidated URIs; RFC 8707 binding at authorize, token and RS;
RFC 9207 `iss` on success and error redirects; consent ticket bound to user and
request + CSRF + `X-Frame-Options: DENY`; `next` handling cannot open-redirect
(Werkzeug encodes `/\evil.com`); REST and OAuth tokens mutually rejected;
principal derived only from the token; every tool scope-checked; per-request
principal isolation (gunicorn ASGI copies `scope["state"]` per request; tools
read the request bound to the call); previews persist nothing; account,
subscription and guest status re-checked on every MCP request and refresh.

Static analysis: pyflakes clean; bandit — 0 medium/high, 5 low B105 false
positives (string constants such as `"pcf_at_"` and `"none"`). pip-audit: no
known vulnerabilities in the resolved requirements (Nov 2026). Container: the
app still runs as the non-root `appuser` in both modes.

## Residual risks

| # | Risk | Notes |
|---|---|---|
| R1 | Projection reads mutate data (by design). A guest's or read-only connection's projection call deletes expired one-time items/past skips, exactly like opening the dashboard. | Required behaviour; disclosed in annotations, descriptions, consent text. Hosts will ask users to approve projection calls. |
| R2 | Host-side confirmation is the only human-in-the-loop for writes; a model can still call a write tool after preview without real user consent if the host auto-approves. | Annotations mark writes destructive; deletes require `confirm=true`; etags; audit; least-privilege scopes on consent. MCP elicitation is not used (stateless JSON mode). |
| R3 | Open DCR/CIMD: anyone can register a client named "ChatGPT". | Redirects pinned to real ChatGPT/Claude callbacks or loopback, so codes cannot reach an attacker's server; consent shows host/verification; phishing via loopback requires code execution on the victim's machine. |
| R4 | SQLite deployments: `FOR UPDATE` is a no-op; races are closed by the per-account in-process lock, which does not span multiple gunicorn workers. | Default SQLite container uses one worker; use PostgreSQL for multi-worker. |
| R5 | iOS API tokens survive web password changes (pre-existing). | Out of scope for this change; recommended follow-up. |
| R6 | Rate limits are in-memory per worker unless `RATELIMIT_STORAGE_URI` is shared; per-IP limits depend on `TRUSTED_PROXY_COUNT`. | Same as existing app. |
| R7 | DNS resolution in CIMD fetch has no explicit timeout beyond the 8 s watchdog on the socket phase. | Allowlisted hosts only by default. |
| R8 | gunicorn's native ASGI worker is newer than `gthread`. | Only used when MCP is enabled; covered by e2e and Docker smoke tests; rollback = flag. |
| R9 | `mcp_idempotency_keys.response_json` stores tool results (names/amounts) for up to 24 h. | GC deletes after 24 h; rows are deleted with the account. |
