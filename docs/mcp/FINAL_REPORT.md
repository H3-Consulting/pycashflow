# Final report and production-readiness assessment

## Outcome

PyCashFlow has a single, shared MCP server for ChatGPT and Claude, served from
the existing Flask application and Docker image behind `MCP_ENABLED`
(default `false`). Users connect with their existing PyCashFlow login
(password, TOTP, passkey) through a built-in OAuth 2.1 authorization server
and can read projections and manage schedules, scenarios, holds and skips
under scopes they approve. Nothing has been deployed or submitted.

## Acceptance criteria

| Criterion | Status |
|---|---|
| All requested MCP tools implemented | Yes — 20 tools ([TOOL_CATALOG.md](TOOL_CATALOG.md)), plus `list_upcoming_transactions` and `preview_change` |
| Existing Flask functionality preserved | Yes — 710 pre-existing tests pass with MCP on and off; Docker smoke (login, dashboard, settings) in both modes |
| Existing iOS API preserved | Yes — `/api/v1` responses unchanged; iOS tokens unaffected by OAuth revocation; REST tests pass |
| OAuth with existing credentials | Yes — password, TOTP and passkey logins hand back to consent (tested) |
| ChatGPT and Claude connect independently | Protocol-level compatibility verified against both platforms' published requirements and their real CIMD documents; separate grants per client (tested). Live connection from the hosted products **not yet performed** (needs a public HTTPS deployment). |
| Every tool enforces scopes | Yes — scope matrix test over all tools |
| Cross-account access prevented | Yes — IDOR tests on every id-taking tool; principal only from token |
| Guest write restrictions preserved | Yes — consent withholds write scopes; runtime refusal; tested |
| Projection calculations keep `update_cash(..., commit=True)` | Yes — single shared pipeline; spy test proves `commit=True` on every projection tool; maintenance persistence tested |
| Projections current after changes | Yes — every call recomputes; REST-made changes visible on the next MCP call; no projection cache across requests |
| No stale-cache issues | Yes — only per-request caching (as before in REST) |
| Writes safe, validated, auditable | Yes — strict validation, locks, etags, idempotency, rollback, audit |
| Duplicate/concurrent operations safe | Yes — tested (PostgreSQL row locks; per-account lock for SQLite) |
| New tests pass | Yes — 376 new tests |
| Regression tests pass | Yes — see [TESTING.md](TESTING.md) |
| Security review completed | Yes — [SECURITY.md](SECURITY.md), including an independent adversarial review |
| Critical/high findings resolved | Yes — no critical; all 3 high fixed and regression-tested |
| Runs in the existing container | Yes — same image, gunicorn ASGI worker when enabled; smoke-tested on SQLite and PostgreSQL |
| ChatGPT submission materials | Yes — `plugins/chatgpt/` (validated against Agent Plugins schemas; placeholders block a real build) |
| Claude connector documentation | Yes — [CLAUDE_CONNECTOR.md](CLAUDE_CONNECTOR.md) |
| Production deployment pending approval | Yes — not deployed, not submitted |

## Production-readiness assessment

**Ready for a staging deployment and live-client testing.** Code, migration,
security controls and automated verification are complete. Before enabling
MCP in production and before any directory submission, complete these
non-code items:

1. Deploy with `MCP_ENABLED=false` first (the service refactor and validation
   hardening ship regardless), then enable on staging with
   `MCP_PUBLIC_BASE_URL`, confirm `TRUSTED_PROXY_COUNT` matches the proxy
   chain, and verify outbound HTTPS to `chatgpt.com`/`claude.ai` (or disable
   CIMD).
2. Connect from ChatGPT developer mode, Claude custom connector, Claude Code and
   MCP Inspector; run the review test prompts.
3. Merge H3-Consulting/pycashflow-site#35, which covers AI-assistant
   connections in the privacy policy (new Section 5) and terms (new
   Section 12) and adds `/support` with contact details and the ChatGPT/Claude
   help article. It updates both effective dates; decide on the 30-day
   material-change notice both documents promise.
4. Prepare the reviewer account (password-only account owner, sample data,
   review-user flag; see `plugins/chatgpt/README.md`) and record the demo
   video. Merging the recording URL into `plugins/chatgpt/plugin.json` makes
   `.github/workflows/chatgpt-package.yml` build the ChatGPT ZIP.
5. Obtain explicit approval for production enablement and each submission.

## Decisions worth reviewing

- **Projection tools are not annotated read-only** because they commit
  maintenance (as required). Hosts will ask users to approve projection calls;
  this is the honest trade-off.
- **Holds are documented as the engine actually behaves** (an extra transaction
  of the schedule's amount tomorrow), not as "pause" (AGENTS.md wording).
- **Forecast horizon capped at 270 days**: the engine only expands quarterly
  items ≈ 9 months ahead, so longer windows would silently omit them.
- **No Plaid refresh from MCP**: projections use the latest stored balance and
  report its age, so AI tool calls never trigger bank API traffic.
- **Insufficient scope is returned as a tool error** with
  `_meta["mcp/www_authenticate"]` (ChatGPT's mechanism) rather than an HTTP
  403, which would require parsing JSON-RPC before the SDK.
- **Redirects pinned to exact ChatGPT/Claude callback URLs** plus loopback;
  other clients need `OAUTH_ALLOWED_REDIRECT_URIS` entries.
- **Grant lifetime 90 days**: users reconnect quarterly (configurable).

## Known limitations

See [SECURITY.md § Residual risks](SECURITY.md#residual-risks). In short:
projection reads mutate data by design; host confirmation is the only
human-in-the-loop for writes (no MCP elicitation in stateless mode); SQLite
concurrency protection is per worker; iOS tokens still survive web password
changes (pre-existing); CIMD requires outbound HTTPS; the gunicorn ASGI worker
is newer than `gthread` (used only when enabled; rollback is a flag).

## Sources consulted (Nov 2026)

- MCP authorization spec 2026-07-28 (authorization, client registration,
  server discovery, security considerations) — modelcontextprotocol.io
- OpenAI: Apps SDK auth, app submission guidelines, "Submit plugins" —
  developers.openai.com
- Anthropic: connector authentication, submission, review criteria —
  claude.com/docs/connectors
- Published CIMD documents: `https://chatgpt.com/oauth/client.json`,
  `https://claude.ai/oauth/mcp-oauth-client-metadata`,
  `https://claude.ai/oauth/claude-code-client-metadata`
- Agent Plugins 1.0.0 JSON Schemas — agent-plugins.org
