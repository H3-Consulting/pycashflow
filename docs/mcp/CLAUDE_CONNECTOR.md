# PyCashFlow for Claude

Claude uses the **same** MCP server as ChatGPT (`https://<host>/mcp`); there is
no Claude-specific implementation or package. Remote MCP servers are submitted
to the Claude Connectors Directory by URL — no ZIP or bundle is needed.

> **Status:** not deployed and not submitted; both require explicit approval.

## Compatibility with Claude's connector requirements (verified Nov 2026)

| Claude requirement | PyCashFlow |
|---|---|
| `401` with `WWW-Authenticate: Bearer resource_metadata=…` starts sign-in | Yes, from `app/mcp/auth.py` (also includes `scope`) |
| PRM `resource` equals the URL the user enters | `MCP_PUBLIC_BASE_URL` + `/mcp` |
| Only the first `authorization_servers` entry is used | Exactly one: the PyCashFlow origin |
| CIMD used only if metadata has `client_id_metadata_document_supported: true` **and** `none` in `token_endpoint_auth_methods_supported` | Both advertised; Claude's document `https://claude.ai/oauth/mcp-oauth-client-metadata` is accepted (host allowlisted) |
| DCR fallback with `registration_endpoint` | `/oauth/register` |
| Callback `https://claude.ai/api/mcp/auth_callback` (and future `claude.com`) | Both on the default redirect allowlist |
| Claude Code: loopback redirect on any port for `localhost` and `127.0.0.1` (CIMD `https://claude.ai/oauth/claude-code-client-metadata`) | Port-agnostic loopback matching; consent page warns that the client runs locally |
| PKCE S256, `code_challenge_methods_supported: ["S256"]` | Mandatory, S256 only |
| `offline_access` appended only if listed | Not listed; refresh tokens are issued anyway to clients registered for `refresh_token` |
| Refresh tokens rotated for public clients; dead refresh → `invalid_grant` | Yes |
| Token endpoint accepts `application/x-www-form-urlencoded`; DCR accepts JSON | Yes |
| Discovery/registration/token respond < 10 s, refresh < 30 s | Local DB work only; CIMD fetch capped at 8 s and cached |
| Every tool has `title` and `readOnlyHint` or `destructiveHint` | All 20 tools; read and write operations are separate tools |
| No money transfers | None |
| Tool descriptions describe behaviour, not instruct Claude | Factual descriptions; behavioural guidance is in server instructions |

## Connect as a custom connector (testing)

1. Server: `MCP_ENABLED=true`, `MCP_PUBLIC_BASE_URL=https://<host>`, HTTPS,
   reachable from Anthropic's egress range `160.79.104.0/21`.
2. Claude (web/desktop): **Settings → Connectors → Add custom connector**,
   URL `https://<host>/mcp`. Leave client ID/secret empty (Claude uses CIMD,
   or DCR as a fallback).
3. Claude opens PyCashFlow's sign-in (password, TOTP or passkey), then the
   consent page. Review the permissions (uncheck write permissions for a
   read-only connection) and choose **Allow**.
4. In a chat, enable the connector and try the sample prompts below. Read-only
   tools run without a per-call prompt; projection and write tools are
   annotated destructive, so Claude asks before each call.
5. Claude Code: `claude mcp add --transport http pycashflow https://<host>/mcp`,
   then `/mcp` to authenticate (loopback redirect).
6. Disconnect from **PyCashFlow → Settings → Connected apps** (affects only
   Claude) or remove the connector in Claude.

Test with MCP Inspector too (Claude's review checklist asks for it):
`npx @modelcontextprotocol/inspector` → Streamable HTTP → `https://<host>/mcp`
→ OAuth flow in the Auth settings.

## Sample prompts

- "Using PyCashFlow, will my balance drop below zero in the next 90 days?"
- "What are my five biggest bills in the next month?"
- "What would my lowest balance be if I moved Rent to the 5th? Don't change
  anything yet." → `preview_change`
- "Okay, make that change." → `update_schedule` with the preview's
  `expected_etag`
- "Add a what-if scenario for a $250 monthly car payment from next month and
  compare it to my plan." → `create_scenario`, `get_cashflow_projection`
- "Skip my next Gym payment." → `list_upcoming_transactions`, `create_skip`
- "Remove the hold on my electricity bill." → `list_holds`, `remove_hold`

## Directory submission (only after approval)

Portal: **claude.ai/directory/manage → Submit new → MCP connector**. Have ready:

1. **Connection:** `https://app.pycashflow.com/mcp` (universal URL).
2. **Tools:** synced automatically; all tools carry titles and annotations
   (the portal groups them read-only vs write).
3. **Listing:** name "PyCashFlow" (≤ 100), one-liner (≤ 200), description
   (≤ 2000), category Finance, documentation URL
   `https://www.pycashflow.com/support#ai-assistants`, privacy policy
   `https://www.pycashflow.com/privacy`, support contact
   `support@pycashflow.com` (`https://www.pycashflow.com/support`), icon
   (`plugins/chatgpt/assets/logo.png` can be reused). The support page and
   the AI-connection sections of the privacy policy and terms come from
   H3-Consulting/pycashflow-site#35; merge it first.
4. **Use cases:** reads and writes data; users need a PyCashFlow account (and,
   on the hosted service, an active subscription).
5. **Company:** H3 Consulting Partners.
6. **Authentication:** "Always required", OAuth sign-in; no Anthropic-held
   client is needed (CIMD/DCR). Do not enter credentials in the portal.
7. **Data handling:** first-party API; no health data; no sponsored content.
8. **Test & launch:** confirm every tool was exercised in Claude and MCP
   Inspector.
9. **Compliance:** seven acknowledgments (including financial transactions —
   PyCashFlow performs none, and prompt injection — stored text is treated as
   data).

### Test account for Verified review

If Anthropic escalates to Verified review, a reviewer requests access by
email. Provide a dedicated account owner with sample data (same seed as the
ChatGPT reviewer account), without TOTP/passkey requirements, and on the hosted
service flagged as a review user so subscription checks pass. Keep it
available; never use a real customer's account.
