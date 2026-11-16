"""Model Context Protocol server for PyCashFlow (ChatGPT and Claude).

One shared, platform-neutral implementation served at ``/mcp`` with the
Streamable HTTP transport. See ``docs/mcp/`` for the tool catalog, OAuth
design, security review and deployment notes.

- ``server``   — builds the SDK server and the authenticated ASGI app
- ``auth``     — bearer-token verification, 401 challenges, rate limiting
- ``runtime``  — per-tool scope/guest checks, app context, idempotency, audit
- ``schemas``  — typed tool output schemas
- ``tools/``   — projections, schedules/scenarios, holds/skips, preview
"""
