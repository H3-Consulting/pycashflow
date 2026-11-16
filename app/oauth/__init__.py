"""OAuth 2.1 authorization server for MCP clients (ChatGPT, Claude).

Registered by :func:`init_oauth` only when ``MCP_ENABLED=true``; with MCP
disabled none of these routes exist and the app behaves exactly as before.

Layout:

- ``config``   — env-driven settings and the public issuer/resource URLs
- ``scopes``   — scope catalogue and consent-screen descriptions
- ``security`` — token formats/hashing, redirect policy, resource normalisation
- ``cimd``     — Client ID Metadata Documents with SSRF protections
- ``server``   — Authlib server, grants and endpoints with PyCashFlow policy
- ``tokens``   — access-token verification for the MCP resource server,
  grant revocation and garbage collection
- ``audit``    — audit events for grant lifecycle and MCP mutations
- ``routes``   — Flask endpoints, consent page and connected-apps page
"""

from __future__ import annotations


def init_oauth(app) -> None:
    """Configure the authorization server and register its blueprint."""
    from app import csrf

    from .config import build_oauth_config
    from .routes import exempt_machine_endpoints, oauth_bp
    from .security import install_log_redaction
    from .server import create_authorization_server

    install_log_redaction()
    config = build_oauth_config(app.config)
    app.extensions["pycashflow_oauth_config"] = config
    app.extensions["pycashflow_oauth_server"] = create_authorization_server(app, config)
    app.register_blueprint(oauth_bp)
    exempt_machine_endpoints(csrf)
