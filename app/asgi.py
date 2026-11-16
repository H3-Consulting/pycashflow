"""ASGI entry point used when the MCP integration is enabled.

``gunicorn --worker-class asgi 'app.asgi:create_asgi_app()'``

Requests are dispatched by path:

* ``/mcp`` → the MCP Streamable HTTP app (bearer-authenticated, see app/mcp)
* everything else → the unchanged Flask app, run through ``a2wsgi`` in a
  thread pool (web UI, REST/iOS API, OAuth endpoints, ``/healthz``)

ASGI lifespan events go to the MCP app so the SDK's session manager starts
and stops with the worker. With ``MCP_ENABLED=false`` this module simply
wraps Flask; the container keeps using the plain WSGI (``gthread``) server.
"""

from __future__ import annotations

import logging
import os

from a2wsgi import WSGIMiddleware

logger = logging.getLogger(__name__)

MCP_PATHS = frozenset({"/mcp", "/mcp/"})


class PathDispatcher:
    def __init__(self, mcp_app, flask_asgi, mcp_server=None):
        self.mcp_app = mcp_app
        self.flask_asgi = flask_asgi
        # Exposed for in-process tests that drive the SDK session manager.
        self.mcp_server = mcp_server

    async def __call__(self, scope, receive, send):
        kind = scope["type"]
        if kind == "lifespan":
            await self.mcp_app(scope, receive, send)
        elif kind == "http" and scope.get("path") in MCP_PATHS:
            # Normalise "/mcp/" to "/mcp" instead of letting the SDK answer
            # with a redirect built from the client-supplied Host header.
            scope = dict(scope, path="/mcp", raw_path=b"/mcp")
            await self.mcp_app(scope, receive, send)
        elif kind == "http":
            await self.flask_asgi(scope, receive, send)
        else:  # websockets are not used by PyCashFlow
            await send({"type": "websocket.close", "code": 1000})


def _flask_threads() -> int:
    try:
        return max(1, int(os.environ.get("GUNICORN_THREADS", "8")))
    except ValueError:
        return 8


def create_asgi_app(flask_app=None):
    """Build the ASGI application (Flask + MCP when enabled)."""
    if flask_app is None:
        from app import create_app

        flask_app = create_app()
    flask_asgi = WSGIMiddleware(flask_app, workers=_flask_threads())
    if not flask_app.config.get("MCP_ENABLED"):
        logger.info("MCP_ENABLED is false; ASGI entry point serves Flask only")
        return flask_asgi
    from app.mcp.server import build_mcp_asgi_app

    mcp_app, mcp_server = build_mcp_asgi_app(flask_app)
    logger.info("MCP endpoint enabled at /mcp")
    return PathDispatcher(mcp_app, flask_asgi, mcp_server)
