"""MCP / OAuth configuration loaded from the Flask config (env-driven)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

from .scopes import ALL_SCOPES

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Exact callback URLs published by ChatGPT and Claude (Nov 2026). "/*" admits
# one extra path segment (ChatGPT callback-ID redirects).
DEFAULT_REDIRECT_URIS = ",".join([
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com/connector/oauth/*",
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
])


class OAuthConfigError(RuntimeError):
    """Raised when MCP is enabled with an unsafe or incomplete configuration."""


def _csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _bool(value, default: bool) -> bool:
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _int(value, default: int, *, minimum: int = 0) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, parsed)


def read_env_config() -> dict:
    """Read MCP/OAuth settings from the process environment for app.config."""
    env = os.environ
    return {
        "MCP_ENABLED": _bool(env.get("MCP_ENABLED"), False),
        "MCP_PUBLIC_BASE_URL": (env.get("MCP_PUBLIC_BASE_URL") or "").strip(),
        "MCP_ALLOWED_HOSTS": env.get("MCP_ALLOWED_HOSTS", ""),
        "MCP_ALLOWED_ORIGINS": env.get("MCP_ALLOWED_ORIGINS", ""),
        "MCP_RATE_LIMIT": env.get("MCP_RATE_LIMIT", "120/minute;2000/hour"),
        "OAUTH_ALLOWED_REDIRECT_URIS": env.get("OAUTH_ALLOWED_REDIRECT_URIS", DEFAULT_REDIRECT_URIS),
        "OAUTH_ALLOW_LOOPBACK_REDIRECTS": _bool(env.get("OAUTH_ALLOW_LOOPBACK_REDIRECTS"), True),
        "OAUTH_DCR_ENABLED": _bool(env.get("OAUTH_DCR_ENABLED"), True),
        "OAUTH_CIMD_ENABLED": _bool(env.get("OAUTH_CIMD_ENABLED"), True),
        "OAUTH_CIMD_ALLOWED_HOSTS": env.get(
            "OAUTH_CIMD_ALLOWED_HOSTS", "chatgpt.com,claude.ai,claude.com"
        ),
        "OAUTH_ACCESS_TOKEN_TTL_SECONDS": _int(env.get("OAUTH_ACCESS_TOKEN_TTL_SECONDS"), 3600, minimum=60),
        "OAUTH_REFRESH_TOKEN_TTL_DAYS": _int(env.get("OAUTH_REFRESH_TOKEN_TTL_DAYS"), 30, minimum=1),
        "OAUTH_GRANT_MAX_AGE_DAYS": _int(env.get("OAUTH_GRANT_MAX_AGE_DAYS"), 90, minimum=0),
        "OAUTH_MAX_DCR_CLIENTS": _int(env.get("OAUTH_MAX_DCR_CLIENTS"), 5000, minimum=1),
    }


@dataclass(frozen=True)
class OAuthConfig:
    base_url: str
    issuer: str
    resource: str
    resource_metadata_url: str
    scopes: tuple[str, ...]
    allowed_redirect_uris: tuple[str, ...]
    allow_loopback_redirects: bool
    dcr_enabled: bool
    cimd_enabled: bool
    cimd_allowed_hosts: frozenset[str]
    access_token_ttl: int
    refresh_token_ttl: int
    grant_max_age: int
    code_ttl: int
    max_dcr_clients: int
    mcp_allowed_hosts: tuple[str, ...]
    mcp_allowed_origins: tuple[str, ...]
    mcp_rate_limit: str

    @property
    def public_host(self) -> str:
        return urlsplit(self.base_url).netloc


def validate_base_url(raw: str) -> str:
    """Validate the public base URL used for the issuer and resource ids."""
    if not raw:
        raise OAuthConfigError(
            "MCP_ENABLED=true requires MCP_PUBLIC_BASE_URL (or FRONTEND_BASE_URL), "
            "e.g. https://cash.example.com"
        )
    parts = urlsplit(raw.strip())
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise OAuthConfigError("MCP_PUBLIC_BASE_URL must be an absolute https:// URL")
    if parts.scheme == "http" and parts.hostname not in _LOCAL_HOSTS:
        raise OAuthConfigError("MCP_PUBLIC_BASE_URL must use https outside localhost")
    if parts.query or parts.fragment or parts.username or parts.password:
        raise OAuthConfigError("MCP_PUBLIC_BASE_URL must not contain credentials, a query or a fragment")
    if parts.path not in ("", "/"):
        raise OAuthConfigError("MCP_PUBLIC_BASE_URL must be the site origin without a path")
    netloc = parts.hostname.lower()
    if parts.port and not (
        (parts.scheme == "https" and parts.port == 443) or (parts.scheme == "http" and parts.port == 80)
    ):
        netloc = f"{netloc}:{parts.port}"
    return f"{parts.scheme}://{netloc}"


def build_oauth_config(app_config) -> OAuthConfig:
    raw_base = app_config.get("MCP_PUBLIC_BASE_URL") or app_config.get("FRONTEND_BASE_URL") or ""
    base_url = validate_base_url(raw_base)
    host = urlsplit(base_url).netloc
    allowed_hosts = tuple(dict.fromkeys([host, *_csv(app_config.get("MCP_ALLOWED_HOSTS"))]))
    allowed_origins = tuple(dict.fromkeys([
        base_url,
        "https://chatgpt.com",
        "https://claude.ai",
        "https://claude.com",
        *_csv(app_config.get("MCP_ALLOWED_ORIGINS")),
    ]))
    return OAuthConfig(
        base_url=base_url,
        issuer=base_url,
        resource=f"{base_url}/mcp",
        resource_metadata_url=f"{base_url}/.well-known/oauth-protected-resource/mcp",
        scopes=ALL_SCOPES,
        allowed_redirect_uris=tuple(_csv(app_config.get("OAUTH_ALLOWED_REDIRECT_URIS", DEFAULT_REDIRECT_URIS))),
        allow_loopback_redirects=bool(app_config.get("OAUTH_ALLOW_LOOPBACK_REDIRECTS", True)),
        dcr_enabled=bool(app_config.get("OAUTH_DCR_ENABLED", True)),
        cimd_enabled=bool(app_config.get("OAUTH_CIMD_ENABLED", True)),
        cimd_allowed_hosts=frozenset(h.lower() for h in _csv(app_config.get("OAUTH_CIMD_ALLOWED_HOSTS"))),
        access_token_ttl=int(app_config.get("OAUTH_ACCESS_TOKEN_TTL_SECONDS", 3600)),
        refresh_token_ttl=int(app_config.get("OAUTH_REFRESH_TOKEN_TTL_DAYS", 30)) * 86400,
        grant_max_age=int(app_config.get("OAUTH_GRANT_MAX_AGE_DAYS", 90)) * 86400,
        code_ttl=300,
        max_dcr_clients=int(app_config.get("OAUTH_MAX_DCR_CLIENTS", 5000)),
        mcp_allowed_hosts=allowed_hosts,
        mcp_allowed_origins=allowed_origins,
        mcp_rate_limit=str(app_config.get("MCP_RATE_LIMIT") or "120/minute;2000/hour"),
    )


def get_oauth_config():
    """Return the active :class:`OAuthConfig` (only set when MCP is enabled)."""
    from flask import current_app

    return current_app.extensions.get("pycashflow_oauth_config")
