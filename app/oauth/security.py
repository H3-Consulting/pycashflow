"""Security primitives for the OAuth authorization server.

* Opaque, prefixed credentials (``pcf_at_`` access, ``pcf_rt_`` refresh,
  ``pcf_ac_`` code) with only SHA-256 hashes persisted. The prefixes make
  OAuth credentials distinguishable from iOS/REST tokens and from each other
  (and easy to spot by secret scanners), but carry no authority themselves.
* Redirect-URI policy and matching (exact match; RFC 8252 port-agnostic match
  for loopback redirects only).
* RFC 8707 resource normalisation.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from urllib.parse import urlsplit, urlunsplit

ACCESS_TOKEN_PREFIX = "pcf_at_"
REFRESH_TOKEN_PREFIX = "pcf_rt_"
CODE_PREFIX = "pcf_ac_"
CLIENT_SECRET_PREFIX = "pcf_cs_"

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}
MAX_REDIRECT_URI_LEN = 1024


def new_secret(prefix: str, nbytes: int = 32) -> str:
    return prefix + secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ── Resource indicators (RFC 8707) ──────────────────────────────────────────


def normalize_resource(uri: str | None) -> str | None:
    """Return a canonical form of a resource URI, or ``None`` if invalid.

    Lower-cases scheme and host, drops default ports and a trailing slash, and
    rejects fragments, credentials and relative URIs.
    """
    if not uri or not isinstance(uri, str) or len(uri) > 512:
        return None
    parts = urlsplit(uri.strip())
    if parts.scheme.lower() not in ("https", "http") or not parts.hostname:
        return None
    if parts.fragment or parts.username or parts.password:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    netloc = host if port is None or (scheme, port) in (("https", 443), ("http", 80)) else f"{host}:{port}"
    path = parts.path.rstrip("/")
    return urlunsplit((scheme, netloc, path, parts.query, ""))


# ── Redirect URIs ───────────────────────────────────────────────────────────


def _hostname(parts) -> str:
    host = (parts.hostname or "").lower()
    return f"[{host}]" if ":" in host else host


def is_loopback_redirect(uri: str) -> bool:
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    if parts.scheme != "http":
        return False
    host = _hostname(parts)
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


class RedirectPolicy:
    """Which redirect URIs clients may register, and how requests match them."""

    def __init__(self, allowed_hosts, allow_loopback: bool):
        self.allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self.allow_loopback = allow_loopback

    def check_registration(self, uri) -> str | None:
        """Return ``None`` if *uri* may be registered, else a reason string."""
        if not isinstance(uri, str) or not uri or len(uri) > MAX_REDIRECT_URI_LEN:
            return "redirect_uri must be a non-empty string"
        if any(ch.isspace() or ord(ch) < 0x20 for ch in uri):
            return "redirect_uri must not contain whitespace or control characters"
        try:
            parts = urlsplit(uri)
            parts.port  # noqa: B018 - raises ValueError on a malformed port
        except ValueError:
            return "redirect_uri is malformed"
        if parts.fragment or "#" in uri:
            return "redirect_uri must not contain a fragment"
        if parts.username or parts.password:
            return "redirect_uri must not contain credentials"
        if is_loopback_redirect(uri):
            if not self.allow_loopback:
                return "loopback redirect URIs are not allowed on this server"
            return None
        if parts.scheme != "https":
            return "redirect_uri must use https (or http on a loopback address)"
        host = _hostname(parts)
        if host not in self.allowed_hosts:
            return f"redirect host {host!r} is not on this server's allowlist"
        return None

    @staticmethod
    def matches(registered: str, requested: str) -> bool:
        """Exact match, except loopback URIs match on any port (RFC 8252 §7.3)."""
        if not isinstance(requested, str):
            return False
        if registered == requested:
            return True
        if not (is_loopback_redirect(registered) and is_loopback_redirect(requested)):
            return False
        try:
            reg = urlsplit(registered)
            req = urlsplit(requested)
            req.port  # noqa: B018 - validate port
        except ValueError:
            return False
        return (
            reg.scheme == req.scheme
            and _hostname(reg) == _hostname(req)
            and reg.path == req.path
            and reg.query == req.query
            and not req.fragment
        )
