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
import re
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


_SEGMENT = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")


class RedirectPolicy:
    """Which redirect URIs clients may register, and how requests match them.

    Non-loopback redirect URIs must appear on an allowlist of exact callback
    URLs. An entry ending in ``/*`` admits exactly one extra path segment of
    ``[A-Za-z0-9_-]`` (ChatGPT's per-connector callbacks). Pinning full
    callback paths, not just hosts, means an open redirect elsewhere on
    chatgpt.com or claude.ai cannot be used to capture authorization codes.
    """

    def __init__(self, allowed_uris, allow_loopback: bool):
        self.exact = frozenset(u for u in allowed_uris if not u.endswith("/*"))
        self.prefixes = tuple(u[:-1] for u in allowed_uris if u.endswith("/*"))
        self.allow_loopback = allow_loopback

    def _allowlisted(self, uri: str) -> bool:
        if uri in self.exact:
            return True
        for prefix in self.prefixes:
            if uri.startswith(prefix) and _SEGMENT.match(uri[len(prefix):]):
                return True
        return False

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
        if not self._allowlisted(uri):
            return "redirect_uri is not on this server's callback allowlist"
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


# ── Log redaction ───────────────────────────────────────────────────────────

import logging  # noqa: E402

_SECRET_PATTERN = re.compile(r"pcf_(at|rt|ac|cs)_[A-Za-z0-9_\-]+")

# Authlib loggers that format issued tokens or client credentials into DEBUG
# messages (e.g. "Issue token {...} to <client>").
_AUTHLIB_CREDENTIAL_LOGGERS = (
    "authlib",
    "authlib.oauth2.rfc6749.grants.authorization_code",
    "authlib.oauth2.rfc6749.grants.refresh_token",
    "authlib.oauth2.rfc6749.authorization_server",
    "authlib.oauth2.rfc6749.authenticate_client",
    "authlib.oauth2.rfc7009.revocation",
    "authlib.oauth2.rfc7591.endpoint",
)


def redact_secrets(text: str) -> str:
    return _SECRET_PATTERN.sub(lambda m: f"pcf_{m.group(1)}_[REDACTED]", text)


class SecretRedactingFilter(logging.Filter):
    """Rewrite log records so OAuth codes, tokens and secrets never reach logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - malformed record; drop args
            message = str(record.msg)
        if "pcf_" in message:
            record.msg = redact_secrets(message)
            record.args = None
        return True


def install_log_redaction() -> None:
    """Attach the redaction filter and keep Authlib at INFO or above."""
    redactor = SecretRedactingFilter()
    for name in _AUTHLIB_CREDENTIAL_LOGGERS:
        log = logging.getLogger(name)
        if not any(isinstance(f, SecretRedactingFilter) for f in log.filters):
            log.addFilter(redactor)
    authlib_logger = logging.getLogger("authlib")
    if authlib_logger.getEffectiveLevel() < logging.INFO:
        authlib_logger.setLevel(logging.INFO)
