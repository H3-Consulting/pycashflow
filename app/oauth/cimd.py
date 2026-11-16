"""OAuth Client ID Metadata Documents (CIMD) with SSRF protections.

A CIMD client uses an HTTPS URL as its ``client_id``; the authorization server
fetches that URL to learn the client's name and redirect URIs. Fetching an
attacker-chosen URL from the server is a classic SSRF vector, so this module:

* only fetches from hosts on ``OAUTH_CIMD_ALLOWED_HOSTS`` (default: ChatGPT and
  Claude); ``*`` permits any *public* host,
* requires ``https`` on port 443, a path, no credentials/fragment, and a short URL,
* resolves DNS once, refuses any non-public address, and connects to that exact
  IP (TLS still verified against the hostname) so DNS rebinding cannot swap
  the target between check and use,
* never follows redirects, times out after 5 s and reads at most 32 KiB,
* validates the document (``client_id`` must equal the URL exactly; redirect
  URIs must satisfy the server's redirect policy) and caches it in
  ``oauth_clients`` honouring ``Cache-Control: max-age`` within [5 min, 24 h],
  serving a stale copy (< 7 days) only when a refresh fails.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

MAX_DOCUMENT_BYTES = 32 * 1024
FETCH_TIMEOUT_SECONDS = 5
MIN_CACHE_SECONDS = 300
MAX_CACHE_SECONDS = 86400
STALE_IF_ERROR = timedelta(days=7)
MAX_URL_LEN = 512


class CimdError(Exception):
    """The client metadata document could not be fetched or is invalid."""


@dataclass
class FetchedDocument:
    document: dict
    max_age: int


def is_cimd_client_id(client_id) -> bool:
    return isinstance(client_id, str) and client_id.startswith("https://")


def validate_cimd_url(url: str, allowed_hosts) -> str:
    """Validate a CIMD URL; return its lower-cased host."""
    if not isinstance(url, str) or len(url) > MAX_URL_LEN:
        raise CimdError("client_id URL is too long")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise CimdError("client_id must be an https URL")
    if parts.username or parts.password or parts.fragment:
        raise CimdError("client_id URL must not contain credentials or a fragment")
    try:
        port = parts.port
    except ValueError:
        raise CimdError("client_id URL has an invalid port")
    if port not in (None, 443):
        raise CimdError("client_id URL must use the default https port")
    if not parts.path or parts.path == "/":
        raise CimdError("client_id URL must contain a path")
    host = parts.hostname.lower()
    allowed = {h.lower() for h in allowed_hosts}
    if "*" not in allowed and host not in allowed:
        raise CimdError(f"client metadata host {host!r} is not trusted by this server")
    if _is_ip_literal(host):
        raise CimdError("client_id URL must use a DNS hostname")
    return host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def resolve_public_ip(host: str) -> str:
    """Resolve *host*; refuse if any address is not globally routable."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise CimdError("client metadata host could not be resolved") from exc
    addresses = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise CimdError("client metadata host resolves to a non-public address")
        addresses.append(str(ip))
    if not addresses:
        raise CimdError("client metadata host could not be resolved")
    return addresses[0]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection to a pre-resolved IP with SNI/cert checks on the host."""

    def __init__(self, host: str, ip: str, **kwargs):
        super().__init__(host, 443, **kwargs)
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _parse_max_age(cache_control: str | None) -> int:
    match = re.search(r"max-age\s*=\s*(\d+)", cache_control or "", re.I)
    if "no-store" in (cache_control or "").lower() or not match:
        return MIN_CACHE_SECONDS
    return max(MIN_CACHE_SECONDS, min(MAX_CACHE_SECONDS, int(match.group(1))))


def http_fetch(url: str, allowed_hosts) -> FetchedDocument:
    """Fetch and JSON-decode a CIMD document under the SSRF constraints."""
    host = validate_cimd_url(url, allowed_hosts)
    ip = resolve_public_ip(host)
    parts = urlsplit(url)
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    context = ssl.create_default_context()
    conn = _PinnedHTTPSConnection(host, ip, timeout=FETCH_TIMEOUT_SECONDS, context=context)
    try:
        conn.request(
            "GET",
            target,
            headers={"Accept": "application/json", "User-Agent": "PyCashFlow-OAuth/1.0"},
        )
        response = conn.getresponse()
        if response.status != 200:
            raise CimdError(f"client metadata request returned HTTP {response.status}")
        content_type = (response.getheader("Content-Type") or "").lower()
        if "json" not in content_type:
            raise CimdError("client metadata must be served as JSON")
        body = response.read(MAX_DOCUMENT_BYTES + 1)
        if len(body) > MAX_DOCUMENT_BYTES:
            raise CimdError("client metadata document is too large")
        max_age = _parse_max_age(response.getheader("Cache-Control"))
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        raise CimdError("client metadata could not be fetched") from exc
    finally:
        conn.close()
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CimdError("client metadata is not valid JSON") from exc
    if not isinstance(document, dict):
        raise CimdError("client metadata must be a JSON object")
    return FetchedDocument(document=document, max_age=max_age)


# The fetcher is a module attribute so tests can substitute a fake.
fetch_document = http_fetch


def validate_document(url: str, document: dict, redirect_policy) -> dict:
    """Validate a CIMD document and return normalised client fields."""
    if document.get("client_id") != url:
        raise CimdError("client metadata client_id does not match its URL")
    redirect_uris = document.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris or len(redirect_uris) > 20:
        raise CimdError("client metadata must list between 1 and 20 redirect_uris")
    allowed_redirects = []
    for uri in redirect_uris:
        if redirect_policy.check_registration(uri) is None:
            allowed_redirects.append(uri)
    if not allowed_redirects:
        raise CimdError("none of the client's redirect_uris are allowed on this server")
    response_types = document.get("response_types") or ["code"]
    if not isinstance(response_types, list) or "code" not in response_types:
        raise CimdError("client metadata must support response_type 'code'")
    grant_types = document.get("grant_types") or ["authorization_code"]
    if not isinstance(grant_types, list) or "authorization_code" not in grant_types:
        raise CimdError("client metadata must support the authorization_code grant")
    supported_grants = [g for g in ("authorization_code", "refresh_token") if g in grant_types]
    name = document.get("client_name")
    if not isinstance(name, str) or not name.strip():
        raise CimdError("client metadata must include client_name")
    client_uri = document.get("client_uri") if isinstance(document.get("client_uri"), str) else None
    return {
        "client_name": _clean_display(name)[:200],
        "client_uri": client_uri[:512] if client_uri and client_uri.startswith("https://") else None,
        "redirect_uris": allowed_redirects,
        "grant_types": supported_grants,
        "response_types": ["code"],
        # All CIMD clients are public PKCE clients here: this server does not
        # advertise private_key_jwt, so clients authenticate with "none".
        "token_endpoint_auth_method": "none",
    }


def _clean_display(value: str) -> str:
    import unicodedata

    return "".join(
        ch for ch in value.strip()
        if unicodedata.category(ch) not in {"Cc", "Cf", "Cs", "Co"}
    )


def resolve_cimd_client(url: str, config, redirect_policy, client_model, db):
    """Return an up-to-date ``OAuthClient`` row for a CIMD client, or raise."""
    validate_cimd_url(url, config.cimd_allowed_hosts)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row = client_model.query.filter_by(client_id=url).first()
    if row is not None and row.registration_type != "cimd":
        raise CimdError("client id is already registered differently")
    if row is not None and row.metadata_expires_at and row.metadata_expires_at > now:
        return row if row.is_active else None
    try:
        fetched = fetch_document(url, config.cimd_allowed_hosts)
        fields = validate_document(url, fetched.document, redirect_policy)
    except CimdError:
        if (
            row is not None
            and row.is_active
            and row.metadata_fetched_at
            and now - row.metadata_fetched_at < STALE_IF_ERROR
        ):
            logger.warning("Using stale client metadata for %s after refresh failure", url)
            return row
        raise
    if row is None:
        row = client_model(client_id=url, registration_type="cimd")
        db.session.add(row)
    row.client_name = fields["client_name"]
    row.client_uri = fields["client_uri"]
    row.redirect_uris = json.dumps(fields["redirect_uris"])
    row.grant_types = json.dumps(fields["grant_types"])
    row.response_types = json.dumps(fields["response_types"])
    row.token_endpoint_auth_method = fields["token_endpoint_auth_method"]
    row.metadata_fetched_at = now
    row.metadata_expires_at = now + timedelta(seconds=fetched.max_age)
    db.session.commit()
    return row if row.is_active else None
