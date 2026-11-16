"""HTTP and TLS diagnostics using ``http.client`` and ``ssl``."""

from __future__ import annotations

import http.client
import math
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit

from .errors import NetopsError

DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_REDIRECTS = 5
MAX_BODY_BYTES = 65536
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "netops-toolkit/1.0"


def parse_target(url: str) -> tuple[str, str, int, str]:
    """Validate an HTTP(S) URL and return scheme, host, port and request path."""
    text = url.strip()
    if not text:
        raise NetopsError("URL must not be empty")
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise NetopsError(f"unsupported URL scheme {parts.scheme!r}; use http:// or https://")
    host = parts.hostname
    if not host:
        raise NetopsError(f"URL {url!r} does not contain a hostname")
    try:
        port = parts.port
    except ValueError as exc:
        raise NetopsError(f"invalid port in URL {url!r}") from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return scheme, host, port, path


def _name_fields(value: Any) -> dict[str, str]:
    """Flatten an :func:`ssl.SSLSocket.getpeercert` name tuple into a dict."""
    fields: dict[str, str] = {}
    for relative_distinguished_name in value or ():
        for key, item in relative_distinguished_name:
            if key in fields:
                fields[key] = f"{fields[key]}, {item}"
            else:
                fields[key] = item
    return fields


@dataclass(frozen=True)
class CertificateInfo:
    """Decoded details of a peer TLS certificate."""

    subject: dict[str, str]
    issuer: dict[str, str]
    not_before: str
    not_after: str
    days_remaining: int
    subject_alt_names: list[str]


def _certificate_datetime(value: str) -> datetime:
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise NetopsError(f"cannot parse certificate date {value!r}: {exc}") from exc


def certificate_info(cert: dict[str, Any], now: datetime | None = None) -> CertificateInfo:
    """Decode the certificate dictionary returned by ``SSLSocket.getpeercert``."""
    if not cert:
        raise NetopsError("TLS peer did not present a usable certificate")
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    if not not_before or not not_after:
        raise NetopsError("TLS certificate is missing its validity dates")
    not_before_dt = _certificate_datetime(str(not_before))
    not_after_dt = _certificate_datetime(str(not_after))
    current = now or datetime.now(timezone.utc)
    remaining_seconds = (not_after_dt - current).total_seconds()
    days_remaining = math.floor(remaining_seconds / 86400)
    subject_alt_names = [
        f"{kind}:{value}" for kind, value in cert.get("subjectAltName", ())
    ]
    return CertificateInfo(
        subject=_name_fields(cert.get("subject")),
        issuer=_name_fields(cert.get("issuer")),
        not_before=not_before_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        not_after=not_after_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        days_remaining=days_remaining,
        subject_alt_names=subject_alt_names,
    )


def _tls_details(connection: http.client.HTTPConnection, insecure: bool) -> dict[str, Any]:
    """Collect TLS version, cipher and certificate details from a live connection."""
    details: dict[str, Any] = {
        "verified": not insecure,
        "protocol": None,
        "cipher": None,
        "bits": None,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "subject_alt_names": [],
    }
    sock = connection.sock
    if sock is None:
        return details
    version = getattr(sock, "version", None)
    details["protocol"] = version() if callable(version) else None
    cipher = getattr(sock, "cipher", None)
    cipher_info = cipher() if callable(cipher) else None
    if cipher_info:
        details["cipher"] = cipher_info[0]
        details["bits"] = cipher_info[2]
    if insecure:
        return details
    peer_cert = sock.getpeercert()
    if not peer_cert:
        return details
    info = certificate_info(peer_cert)
    details.update(
        {
            "subject": info.subject,
            "issuer": info.issuer,
            "not_before": info.not_before,
            "not_after": info.not_after,
            "days_remaining": info.days_remaining,
            "subject_alt_names": info.subject_alt_names,
        }
    )
    return details


def _peer_address(connection: http.client.HTTPConnection) -> str | None:
    sock = connection.sock
    if sock is None:
        return None
    try:
        peer = sock.getpeername()
    except OSError:
        return None
    if isinstance(peer, tuple) and len(peer) >= 2:
        host, port = str(peer[0]), peer[1]
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return str(peer)


def _open_connection(
    scheme: str, host: str, port: int, timeout: float, insecure: bool
) -> http.client.HTTPConnection:
    if scheme == "https":
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def request_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    insecure: bool = False,
) -> dict[str, Any]:
    """Perform a GET request, following redirects and recording each hop."""
    if timeout <= 0:
        raise NetopsError("timeout must be greater than zero")
    if max_redirects < 0:
        raise NetopsError("max redirects must not be negative")

    original_url = url.strip()
    current_url = original_url
    redirects: list[dict[str, Any]] = []
    started = time.perf_counter()
    while True:
        scheme, host, port, path = parse_target(current_url)
        connection = _open_connection(scheme, host, port, timeout, insecure)
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            # The socket is released by http.client when the response closes,
            # so capture TLS and peer details while the connection is live.
            tls = _tls_details(connection, insecure) if scheme == "https" else None
            remote = _peer_address(connection)
            response = connection.getresponse()
            status = response.status
            reason = response.reason
            headers = list(response.getheaders())
            content_length: int | None = None
            for name, value in headers:
                if name.lower() == "content-length":
                    try:
                        content_length = int(value)
                    except ValueError:
                        content_length = None
                    break
            body = response.read(MAX_BODY_BYTES)
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise NetopsError(f"request to {current_url} failed: {exc}") from exc
        finally:
            connection.close()

        location = next(
            (value for name, value in headers if name.lower() == "location"), None
        )
        if status in REDIRECT_STATUSES and location:
            redirects.append({"url": current_url, "status": status, "location": location})
            current_url = urljoin(current_url, location)
            if len(redirects) > max_redirects:
                raise NetopsError(f"too many redirects (more than {max_redirects})")
            continue

        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "url": original_url,
            "final_url": current_url,
            "status": status,
            "reason": reason,
            "remote": remote,
            "headers": [{"name": name, "value": value} for name, value in headers],
            "redirects": redirects,
            "tls": tls,
            "content_length": content_length,
            "body_bytes_read": len(body),
            "elapsed_ms": elapsed_ms,
        }
