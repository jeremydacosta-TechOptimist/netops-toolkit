"""Shared helpers for the offline test suite."""

from __future__ import annotations

import contextlib
import io
import os
import socket
import struct
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from netops import cli  # noqa: E402
from netops import dnsdiag  # noqa: E402


def run_cli(args: list[str]) -> tuple[int, str, str]:
    """Run the CLI in-process and capture its exit code, stdout and stderr."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = cli.main(args)
        except SystemExit as exc:
            code = int(exc.code) if exc.code is not None else 0
    return code, stdout.getvalue(), stderr.getvalue()


@contextlib.contextmanager
def tcp_listener() -> Iterator[int]:
    """Yield a port with a live TCP listener bound to 127.0.0.1."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    server.settimeout(0.1)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                connection.close()
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        server.close()
        thread.join(timeout=2)


@contextlib.contextmanager
def unused_tcp_port() -> Iterator[int]:
    """Yield a TCP port number that has been released and has no listener."""
    with tcp_listener() as port:
        pass
    yield port


def build_dns_response(
    query: bytes,
    answers: list[tuple[int, int, bytes]],
    rcode: int = 0,
) -> bytes:
    """Build a DNS response for *query* with the given (type, ttl, rdata) answers."""
    query_id, _, _, _, _, _ = struct.unpack("!HHHHHH", query[:12])
    offset = 12
    while query[offset] != 0:
        offset += 1 + query[offset]
    question_end = offset + 1 + 4
    question = query[12:question_end]
    header = struct.pack("!HHHHHH", query_id, 0x8180 | rcode, 1, len(answers), 0, 0)
    body = bytearray(question)
    for record_type, ttl, rdata in answers:
        body += b"\xc0\x0c" + struct.pack("!HHIH", record_type, 1, ttl, len(rdata)) + rdata
    return header + bytes(body)


class FakeDnsServer:
    """Tiny UDP DNS responder used to test the wire client offline."""

    def __init__(self, transform: Any) -> None:
        self._transform = transform
        self._stop = threading.Event()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.1)
        self.port = self._socket.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self._socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            response = self._transform(data)
            if response:
                try:
                    self._socket.sendto(response, peer)
                except OSError:
                    break

    def close(self) -> None:
        self._stop.set()
        self._socket.close()
        self._thread.join(timeout=2)


def dns_query_type(query: bytes) -> int:
    """Extract the QTYPE from a raw DNS query packet."""
    offset = 12
    while query[offset] != 0:
        offset += 1 + query[offset]
    return struct.unpack("!H", query[offset + 1 : offset + 3])[0]


def standard_dns_responder(query: bytes) -> bytes:
    """Answer a DNS query with a fixed but realistic record set."""
    record_type = dns_query_type(query)
    if record_type == dnsdiag.QTYPES["A"]:
        return build_dns_response(
            query,
            [
                (dnsdiag.QTYPES["A"], 300, bytes([192, 0, 2, 5])),
                (dnsdiag.QTYPES["A"], 300, bytes([192, 0, 2, 6])),
            ],
        )
    if record_type == dnsdiag.QTYPES["AAAA"]:
        return build_dns_response(
            query,
            [(dnsdiag.QTYPES["AAAA"], 300, bytes.fromhex("20010db8000000000000000000000001"))],
        )
    if record_type == dnsdiag.QTYPES["MX"]:
        rdata = struct.pack("!H", 10) + dnsdiag.encode_name("mail.example.com")
        return build_dns_response(query, [(dnsdiag.QTYPES["MX"], 300, rdata)])
    if record_type == dnsdiag.QTYPES["TXT"]:
        return build_dns_response(
            query, [(dnsdiag.QTYPES["TXT"], 300, b"\x0bhello world")]
        )
    if record_type == dnsdiag.QTYPES["NS"]:
        return build_dns_response(
            query, [(dnsdiag.QTYPES["NS"], 300, dnsdiag.encode_name("ns1.example.com"))]
        )
    if record_type == dnsdiag.QTYPES["PTR"]:
        return build_dns_response(
            query, [(dnsdiag.QTYPES["PTR"], 300, dnsdiag.encode_name("host.example.com"))]
        )
    return build_dns_response(query, [], rcode=3)


class _TestHttpHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # noqa: D401 - silence test server
        """Suppress request logging."""

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path == "/ok":
            body = b"netops-test-body"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Test-Header", "netops")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
        elif self.path == "/chain":
            self.send_response(301)
            self.send_header("Location", "/redirect")
            self.end_headers()
        elif self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


@contextlib.contextmanager
def http_server() -> Iterator[str]:
    """Yield the base URL of a local HTTP test server."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TestHttpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
