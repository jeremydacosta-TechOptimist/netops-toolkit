"""DNS diagnostics built on the standard library socket API.

A/AAAA answers could be fetched with ``socket.getaddrinfo``, but MX, TXT, NS and
PTR records are not exposed there. This module therefore implements the small
subset of the DNS wire format that the CLI needs, using ``socket`` directly.
"""

from __future__ import annotations

import ipaddress
import os
import random
import socket
import struct
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .errors import NetopsError

QTYPES: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
QTYPE_NAMES: dict[int, str] = {value: name for name, value in QTYPES.items()}
RCODE_NAMES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}
DEFAULT_PORT = 53
DEFAULT_TIMEOUT = 3.0
MAX_UDP_PAYLOAD = 4096
CLASS_IN = 1
QUERY_FLAGS = 0x0100  # recursion desired


class DnsFormatError(NetopsError):
    """Raised when a DNS response cannot be decoded."""


def normalize_qtype(value: str) -> str:
    """Validate and normalise a DNS record type name."""
    record_type = value.strip().upper()
    if record_type not in QTYPES:
        supported = ", ".join(QTYPES)
        raise NetopsError(f"unsupported DNS record type {value!r}; choose from {supported}")
    return record_type


def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format (``.`` is the root)."""
    stripped = name.strip()
    if stripped == ".":
        return b"\x00"
    normalized = stripped.rstrip(".")
    if not normalized:
        raise NetopsError("DNS name must not be empty")
    if len(normalized) > 253:
        raise NetopsError(f"DNS name {name!r} is longer than 253 characters")
    try:
        labels = [label.encode("ascii") for label in normalized.split(".")]
    except UnicodeEncodeError as exc:
        raise NetopsError(f"DNS name {name!r} must use ASCII characters") from exc
    encoded = bytearray()
    for label in labels:
        if not label:
            raise NetopsError(f"DNS name {name!r} contains an empty label")
        if len(label) > 63:
            raise NetopsError(f"DNS label {label!r} is longer than 63 bytes")
        encoded.append(len(label))
        encoded.extend(label)
    encoded.append(0)
    return bytes(encoded)


def build_query(name: str, qtype: str, query_id: int | None = None) -> bytes:
    """Build a recursive IN query packet."""
    record_type = QTYPES[normalize_qtype(qtype)]
    if query_id is None:
        query_id = random.randrange(0, 65536)
    header = struct.pack("!HHHHHH", query_id, QUERY_FLAGS, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", record_type, CLASS_IN)


def parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at *offset*."""
    labels: list[str] = []
    original_offset: int | None = None
    jumps = 0
    while True:
        if offset >= len(data):
            raise DnsFormatError("truncated DNS name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsFormatError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if original_offset is None:
                original_offset = offset + 2
            offset = pointer
            jumps += 1
            if jumps > 64:
                raise DnsFormatError("DNS compression pointer loop detected")
            continue
        if length & 0xC0:
            raise DnsFormatError("unsupported DNS label type")
        offset += 1
        if offset + length > len(data):
            raise DnsFormatError("truncated DNS label")
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    if original_offset is not None:
        offset = original_offset
    return ".".join(labels), offset


def _decode_rdata(data: bytes, start: int, end: int, record_type: int) -> str:
    """Decode the RDATA of one resource record into display text."""
    rdata = data[start:end]
    if record_type == QTYPES["A"]:
        if len(rdata) != 4:
            raise DnsFormatError("malformed A record")
        return str(ipaddress.IPv4Address(rdata))
    if record_type == QTYPES["AAAA"]:
        if len(rdata) != 16:
            raise DnsFormatError("malformed AAAA record")
        return str(ipaddress.IPv6Address(rdata))
    if record_type == QTYPES["MX"]:
        if len(rdata) < 3:
            raise DnsFormatError("malformed MX record")
        preference = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = parse_name(data, start + 2)
        return f"{preference} {exchange or '.'}"
    if record_type in (QTYPES["NS"], QTYPES["CNAME"], QTYPES["PTR"]):
        target, _ = parse_name(data, start)
        return target
    if record_type == QTYPES["TXT"]:
        chunks: list[str] = []
        cursor = 0
        while cursor < len(rdata):
            chunk_length = rdata[cursor]
            cursor += 1
            if cursor + chunk_length > len(rdata):
                raise DnsFormatError("malformed TXT record")
            chunks.append(rdata[cursor : cursor + chunk_length].decode("utf-8", errors="replace"))
            cursor += chunk_length
        return " ".join(chunks)
    return rdata.hex()


def parse_response(data: bytes) -> dict[str, Any]:
    """Decode a DNS response packet into a JSON-friendly dictionary."""
    if len(data) < 12:
        raise DnsFormatError("DNS response is shorter than the 12-byte header")
    query_id, flags, question_count, answer_count, _, _ = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    offset = 12
    questions: list[dict[str, Any]] = []
    for _ in range(question_count):
        question_name, offset = parse_name(data, offset)
        if offset + 4 > len(data):
            raise DnsFormatError("truncated question section")
        record_type, record_class = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append(
            {
                "name": question_name,
                "type": QTYPE_NAMES.get(record_type, f"TYPE{record_type}"),
                "class": record_class,
            }
        )

    answers: list[dict[str, Any]] = []
    for _ in range(answer_count):
        answer_name, offset = parse_name(data, offset)
        if offset + 10 > len(data):
            raise DnsFormatError("truncated answer section")
        record_type, _, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata_end = offset + rdlength
        if rdata_end > len(data):
            raise DnsFormatError("truncated resource record data")
        value = _decode_rdata(data, offset, rdata_end, record_type)
        answers.append(
            {
                "name": answer_name,
                "type": QTYPE_NAMES.get(record_type, f"TYPE{record_type}"),
                "ttl": ttl,
                "value": value,
            }
        )
        offset = rdata_end

    return {
        "id": query_id,
        "flags": flags,
        "rcode": rcode,
        "status": RCODE_NAMES.get(rcode, f"RCODE{rcode}"),
        "truncated": bool(flags & 0x0200),
        "questions": questions,
        "answers": answers,
        "answer_count": len(answers),
    }


def parse_server(value: str) -> tuple[str, int]:
    """Parse ``ADDRESS``, ``ADDRESS:PORT`` or ``[IPv6]:PORT``."""
    text = value.strip()
    if not text:
        raise NetopsError("DNS server address must not be empty")
    if text.startswith("["):
        host, separator, remainder = text[1:].partition("]")
        if not separator:
            raise NetopsError(f"invalid DNS server {value!r}")
        if remainder:
            if not remainder.startswith(":"):
                raise NetopsError(f"invalid DNS server {value!r}")
            return host, _parse_port(remainder[1:])
        return host, DEFAULT_PORT
    if text.count(":") == 1:
        host, _, port_text = text.partition(":")
        return host, _parse_port(port_text)
    return text, DEFAULT_PORT


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise NetopsError(f"invalid DNS server port {value!r}") from exc
    if not 1 <= port <= 65535:
        raise NetopsError(f"DNS server port {port} is outside the valid range 1-65535")
    return port


def format_server(host: str, port: int) -> str:
    """Render a server address for display and for :func:`query`."""
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def detect_nameservers() -> list[str]:
    """Return the DNS servers configured on this machine, in preference order."""
    candidates: list[str] = []
    if os.name == "nt":
        try:
            import winreg
        except ImportError:  # pragma: no cover - winreg always exists on Windows
            return []
        try:
            parameters = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, parameters) as key:
                for value_name in ("NameServer", "DhcpNameServer"):
                    try:
                        value, _ = winreg.QueryValueEx(key, value_name)
                    except FileNotFoundError:
                        continue
                    candidates.extend(str(value).replace(",", " ").split())
            interfaces_name = parameters + r"\Interfaces"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interfaces_name) as interfaces:
                index = 0
                while True:
                    try:
                        interface_name = winreg.EnumKey(interfaces, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(interfaces, interface_name) as interface:
                            for value_name in ("NameServer", "DhcpNameServer"):
                                try:
                                    value, _ = winreg.QueryValueEx(interface, value_name)
                                except FileNotFoundError:
                                    continue
                                candidates.extend(str(value).replace(",", " ").split())
                    except OSError:
                        continue
        except OSError:
            return []
    else:  # pragma: no cover - exercised on POSIX CI runners
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        candidates.append(parts[1])
        except OSError:
            return []

    servers: list[str] = []
    for candidate in candidates:
        address = candidate.strip()
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        if address not in servers:
            servers.append(address)
    return servers


@dataclass(frozen=True)
class DnsRecord:
    """A decoded answer record."""

    name: str
    record_type: str
    ttl: int
    value: str


@dataclass(frozen=True)
class QueryOutcome:
    """Result of one DNS query."""

    query_name: str
    record_type: str
    status: str
    rcode: int
    answers: list[DnsRecord]
    elapsed_ms: float
    truncated: bool = False


def _lookup_name(name: str, record_type: str) -> str:
    """Return the name to query, converting IPs for PTR lookups."""
    text = name.strip()
    if not text:
        raise NetopsError("DNS name must not be empty")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        if record_type == "PTR":
            raise NetopsError("PTR lookups require an IP address") from None
        return text
    if record_type == "PTR":
        return address.reverse_pointer
    raise NetopsError(
        f"{record_type} lookups require a hostname, not the IP address {text}; use --type PTR"
    )


def query(
    name: str,
    qtype: str,
    server: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> QueryOutcome:
    """Send one DNS query over UDP and decode the response."""
    record_type = normalize_qtype(qtype)
    query_name = _lookup_name(name, record_type)
    host, port = parse_server(server)
    if timeout <= 0:
        raise NetopsError("timeout must be greater than zero")
    query_id = random.randrange(0, 65536)
    packet = build_query(query_name, record_type, query_id)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(MAX_UDP_PAYLOAD)
    except (TimeoutError, socket.timeout) as exc:
        raise NetopsError(
            f"DNS query for {query_name} timed out after {timeout:.1f}s ({format_server(host, port)})"
        ) from exc
    except OSError as exc:
        raise NetopsError(
            f"DNS query for {query_name} failed against {format_server(host, port)}: {exc}"
        ) from exc
    finally:
        sock.close()
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    parsed = parse_response(data)
    if parsed["id"] != query_id:
        raise NetopsError(f"DNS response id mismatch for {query_name}")
    answers = [
        DnsRecord(
            name=answer["name"],
            record_type=answer["type"],
            ttl=answer["ttl"],
            value=answer["value"],
        )
        for answer in parsed["answers"]
    ]
    return QueryOutcome(
        query_name=query_name,
        record_type=record_type,
        status=parsed["status"],
        rcode=parsed["rcode"],
        answers=answers,
        elapsed_ms=elapsed_ms,
        truncated=parsed["truncated"],
    )


def _select_nameserver(candidates: Sequence[str], timeout: float) -> str:
    """Return the first configured nameserver that answers a root NS query.

    Multiple interfaces (VPNs, virtual adapters) can register stale DNS servers
    in the registry, so a cheap probe avoids reporting a failure against a
    resolver that is not actually reachable.
    """
    probe_timeout = min(timeout, 1.5)
    for candidate in candidates:
        try:
            query(".", "NS", format_server(candidate, DEFAULT_PORT), probe_timeout)
        except NetopsError:
            continue
        return candidate
    return candidates[0]


def run_queries(
    name: str,
    qtypes: Sequence[str] | None = None,
    server: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Run several record lookups for *name* and return a combined report."""
    requested: list[str] = []
    for candidate in qtypes or ():
        record_type = normalize_qtype(candidate)
        if record_type not in requested:
            requested.append(record_type)
    if not requested:
        try:
            ipaddress.ip_address(name.strip())
        except ValueError:
            requested = ["A", "AAAA"]
        else:
            requested = ["PTR"]

    if server is None:
        detected = detect_nameservers()
        if not detected:
            raise NetopsError("no system DNS resolver detected; pass --server ADDRESS")
        host, port = _select_nameserver(detected, timeout), DEFAULT_PORT
        system_resolver = True
    else:
        host, port = parse_server(server)
        system_resolver = False
    server_text = format_server(host, port)

    started = time.perf_counter()
    queries: list[dict[str, Any]] = []
    for record_type in requested:
        try:
            outcome = query(name, record_type, server_text, timeout)
        except NetopsError as exc:
            queries.append(
                {
                    "name": name,
                    "type": record_type,
                    "status": "ERROR",
                    "answer_count": 0,
                    "answers": [],
                    "elapsed_ms": None,
                    "error": str(exc),
                }
            )
            continue
        queries.append(
            {
                "name": outcome.query_name,
                "type": outcome.record_type,
                "status": outcome.status,
                "answer_count": len(outcome.answers),
                "answers": [
                    {
                        "name": answer.name,
                        "type": answer.record_type,
                        "ttl": answer.ttl,
                        "value": answer.value,
                    }
                    for answer in outcome.answers
                ],
                "elapsed_ms": outcome.elapsed_ms,
                "error": None,
            }
        )
    total_elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    ok = all(
        entry["error"] is None and entry["status"] == "NOERROR" for entry in queries
    )
    return {
        "name": name,
        "server": server_text,
        "system_resolver": system_resolver,
        "queries": queries,
        "ok": ok,
        "total_elapsed_ms": total_elapsed_ms,
    }
