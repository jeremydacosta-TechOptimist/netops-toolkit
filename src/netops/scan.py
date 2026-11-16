"""TCP connect scanning and ping-style reachability probes."""

from __future__ import annotations

import socket
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from .errors import NetopsError

DEFAULT_TIMEOUT = 0.75
DEFAULT_WORKERS = 64
MAX_WORKERS = 256
MAX_PORT = 65535
DEFAULT_PORTS = (22, 80, 443)

#: Curated TCP service names shown as hints next to scanned ports.
SERVICE_HINTS: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp-server",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    500: "isakmp",
    514: "syslog",
    515: "printer",
    548: "afp",
    554: "rtsp",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    902: "vmware",
    989: "ftps-data",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "ms-sql-s",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker",
    2376: "docker-tls",
    3000: "grafana",
    3306: "mysql",
    3389: "ms-wbt-server",
    5060: "sip",
    5222: "xmpp",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    6443: "kubernetes",
    8080: "http-alt",
    8443: "https-alt",
    8888: "sun-answerbook",
    9090: "prometheus",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcache",
    27017: "mongodb",
}

#: Frequently probed ports for the ``-p top`` shortcut.
COMMON_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    587,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    9200,
)


def parse_ports(spec: str) -> list[int]:
    """Parse a port specification such as ``22,80,8000-8010`` or ``top``."""
    ports: set[int] = set()
    for raw_token in spec.split(","):
        token = raw_token.strip().lower()
        if not token:
            raise NetopsError(f"invalid port specification {spec!r}")
        if token == "top":
            ports.update(COMMON_PORTS)
            continue
        if "-" in token:
            start_text, _, end_text = token.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise NetopsError(f"invalid port range {raw_token.strip()!r}") from exc
            if start < 1 or end > MAX_PORT or start > end:
                raise NetopsError(
                    f"port range {raw_token.strip()!r} must use ports 1-{MAX_PORT} in ascending order"
                )
            ports.update(range(start, end + 1))
            continue
        try:
            port = int(token)
        except ValueError as exc:
            raise NetopsError(f"invalid port {raw_token.strip()!r}") from exc
        if not 1 <= port <= MAX_PORT:
            raise NetopsError(f"port {port} is outside the valid range 1-{MAX_PORT}")
        ports.add(port)
    if not ports:
        raise NetopsError("no ports selected")
    return sorted(ports)


def resolve_host(host: str) -> list[str]:
    """Resolve *host* and return its addresses, preferring IPv4."""
    target = host.strip()
    if not target:
        raise NetopsError("host must not be empty")
    try:
        infos = socket.getaddrinfo(target, 0, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise NetopsError(f"cannot resolve host {target!r}: {exc}") from exc
    addresses: list[str] = []
    for family, _, _, _, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = sockaddr[0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise NetopsError(f"cannot resolve host {target!r} to a usable IP address")
    ipv4 = [address for address in addresses if ":" not in address]
    ipv6 = [address for address in addresses if ":" in address]
    return ipv4 + ipv6


@dataclass(frozen=True)
class PortResult:
    """Outcome of one TCP connect probe."""

    port: int
    state: str
    service: str | None
    latency_ms: float | None
    error: str | None = None


def probe_tcp(address: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> PortResult:
    """Attempt a TCP connection to *address*:*port* and classify the result."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    service = SERVICE_HINTS.get(port)
    started = time.perf_counter()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
    except ConnectionRefusedError:
        return PortResult(port, "closed", service, None)
    except (TimeoutError, socket.timeout):
        return PortResult(port, "filtered", service, None, f"no response within {timeout:.2f}s")
    except OSError as exc:
        return PortResult(port, "error", service, None, str(exc))
    else:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return PortResult(port, "open", service, latency_ms)
    finally:
        sock.close()


def scan_ports(
    host: str,
    ports: Sequence[int] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    workers: int = DEFAULT_WORKERS,
) -> dict[str, Any]:
    """Run a multithreaded TCP connect scan against *host*."""
    port_list = sorted({int(port) for port in (ports if ports is not None else DEFAULT_PORTS)})
    if not port_list:
        raise NetopsError("at least one port is required")
    for port in port_list:
        if not 1 <= port <= MAX_PORT:
            raise NetopsError(f"port {port} is outside the valid range 1-{MAX_PORT}")
    if timeout <= 0:
        raise NetopsError("timeout must be greater than zero")
    worker_count = max(1, min(int(workers), MAX_WORKERS, len(port_list)))
    addresses = resolve_host(host)
    target = addresses[0]

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="netops-scan") as executor:
        results = list(executor.map(lambda port: probe_tcp(target, port, timeout), port_list))
    elapsed = time.perf_counter() - started
    results.sort(key=lambda result: result.port)

    counts = {"open": 0, "closed": 0, "filtered": 0, "error": 0}
    for result in results:
        counts[result.state] += 1

    return {
        "host": host,
        "addresses": addresses,
        "target": target,
        "timeout_seconds": timeout,
        "workers": worker_count,
        "elapsed_seconds": round(elapsed, 3),
        "scanned": len(results),
        "counts": counts,
        "results": [
            {
                "port": result.port,
                "state": result.state,
                "service": result.service,
                "latency_ms": result.latency_ms,
                "error": result.error,
            }
            for result in results
        ],
    }


@dataclass(frozen=True)
class ReachResult:
    """Reachability outcome for a single target."""

    target: str
    address: str
    reachable: bool
    state: str
    port: int | None
    latency_ms: float | None
    detail: str


def check_reachability(
    targets: Sequence[str],
    ports: Sequence[int] | None = None,
    timeout: float = 1.0,
    tries: int = 2,
) -> dict[str, Any]:
    """Probe *targets* over TCP as a ping substitute.

    A target is reported reachable when any probe receives a response, either a
    completed handshake or a TCP reset from a closed port. Both prove that the
    IP layer reaches the host; the state column distinguishes the two.
    """
    if not targets:
        raise NetopsError("at least one target is required")
    probe_ports: list[int] = []
    for port in ports if ports is not None else (443,):
        if not 1 <= int(port) <= MAX_PORT:
            raise NetopsError(f"port {port} is outside the valid range 1-{MAX_PORT}")
        if int(port) not in probe_ports:
            probe_ports.append(int(port))
    if timeout <= 0:
        raise NetopsError("timeout must be greater than zero")
    if tries < 1:
        raise NetopsError("tries must be at least 1")

    results: list[dict[str, Any]] = []
    for target in targets:
        stripped = target.strip()
        if not stripped:
            raise NetopsError("target must not be empty")
        addresses = resolve_host(stripped)
        address = addresses[0]
        reachable = False
        state = "unreachable"
        hit_port: int | None = None
        latency: float | None = None
        detail = ""
        for port in probe_ports:
            last_state = "unreachable"
            last_error: str | None = None
            for _ in range(tries):
                probe = probe_tcp(address, port, timeout)
                if probe.state in ("open", "closed"):
                    reachable = True
                    state = "open" if probe.state == "open" else "refused"
                    hit_port = port
                    latency = probe.latency_ms
                    detail = (
                        f"tcp/{port} open"
                        if probe.state == "open"
                        else f"tcp/{port} refused (host responded)"
                    )
                    break
                last_state = probe.state
                last_error = probe.error
            if reachable:
                break
            state = "unreachable" if last_state == "filtered" else last_state
            detail = last_error or f"no response on tcp/{port}"
        results.append(
            {
                "target": stripped,
                "address": address,
                "reachable": reachable,
                "state": state,
                "port": hit_port,
                "latency_ms": latency,
                "detail": detail,
            }
        )

    reachable_count = sum(1 for result in results if result["reachable"])
    return {
        "targets": [result["target"] for result in results],
        "ports": probe_ports,
        "timeout_seconds": timeout,
        "tries": tries,
        "reachable_count": reachable_count,
        "unreachable_count": len(results) - reachable_count,
        "results": results,
    }
