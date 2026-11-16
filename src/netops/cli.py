"""Command-line interface for the netops toolbox."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Any

from . import __version__, dnsdiag, httpdiag, oui, scan, subnets, units, vlsm
from .errors import EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, NetopsError
from .output import format_count, format_percent, format_table, print_json

DESCRIPTION = "Zero-dependency network operations toolbox for the command line."
EPILOG = "Run 'netops COMMAND --help' for the options of each command."

DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "PTR", "CNAME")


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid number {value!r}") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return number


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer {value!r}") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return number


def _non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer {value!r}") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("value must not be negative")
    return number


def _worker_count(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer {value!r}") from exc
    if not 1 <= number <= scan.MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"workers must be between 1 and {scan.MAX_WORKERS}")
    return number


def _prefix_length(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid prefix length {value!r}") from exc
    if not 0 <= number <= 128:
        raise argparse.ArgumentTypeError("prefix length must be between 0 and 128")
    return number


def _cidr(value: str) -> str:
    try:
        return str(subnets.parse_network(value))
    except NetopsError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _cidr_input(value: str) -> str:
    try:
        subnets.parse_interface(value)
    except NetopsError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value.strip()


def _mac_address(value: str) -> str:
    try:
        oui.parse_mac(value)
    except NetopsError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


def _port_list(value: str) -> list[int]:
    try:
        return scan.parse_ports(value)
    except NetopsError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _vlan_request(value: str) -> tuple[str, int]:
    name, separator, hosts = value.partition("=")
    if not separator or not name.strip():
        raise argparse.ArgumentTypeError(
            f"invalid VLAN requirement {value!r}; expected NAME=HOSTS, e.g. VLAN10=50"
        )
    try:
        host_count = int(hosts)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid host count in {value!r}; expected an integer"
        ) from exc
    if host_count < 1:
        raise argparse.ArgumentTypeError(f"host count in {value!r} must be at least 1")
    return name.strip(), host_count


def _size_value(value: str) -> str:
    try:
        units.parse_size(value)
    except NetopsError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


def _rate_value(value: str) -> str:
    try:
        units.parse_rate(value)
    except NetopsError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    word = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {word}"


def _network_flags(report: dict[str, Any]) -> str:
    flags = [
        label
        for label, key in (
            ("private", "is_private"),
            ("loopback", "is_loopback"),
            ("link-local", "is_link_local"),
            ("multicast", "is_multicast"),
        )
        if report[key]
    ]
    return ", ".join(flags) if flags else "global"


def _cmd_subnet(args: argparse.Namespace) -> int:
    reports = [subnets.network_report(cidr) for cidr in args.cidrs]
    if args.split_prefix is not None:
        splits = [
            subnets.split_network(cidr, args.split_prefix) for cidr in args.cidrs
        ]
        if args.json:
            print_json({"networks": reports, "splits": splits})
            return EXIT_OK
        for index, report in enumerate(reports):
            split = splits[index]
            print(f"Split of {report['cidr']} into /{split['new_prefix_length']} subnets")
            print(f"Subnets : {format_count(split['count'])}")
            print()
            rows = []
            for subnet_cidr in split["subnets"]:
                child = subnets.network_report(subnet_cidr)
                rows.append(
                    (
                        child["cidr"],
                        child["network_address"],
                        child["broadcast_address"] or "-",
                        format_count(child["usable_hosts"]),
                    )
                )
            print(format_table(("Subnet", "Network", "Broadcast", "Usable hosts"), rows))
        return EXIT_OK

    if args.json:
        print_json({"networks": reports})
        return EXIT_OK
    for index, report in enumerate(reports):
        if index:
            print()
        if report["host_bits_set"]:
            print(f"Input         : {report['input']} (host bits normalised)")
        print(f"Network       : {report['cidr']}")
        print(f"Version       : IPv{report['version']} (/{report['prefix_length']})")
        print(f"Network addr  : {report['network_address']}")
        print(f"Broadcast     : {report['broadcast_address'] or '-'}")
        print(f"Netmask       : {report['netmask'] or '-'}")
        print(f"Wildcard      : {report['wildcard'] or '-'}")
        print(f"Host range    : {report['first_host']} - {report['last_host']}")
        print(f"Addresses     : {format_count(report['total_addresses'])}")
        print(f"Usable hosts  : {format_count(report['usable_hosts'])}")
        print(f"Flags         : {_network_flags(report)}")
    return EXIT_OK


def _cmd_summarize(args: argparse.Namespace) -> int:
    report = subnets.summarize_networks(args.cidrs)
    if args.json:
        print_json(report)
        return EXIT_OK
    print(f"Input networks ({report['input_count']}):")
    for cidr in report["input"]:
        print(f"  {cidr}")
    print()
    print(f"Summarised networks ({report['collapsed_count']}):")
    for cidr in report["collapsed"]:
        print(f"  {cidr}")
    print()
    print(f"Networks saved   : {format_count(report['saved_networks'])}")
    print(f"Addresses covered: {format_count(report['addresses_covered'])}")
    return EXIT_OK


def _cmd_overlap(args: argparse.Namespace) -> int:
    report = subnets.find_overlaps(args.cidrs)
    if args.json:
        print_json(report)
        return EXIT_RUNTIME if report["overlap_count"] else EXIT_OK
    if not report["pairs"]:
        print(f"No overlaps found across {len(report['networks'])} networks.")
        return EXIT_OK
    print(f"Overlaps detected: {report['overlap_count']}")
    print()
    rows = [(pair["first"], pair["second"], pair["relation"]) for pair in report["pairs"]]
    print(format_table(("First network", "Second network", "Relation"), rows))
    return EXIT_RUNTIME


def _cmd_vlsm(args: argparse.Namespace) -> int:
    report = vlsm.plan_vlsm(args.parent, args.requests)
    if args.json:
        print_json(report)
        return EXIT_OK
    print(f"Parent : {report['parent']} ({format_count(report['parent_addresses'])} addresses)")
    print()
    rows = [
        (
            allocation["vlan"],
            format_count(allocation["requested_hosts"]),
            f"/{allocation['prefix_length']}",
            allocation["cidr"],
            format_count(allocation["usable_hosts"]),
            f"{allocation['first_host']} - {allocation['last_host']}",
            format_percent(allocation["utilization_percent"]),
        )
        for allocation in report["allocations"]
    ]
    print(
        format_table(
            ("VLAN", "Requested", "Prefix", "Network", "Usable", "Host range", "Util"),
            rows,
        )
    )
    print()
    print(f"Free space   : {format_count(report['free_addresses'])} addresses")
    if report["free_blocks"]:
        print(f"Free blocks  : {', '.join(report['free_blocks'])}")
    print(
        f"Capacity     : {format_count(report['allocated_addresses'])}/"
        f"{format_count(report['allocated_addresses'] + report['free_addresses'])} addresses "
        f"({format_percent(report['capacity_percent'])})"
    )
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    report = scan.scan_ports(
        args.host,
        ports=args.ports,
        timeout=args.timeout,
        workers=args.workers,
    )
    if args.json:
        print_json(report)
        return EXIT_OK
    print(f"Target  : {report['host']} ({report['target']})")
    print(
        f"Ports   : {report['scanned']} | workers: {report['workers']} "
        f"| timeout: {report['timeout_seconds']:.2f}s"
    )
    print()
    rows = [
        (
            f"{result['port']}/tcp",
            result["state"],
            result["service"] or "-",
            f"{result['latency_ms']:.2f} ms" if result["latency_ms"] is not None else "-",
        )
        for result in report["results"]
    ]
    print(format_table(("Port", "State", "Service", "Latency"), rows))
    print()
    counts = report["counts"]
    print(
        f"{report['scanned']} scanned: {counts['open']} open, {counts['closed']} closed, "
        f"{counts['filtered']} filtered, {counts['error']} error "
        f"in {report['elapsed_seconds']:.2f}s"
    )
    return EXIT_OK


def _cmd_reach(args: argparse.Namespace) -> int:
    report = scan.check_reachability(
        args.targets,
        ports=args.ports,
        timeout=args.timeout,
        tries=args.tries,
    )
    if args.json:
        print_json(report)
        return EXIT_RUNTIME if report["unreachable_count"] else EXIT_OK
    rows = [
        (
            result["target"],
            result["address"],
            result["state"],
            str(result["port"]) if result["port"] is not None else "-",
            f"{result['latency_ms']:.2f} ms" if result["latency_ms"] is not None else "-",
            result["detail"],
        )
        for result in report["results"]
    ]
    print(format_table(("Target", "Address", "State", "Port", "Latency", "Detail"), rows))
    print()
    print(
        f"{report['reachable_count']} reachable, {report['unreachable_count']} unreachable "
        f"(ports: {', '.join(str(port) for port in report['ports'])}, "
        f"timeout: {report['timeout_seconds']:.2f}s)"
    )
    return EXIT_RUNTIME if report["unreachable_count"] else EXIT_OK


def _cmd_dns(args: argparse.Namespace) -> int:
    report = dnsdiag.run_queries(
        args.name,
        qtypes=args.qtypes,
        server=args.server,
        timeout=args.timeout,
    )
    if args.json:
        print_json(report)
        return EXIT_OK if report["ok"] else EXIT_RUNTIME
    resolver = "system resolver" if report["system_resolver"] else "--server"
    print(f"DNS diagnostics for {report['name']}")
    print(f"Server: {report['server']} ({resolver})")
    print()
    for index, query in enumerate(report["queries"]):
        if index:
            print()
        if query["error"]:
            print(f"{query['type']} {query['name']}  ERROR")
            print(f"  {query['error']}")
            continue
        print(
            f"{query['type']} {query['name']}  {query['status']}  "
            f"{_plural(query['answer_count'], 'answer')}  {query['elapsed_ms']:.2f} ms"
        )
        if not query["answers"]:
            print("  (no answer records)")
        for answer in query["answers"]:
            print(f"  {answer['value']}  ttl {answer['ttl']}")
    print()
    failed = sum(1 for query in report["queries"] if query["error"] or query["status"] != "NOERROR")
    print(
        f"Summary: {_plural(len(report['queries']), 'query', 'queries')}, "
        f"{len(report['queries']) - failed} NOERROR, {failed} failed, "
        f"total {report['total_elapsed_ms']:.2f} ms"
    )
    return EXIT_OK if report["ok"] else EXIT_RUNTIME


def _cmd_http(args: argparse.Namespace) -> int:
    report = httpdiag.request_url(
        args.url,
        timeout=args.timeout,
        max_redirects=args.max_redirects,
        insecure=args.insecure,
    )
    if args.json:
        print_json(report)
        return EXIT_OK if report["status"] < 400 else EXIT_RUNTIME
    print(f"GET {report['url']}")
    print(f"Final URL : {report['final_url']}")
    print(f"Status    : {report['status']} {report['reason']}")
    print(f"Remote    : {report['remote'] or '-'}")
    print(f"Elapsed   : {report['elapsed_ms']:.2f} ms")
    print()
    if report["redirects"]:
        print(f"Redirects ({len(report['redirects'])}):")
        for index, hop in enumerate(report["redirects"], start=1):
            print(f"  {index}. {hop['status']} {hop['url']} -> {hop['location']}")
    else:
        print("Redirects: none")
    print()
    if report["tls"]:
        tls = report["tls"]
        print("TLS")
        print(f"  Protocol    : {tls['protocol'] or '-'}")
        if tls["cipher"]:
            print(f"  Cipher      : {tls['cipher']} ({tls['bits']} bits)")
        print(f"  Verified    : {'yes' if tls['verified'] else 'no (--insecure)'}")
        if tls["subject"]:
            subject = tls["subject"].get("commonName") or next(iter(tls["subject"].values()))
            print(f"  Subject     : {subject}")
        if tls["issuer"]:
            issuer = tls["issuer"].get("commonName") or next(iter(tls["issuer"].values()))
            print(f"  Issuer      : {issuer}")
        if tls["not_before"]:
            print(f"  Valid from  : {tls['not_before']}")
        if tls["not_after"]:
            print(f"  Valid until : {tls['not_after']}")
        if tls["days_remaining"] is not None:
            print(f"  Days left   : {tls['days_remaining']}")
        if tls["subject_alt_names"]:
            print(f"  SANs        : {', '.join(tls['subject_alt_names'])}")
        print()
    print(f"Headers ({len(report['headers'])}):")
    for header in report["headers"]:
        print(f"  {header['name']}: {header['value']}")
    print()
    print(
        f"Body: {report['body_bytes_read']} bytes read"
        + (
            f" (Content-Length: {report['content_length']})"
            if report["content_length"] is not None
            else ""
        )
    )
    return EXIT_OK if report["status"] < 400 else EXIT_RUNTIME


def _cmd_mac(args: argparse.Namespace) -> int:
    addresses = [oui.parse_mac(value) for value in args.macs]
    if args.json:
        print_json(
            {
                "addresses": [
                    {
                        "input": address.input,
                        "normalized": address.normalized,
                        "oui": address.oui,
                        "vendor": address.vendor,
                        "locally_administered": address.locally_administered,
                        "multicast": address.multicast,
                    }
                    for address in addresses
                ]
            }
        )
        return EXIT_OK
    if len(addresses) == 1:
        address = addresses[0]
        print(f"MAC        : {address.normalized}")
        print(f"OUI        : {address.oui}")
        print(f"Vendor     : {address.vendor or 'Unknown (no match in the curated OUI table)'}")
        scope = "multicast" if address.multicast else "unicast"
        administration = (
            "locally administered" if address.locally_administered else "globally administered"
        )
        print(f"Scope      : {scope}, {administration}")
        return EXIT_OK
    rows = [
        (
            address.normalized,
            address.oui,
            address.vendor or "Unknown",
        )
        for address in addresses
    ]
    print(format_table(("MAC", "OUI", "Vendor"), rows))
    return EXIT_OK


def _cmd_bandwidth(args: argparse.Namespace) -> int:
    report = units.calculate(args.size, args.rate)
    if args.json:
        print_json(report)
        return EXIT_OK
    if report["size"]:
        size = report["size"]
        print(f"Data size: {size['input']}")
        print(f"  Bytes   : {format_count(size['bytes'])}")
        print(f"  Decimal : {size['decimal']}")
        print(f"  Binary  : {size['binary']}")
    if report["rate"]:
        if report["size"]:
            print()
        rate = report["rate"]
        print(f"Link rate: {rate['input']}")
        print(f"  Bits/s  : {format_count(rate['bits_per_second'])} bit/s")
        print(
            f"  Bytes/s : {format_count(round(rate['bytes_per_second']))} B/s "
            f"({rate['megabytes_per_second']:.2f} MB/s, "
            f"{rate['mebibytes_per_second']:.2f} MiB/s)"
        )
    if report["transfer"]:
        transfer = report["transfer"]
        print()
        seconds_text = f"{transfer['seconds']:.2f} s"
        if transfer["human"] == seconds_text:
            print(f"Transfer time: {seconds_text}")
        else:
            print(f"Transfer time: {seconds_text} ({transfer['human']})")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    """Build the full argparse command tree."""
    parser = argparse.ArgumentParser(
        prog="netops",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    subnet_parser = subparsers.add_parser(
        "subnet",
        help="Inspect CIDR blocks: network, broadcast, host range and counts.",
        description="Inspect one or more IPv4/IPv6 CIDR blocks.",
    )
    subnet_parser.add_argument("cidrs", nargs="+", metavar="CIDR", type=_cidr_input)
    subnet_parser.add_argument(
        "--split",
        dest="split_prefix",
        metavar="PREFIX",
        type=_prefix_length,
        help="also split each network into subnets of PREFIX length",
    )
    subnet_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    subnet_parser.set_defaults(handler=_cmd_subnet)

    summarize_parser = subparsers.add_parser(
        "summarize",
        help="Collapse CIDRs into the smallest equivalent network list.",
        description="Summarise a list of CIDR blocks with address aggregation.",
    )
    summarize_parser.add_argument("cidrs", nargs="+", metavar="CIDR", type=_cidr)
    summarize_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    summarize_parser.set_defaults(handler=_cmd_summarize)

    overlap_parser = subparsers.add_parser(
        "overlap",
        help="Detect overlapping or nested CIDR blocks.",
        description="Check every pair of CIDR blocks for overlap (exit 1 when overlaps exist).",
    )
    overlap_parser.add_argument("cidrs", nargs="+", metavar="CIDR", type=_cidr)
    overlap_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    overlap_parser.set_defaults(handler=_cmd_overlap)

    vlsm_parser = subparsers.add_parser(
        "vlsm",
        help="Plan VLSM subnet allocations for VLAN host counts.",
        description="Allocate non-overlapping subnets inside a parent IPv4 prefix.",
    )
    vlsm_parser.add_argument("parent", metavar="PARENT_CIDR", type=_cidr)
    vlsm_parser.add_argument(
        "requests",
        nargs="+",
        metavar="VLAN=HOSTS",
        type=_vlan_request,
        help="VLAN name and requested usable hosts, for example VLAN10=50",
    )
    vlsm_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    vlsm_parser.set_defaults(handler=_cmd_vlsm)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan TCP ports on a host with a multithreaded connect scan.",
        description="Multithreaded TCP connect scan with timeouts and service hints.",
    )
    scan_parser.add_argument("host", metavar="HOST", help="hostname or IP address to scan")
    scan_parser.add_argument(
        "-p",
        "--ports",
        type=_port_list,
        default="22,80,443",
        metavar="PORTS",
        help="ports to scan: comma list, ranges (8000-8010) or 'top' (default: 22,80,443)",
    )
    scan_parser.add_argument(
        "-t", "--timeout", type=_positive_float, default=scan.DEFAULT_TIMEOUT, metavar="SECONDS"
    )
    scan_parser.add_argument(
        "-w",
        "--workers",
        type=_worker_count,
        default=scan.DEFAULT_WORKERS,
        metavar="N",
        help="number of scanner threads (default: 64)",
    )
    scan_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    scan_parser.set_defaults(handler=_cmd_scan)

    reach_parser = subparsers.add_parser(
        "reach",
        help="Probe hosts over TCP as a ping substitute.",
        description="TCP reachability probe with per-target latency (exit 1 if any target is down).",
    )
    reach_parser.add_argument("targets", nargs="+", metavar="TARGET")
    reach_parser.add_argument(
        "-p",
        "--ports",
        type=_port_list,
        default="443",
        metavar="PORTS",
        help="ports probed in order until a response is received (default: 443)",
    )
    reach_parser.add_argument(
        "-t", "--timeout", type=_positive_float, default=1.0, metavar="SECONDS"
    )
    reach_parser.add_argument(
        "--tries", type=_positive_int, default=2, metavar="N", help="attempts per port (default: 2)"
    )
    reach_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    reach_parser.set_defaults(handler=_cmd_reach)

    dns_parser = subparsers.add_parser(
        "dns",
        help="Run DNS lookups with per-query timing.",
        description=(
            "Query A, AAAA, MX, TXT, NS, PTR or CNAME records through the system resolver "
            "or an explicit server."
        ),
    )
    dns_parser.add_argument("name", metavar="NAME_OR_IP")
    dns_parser.add_argument(
        "--type",
        dest="qtypes",
        action="append",
        type=str.upper,
        choices=DNS_TYPES,
        metavar="TYPE",
        help="record type to query, repeatable (default: A, AAAA; PTR for IP addresses)",
    )
    dns_parser.add_argument(
        "--server", metavar="ADDRESS[:PORT]", help="DNS server to query instead of the system resolver"
    )
    dns_parser.add_argument(
        "-t", "--timeout", type=_positive_float, default=dnsdiag.DEFAULT_TIMEOUT, metavar="SECONDS"
    )
    dns_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    dns_parser.set_defaults(handler=_cmd_dns)

    http_parser = subparsers.add_parser(
        "http",
        help="Check HTTP status, headers, redirects and TLS certificates.",
        description="HTTP/TLS diagnostics: status, headers, redirect chain and certificate details.",
    )
    http_parser.add_argument("url", metavar="URL")
    http_parser.add_argument(
        "-t", "--timeout", type=_positive_float, default=httpdiag.DEFAULT_TIMEOUT, metavar="SECONDS"
    )
    http_parser.add_argument(
        "--max-redirects",
        type=_non_negative_int,
        default=httpdiag.DEFAULT_MAX_REDIRECTS,
        metavar="N",
    )
    http_parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify TLS certificates (certificate details are then unavailable)",
    )
    http_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    http_parser.set_defaults(handler=_cmd_http)

    mac_parser = subparsers.add_parser(
        "mac",
        help="Look up the vendor of a MAC address using the embedded OUI table.",
        description="Parse a MAC address (or bare OUI) and resolve the vendor offline.",
    )
    mac_parser.add_argument("macs", nargs="+", metavar="MAC", type=_mac_address)
    mac_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    mac_parser.set_defaults(handler=_cmd_mac)

    bandwidth_parser = subparsers.add_parser(
        "bandwidth",
        help="Convert data sizes and link rates, and estimate transfer time.",
        description="Decimal/binary data sizes, throughput conversion and transfer-time estimates.",
    )
    bandwidth_parser.add_argument(
        "--size", type=_size_value, metavar="SIZE", help="data size such as 10GB or 1.5GiB"
    )
    bandwidth_parser.add_argument(
        "--rate", type=_rate_value, metavar="RATE", help="link rate such as 100Mbps or 1Gbps"
    )
    bandwidth_parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    bandwidth_parser.set_defaults(handler=_cmd_bandwidth)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE
    if args.command == "bandwidth" and args.size is None and args.rate is None:
        parser.error("bandwidth requires --size and/or --rate")
    try:
        return int(args.handler(args))
    except NetopsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("interrupted", file=sys.stderr)
        return 130
