"""IPv4 and IPv6 subnet arithmetic: parsing, reporting, splitting and overlap checks."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Any

from .errors import NetopsError

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Interface = ipaddress.IPv4Interface | ipaddress.IPv6Interface

MAX_PREFIX_LENGTH = {4: 32, 6: 128}
SPLIT_LIMIT = 4096


def parse_network(value: str, *, strict: bool = True) -> Network:
    """Parse a CIDR string into an IPv4 or IPv6 network object.

    With ``strict=True`` (the default) host bits set in the address part, for
    example ``192.0.2.1/24``, are rejected so that typos do not silently become
    a different network. Inspection commands parse leniently instead.
    """
    try:
        return ipaddress.ip_network(value.strip(), strict=strict)
    except ValueError as exc:
        raise NetopsError(f"invalid CIDR {value!r}: {exc}") from exc


def parse_interface(value: str) -> Interface:
    """Parse an address with a prefix length, accepting host bits."""
    try:
        return ipaddress.ip_interface(value.strip())
    except ValueError as exc:
        raise NetopsError(f"invalid CIDR {value!r}: {exc}") from exc



def usable_host_count(network: Network) -> int:
    """Return the number of usable host addresses in *network*.

    IPv4 follows the usual conventions: two reserved addresses for prefixes up
    to /30, two usable addresses for a /31 point-to-point link (RFC 3021) and
    one address for a /32 host route. IPv6 has no broadcast address, so every
    address in the prefix is counted.
    """
    if network.version == 6:
        return network.num_addresses
    if network.prefixlen == 32:
        return 1
    if network.prefixlen == 31:
        return 2
    return network.num_addresses - 2


def host_range(network: Network) -> tuple[str, str]:
    """Return the first and last usable host address of *network*."""
    if network.version == 6:
        return str(network.network_address), str(network.broadcast_address)
    if network.prefixlen >= 31:
        return str(network.network_address), str(network.broadcast_address)
    return str(network.network_address + 1), str(network.broadcast_address - 1)


def network_report(value: str) -> dict[str, Any]:
    """Return a JSON-friendly description of a single CIDR block.

    Host bits in the input are normalised: ``192.0.2.10/26`` describes
    ``192.0.2.0/26`` and reports ``host_bits_set`` as ``True``.
    """
    text = value.strip()
    interface = parse_interface(text)
    network = interface.network
    first_host, last_host = host_range(network)
    return {
        "input": text,
        "host_bits_set": interface.ip != network.network_address,
        "input_address": str(interface.ip),
        "cidr": str(network),
        "version": network.version,
        "prefix_length": network.prefixlen,
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address) if network.version == 4 else None,
        "netmask": str(network.netmask) if network.version == 4 else None,
        "wildcard": str(network.hostmask) if network.version == 4 else None,
        "first_host": first_host,
        "last_host": last_host,
        "total_addresses": network.num_addresses,
        "usable_hosts": usable_host_count(network),
        "is_private": network.is_private,
        "is_loopback": network.is_loopback,
        "is_link_local": network.is_link_local,
        "is_multicast": network.is_multicast,
    }


def split_network(value: str, new_prefix_length: int) -> dict[str, Any]:
    """Split *value* into equally sized subnets of *new_prefix_length*."""
    network = parse_interface(value).network
    maximum = MAX_PREFIX_LENGTH[network.version]
    if new_prefix_length < network.prefixlen:
        raise NetopsError(
            f"cannot split /{network.prefixlen} into /{new_prefix_length}: "
            "the new prefix must be equal to or longer than the parent prefix"
        )
    if new_prefix_length > maximum:
        raise NetopsError(
            f"prefix /{new_prefix_length} is out of range for IPv{network.version} (0-{maximum})"
        )
    count = 2 ** (new_prefix_length - network.prefixlen)
    if count > SPLIT_LIMIT:
        raise NetopsError(
            f"/{network.prefixlen} split into /{new_prefix_length} produces {count} subnets; "
            f"the limit is {SPLIT_LIMIT}, use a longer prefix"
        )
    subnets = [str(subnet) for subnet in network.subnets(new_prefix=new_prefix_length)]
    return {
        "parent": str(network),
        "new_prefix_length": new_prefix_length,
        "count": count,
        "subnets": subnets,
    }


def summarize_networks(values: Sequence[str]) -> dict[str, Any]:
    """Collapse a list of CIDRs into the smallest equivalent set of blocks."""
    if not values:
        raise NetopsError("at least one CIDR is required to summarise")
    networks = [parse_network(value) for value in values]
    grouped: dict[int, list[Network]] = {}
    for network in networks:
        grouped.setdefault(network.version, []).append(network)
    collapsed: list[Network] = []
    for version in sorted(grouped):
        collapsed.extend(ipaddress.collapse_addresses(grouped[version]))
    collapsed.sort(key=lambda net: (net.version, int(net.network_address), net.prefixlen))
    return {
        "input": [str(network) for network in networks],
        "input_count": len(networks),
        "collapsed": [str(network) for network in collapsed],
        "collapsed_count": len(collapsed),
        "saved_networks": len(networks) - len(collapsed),
        "addresses_covered": sum(network.num_addresses for network in collapsed),
    }


def find_overlaps(values: Sequence[str]) -> dict[str, Any]:
    """Compare every pair of CIDRs and report the ones that overlap.

    Two CIDR blocks of the same address family are either disjoint or one is
    contained in the other, so the relation is reported explicitly.
    """
    if len(values) < 2:
        raise NetopsError("at least two CIDRs are required to check for overlap")
    networks = [parse_network(value) for value in values]
    pairs: list[dict[str, str]] = []
    for index, first in enumerate(networks):
        for second in networks[index + 1 :]:
            if first.version != second.version or not first.overlaps(second):
                continue
            if first == second:
                relation = "identical"
            elif second.subnet_of(first):
                relation = "contains"
            elif first.subnet_of(second):
                relation = "contained-by"
            else:  # pragma: no cover - aligned CIDR blocks are nested or disjoint
                relation = "overlap"
            pairs.append({"first": str(first), "second": str(second), "relation": relation})
    return {
        "networks": [str(network) for network in networks],
        "overlap_count": len(pairs),
        "pairs": pairs,
    }
