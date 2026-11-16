"""VLSM planning: allocate contiguous IPv4 subnets for VLAN host requirements."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Any

from .errors import NetopsError
from .subnets import host_range, parse_network, usable_host_count

MAX_IPV4_PREFIX = 32


def required_ipv4_prefix(hosts: int) -> int:
    """Return the shortest IPv4 prefix that fits *hosts* usable addresses."""
    if hosts < 1:
        raise NetopsError(f"host count must be at least 1, got {hosts}")
    for prefix_length in range(MAX_IPV4_PREFIX, -1, -1):
        candidate = ipaddress.IPv4Network((0, prefix_length))
        if usable_host_count(candidate) >= hosts:
            return prefix_length
    raise NetopsError(f"cannot allocate {hosts} hosts inside the IPv4 address space")


def aligned_free_blocks(start: int, count: int) -> list[str]:
    """Split a free address range into the largest aligned IPv4 CIDR blocks."""
    blocks: list[str] = []
    cursor = start
    remaining = count
    while remaining > 0:
        for prefix_length in range(0, MAX_IPV4_PREFIX + 1):
            block_size = 1 << (MAX_IPV4_PREFIX - prefix_length)
            if block_size <= remaining and cursor % block_size == 0:
                blocks.append(str(ipaddress.IPv4Network((cursor, prefix_length))))
                cursor += block_size
                remaining -= block_size
                break
        else:  # pragma: no cover - a /32 block always matches
            raise NetopsError("internal error while computing free address space")
    return blocks


def plan_vlsm(parent_value: str, requests: Sequence[tuple[str, int]]) -> dict[str, Any]:
    """Plan subnets for *requests* inside *parent_value* using a VLSM strategy.

    Requirements are validated, sorted from largest to smallest and allocated
    from the start of the parent block. Because every block size is a power of
    two and lengths are strictly non-increasing, each subnet stays naturally
    aligned and never overlaps another one.
    """
    parent = parse_network(parent_value)
    if parent.version != 4:
        raise NetopsError("VLSM planning supports IPv4 parent prefixes only")
    if not requests:
        raise NetopsError("at least one VLAN requirement is required")

    original: list[tuple[str, int]] = []
    seen: set[str] = set()
    wanted: list[tuple[str, int, int]] = []
    for name, hosts in requests:
        label = name.strip()
        if not label:
            raise NetopsError("VLAN name must not be empty")
        key = label.casefold()
        if key in seen:
            raise NetopsError(f"duplicate VLAN name {label!r}")
        seen.add(key)
        if hosts < 1:
            raise NetopsError(f"VLAN {label!r} requests {hosts} hosts; the minimum is 1")
        prefix_length = required_ipv4_prefix(hosts)
        original.append((label, hosts))
        wanted.append((label, hosts, prefix_length))

    wanted.sort(key=lambda item: (item[2], item[0].casefold()))
    block_sizes = [1 << (MAX_IPV4_PREFIX - prefix_length) for _, _, prefix_length in wanted]
    total_needed = sum(block_sizes)
    if total_needed > parent.num_addresses:
        raise NetopsError(
            f"requirements need {total_needed} addresses but {parent} only has "
            f"{parent.num_addresses}; use a larger parent prefix"
        )

    parent_start = int(parent.network_address)
    cursor = parent_start
    allocations: list[dict[str, Any]] = []
    for (label, hosts, prefix_length), block_size in zip(wanted, block_sizes):
        network = ipaddress.IPv4Network((cursor, prefix_length))
        first_host, last_host = host_range(network)
        usable = usable_host_count(network)
        allocations.append(
            {
                "vlan": label,
                "requested_hosts": hosts,
                "cidr": str(network),
                "prefix_length": prefix_length,
                "network_address": str(network.network_address),
                "first_host": first_host,
                "last_host": last_host,
                "broadcast_address": str(network.broadcast_address),
                "usable_hosts": usable,
                "utilization_percent": round(hosts / usable * 100, 1),
            }
        )
        cursor += block_size

    used_addresses = cursor - parent_start
    free_addresses = parent.num_addresses - used_addresses
    return {
        "parent": str(parent),
        "parent_prefix_length": parent.prefixlen,
        "parent_addresses": parent.num_addresses,
        "requests": [{"vlan": label, "hosts": hosts} for label, hosts in original],
        "allocations": allocations,
        "allocated_addresses": used_addresses,
        "free_addresses": free_addresses,
        "capacity_percent": round(used_addresses / parent.num_addresses * 100, 1),
        "free_blocks": aligned_free_blocks(cursor, free_addresses),
        "total_requested_hosts": sum(hosts for _, hosts in original),
    }
