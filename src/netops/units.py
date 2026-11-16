"""Data-size and bandwidth calculators with decimal and binary units."""

from __future__ import annotations

import re
from typing import Any

from .errors import NetopsError

_SIZE_UNITS: dict[str, int] = {
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "pb": 1000**5,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
    "pib": 1024**5,
}
_RATE_UNITS: dict[str, int] = {
    "bps": 1,
    "kbps": 1000,
    "mbps": 1000**2,
    "gbps": 1000**3,
    "tbps": 1000**4,
}
_QUANTITY_PATTERN = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([A-Za-z]+)\s*$")


def _split_quantity(text: str, kind: str) -> tuple[float, str]:
    match = _QUANTITY_PATTERN.match(text or "")
    if not match:
        raise NetopsError(
            f"invalid {kind} {text!r}; expected a number followed by a unit, e.g. 10GB"
        )
    return float(match.group(1)), match.group(2).lower()


def parse_size(value: str) -> int:
    """Parse a data size such as ``10GB`` or ``1.5GiB`` into bytes."""
    amount, unit = _split_quantity(value, "data size")
    if unit not in _SIZE_UNITS:
        supported = ", ".join(unit.upper() for unit in _SIZE_UNITS)
        raise NetopsError(f"unknown data-size unit {unit!r}; use one of: {supported}")
    size_in_bytes = amount * _SIZE_UNITS[unit]
    if size_in_bytes <= 0:
        raise NetopsError("data size must be greater than zero")
    return int(round(size_in_bytes))


def parse_rate(value: str) -> int:
    """Parse a link rate such as ``100Mbps`` or ``1.5Gbps`` into bits per second."""
    amount, unit = _split_quantity(value, "link rate")
    if unit not in _RATE_UNITS:
        supported = ", ".join(unit.upper() for unit in _RATE_UNITS)
        raise NetopsError(f"unknown link-rate unit {unit!r}; use one of: {supported}")
    bits_per_second = amount * _RATE_UNITS[unit]
    if bits_per_second <= 0:
        raise NetopsError("link rate must be greater than zero")
    return int(round(bits_per_second))


def format_decimal_size(size_in_bytes: int) -> str:
    """Format bytes using decimal (SI) units."""
    for unit, factor in (("PB", 1000**5), ("TB", 1000**4), ("GB", 1000**3), ("MB", 1000**2), ("KB", 1000)):
        if size_in_bytes >= factor:
            return f"{size_in_bytes / factor:.2f} {unit}"
    return f"{size_in_bytes} B"


def format_binary_size(size_in_bytes: int) -> str:
    """Format bytes using binary (IEC) units."""
    for unit, factor in (
        ("PiB", 1024**5),
        ("TiB", 1024**4),
        ("GiB", 1024**3),
        ("MiB", 1024**2),
        ("KiB", 1024),
    ):
        if size_in_bytes >= factor:
            return f"{size_in_bytes / factor:.2f} {unit}"
    return f"{size_in_bytes} B"


def format_rate(bits_per_second: int) -> str:
    """Format a bit rate using decimal units."""
    for unit, factor in (("Tbps", 1000**4), ("Gbps", 1000**3), ("Mbps", 1000**2), ("Kbps", 1000)):
        if bits_per_second >= factor:
            return f"{bits_per_second / factor:.2f} {unit}"
    return f"{bits_per_second} bps"


def format_duration(seconds: float) -> str:
    """Format a duration in seconds as a compact human-readable string."""
    if seconds < 0:
        raise NetopsError("duration must not be negative")
    if seconds < 60:
        return f"{seconds:.2f} s"
    totals = int(round(seconds))
    hours, remainder = divmod(totals, 3600)
    minutes, remainder = divmod(remainder, 60)
    if hours:
        return f"{hours} h {minutes} min {remainder} s"
    return f"{minutes} min {remainder} s"


def size_report(value: str) -> dict[str, Any]:
    """Return decimal and binary representations of a data size."""
    size_in_bytes = parse_size(value)
    return {
        "input": value,
        "bytes": size_in_bytes,
        "decimal": format_decimal_size(size_in_bytes),
        "binary": format_binary_size(size_in_bytes),
    }


def rate_report(value: str) -> dict[str, Any]:
    """Return throughput conversions for a link rate."""
    bits_per_second = parse_rate(value)
    bytes_per_second = bits_per_second / 8
    return {
        "input": value,
        "bits_per_second": bits_per_second,
        "bytes_per_second": round(bytes_per_second, 2),
        "megabytes_per_second": round(bytes_per_second / 1_000_000, 2),
        "mebibytes_per_second": round(bytes_per_second / (1024**2), 2),
    }


def transfer_report(size_value: str, rate_value: str) -> dict[str, Any]:
    """Estimate how long a transfer takes at a constant link rate."""
    size_in_bytes = parse_size(size_value)
    bits_per_second = parse_rate(rate_value)
    seconds = size_in_bytes * 8 / bits_per_second
    return {
        "size": size_value,
        "rate": rate_value,
        "seconds": round(seconds, 3),
        "human": format_duration(seconds),
    }


def calculate(size_value: str | None, rate_value: str | None) -> dict[str, Any]:
    """Build the combined report used by the ``bandwidth`` subcommand."""
    if size_value is None and rate_value is None:
        raise NetopsError("provide --size and/or --rate")
    report: dict[str, Any] = {
        "size": size_report(size_value) if size_value else None,
        "rate": rate_report(rate_value) if rate_value else None,
        "transfer": None,
    }
    if size_value and rate_value:
        report["transfer"] = transfer_report(size_value, rate_value)
    return report
