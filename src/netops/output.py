"""Small formatting helpers shared by the command-line subcommands."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any


def format_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    """Render rows as a left-aligned plain-text table."""
    rendered = [[str(cell) for cell in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in rendered:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = [
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)).rstrip(),
        "  ".join("-" * width for width in widths).rstrip(),
    ]
    for row in rendered:
        lines.append("  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip())
    return "\n".join(lines)


def print_json(payload: Any) -> None:
    """Print a stable, indented JSON document."""
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def format_count(value: int) -> str:
    """Format an integer with thousands separators."""
    return f"{value:,}"


def format_percent(value: float) -> str:
    """Format a percentage with one decimal place."""
    return f"{value:.1f}%"
