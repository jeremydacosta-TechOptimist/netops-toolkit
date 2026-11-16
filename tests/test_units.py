"""Tests for data-size and bandwidth calculations."""

from __future__ import annotations

import json
import unittest

from helpers import run_cli

from netops import units
from netops.errors import NetopsError


class ParseTests(unittest.TestCase):
    def test_decimal_sizes(self) -> None:
        self.assertEqual(units.parse_size("10GB"), 10_000_000_000)
        self.assertEqual(units.parse_size("1MB"), 1_000_000)
        self.assertEqual(units.parse_size("500 b"), 500)
        self.assertEqual(units.parse_size("1.5GB"), 1_500_000_000)

    def test_binary_sizes(self) -> None:
        self.assertEqual(units.parse_size("1GiB"), 1024**3)
        self.assertEqual(units.parse_size("1.5GiB"), 1_610_612_736)
        self.assertEqual(units.parse_size("1KiB"), 1024)

    def test_invalid_sizes(self) -> None:
        for value in ("10", "10XB", "GB", "0GB", "-5GB"):
            with self.subTest(value=value), self.assertRaises(NetopsError):
                units.parse_size(value)

    def test_rates(self) -> None:
        self.assertEqual(units.parse_rate("100Mbps"), 100_000_000)
        self.assertEqual(units.parse_rate("1.5Gbps"), 1_500_000_000)
        self.assertEqual(units.parse_rate("1Tbps"), 1_000_000_000_000)

    def test_invalid_rates(self) -> None:
        for value in ("100MB/s", "100", "0bps"):
            with self.subTest(value=value), self.assertRaises(NetopsError):
                units.parse_rate(value)


class FormatTests(unittest.TestCase):
    def test_decimal_formatting(self) -> None:
        self.assertEqual(units.format_decimal_size(10_000_000_000), "10.00 GB")
        self.assertEqual(units.format_decimal_size(500), "500 B")

    def test_binary_formatting(self) -> None:
        self.assertEqual(units.format_binary_size(10_000_000_000), "9.31 GiB")
        self.assertEqual(units.format_binary_size(1024**3), "1.00 GiB")

    def test_rate_formatting(self) -> None:
        self.assertEqual(units.format_rate(100_000_000), "100.00 Mbps")
        self.assertEqual(units.format_rate(1_000_000_000), "1.00 Gbps")

    def test_duration_formatting(self) -> None:
        self.assertEqual(units.format_duration(800), "13 min 20 s")
        self.assertEqual(units.format_duration(45.5), "45.50 s")
        self.assertEqual(units.format_duration(3600), "1 h 0 min 0 s")

    def test_negative_duration_raises(self) -> None:
        with self.assertRaises(NetopsError):
            units.format_duration(-1)


class CalculationTests(unittest.TestCase):
    def test_transfer_time(self) -> None:
        report = units.transfer_report("10GB", "100Mbps")
        self.assertEqual(report["seconds"], 800.0)
        self.assertEqual(report["human"], "13 min 20 s")

    def test_rate_report(self) -> None:
        report = units.rate_report("100Mbps")
        self.assertEqual(report["bits_per_second"], 100_000_000)
        self.assertEqual(report["bytes_per_second"], 12_500_000.0)
        self.assertEqual(report["megabytes_per_second"], 12.5)
        self.assertEqual(report["mebibytes_per_second"], 11.92)

    def test_size_report(self) -> None:
        report = units.size_report("1GiB")
        self.assertEqual(report["bytes"], 1_073_741_824)
        self.assertEqual(report["decimal"], "1.07 GB")
        self.assertEqual(report["binary"], "1.00 GiB")

    def test_calculate_requires_input(self) -> None:
        with self.assertRaises(NetopsError):
            units.calculate(None, None)


class BandwidthCliTests(unittest.TestCase):
    def test_json_with_size_and_rate(self) -> None:
        code, output, _ = run_cli(
            ["bandwidth", "--json", "--size", "10GB", "--rate", "100Mbps"]
        )
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["size"]["bytes"], 10_000_000_000)
        self.assertEqual(payload["rate"]["bits_per_second"], 100_000_000)
        self.assertEqual(payload["transfer"]["seconds"], 800.0)

    def test_human_output(self) -> None:
        code, output, _ = run_cli(["bandwidth", "--size", "10GB", "--rate", "100Mbps"])
        self.assertEqual(code, 0)
        self.assertIn("Decimal : 10.00 GB", output)
        self.assertIn("Binary  : 9.31 GiB", output)
        self.assertIn("Transfer time: 800.00 s (13 min 20 s)", output)

    def test_size_only(self) -> None:
        code, output, _ = run_cli(["bandwidth", "--size", "512MiB"])
        self.assertEqual(code, 0)
        self.assertIn("536,870,912", output)

    def test_missing_options_is_usage_error(self) -> None:
        code, _, stderr = run_cli(["bandwidth"])
        self.assertEqual(code, 2)
        self.assertIn("--size and/or --rate", stderr)

    def test_invalid_unit_is_usage_error(self) -> None:
        code, _, stderr = run_cli(["bandwidth", "--size", "10XB"])
        self.assertEqual(code, 2)
        self.assertIn("unknown data-size unit", stderr)


if __name__ == "__main__":
    unittest.main()
