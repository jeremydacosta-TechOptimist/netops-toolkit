"""Tests for the overall CLI surface: help, version, exit codes and JSON."""

from __future__ import annotations

import json
import unittest

from helpers import run_cli

COMMANDS = [
    "subnet",
    "summarize",
    "overlap",
    "vlsm",
    "scan",
    "reach",
    "dns",
    "http",
    "mac",
    "bandwidth",
]


class HelpTests(unittest.TestCase):
    def test_top_level_help_lists_every_command(self) -> None:
        code, output, _ = run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("usage: netops", output)
        for command in COMMANDS:
            self.assertIn(command, output)

    def test_no_command_returns_usage_exit_code(self) -> None:
        code, output, _ = run_cli([])
        self.assertEqual(code, 2)
        self.assertIn("usage: netops", output)

    def test_version(self) -> None:
        code, output, _ = run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("netops 1.0.0", output)

    def test_every_subcommand_supports_help_and_json(self) -> None:
        for command in COMMANDS:
            with self.subTest(command=command):
                code, output, _ = run_cli([command, "--help"])
                self.assertEqual(code, 0)
                self.assertIn(f"usage: netops {command}", output)
                self.assertIn("--json", output)

    def test_unknown_command_is_usage_error(self) -> None:
        code, _, stderr = run_cli(["does-not-exist"])
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", stderr)


class JsonContractTests(unittest.TestCase):
    def test_subnet_json(self) -> None:
        code, output, _ = run_cli(["subnet", "--json", "2001:db8::/48"])
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(payload["networks"][0]["version"], 6)
        self.assertEqual(payload["networks"][0]["prefix_length"], 48)

    def test_summarize_json(self) -> None:
        code, output, _ = run_cli(
            ["summarize", "--json", "198.51.100.0/25", "198.51.100.128/25"]
        )
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(payload["collapsed"], ["198.51.100.0/24"])

    def test_overlap_json(self) -> None:
        code, output, _ = run_cli(
            ["overlap", "--json", "198.51.100.0/24", "198.51.100.64/26"]
        )
        payload = json.loads(output)
        self.assertEqual(code, 1)
        self.assertEqual(payload["overlap_count"], 1)

    def test_vlsm_json(self) -> None:
        code, output, _ = run_cli(
            ["vlsm", "--json", "198.51.100.0/24", "USERS=100", "VOICE=20"]
        )
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(payload["allocations"][0]["cidr"], "198.51.100.0/25")

    def test_mac_json(self) -> None:
        code, output, _ = run_cli(["mac", "--json", "b8:27:eb:01:02:03"])
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertIn("Raspberry Pi", payload["addresses"][0]["vendor"])

    def test_bandwidth_json(self) -> None:
        code, output, _ = run_cli(["bandwidth", "--json", "--rate", "1Gbps"])
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(payload["rate"]["bits_per_second"], 1_000_000_000)
        self.assertEqual(payload["rate"]["megabytes_per_second"], 125.0)
        self.assertIsNone(payload["transfer"])


if __name__ == "__main__":
    unittest.main()
