"""Tests for subnet arithmetic, splitting, summarisation and overlap checks."""

from __future__ import annotations

import json
import unittest

from helpers import run_cli

from netops import subnets
from netops.errors import NetopsError


class NetworkReportTests(unittest.TestCase):
    def test_ipv4_slash_24(self) -> None:
        report = subnets.network_report("192.0.2.0/24")
        self.assertEqual(report["cidr"], "192.0.2.0/24")
        self.assertEqual(report["version"], 4)
        self.assertEqual(report["network_address"], "192.0.2.0")
        self.assertEqual(report["broadcast_address"], "192.0.2.255")
        self.assertEqual(report["netmask"], "255.255.255.0")
        self.assertEqual(report["wildcard"], "0.0.0.255")
        self.assertEqual(report["first_host"], "192.0.2.1")
        self.assertEqual(report["last_host"], "192.0.2.254")
        self.assertEqual(report["total_addresses"], 256)
        self.assertEqual(report["usable_hosts"], 254)
        self.assertTrue(report["is_private"])

    def test_ipv4_slash_30(self) -> None:
        report = subnets.network_report("198.51.100.4/30")
        self.assertEqual(report["first_host"], "198.51.100.5")
        self.assertEqual(report["last_host"], "198.51.100.6")
        self.assertEqual(report["usable_hosts"], 2)

    def test_ipv4_slash_31_point_to_point(self) -> None:
        report = subnets.network_report("203.0.113.0/31")
        self.assertEqual(report["first_host"], "203.0.113.0")
        self.assertEqual(report["last_host"], "203.0.113.1")
        self.assertEqual(report["usable_hosts"], 2)

    def test_ipv4_slash_32_host_route(self) -> None:
        report = subnets.network_report("203.0.113.7/32")
        self.assertEqual(report["first_host"], "203.0.113.7")
        self.assertEqual(report["last_host"], "203.0.113.7")
        self.assertEqual(report["usable_hosts"], 1)
        self.assertEqual(report["total_addresses"], 1)

    def test_host_bits_are_normalised(self) -> None:
        report = subnets.network_report("192.0.2.10/26")
        self.assertEqual(report["cidr"], "192.0.2.0/26")
        self.assertEqual(report["input"], "192.0.2.10/26")
        self.assertEqual(report["input_address"], "192.0.2.10")
        self.assertTrue(report["host_bits_set"])
        aligned = subnets.network_report("192.0.2.0/26")
        self.assertFalse(aligned["host_bits_set"])

    def test_ipv6_slash_64(self) -> None:
        report = subnets.network_report("2001:db8:1::/64")
        self.assertEqual(report["version"], 6)
        self.assertIsNone(report["broadcast_address"])
        self.assertIsNone(report["netmask"])
        self.assertIsNone(report["wildcard"])
        self.assertEqual(report["network_address"], "2001:db8:1::")
        self.assertEqual(report["first_host"], "2001:db8:1::")
        self.assertEqual(report["last_host"], "2001:db8:1:0:ffff:ffff:ffff:ffff")
        self.assertEqual(report["usable_hosts"], 2**64)

    def test_ipv6_slash_127(self) -> None:
        report = subnets.network_report("2001:db8::/127")
        self.assertEqual(report["usable_hosts"], 2)
        self.assertEqual(report["total_addresses"], 2)

    def test_public_ipv6_is_not_private(self) -> None:
        report = subnets.network_report("2606:4700::/32")
        self.assertFalse(report["is_private"])

    def test_strict_parsing_rejects_host_bits(self) -> None:
        with self.assertRaises(NetopsError) as context:
            subnets.parse_network("192.0.2.1/24")
        self.assertIn("host bits", str(context.exception))
        self.assertEqual(
            str(subnets.parse_network("192.0.2.1/24", strict=False)), "192.0.2.0/24"
        )

    def test_invalid_cidr_raises(self) -> None:
        for value in ("not-a-cidr", "192.0.2.0/33", "2001:db8::/129"):
            with self.subTest(value=value), self.assertRaises(NetopsError):
                subnets.parse_network(value)


class SplitTests(unittest.TestCase):
    def test_split_slash_24_into_slash_26(self) -> None:
        report = subnets.split_network("192.0.2.0/24", 26)
        self.assertEqual(report["count"], 4)
        self.assertEqual(
            report["subnets"],
            ["192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26", "192.0.2.192/26"],
        )

    def test_split_accepts_host_bits(self) -> None:
        report = subnets.split_network("192.0.2.100/24", 26)
        self.assertEqual(report["parent"], "192.0.2.0/24")
        self.assertEqual(report["count"], 4)

    def test_split_rejects_shorter_prefix(self) -> None:
        with self.assertRaises(NetopsError):
            subnets.split_network("192.0.2.0/24", 20)

    def test_split_rejects_out_of_range_prefix(self) -> None:
        with self.assertRaises(NetopsError):
            subnets.split_network("192.0.2.0/24", 33)

    def test_split_honours_output_limit(self) -> None:
        with self.assertRaises(NetopsError) as context:
            subnets.split_network("2001:db8::/32", 48)
        self.assertIn("65536", str(context.exception))


class SummarizeTests(unittest.TestCase):
    def test_adjacent_halves_collapse(self) -> None:
        report = subnets.summarize_networks(["192.0.2.0/25", "192.0.2.128/25"])
        self.assertEqual(report["collapsed"], ["192.0.2.0/24"])
        self.assertEqual(report["input_count"], 2)
        self.assertEqual(report["collapsed_count"], 1)
        self.assertEqual(report["saved_networks"], 1)
        self.assertEqual(report["addresses_covered"], 256)

    def test_mixed_address_families(self) -> None:
        report = subnets.summarize_networks(["192.0.2.0/24", "2001:db8::/32"])
        self.assertEqual(report["collapsed_count"], 2)
        self.assertIn("192.0.2.0/24", report["collapsed"])
        self.assertIn("2001:db8::/32", report["collapsed"])

    def test_duplicates_collapse(self) -> None:
        report = subnets.summarize_networks(["192.0.2.0/24", "192.0.2.0/24"])
        self.assertEqual(report["collapsed"], ["192.0.2.0/24"])

    def test_empty_input_raises(self) -> None:
        with self.assertRaises(NetopsError):
            subnets.summarize_networks([])


class OverlapTests(unittest.TestCase):
    def test_nested_network_is_reported(self) -> None:
        report = subnets.find_overlaps(
            ["192.0.2.0/24", "192.0.2.128/25", "198.51.100.0/24"]
        )
        self.assertEqual(report["overlap_count"], 1)
        self.assertEqual(report["pairs"][0]["relation"], "contains")
        self.assertEqual(report["pairs"][0]["first"], "192.0.2.0/24")
        self.assertEqual(report["pairs"][0]["second"], "192.0.2.128/25")

    def test_identical_networks(self) -> None:
        report = subnets.find_overlaps(["192.0.2.0/24", "192.0.2.0/24"])
        self.assertEqual(report["overlap_count"], 1)
        self.assertEqual(report["pairs"][0]["relation"], "identical")

    def test_disjoint_networks(self) -> None:
        report = subnets.find_overlaps(["192.0.2.0/24", "198.51.100.0/24"])
        self.assertEqual(report["overlap_count"], 0)
        self.assertEqual(report["pairs"], [])

    def test_mixed_families_never_overlap(self) -> None:
        report = subnets.find_overlaps(["192.0.2.0/24", "2001:db8::/32"])
        self.assertEqual(report["overlap_count"], 0)

    def test_requires_two_networks(self) -> None:
        with self.assertRaises(NetopsError):
            subnets.find_overlaps(["192.0.2.0/24"])


class SubnetCliTests(unittest.TestCase):
    def test_subnet_json(self) -> None:
        code, output, _ = run_cli(["subnet", "--json", "192.0.2.10/26"])
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["networks"][0]["cidr"], "192.0.2.0/26")
        self.assertTrue(payload["networks"][0]["host_bits_set"])

    def test_subnet_human_output(self) -> None:
        code, output, _ = run_cli(["subnet", "192.0.2.0/26"])
        self.assertEqual(code, 0)
        self.assertIn("Network       : 192.0.2.0/26", output)
        self.assertIn("Usable hosts  : 62", output)

    def test_subnet_split_human_output(self) -> None:
        code, output, _ = run_cli(["subnet", "--split", "26", "192.0.2.0/24"])
        self.assertEqual(code, 0)
        self.assertIn("192.0.2.192/26", output)

    def test_invalid_cidr_exits_with_usage_error(self) -> None:
        code, _, stderr = run_cli(["summarize", "192.0.2.1/24"])
        self.assertEqual(code, 2)
        self.assertIn("host bits", stderr)

    def test_summarize_human_output(self) -> None:
        code, output, _ = run_cli(
            ["summarize", "192.0.2.0/25", "192.0.2.128/25"]
        )
        self.assertEqual(code, 0)
        self.assertIn("Summarised networks (1):", output)
        self.assertIn("192.0.2.0/24", output)

    def test_overlap_exit_code(self) -> None:
        code, output, _ = run_cli(
            ["overlap", "192.0.2.0/24", "192.0.2.0/25"]
        )
        self.assertEqual(code, 1)
        self.assertIn("contains", output)
        code, _, _ = run_cli(["overlap", "192.0.2.0/24", "198.51.100.0/24"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
