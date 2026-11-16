"""Tests for the VLSM planner."""

from __future__ import annotations

import ipaddress
import json
import unittest

from helpers import run_cli

from netops import vlsm
from netops.errors import NetopsError

BASE_PLAN = [
    ("VLAN10", 50),
    ("VLAN20", 20),
    ("VLAN30", 2),
]


class RequiredPrefixTests(unittest.TestCase):
    def test_host_count_boundaries(self) -> None:
        expectations = {
            1: 32,
            2: 31,
            3: 29,
            30: 27,
            31: 26,
            62: 26,
            63: 25,
            254: 24,
            255: 23,
        }
        for hosts, prefix in expectations.items():
            with self.subTest(hosts=hosts):
                self.assertEqual(vlsm.required_ipv4_prefix(hosts), prefix)

    def test_invalid_host_counts(self) -> None:
        for hosts in (0, -1):
            with self.subTest(hosts=hosts), self.assertRaises(NetopsError):
                vlsm.required_ipv4_prefix(hosts)


class PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = vlsm.plan_vlsm("192.0.2.0/24", BASE_PLAN)

    def test_allocations_are_sorted_and_sized(self) -> None:
        self.assertEqual(
            [allocation["cidr"] for allocation in self.report["allocations"]],
            ["192.0.2.0/26", "192.0.2.64/27", "192.0.2.96/31"],
        )
        self.assertEqual(
            [allocation["vlan"] for allocation in self.report["allocations"]],
            ["VLAN10", "VLAN20", "VLAN30"],
        )
        self.assertEqual(
            [allocation["prefix_length"] for allocation in self.report["allocations"]],
            [26, 27, 31],
        )

    def test_allocations_cover_requests(self) -> None:
        for allocation, (_, hosts) in zip(self.report["allocations"], BASE_PLAN):
            self.assertGreaterEqual(allocation["usable_hosts"], hosts)
            self.assertGreater(allocation["utilization_percent"], 0)

    def test_capacity_accounting(self) -> None:
        self.assertEqual(self.report["allocated_addresses"], 98)
        self.assertEqual(self.report["free_addresses"], 158)
        self.assertEqual(self.report["parent_addresses"], 256)
        self.assertEqual(self.report["capacity_percent"], 38.3)
        self.assertEqual(self.report["total_requested_hosts"], 72)

    def test_allocations_and_free_blocks_cover_parent_without_overlap(self) -> None:
        pieces = [
            ipaddress.ip_network(allocation["cidr"])
            for allocation in self.report["allocations"]
        ] + [ipaddress.ip_network(block) for block in self.report["free_blocks"]]
        collapsed = list(ipaddress.collapse_addresses(pieces))
        self.assertEqual(collapsed, [ipaddress.ip_network("192.0.2.0/24")])

    def test_free_blocks_are_aligned(self) -> None:
        for block in self.report["free_blocks"]:
            network = ipaddress.ip_network(block)
            self.assertEqual(int(network.network_address) % network.num_addresses, 0)

    def test_requests_preserve_input_order(self) -> None:
        self.assertEqual(
            self.report["requests"],
            [{"vlan": "VLAN10", "hosts": 50}, {"vlan": "VLAN20", "hosts": 20}, {"vlan": "VLAN30", "hosts": 2}],
        )

    def test_plan_that_exceeds_parent_raises(self) -> None:
        with self.assertRaises(NetopsError) as context:
            vlsm.plan_vlsm("192.0.2.0/28", [("A", 50)])
        self.assertIn("only has 16", str(context.exception))

    def test_duplicate_names_raise(self) -> None:
        with self.assertRaises(NetopsError):
            vlsm.plan_vlsm("192.0.2.0/24", [("VLAN10", 10), ("vlan10", 10)])

    def test_empty_name_raises(self) -> None:
        with self.assertRaises(NetopsError):
            vlsm.plan_vlsm("192.0.2.0/24", [("  ", 10)])

    def test_ipv6_parent_raises(self) -> None:
        with self.assertRaises(NetopsError):
            vlsm.plan_vlsm("2001:db8::/64", [("VLAN10", 10)])

    def test_no_requests_raises(self) -> None:
        with self.assertRaises(NetopsError):
            vlsm.plan_vlsm("192.0.2.0/24", [])

    def test_exact_fit(self) -> None:
        report = vlsm.plan_vlsm("192.0.2.0/24", [("VLAN10", 126), ("VLAN20", 126)])
        self.assertEqual(report["free_addresses"], 0)
        self.assertEqual(report["free_blocks"], [])
        self.assertEqual(
            [allocation["cidr"] for allocation in report["allocations"]],
            ["192.0.2.0/25", "192.0.2.128/25"],
        )


class VlsmCliTests(unittest.TestCase):
    def test_vlsm_json(self) -> None:
        code, output, _ = run_cli(
            ["vlsm", "--json", "192.0.2.0/24", "VLAN10=50", "VLAN20=20"]
        )
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["parent"], "192.0.2.0/24")
        self.assertEqual(payload["allocations"][0]["cidr"], "192.0.2.0/26")
        self.assertEqual(payload["free_addresses"], 160)

    def test_vlsm_human_output(self) -> None:
        code, output, _ = run_cli(
            ["vlsm", "192.0.2.0/24", "VLAN10=50", "VLAN20=20", "VLAN30=2"]
        )
        self.assertEqual(code, 0)
        self.assertIn("VLAN10", output)
        self.assertIn("192.0.2.96/31", output)
        self.assertIn("Free blocks", output)

    def test_vlsm_runtime_failure_exit_code(self) -> None:
        code, _, stderr = run_cli(["vlsm", "192.0.2.0/28", "VLAN10=50"])
        self.assertEqual(code, 1)
        self.assertIn("only has 16", stderr)

    def test_invalid_vlan_spec_is_usage_error(self) -> None:
        code, _, _ = run_cli(["vlsm", "192.0.2.0/24", "VLAN10"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
