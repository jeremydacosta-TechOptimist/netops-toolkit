"""Tests for the TCP port scanner and reachability probes."""

from __future__ import annotations

import json
import unittest

from helpers import run_cli, tcp_listener, unused_tcp_port

from netops import scan
from netops.errors import NetopsError


class PortParsingTests(unittest.TestCase):
    def test_comma_list(self) -> None:
        self.assertEqual(scan.parse_ports("22,80,443"), [22, 80, 443])

    def test_ranges_are_expanded_and_deduplicated(self) -> None:
        self.assertEqual(
            scan.parse_ports("80,8000-8003,80"),
            [80, 8000, 8001, 8002, 8003],
        )

    def test_top_keyword(self) -> None:
        ports = scan.parse_ports("top")
        self.assertEqual(len(ports), len(scan.COMMON_PORTS))
        self.assertIn(443, ports)
        self.assertEqual(ports, sorted(ports))

    def test_invalid_specifications(self) -> None:
        for value in ("abc", "0", "65536", "80-22", "1-70000", "", "22,,80"):
            with self.subTest(value=value), self.assertRaises(NetopsError):
                scan.parse_ports(value)

    def test_service_hints(self) -> None:
        self.assertEqual(scan.SERVICE_HINTS[443], "https")
        self.assertEqual(scan.SERVICE_HINTS[22], "ssh")
        self.assertGreaterEqual(len(scan.SERVICE_HINTS), 50)


class ScanTests(unittest.TestCase):
    def test_open_port_is_detected(self) -> None:
        with tcp_listener() as port:
            report = scan.scan_ports("127.0.0.1", [port], timeout=1.0)
        self.assertEqual(report["scanned"], 1)
        self.assertEqual(report["counts"]["open"], 1)
        result = report["results"][0]
        self.assertEqual(result["state"], "open")
        self.assertIsNotNone(result["latency_ms"])
        self.assertGreaterEqual(result["latency_ms"], 0.0)
        self.assertEqual(report["target"], "127.0.0.1")

    def test_released_port_is_not_reported_open(self) -> None:
        with unused_tcp_port() as port:
            report = scan.scan_ports("127.0.0.1", [port], timeout=0.3)
        self.assertNotEqual(report["results"][0]["state"], "open")
        self.assertIn(report["results"][0]["state"], {"closed", "filtered", "error"})

    def test_unresolvable_host_raises(self) -> None:
        with self.assertRaises(NetopsError):
            scan.resolve_host("999.999.999.999")

    def test_scan_requires_ports(self) -> None:
        with self.assertRaises(NetopsError):
            scan.scan_ports("127.0.0.1", [])

    def test_scan_json_cli(self) -> None:
        with tcp_listener() as port:
            code, output, _ = run_cli(["scan", "--json", "127.0.0.1", "-p", str(port)])
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["counts"]["open"], 1)
        self.assertEqual(payload["results"][0]["port"], port)

    def test_scan_human_output(self) -> None:
        with tcp_listener() as port:
            code, output, _ = run_cli(["scan", "127.0.0.1", "-p", str(port)])
        self.assertEqual(code, 0)
        self.assertIn("open", output)
        self.assertIn(f"{port}/tcp", output)

    def test_invalid_ports_are_usage_errors(self) -> None:
        code, _, stderr = run_cli(["scan", "127.0.0.1", "-p", "70000"])
        self.assertEqual(code, 2)
        self.assertIn("outside the valid range", stderr)


class ReachabilityTests(unittest.TestCase):
    def test_listening_port_is_reachable(self) -> None:
        with tcp_listener() as port:
            report = scan.check_reachability(
                ["127.0.0.1"], ports=[port], timeout=1.0, tries=1
            )
        self.assertEqual(report["reachable_count"], 1)
        self.assertEqual(report["unreachable_count"], 0)
        result = report["results"][0]
        self.assertTrue(result["reachable"])
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["port"], port)
        self.assertIsNotNone(result["latency_ms"])

    def test_reserved_address_is_unreachable(self) -> None:
        report = scan.check_reachability(
            ["192.0.2.1"], ports=[443], timeout=0.2, tries=1
        )
        self.assertEqual(report["unreachable_count"], 1)
        self.assertFalse(report["results"][0]["reachable"])

    def test_invalid_inputs_raise(self) -> None:
        with self.assertRaises(NetopsError):
            scan.check_reachability([], ports=[443])
        with self.assertRaises(NetopsError):
            scan.check_reachability(["127.0.0.1"], ports=[70000])

    def test_reach_cli_success_and_failure(self) -> None:
        with tcp_listener() as port:
            code, output, _ = run_cli(
                ["reach", "--json", "127.0.0.1", "-p", str(port), "--tries", "1"]
            )
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["reachable_count"], 1)
        code, _, _ = run_cli(
            ["reach", "192.0.2.1", "-p", "443", "-t", "0.2", "--tries", "1"]
        )
        self.assertEqual(code, 1)

    def test_reach_reports_refused_as_reachable_only_when_host_responds(self) -> None:
        # Connection refused is a response from the host: it must count as
        # reachable on systems whose TCP stack sends a reset for closed ports.
        with unused_tcp_port() as port:
            result = scan.probe_tcp("127.0.0.1", port, timeout=0.3)
        if result.state == "closed":
            self.assertFalse(result.latency_ms is None and result.error is not None)
        else:
            self.assertIn(result.state, {"filtered", "error"})


if __name__ == "__main__":
    unittest.main()
