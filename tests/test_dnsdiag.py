"""Tests for the DNS wire client and diagnostics."""

from __future__ import annotations

import json
import struct
import unittest

from helpers import (
    FakeDnsServer,
    build_dns_response,
    run_cli,
    standard_dns_responder,
)

from netops import dnsdiag
from netops.errors import NetopsError


class WireFormatTests(unittest.TestCase):
    def test_encode_name(self) -> None:
        self.assertEqual(
            dnsdiag.encode_name("example.com"), b"\x07example\x03com\x00"
        )
        self.assertEqual(
            dnsdiag.encode_name("example.com."), b"\x07example\x03com\x00"
        )

    def test_encode_root_name(self) -> None:
        self.assertEqual(dnsdiag.encode_name("."), b"\x00")

    def test_encode_invalid_names(self) -> None:
        with self.assertRaises(NetopsError):
            dnsdiag.encode_name("")
        with self.assertRaises(NetopsError):
            dnsdiag.encode_name("a" * 64 + ".example")
        with self.assertRaises(NetopsError):
            dnsdiag.encode_name("exämple.com")

    def test_build_query_fields(self) -> None:
        packet = dnsdiag.build_query("example.com", "A", query_id=0x1234)
        self.assertEqual(packet[:2], b"\x12\x34")
        self.assertEqual(struct.unpack("!H", packet[2:4])[0], 0x0100)
        self.assertEqual(struct.unpack("!H", packet[4:6])[0], 1)
        self.assertEqual(packet[-4:], struct.pack("!HH", dnsdiag.QTYPES["A"], 1))

    def test_build_query_rejects_unknown_type(self) -> None:
        with self.assertRaises(NetopsError):
            dnsdiag.build_query("example.com", "SOA")

    def test_parse_response_a_records(self) -> None:
        query = dnsdiag.build_query("example.com", "A", query_id=0x0102)
        response = build_dns_response(
            query,
            [
                (dnsdiag.QTYPES["A"], 300, bytes([192, 0, 2, 5])),
                (dnsdiag.QTYPES["A"], 60, bytes([192, 0, 2, 6])),
            ],
        )
        parsed = dnsdiag.parse_response(response)
        self.assertEqual(parsed["id"], 0x0102)
        self.assertEqual(parsed["status"], "NOERROR")
        self.assertEqual(parsed["answer_count"], 2)
        self.assertEqual(parsed["answers"][0]["value"], "192.0.2.5")
        self.assertEqual(parsed["answers"][1]["ttl"], 60)
        self.assertEqual(parsed["questions"][0]["name"], "example.com")

    def test_compressed_names_are_decoded(self) -> None:
        query = dnsdiag.build_query("example.com", "A", query_id=0x0001)
        response = build_dns_response(
            query, [(dnsdiag.QTYPES["A"], 10, bytes([203, 0, 113, 9]))]
        )
        parsed = dnsdiag.parse_response(response)
        self.assertEqual(parsed["answers"][0]["name"], "example.com")

    def test_parse_specific_record_types(self) -> None:
        cases = {
            "AAAA": (
                dnsdiag.QTYPES["AAAA"],
                bytes.fromhex("20010db8000000000000000000000001"),
                "2001:db8::1",
            ),
            "MX": (
                dnsdiag.QTYPES["MX"],
                struct.pack("!H", 10) + dnsdiag.encode_name("mail.example.com"),
                "10 mail.example.com",
            ),
            "TXT": (dnsdiag.QTYPES["TXT"], b"\x0bhello world", "hello world"),
            "NS": (
                dnsdiag.QTYPES["NS"],
                dnsdiag.encode_name("ns1.example.com"),
                "ns1.example.com",
            ),
            "PTR": (
                dnsdiag.QTYPES["PTR"],
                dnsdiag.encode_name("host.example.com"),
                "host.example.com",
            ),
        }
        for record_type, (qtype, rdata, expected) in cases.items():
            with self.subTest(record_type=record_type):
                query = dnsdiag.build_query("example.com", record_type, query_id=1)
                parsed = dnsdiag.parse_response(
                    build_dns_response(query, [(qtype, 120, rdata)])
                )
                self.assertEqual(parsed["answers"][0]["value"], expected)
                self.assertEqual(parsed["answers"][0]["type"], record_type)

    def test_nxdomain_status(self) -> None:
        query = dnsdiag.build_query("missing.example", "A", query_id=7)
        parsed = dnsdiag.parse_response(build_dns_response(query, [], rcode=3))
        self.assertEqual(parsed["status"], "NXDOMAIN")
        self.assertEqual(parsed["answer_count"], 0)

    def test_malformed_packets_raise(self) -> None:
        with self.assertRaises(NetopsError):
            dnsdiag.parse_response(b"\x00\x01")
        query = dnsdiag.build_query("example.com", "A", query_id=1)
        truncated = build_dns_response(
            query, [(dnsdiag.QTYPES["A"], 10, bytes([192, 0, 2, 1]))]
        )[:-2]
        with self.assertRaises(NetopsError):
            dnsdiag.parse_response(truncated)


class ServerParsingTests(unittest.TestCase):
    def test_parse_server_variants(self) -> None:
        self.assertEqual(dnsdiag.parse_server("1.1.1.1"), ("1.1.1.1", 53))
        self.assertEqual(dnsdiag.parse_server("127.0.0.1:5300"), ("127.0.0.1", 5300))
        self.assertEqual(dnsdiag.parse_server("[::1]:5300"), ("::1", 5300))
        self.assertEqual(dnsdiag.parse_server("::1"), ("::1", 53))

    def test_parse_server_rejects_invalid_input(self) -> None:
        for value in ("", "1.1.1.1:0", "1.1.1.1:70000", "1.1.1.1:abc"):
            with self.subTest(value=value), self.assertRaises(NetopsError):
                dnsdiag.parse_server(value)

    def test_format_server(self) -> None:
        self.assertEqual(dnsdiag.format_server("1.1.1.1", 53), "1.1.1.1:53")
        self.assertEqual(dnsdiag.format_server("::1", 53), "[::1]:53")

    def test_normalize_qtype(self) -> None:
        self.assertEqual(dnsdiag.normalize_qtype("mx"), "MX")
        with self.assertRaises(NetopsError):
            dnsdiag.normalize_qtype("SOA")

    def test_detect_nameservers_returns_strings(self) -> None:
        servers = dnsdiag.detect_nameservers()
        self.assertIsInstance(servers, list)
        for server in servers:
            self.assertIsInstance(server, str)


class QueryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = FakeDnsServer(standard_dns_responder)

    def tearDown(self) -> None:
        self.server.close()

    def test_query_a(self) -> None:
        outcome = dnsdiag.query("example.com", "A", self.server.address, timeout=2.0)
        self.assertEqual(outcome.status, "NOERROR")
        self.assertEqual(outcome.record_type, "A")
        self.assertEqual(
            [record.value for record in outcome.answers], ["192.0.2.5", "192.0.2.6"]
        )
        self.assertGreaterEqual(outcome.elapsed_ms, 0.0)

    def test_query_mx(self) -> None:
        outcome = dnsdiag.query("example.com", "MX", self.server.address, timeout=2.0)
        self.assertEqual(outcome.answers[0].value, "10 mail.example.com")

    def test_query_timeout_raises(self) -> None:
        silent = FakeDnsServer(lambda query: b"")
        try:
            with self.assertRaises(NetopsError):
                dnsdiag.query("example.com", "A", silent.address, timeout=0.2)
        finally:
            silent.close()

    def test_lookup_name_validation(self) -> None:
        with self.assertRaises(NetopsError):
            dnsdiag._lookup_name("192.0.2.1", "A")
        self.assertEqual(
            dnsdiag._lookup_name("192.0.2.1", "PTR"), "1.2.0.192.in-addr.arpa"
        )
        self.assertEqual(dnsdiag._lookup_name("Example.COM", "A"), "Example.COM")


class RunQueriesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = FakeDnsServer(standard_dns_responder)

    def tearDown(self) -> None:
        self.server.close()

    def test_combined_report(self) -> None:
        report = dnsdiag.run_queries(
            "example.com", ["A", "MX"], server=self.server.address, timeout=2.0
        )
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["queries"]), 2)
        self.assertEqual(report["queries"][0]["status"], "NOERROR")
        self.assertEqual(report["queries"][0]["answer_count"], 2)
        self.assertEqual(report["queries"][1]["answers"][0]["value"], "10 mail.example.com")
        self.assertGreaterEqual(report["total_elapsed_ms"], 0.0)

    def test_ip_address_defaults_to_ptr(self) -> None:
        report = dnsdiag.run_queries(
            "192.0.2.5", server=self.server.address, timeout=2.0
        )
        self.assertEqual(report["queries"][0]["type"], "PTR")
        self.assertEqual(report["queries"][0]["name"], "5.2.0.192.in-addr.arpa")
        self.assertEqual(report["queries"][0]["answers"][0]["value"], "host.example.com")
        self.assertTrue(report["ok"])

    def test_nxdomain_is_not_ok(self) -> None:
        nxdomain = FakeDnsServer(
            lambda query: build_dns_response(query, [], rcode=3)
        )
        try:
            report = dnsdiag.run_queries(
                "missing.example", ["A"], server=nxdomain.address, timeout=2.0
            )
        finally:
            nxdomain.close()
        self.assertFalse(report["ok"])
        self.assertEqual(report["queries"][0]["status"], "NXDOMAIN")

    def test_transport_errors_are_reported_per_query(self) -> None:
        silent = FakeDnsServer(lambda query: b"")
        try:
            report = dnsdiag.run_queries(
                "example.com", ["A", "AAAA"], server=silent.address, timeout=0.2
            )
        finally:
            silent.close()
        self.assertFalse(report["ok"])
        self.assertEqual(len(report["queries"]), 2)
        for query in report["queries"]:
            self.assertEqual(query["status"], "ERROR")
            self.assertIn("timed out", query["error"])


class DnsCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = FakeDnsServer(standard_dns_responder)

    def tearDown(self) -> None:
        self.server.close()

    def test_json_output(self) -> None:
        code, output, _ = run_cli(
            [
                "dns",
                "--json",
                "example.com",
                "--server",
                self.server.address,
                "--type",
                "A",
            ]
        )
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["queries"][0]["status"], "NOERROR")
        self.assertFalse(payload["system_resolver"])

    def test_human_output(self) -> None:
        code, output, _ = run_cli(
            ["dns", "example.com", "--server", self.server.address, "--type", "MX"]
        )
        self.assertEqual(code, 0)
        self.assertIn("NOERROR", output)
        self.assertIn("10 mail.example.com", output)
        self.assertIn("Summary:", output)

    def test_nxdomain_exit_code(self) -> None:
        nxdomain = FakeDnsServer(lambda query: build_dns_response(query, [], rcode=3))
        try:
            code, _, _ = run_cli(
                ["dns", "--json", "missing.example", "--server", nxdomain.address]
            )
        finally:
            nxdomain.close()
        self.assertEqual(code, 1)

    def test_unsupported_type_is_usage_error(self) -> None:
        code, _, _ = run_cli(["dns", "example.com", "--type", "SOA"])
        self.assertEqual(code, 2)

    def test_a_lookup_for_ip_is_runtime_error(self) -> None:
        code, output, _ = run_cli(
            ["dns", "192.0.2.1", "--type", "A", "--server", self.server.address]
        )
        self.assertEqual(code, 1)
        self.assertIn("require a hostname", output)


if __name__ == "__main__":
    unittest.main()
