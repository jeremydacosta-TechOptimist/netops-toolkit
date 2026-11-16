"""Tests for HTTP and TLS diagnostics."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from helpers import http_server, run_cli

from netops import httpdiag
from netops.errors import NetopsError


class ParseTargetTests(unittest.TestCase):
    def test_https_default_port(self) -> None:
        self.assertEqual(
            httpdiag.parse_target("https://example.com"), ("https", "example.com", 443, "/")
        )

    def test_http_default_port_and_path(self) -> None:
        self.assertEqual(
            httpdiag.parse_target("http://example.com/status?full=1"),
            ("http", "example.com", 80, "/status?full=1"),
        )

    def test_explicit_port(self) -> None:
        self.assertEqual(
            httpdiag.parse_target("http://127.0.0.1:8080/ok"),
            ("http", "127.0.0.1", 8080, "/ok"),
        )

    def test_invalid_urls(self) -> None:
        for url in ("ftp://example.com", "example.com", "http://", "http://example.com:abc/"):
            with self.subTest(url=url), self.assertRaises(NetopsError):
                httpdiag.parse_target(url)


class CertificateTests(unittest.TestCase):
    CERTIFICATE = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),), (("commonName", "Test Root"),)),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Feb  1 00:00:00 2026 GMT",
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }

    def test_certificate_fields(self) -> None:
        info = httpdiag.certificate_info(
            self.CERTIFICATE, now=datetime(2026, 1, 26, tzinfo=timezone.utc)
        )
        self.assertEqual(info.subject["commonName"], "example.com")
        self.assertEqual(info.issuer["organizationName"], "Test CA")
        self.assertEqual(info.not_before, "2026-01-01 00:00:00 UTC")
        self.assertEqual(info.not_after, "2026-02-01 00:00:00 UTC")
        self.assertEqual(info.days_remaining, 6)
        self.assertEqual(
            info.subject_alt_names, ["DNS:example.com", "DNS:www.example.com"]
        )

    def test_expired_certificate_reports_negative_days(self) -> None:
        info = httpdiag.certificate_info(
            self.CERTIFICATE, now=datetime(2026, 2, 2, tzinfo=timezone.utc)
        )
        self.assertEqual(info.days_remaining, -1)

    def test_missing_certificate_raises(self) -> None:
        with self.assertRaises(NetopsError):
            httpdiag.certificate_info({})
        with self.assertRaises(NetopsError):
            httpdiag.certificate_info({"subject": ()})


class RequestTests(unittest.TestCase):
    def test_ok_response(self) -> None:
        with http_server() as base_url:
            report = httpdiag.request_url(base_url + "/ok", timeout=5.0)
        self.assertEqual(report["status"], 200)
        self.assertEqual(report["reason"], "OK")
        self.assertEqual(report["redirects"], [])
        self.assertIsNone(report["tls"])
        self.assertEqual(report["body_bytes_read"], len(b"netops-test-body"))
        names = [header["name"].lower() for header in report["headers"]]
        self.assertIn("x-test-header", names)
        self.assertTrue(report["remote"].startswith("127.0.0.1:"))

    def test_redirect_is_followed(self) -> None:
        with http_server() as base_url:
            report = httpdiag.request_url(base_url + "/redirect", timeout=5.0)
        self.assertEqual(len(report["redirects"]), 1)
        self.assertEqual(report["redirects"][0]["status"], 302)
        self.assertEqual(report["redirects"][0]["location"], "/ok")
        self.assertEqual(report["status"], 200)
        self.assertTrue(report["final_url"].endswith("/ok"))

    def test_redirect_chain(self) -> None:
        with http_server() as base_url:
            report = httpdiag.request_url(base_url + "/chain", timeout=5.0)
        self.assertEqual([hop["status"] for hop in report["redirects"]], [301, 302])
        self.assertEqual(report["status"], 200)

    def test_redirect_loop_raises(self) -> None:
        with http_server() as base_url:
            with self.assertRaises(NetopsError):
                httpdiag.request_url(base_url + "/loop", timeout=5.0, max_redirects=2)

    def test_max_redirects_zero(self) -> None:
        with http_server() as base_url:
            with self.assertRaises(NetopsError):
                httpdiag.request_url(base_url + "/redirect", timeout=5.0, max_redirects=0)

    def test_not_found_response(self) -> None:
        with http_server() as base_url:
            report = httpdiag.request_url(base_url + "/missing", timeout=5.0)
        self.assertEqual(report["status"], 404)


class HttpCliTests(unittest.TestCase):
    def test_json_output(self) -> None:
        with http_server() as base_url:
            code, output, _ = run_cli(["http", "--json", base_url + "/ok"])
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["status"], 200)
        self.assertTrue(payload["url"].endswith("/ok"))

    def test_human_output(self) -> None:
        with http_server() as base_url:
            code, output, _ = run_cli(["http", base_url + "/ok"])
        self.assertEqual(code, 0)
        self.assertIn("Status    : 200 OK", output)
        self.assertIn("Redirects: none", output)

    def test_http_error_status_exit_code(self) -> None:
        with http_server() as base_url:
            code, _, _ = run_cli(["http", base_url + "/missing"])
        self.assertEqual(code, 1)

    def test_connection_failure_exit_code(self) -> None:
        code, _, stderr = run_cli(
            ["http", "http://127.0.0.1:1/", "--timeout", "0.5"]
        )
        self.assertEqual(code, 1)
        self.assertIn("error:", stderr)


if __name__ == "__main__":
    unittest.main()
