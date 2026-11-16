"""Tests for MAC address parsing and the curated OUI vendor table."""

from __future__ import annotations

import json
import unittest

from helpers import run_cli

from netops import oui
from netops.errors import NetopsError


class VendorTableTests(unittest.TestCase):
    def test_table_has_at_least_sixty_entries(self) -> None:
        self.assertGreaterEqual(len(oui.VENDOR_PREFIXES), 60)

    def test_prefixes_are_well_formed(self) -> None:
        for prefix in oui.VENDOR_PREFIXES:
            with self.subTest(prefix=prefix):
                self.assertEqual(len(prefix), 6)
                self.assertEqual(prefix, prefix.upper())
                int(prefix, 16)

    def test_expected_vendors_are_present(self) -> None:
        expected = {
            "00000C": "Cisco",
            "000C29": "VMware",
            "B827EB": "Raspberry Pi",
            "2C6BF5": "Juniper",
            "00090F": "Fortinet",
            "245A4C": "Ubiquiti",
            "4C5E0C": "MikroTik",
            "3CFDFE": "Intel",
        }
        for prefix, fragment in expected.items():
            with self.subTest(prefix=prefix):
                self.assertIn(fragment, oui.VENDOR_PREFIXES[prefix])


class MacParsingTests(unittest.TestCase):
    def test_colon_notation(self) -> None:
        info = oui.parse_mac("00:1b:63:84:45:e6")
        self.assertEqual(info.normalized, "00:1B:63:84:45:E6")
        self.assertEqual(info.oui, "001B63")
        self.assertEqual(info.vendor, "Apple, Inc.")
        self.assertFalse(info.locally_administered)
        self.assertFalse(info.multicast)

    def test_hyphen_and_cisco_notation(self) -> None:
        self.assertEqual(
            oui.parse_mac("00-1b-63-84-45-e6").normalized, "00:1B:63:84:45:E6"
        )
        self.assertEqual(
            oui.parse_mac("001b.6384.45e6").normalized, "00:1B:63:84:45:E6"
        )

    def test_bare_hex_and_oui_only(self) -> None:
        self.assertEqual(
            oui.parse_mac("001B638445E6").normalized, "00:1B:63:84:45:E6"
        )
        info = oui.parse_mac("00-00-0C")
        self.assertEqual(info.oui, "00000C")
        self.assertEqual(info.normalized, "00:00:0C")
        self.assertEqual(info.vendor, "Cisco Systems, Inc.")

    def test_unknown_oui_has_no_vendor(self) -> None:
        info = oui.parse_mac("02:00:00:00:00:01")
        self.assertIsNone(info.vendor)
        self.assertTrue(info.locally_administered)
        self.assertFalse(info.multicast)

    def test_multicast_bit(self) -> None:
        info = oui.parse_mac("01:00:5E:00:00:01")
        self.assertTrue(info.multicast)

    def test_invalid_addresses(self) -> None:
        for value in ("", "00:11:22:33", "ZZ:00:0C:12:34:56", "00:00:0C:12:34:56:78"):
            with self.subTest(value=value), self.assertRaises(NetopsError):
                oui.parse_mac(value)


class MacCliTests(unittest.TestCase):
    def test_single_address_human_output(self) -> None:
        code, output, _ = run_cli(["mac", "00:00:0c:12:34:56"])
        self.assertEqual(code, 0)
        self.assertIn("Vendor     : Cisco Systems, Inc.", output)
        self.assertIn("MAC        : 00:00:0C:12:34:56", output)

    def test_json_output(self) -> None:
        code, output, _ = run_cli(
            ["mac", "--json", "00:00:0c:12:34:56", "02:00:00:00:00:01"]
        )
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(len(payload["addresses"]), 2)
        self.assertEqual(payload["addresses"][0]["vendor"], "Cisco Systems, Inc.")
        self.assertIsNone(payload["addresses"][1]["vendor"])

    def test_invalid_address_is_usage_error(self) -> None:
        code, _, stderr = run_cli(["mac", "not-a-mac"])
        self.assertEqual(code, 2)
        self.assertIn("invalid MAC address", stderr)


if __name__ == "__main__":
    unittest.main()
