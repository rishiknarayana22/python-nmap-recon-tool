
import unittest
from unittest.mock import patch
import socket
import xml.etree.ElementTree as ET

from scanner import (
    is_valid_target,
    parse_nmap_xml,
    parse_ports,
    print_scan_summary,
)


class TestTargetValidation(unittest.TestCase):

    def test_valid_ipv4(self):
        self.assertTrue(is_valid_target("192.168.1.1"))

    def test_valid_ipv6(self):
        self.assertTrue(is_valid_target("::1"))

    def test_empty_target(self):
        self.assertFalse(is_valid_target(""))

    def test_invalid_target_format(self):
        self.assertFalse(is_valid_target("not a valid target"))

    @patch("scanner.socket.getaddrinfo")
    def test_valid_hostname(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
        ]

        self.assertTrue(is_valid_target("example.com"))

    @patch("scanner.socket.getaddrinfo")
    def test_unresolvable_hostname(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror

        self.assertFalse(is_valid_target("example.invalid"))


class TestNmapXMLParsing(unittest.TestCase):

    def test_extract_port_and_service(self):
        xml_text = """
        <nmaprun>
            <host>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="nginx" version="1.24"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        """

        rows = parse_nmap_xml(
            xml_text,
            "127.0.0.1",
            "2026-01-01T10:00:00+05:30"
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target"], "127.0.0.1")
        self.assertEqual(rows[0]["protocol"], "tcp")
        self.assertEqual(rows[0]["port"], "80")
        self.assertEqual(rows[0]["state"], "open")
        self.assertEqual(rows[0]["service"], "http")
        self.assertEqual(rows[0]["product"], "nginx")
        self.assertEqual(rows[0]["version"], "1.24")

    def test_no_ports(self):
        xml_text = """
        <nmaprun>
            <host>
                <ports/>
            </host>
        </nmaprun>
        """

        rows = parse_nmap_xml(
            xml_text,
            "127.0.0.1",
            "2026-01-01T10:00:00+05:30"
        )

        self.assertEqual(rows, [])

    def test_missing_service_information(self):
        xml_text = """
        <nmaprun>
            <host>
                <ports>
                    <port protocol="tcp" portid="443">
                        <state state="closed"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        """

        rows = parse_nmap_xml(
            xml_text,
            "127.0.0.1",
            "2026-01-01T10:00:00+05:30"
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "closed")
        self.assertEqual(rows[0]["service"], "unknown")
        self.assertEqual(rows[0]["product"], "")
        self.assertEqual(rows[0]["version"], "")

    def test_malformed_xml(self):
        xml_text = "<nmaprun><host>"

        with self.assertRaises(ET.ParseError):
            parse_nmap_xml(
                xml_text,
                "127.0.0.1",
                "2026-01-01T10:00:00+05:30"
            )


class TestPortParsing(unittest.TestCase):

    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_multiple_ports(self):
        self.assertEqual(
            parse_ports("22,80,443"),
            [22, 80, 443]
        )

    def test_whitespace_is_accepted(self):
        self.assertEqual(
            parse_ports(" 22, 80, 443 "),
            [22, 80, 443]
        )

    def test_port_zero_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_port_above_range_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("65536")

    def test_duplicate_ports_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("80,80")

    def test_empty_port_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("22,,80")

    def test_non_numeric_port_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("abc")


class TestScanSummary(unittest.TestCase):

    @patch("builtins.print")
    def test_summary_counts_port_states(self, mock_print):
        ports = [22, 80, 443, 3306, 8080]

        rows = [
            {"state": "open"},
            {"state": "closed"},
            {"state": "filtered"},
            {"state": "open"},
            {"state": "open"},
        ]

        print_scan_summary("127.0.0.1", ports, rows)

        output = "\n".join(
            str(call.args[0])
            for call in mock_print.call_args_list
        )

        self.assertIn("Target: 127.0.0.1", output)
        self.assertIn("Ports requested: 5", output)
        self.assertIn("Port results returned: 5", output)
        self.assertIn("Open ports: 3", output)
        self.assertIn("Closed ports: 1", output)
        self.assertIn("Filtered ports: 1", output)
        self.assertIn("Other states: 0", output)

    @patch("builtins.print")
    def test_summary_with_no_results(self, mock_print):
        print_scan_summary("127.0.0.1", [22, 80], [])

        output = "\n".join(
            str(call.args[0])
            for call in mock_print.call_args_list
        )

        self.assertIn("Ports requested: 2", output)
        self.assertIn("Port results returned: 0", output)
        self.assertIn("Open ports: 0", output)
        self.assertIn("Other states: 0", output)


if __name__ == "__main__":
    unittest.main()
