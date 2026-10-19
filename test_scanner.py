
import unittest
from unittest.mock import patch
import socket
import xml.etree.ElementTree as ET

from scanner import is_valid_target, parse_nmap_xml


class TestTargetValidation(unittest.TestCase):

    def test_valid_ipv4(self):
        self.assertTrue(is_valid_target("127.0.0.1"))

    def test_valid_ipv6(self):
        self.assertTrue(is_valid_target("::1"))

    def test_empty_target(self):
        self.assertFalse(is_valid_target(""))

    def test_invalid_target_format(self):
        self.assertFalse(is_valid_target("hello world"))

    @patch("scanner.socket.getaddrinfo")
    def test_hostname_that_resolves(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("192.0.2.1", 0))
        ]

        self.assertTrue(is_valid_target("lab.example"))

    @patch("scanner.socket.getaddrinfo")
    def test_hostname_that_does_not_resolve(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("Name not found")

        self.assertFalse(is_valid_target("lab.example"))


class TestNmapXMLParsing(unittest.TestCase):

    def test_parse_nmap_xml_extracts_port_and_service(self):
        xml_text = """
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache" version="2.4"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """

        rows = parse_nmap_xml(
            xml_text,
            "127.0.0.1",
            "2026-10-19T10:00:00"
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timestamp"], "2026-10-19T10:00:00")
        self.assertEqual(rows[0]["target"], "127.0.0.1")
        self.assertEqual(rows[0]["protocol"], "tcp")
        self.assertEqual(rows[0]["port"], "80")
        self.assertEqual(rows[0]["state"], "open")
        self.assertEqual(rows[0]["service"], "http")
        self.assertEqual(rows[0]["product"], "Apache")
        self.assertEqual(rows[0]["version"], "2.4")

    def test_parse_nmap_xml_with_no_ports(self):
        xml_text = "<nmaprun><host><ports/></host></nmaprun>"

        rows = parse_nmap_xml(
            xml_text,
            "127.0.0.1",
            "2026-10-19T10:00:00"
        )

        self.assertEqual(rows, [])

    def test_parse_nmap_xml_missing_service(self):
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
            "2026-10-19T10:00:00"
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "closed")
        self.assertEqual(rows[0]["service"], "unknown")
        self.assertEqual(rows[0]["product"], "")
        self.assertEqual(rows[0]["version"], "")

    def test_parse_nmap_xml_invalid_xml(self):
        with self.assertRaises(ET.ParseError):
            parse_nmap_xml(
                "<nmaprun><host>",
                "127.0.0.1",
                "2026-10-19T10:00:00"
            )


if __name__ == "__main__":
    unittest.main()
