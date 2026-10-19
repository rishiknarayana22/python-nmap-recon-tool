
import unittest
from unittest.mock import patch

from scanner import is_valid_target


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
        mock_dns.return_value = [(None, None, None, None, ("192.0.2.1", 0))]
        self.assertTrue(is_valid_target("lab.example"))

    @patch("scanner.socket.getaddrinfo")
    def test_hostname_that_does_not_resolve(self, mock_dns):
        import socket
        mock_dns.side_effect = socket.gaierror("Name not found")
        self.assertFalse(is_valid_target("lab.example"))


if __name__ == "__main__":
    unittest.main()
