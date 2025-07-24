import unittest
from src.core.scanner import NetworkScanner

class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = NetworkScanner(threads=10, timeout=1, verbose=False)

    def test_validate_target(self):
        self.assertIsNotNone(self.scanner.validator.validate_target("127.0.0.1"))
        self.assertIsNone(self.scanner.validator.validate_target("invalid.example.com"))

    def test_parse_ports(self):
        ports = self.scanner.port_scanner.parse_ports("common")
        self.assertTrue(len(ports) > 0)
        ports = self.scanner.port_scanner.parse_ports("1-10")
        self.assertEqual(len(ports), 10)
        ports = self.scanner.port_scanner.parse_ports("80,443")
        self.assertEqual(ports, [80, 443])

if __name__ == '__main__':
    unittest.main()