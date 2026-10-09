import unittest

from ioc_enricher import classify_ip, enrich_iocs


class TestIOCEnricher(unittest.TestCase):

    def test_private_ip(self):
        result = classify_ip("172.31.5.141")

        self.assertTrue(result["valid"])
        self.assertEqual(result["type"], "ipv4")
        self.assertEqual(result["scope"], "private")

    def test_loopback_ip(self):
        result = classify_ip("127.0.0.1")

        self.assertTrue(result["valid"])
        self.assertEqual(result["scope"], "loopback")

    def test_public_ip(self):
        result = classify_ip("8.8.8.8")

        self.assertTrue(result["valid"])
        self.assertEqual(result["scope"], "global")

    def test_invalid_ip(self):
        result = classify_ip("not-an-ip")

        self.assertFalse(result["valid"])
        self.assertEqual(result["scope"], "invalid")

    def test_ioc_enrichment_structure(self):
        iocs = {
            "ipv4": ["192.0.2.50"],
            "ipv6": [],
            "sha256": [],
            "sha1": [],
            "md5": [],
            "urls": ["https://example.com/test"],
            "domains": ["example.com"]
        }

        result = enrich_iocs(iocs)

        self.assertEqual(len(result["ips"]), 1)
        self.assertEqual(len(result["urls"]), 1)
        self.assertEqual(len(result["domains"]), 1)
        self.assertEqual(len(result["hashes"]), 0)


if __name__ == "__main__":
    unittest.main()
