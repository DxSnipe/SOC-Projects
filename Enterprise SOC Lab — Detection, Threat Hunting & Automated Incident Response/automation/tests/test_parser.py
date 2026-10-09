import json
import unittest
from pathlib import Path

from soc_alert_parser import parse_alert, calculate_risk, classify_ip, load_risk_config


class TestSOCAlertParser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sample_path = Path("sample_alert.json")

        with open(sample_path, "r", encoding="utf-8") as f:
            cls.alert = json.load(f)

        cls.result = parse_alert(cls.alert)
        cls.config = load_risk_config("config/risk_config.json")

    # ---------- Parser tests ----------

    def test_rule_id_extraction(self):
        self.assertEqual(self.result["rule_id"], "5712")

    def test_source_ip_extraction(self):
        self.assertEqual(self.result["source_ip"], "192.0.2.50")

    def test_mitre_extraction(self):
        self.assertIn(
            "Brute Force",
            self.result["mitre"]["techniques"]
        )

    def test_destination_user_extraction(self):
        self.assertEqual(
            self.result["destination_user"],
            "test-user"
        )

    # ---------- IP classification ----------

    def test_loopback_ip_classification(self):
        self.assertEqual(
            classify_ip("127.0.0.1"),
            "loopback"
        )

    def test_private_ip_classification(self):
        self.assertEqual(
            classify_ip("172.31.5.141"),
            "private"
        )

    def test_public_ip_classification(self):
        self.assertEqual(
            classify_ip("8.8.8.8"),
            "public"
        )

    # ---------- Network risk ----------

    def test_public_ip_adds_network_risk(self):
        result = self.result.copy()
        result["destination_ip"] = "8.8.8.8"

        risk = calculate_risk(result, self.config)

        self.assertIn(
            "+1 Public network address",
            risk["factors"]
        )

    def test_private_ip_does_not_add_network_risk(self):
        result = self.result.copy()
        result["destination_ip"] = "172.31.5.141"

        risk = calculate_risk(result, self.config)

        self.assertNotIn(
            "+1 Public network address",
            risk["factors"]
        )

    def test_loopback_ip_does_not_add_network_risk(self):
        result = self.result.copy()
        result["destination_ip"] = "127.0.0.1"

        risk = calculate_risk(result, self.config)

        self.assertNotIn(
            "+1 Public network address",
            risk["factors"]
        )

    # ---------- Risk scoring ----------

    def test_low_risk(self):
        result = self.result.copy()

        risk = calculate_risk(result, self.config)

        self.assertEqual(risk["score"], 2)
        self.assertEqual(risk["rating"], "LOW")

    def test_medium_risk(self):
        result = self.result.copy()
        result["description"] = "PowerShell authentication failure"

        risk = calculate_risk(result, self.config)

        self.assertEqual(risk["score"], 5)
        self.assertEqual(risk["rating"], "MEDIUM")

    def test_high_risk(self):
        result = self.result.copy()

        result["description"] = "Encoded PowerShell activity"
        result["destination_ip"] = "8.8.8.8"
        result["iocs"] = {
            "ipv4": ["8.8.8.8"],
            "sha256": [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
            "urls": [
                "https://example.com/test"
            ]
        }

        risk = calculate_risk(result, self.config)

        self.assertEqual(risk["score"], 10)
        self.assertEqual(risk["rating"], "HIGH")

    def test_encoded_powershell_is_not_double_counted(self):
        result = self.result.copy()
        result["description"] = "Encoded PowerShell"

        risk = calculate_risk(result, self.config)

        self.assertIn(
            "+3 Encoded PowerShell",
            risk["factors"]
        )

        self.assertNotIn(
            "+2 PowerShell activity",
            risk["factors"]
        )


if __name__ == "__main__":
    unittest.main()
