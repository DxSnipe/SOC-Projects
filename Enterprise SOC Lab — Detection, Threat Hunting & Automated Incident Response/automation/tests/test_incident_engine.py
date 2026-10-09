import unittest

from incident_engine import (
    generate_incident_id,
    determine_severity,
    build_incident,
)


class TestIncidentEngine(unittest.TestCase):

    def test_incident_id(self):
        incident_id = generate_incident_id(
            "2026-10-08T06:18:30.000+0000",
            1
        )

        self.assertEqual(
            incident_id,
            "INC-20261008-001"
        )

    def test_high_severity(self):
        severity = determine_severity(
            {"rating": "HIGH"}
        )

        self.assertEqual(severity, "HIGH")

    def test_medium_severity(self):
        severity = determine_severity(
            {"rating": "MEDIUM"}
        )

        self.assertEqual(severity, "MEDIUM")

    def test_low_severity(self):
        severity = determine_severity(
            {"rating": "LOW"}
        )

        self.assertEqual(severity, "LOW")

    def test_unknown_rating_defaults_low(self):
        severity = determine_severity(
            {"rating": "UNKNOWN"}
        )

        self.assertEqual(severity, "LOW")

    def test_build_incident(self):
        result = {
            "timestamp": "2026-10-08T06:18:30.000+0000",
            "alert_id": "example-alert-001",
            "rule_id": "5712",
            "description": "Brute force detected",
            "agent_name": "example-wazuh-server",
            "source_ip": "192.0.2.50",
            "source_port": "54321",
            "destination_ip": None,
            "destination_port": None,
            "source_user": None,
            "destination_user": "test-user",
            "full_log": "Brute force detected",
            "risk": {
                "score": 2,
                "rating": "LOW",
                "factors": ["Brute Force"]
            },
            "mitre": {
                "techniques": ["Brute Force"],
                "tactics": ["Credential Access"]
            },
            "iocs": {
                "ipv4": ["192.0.2.50"],
                "ipv6": [],
                "sha256": [],
                "sha1": [],
                "md5": [],
                "urls": [],
                "domains": []
            },
            "enrichment": {
                "ips": [],
                "domains": [],
                "urls": [],
                "hashes": []
            }
        }

        incident = build_incident(result)

        self.assertEqual(
            incident["incident_id"],
            "INC-20261008-001"
        )

        self.assertEqual(
            incident["status"],
            "OPEN"
        )

        self.assertEqual(
            incident["severity"],
            "LOW"
        )

        self.assertEqual(
            incident["analyst_assessment"]["classification"],
            "UNREVIEWED"
        )

        self.assertFalse(
            incident["analyst_assessment"]["compromise_confirmed"]
        )

        self.assertEqual(
            incident["source_alert_id"],
            "example-alert-001"
        )


if __name__ == "__main__":
    unittest.main()
