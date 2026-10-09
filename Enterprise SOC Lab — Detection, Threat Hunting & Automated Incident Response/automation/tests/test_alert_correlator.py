import unittest

from alert_correlator import (
    correlation_reasons,
    correlate_alerts,
    get_process_guid,
)


class TestAlertCorrelator(unittest.TestCase):

    def test_process_guid_correlation(self):
        alert_a = {
            "timestamp": "2026-10-08T06:18:30.000+0000",
            "agent": {"id": "001"},
            "data": {"ProcessGuid": "{ABC-123}"},
        }

        alert_b = {
            "timestamp": "2026-10-08T06:18:31.000+0000",
            "agent": {"id": "001"},
            "data": {"ProcessGuid": "{ABC-123}"},
        }

        reasons = correlation_reasons(alert_a, alert_b)

        self.assertIn("same ProcessGuid", reasons)

    def test_shared_source_ip_correlation(self):
        alert_a = {
            "timestamp": "2026-10-08T06:18:30.000+0000",
            "agent": {"id": "001"},
            "data": {"srcip": "192.0.2.50"},
        }

        alert_b = {
            "timestamp": "2026-10-08T06:18:40.000+0000",
            "agent": {"id": "001"},
            "data": {"srcip": "192.0.2.50"},
        }

        reasons = correlation_reasons(alert_a, alert_b)

        self.assertIn(
            "shared IOC: 192.0.2.50",
            reasons
        )

    def test_nested_wazuh_sysmon_process_guid(self):
        alert = {
            "data": {
                "win": {
                    "eventdata": {
                        "processGuid": "{73915500-2466-6ac7-4e01-000000007800}"
                    }
                }
            }
        }

        process_guid = get_process_guid(alert)

        self.assertEqual(
            process_guid,
            "{73915500-2466-6ac7-4e01-000000007800}"
        )

    def test_same_agent_and_close_time(self):
        alert_a = {
            "timestamp": "2026-10-08T06:18:30.000+0000",
            "agent": {"id": "001"},
            "data": {},
        }

        alert_b = {
            "timestamp": "2026-10-08T06:18:45.000+0000",
            "agent": {"id": "001"},
            "data": {},
        }

        reasons = correlation_reasons(alert_a, alert_b)

        self.assertIn(
            "same agent with close timing",
            reasons
        )

    def test_distant_alerts_not_correlated(self):
        alert_a = {
            "timestamp": "2026-10-08T06:18:30.000+0000",
            "agent": {"id": "001"},
            "data": {},
        }

        alert_b = {
            "timestamp": "2026-10-08T08:18:30.000+0000",
            "agent": {"id": "001"},
            "data": {},
        }

        reasons = correlation_reasons(alert_a, alert_b)

        self.assertEqual(reasons, [])

    def test_different_process_guid(self):
        alert_a = {
            "timestamp": "2026-10-08T06:18:30.000+0000",
            "agent": {"id": "001"},
            "data": {"ProcessGuid": "{ABC-123}"},
        }

        alert_b = {
            "timestamp": "2026-10-08T06:18:31.000+0000",
            "agent": {"id": "001"},
            "data": {"ProcessGuid": "{XYZ-789}"},
        }

        reasons = correlation_reasons(alert_a, alert_b)

        self.assertNotIn("same ProcessGuid", reasons)

    def test_multiple_alerts_are_grouped(self):
        alerts = [
            {
                "timestamp": "2026-10-08T06:18:30.000+0000",
                "agent": {"id": "001"},
                "data": {
                    "ProcessGuid": "{ABC-123}",
                    "srcip": "192.0.2.50",
                },
            },
            {
                "timestamp": "2026-10-08T06:18:32.000+0000",
                "agent": {"id": "001"},
                "data": {
                    "ProcessGuid": "{ABC-123}",
                    "srcip": "192.0.2.50",
                },
            },
            {
                "timestamp": "2026-10-08T09:00:00.000+0000",
                "agent": {"id": "002"},
                "data": {
                    "srcip": "198.51.100.20",
                },
            },
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 2)
        self.assertEqual(len(groups[0]["alerts"]), 2)
        self.assertEqual(len(groups[1]["alerts"]), 1)

        self.assertIn(
            "same ProcessGuid",
            groups[0]["reasons"]
        )

        self.assertIn(
            "shared IOC: 192.0.2.50",
            groups[0]["reasons"]
        )

if __name__ == "__main__":
    unittest.main()
