import unittest

from response_engine import (
    determine_response,
    apply_response,
)


class TestResponseEngine(unittest.TestCase):

    def test_low_severity(self):
        incident = {"severity": "LOW"}

        response = determine_response(
            incident,
            "SIMULATE"
        )

        self.assertEqual(
            response["action"],
            "MONITOR_AND_VALIDATE"
        )

        self.assertFalse(
            response["executed"]
        )

        self.assertFalse(
            response["approval_required"]
        )

    def test_medium_severity(self):
        incident = {"severity": "MEDIUM"}

        response = determine_response(
            incident,
            "APPROVAL"
        )

        self.assertEqual(
            response["action"],
            "INVESTIGATION_REQUIRED"
        )

        self.assertTrue(
            response["approval_required"]
        )

    def test_high_severity(self):
        incident = {"severity": "HIGH"}

        response = determine_response(
            incident,
            "APPROVAL"
        )

        self.assertEqual(
            response["action"],
            "CONTAINMENT_REVIEW"
        )

        self.assertTrue(
            response["approval_required"]
        )

    def test_invalid_mode(self):
        incident = {"severity": "LOW"}

        with self.assertRaises(ValueError):
            determine_response(
                incident,
                "INVALID"
            )

    def test_apply_response(self):
        incident = {
            "incident_id": "INC-20261008-001",
            "severity": "MEDIUM",
        }

        response = determine_response(
            incident,
            "SIMULATE"
        )

        updated = apply_response(
            incident,
            response
        )

        self.assertIn(
            "response",
            updated
        )

        self.assertEqual(
            updated["response"]["action"],
            "INVESTIGATION_REQUIRED"
        )

        self.assertFalse(
            updated["response"]["executed"]
        )


if __name__ == "__main__":
    unittest.main()
