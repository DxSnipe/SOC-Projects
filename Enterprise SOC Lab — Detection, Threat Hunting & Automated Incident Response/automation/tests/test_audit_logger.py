import json
import tempfile
import unittest
from pathlib import Path

from audit_logger import write_audit_event


class TestAuditLogger(unittest.TestCase):

    def test_write_audit_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "audit.jsonl"

            event = write_audit_event(
                action="INCIDENT_CREATED",
                status="SUCCESS",
                incident_id="INC-20261008-001",
                details={
                    "severity": "MEDIUM"
                },
                audit_file=audit_file
            )

            self.assertEqual(
                event["action"],
                "INCIDENT_CREATED"
            )

            self.assertEqual(
                event["status"],
                "SUCCESS"
            )

            self.assertEqual(
                event["incident_id"],
                "INC-20261008-001"
            )

            with audit_file.open(
                "r",
                encoding="utf-8"
            ) as file:
                line = file.readline()

            stored_event = json.loads(line)

            self.assertEqual(
                stored_event["action"],
                "INCIDENT_CREATED"
            )

    def test_multiple_events_append(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = Path(temp_dir) / "audit.jsonl"

            write_audit_event(
                action="INCIDENT_CREATED",
                status="SUCCESS",
                audit_file=audit_file
            )

            write_audit_event(
                action="SOAR_DECISION",
                status="RECORDED",
                audit_file=audit_file
            )

            with audit_file.open(
                "r",
                encoding="utf-8"
            ) as file:
                lines = file.readlines()

            self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
