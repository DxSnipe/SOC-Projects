import json
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_AUDIT_FILE = "output/audit.log.jsonl"


def write_audit_event(
    action,
    status,
    incident_id=None,
    details=None,
    audit_file=DEFAULT_AUDIT_FILE
):
    """
    Append one structured audit event to a JSONL file.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "status": status,
        "incident_id": incident_id,
        "details": details or {}
    }

    path = Path(audit_file)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(
            json.dumps(event)
            + "\n"
        )

    return event
