from datetime import datetime


def generate_incident_id(timestamp=None, sequence=1):
    """
    Generate a portable incident ID.

    Example:
    INC-20261008-001
    """
    if timestamp:
        try:
            normalized = timestamp.replace("+0000", "+00:00")
            date_part = datetime.fromisoformat(
                normalized
            ).strftime("%Y%m%d")
        except ValueError:
            date_part = datetime.now().strftime("%Y%m%d")
    else:
        date_part = datetime.now().strftime("%Y%m%d")

    return f"INC-{date_part}-{sequence:03d}"


def determine_severity(risk):
    """
    Convert the explainable risk rating into an incident severity.
    """
    rating = risk.get("rating", "LOW").upper()

    severity_map = {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW"
    }

    return severity_map.get(rating, "LOW")


def build_incident(result, related_alerts=None, sequence=1):
    """
    Build a structured SOC incident candidate from a parsed alert.
    """
    related_alerts = related_alerts or []

    incident_id = generate_incident_id(
        result.get("timestamp"),
        sequence
    )

    severity = determine_severity(
        result.get("risk", {})
    )

    techniques = result.get("mitre", {}).get(
        "techniques", []
    )

    tactics = result.get("mitre", {}).get(
        "tactics", []
    )

    return {
        "incident_id": incident_id,
        "status": "OPEN",
        "severity": severity,
        "created_at": result.get("timestamp"),
        "source_alert_id": result.get("alert_id"),
        "rule_id": result.get("rule_id"),
        "title": result.get("description"),
        "agent": result.get("agent_name"),
        "summary": (
            f"Automated incident candidate generated from "
            f"Wazuh rule {result.get('rule_id')}."
        ),
        "risk": result.get("risk", {}),
        "mitre": {
            "techniques": techniques,
            "tactics": tactics
        },
        "iocs": result.get("iocs", {}),
        "enrichment": result.get("enrichment", {}),
        "evidence": {
            "full_log": result.get("full_log"),
            "source_ip": result.get("source_ip"),
            "source_port": result.get("source_port"),
            "destination_ip": result.get("destination_ip"),
            "destination_port": result.get("destination_port"),
            "source_user": result.get("source_user"),
            "destination_user": result.get("destination_user")
        },
        "correlation": {
            "related_alert_count": len(related_alerts),
            "related_alert_ids": [
                alert.get("id")
                for alert in related_alerts
                if alert.get("id")
            ],
            "reasons": []
        },
        "analyst_assessment": {
            "classification": "UNREVIEWED",
            "compromise_confirmed": False,
            "notes": ""
        },
        "recommended_action": (
            "Review the alert evidence, validate the extracted "
            "observables, determine whether the activity is "
            "benign, suspicious, or malicious, and investigate "
            "related activity before taking response action."
        )
    }
