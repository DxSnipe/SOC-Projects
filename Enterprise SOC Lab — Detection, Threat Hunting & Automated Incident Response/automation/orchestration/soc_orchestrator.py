import argparse
import json
from pathlib import Path

from soc_alert_parser import (
    load_alerts,
    parse_alert,
    calculate_risk,
    load_risk_config,
)
from alert_correlator import correlate_alerts
from incident_engine import build_incident
from soar.response_engine import determine_response, apply_response
from audit.audit_logger import write_audit_event


DEFAULT_ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"
DEFAULT_CONFIG_FILE = "config/risk_config.json"
DEFAULT_OUTPUT_DIR = "output/orchestrated"


def select_alerts(alerts, rule_id=None):
    """
    Select alerts for orchestration.

    If a rule ID is supplied, only alerts matching that
    Wazuh rule are selected.

    Otherwise, the latest alert is selected.
    """

    if rule_id:
        selected = [
            alert
            for alert in alerts
            if alert.get("rule", {}).get("id") == rule_id
        ]

        return selected

    if alerts:
        return [alerts[-1]]

    return []


def create_incident(alerts, config):
    """
    Parse, score, correlate, and create an incident candidate.
    """

    if not alerts:
        return None

    parsed_results = []

    for alert in alerts:
        result = parse_alert(alert)

        result["risk"] = calculate_risk(
            result,
            config
        )

        parsed_results.append(result)

    groups = correlate_alerts(alerts)

    if not groups:
        return None

    # Use the first correlation group from the
    # intentionally selected alert set.
    group = groups[0]

    primary_alert = group["alerts"][0]

    primary_result = next(
        result
        for result in parsed_results
        if result["alert_id"] == primary_alert.get("id")
    )

    related_alerts = [
        alert
        for alert in group["alerts"]
        if alert.get("id") != primary_alert.get("id")
    ]

    incident = build_incident(
        primary_result,
        related_alerts=related_alerts,
        sequence=1
    )

    incident["correlation"]["reasons"] = group["reasons"]

    return incident


def save_incident(incident, output_dir):
    """
    Save the complete orchestrated incident.
    """

    output_path = Path(output_dir)

    output_path.mkdir(
        parents=True,
        exist_ok=True
    )

    incident_file = output_path / "incident.json"

    with incident_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            incident,
            file,
            indent=4
        )

    return incident_file


def run_orchestration(
    alert_file=DEFAULT_ALERT_FILE,
    config_file=DEFAULT_CONFIG_FILE,
    output_dir=DEFAULT_OUTPUT_DIR,
    mode="SIMULATE",
    rule_id=None,
):
    """
    Execute the complete safe SOC automation workflow:

    Wazuh alert
        -> alert selection
        -> parsing
        -> risk assessment
        -> correlation
        -> incident creation
        -> SOAR decision
        -> audit logging
    """

    output_path = Path(output_dir)

    output_path.mkdir(
        parents=True,
        exist_ok=True
    )

    # ---------------------------------------------------------
    # 1. LOAD ALERTS
    # ---------------------------------------------------------
    alerts = load_alerts(alert_file)

    if not alerts:
        raise RuntimeError(
            "No valid Wazuh alerts found."
        )

    # ---------------------------------------------------------
    # 2. SELECT ALERTS
    # ---------------------------------------------------------
    selected_alerts = select_alerts(
        alerts,
        rule_id=rule_id
    )

    if not selected_alerts:
        if rule_id:
            raise RuntimeError(
                f"No Wazuh alerts found for rule {rule_id}."
            )

        raise RuntimeError(
            "No alerts available for orchestration."
        )

    write_audit_event(
        action="SELECT_ALERTS",
        status="SUCCESS",
        details={
            "total_alerts_loaded": len(alerts),
            "selected_alert_count": len(selected_alerts),
            "rule_id": rule_id,
        },
        audit_file=str(
            output_path / "audit.log.jsonl"
        )
    )

    # ---------------------------------------------------------
    # 3. LOAD RISK CONFIG
    # ---------------------------------------------------------
    config = load_risk_config(
        config_file
    )

    write_audit_event(
        action="LOAD_RISK_CONFIG",
        status="SUCCESS",
        details={
            "config_file": config_file
        },
        audit_file=str(
            output_path / "audit.log.jsonl"
        )
    )

    # ---------------------------------------------------------
    # 4. CREATE INCIDENT
    # ---------------------------------------------------------
    incident = create_incident(
        selected_alerts,
        config
    )

    if incident is None:
        write_audit_event(
            action="CREATE_INCIDENT",
            status="NO_INCIDENT",
            details={},
            audit_file=str(
                output_path / "audit.log.jsonl"
            )
        )

        return None

    write_audit_event(
        action="CREATE_INCIDENT",
        status="SUCCESS",
        incident_id=incident["incident_id"],
        details={
            "severity": incident["severity"],
            "rule_id": incident["rule_id"],
            "risk": incident["risk"],
        },
        audit_file=str(
            output_path / "audit.log.jsonl"
        )
    )

    # ---------------------------------------------------------
    # 5. SOAR RESPONSE DECISION
    # ---------------------------------------------------------
    response = determine_response(
        incident,
        mode=mode
    )

    incident = apply_response(
        incident,
        response
    )

    write_audit_event(
        action="SOAR_RESPONSE_DECISION",
        status="SUCCESS",
        incident_id=incident["incident_id"],
        details={
            "mode": response["mode"],
            "action": response["action"],
            "approval_required": response[
                "approval_required"
            ],
            "executed": response["executed"],
        },
        audit_file=str(
            output_path / "audit.log.jsonl"
        )
    )

    # ---------------------------------------------------------
    # 6. SAVE INCIDENT
    # ---------------------------------------------------------
    incident_file = save_incident(
        incident,
        output_dir
    )

    write_audit_event(
        action="SAVE_INCIDENT",
        status="SUCCESS",
        incident_id=incident["incident_id"],
        details={
            "incident_file": str(
                incident_file
            )
        },
        audit_file=str(
            output_path / "audit.log.jsonl"
        )
    )

    return incident


def print_summary(incident):
    """
    Print a concise analyst-facing summary.
    """

    if incident is None:
        print(
            "\nNo incident candidate generated."
        )
        return

    response = incident.get(
        "response",
        {}
    )

    print(
        "\n=== SOC ORCHESTRATION RESULT ==="
    )

    print(
        f"Incident ID:       "
        f"{incident['incident_id']}"
    )

    print(
        f"Severity:          "
        f"{incident['severity']}"
    )

    print(
        f"Risk Score:        "
        f"{incident['risk'].get('score')}"
    )

    print(
        f"Risk Rating:       "
        f"{incident['risk'].get('rating')}"
    )

    print(
        f"Rule:              "
        f"{incident['rule_id']}"
    )

    print(
        f"Title:             "
        f"{incident['title']}"
    )

    print(
        f"Related Alerts:    "
        f"{incident['correlation']['related_alert_count']}"
    )

    print("\n--- SOAR Decision ---")

    print(
        f"Mode:              "
        f"{response.get('mode')}"
    )

    print(
        f"Action:            "
        f"{response.get('action')}"
    )

    print(
        f"Approval Required: "
        f"{response.get('approval_required')}"
    )

    print(
        f"Executed:          "
        f"{response.get('executed')}"
    )

    print(
        f"Rationale:         "
        f"{response.get('rationale')}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "SOC alert-to-incident-to-SOAR orchestrator"
        )
    )

    parser.add_argument(
        "--alert-file",
        default=DEFAULT_ALERT_FILE,
        help="Path to Wazuh alerts.json"
    )

    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_FILE,
        help="Path to risk configuration"
    )

    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for orchestration artifacts"
    )

    parser.add_argument(
        "--rule",
        help=(
            "Only orchestrate alerts matching "
            "this Wazuh rule ID"
        )
    )

    parser.add_argument(
        "--mode",
        choices=[
            "SIMULATE",
            "APPROVAL",
            "EXECUTE",
        ],
        default="SIMULATE",
        help="SOAR response mode"
    )

    args = parser.parse_args()

    try:
        incident = run_orchestration(
            alert_file=args.alert_file,
            config_file=args.config,
            output_dir=args.output_dir,
            mode=args.mode,
            rule_id=args.rule,
        )

    except (
        FileNotFoundError,
        PermissionError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(
            f"Orchestration error: {error}"
        )
        return

    print_summary(incident)


if __name__ == "__main__":
    main()
