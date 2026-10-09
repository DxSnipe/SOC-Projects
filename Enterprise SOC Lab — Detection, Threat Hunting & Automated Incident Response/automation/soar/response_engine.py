VALID_MODES = {
    "SIMULATE",
    "APPROVAL",
    "EXECUTE",
}


def determine_response(incident, mode="SIMULATE"):
    """
    Determine a safe SOAR response based on incident severity.

    This function does not execute system changes.
    It produces a response decision for analyst review.
    """
    mode = mode.upper()

    if mode not in VALID_MODES:
        raise ValueError(
            f"Unsupported response mode: {mode}"
        )

    severity = incident.get("severity", "LOW").upper()

    if severity == "HIGH":
        action = "CONTAINMENT_REVIEW"
        rationale = (
            "High-severity incident requires analyst review "
            "for potential containment."
        )

    elif severity == "MEDIUM":
        action = "INVESTIGATION_REQUIRED"
        rationale = (
            "Medium-severity incident requires additional "
            "investigation before containment."
        )

    else:
        action = "MONITOR_AND_VALIDATE"
        rationale = (
            "Low-severity incident should be validated and "
            "monitored before response."
        )

    return {
        "mode": mode,
        "action": action,
        "rationale": rationale,
        "executed": False,
        "approval_required": mode in {
            "APPROVAL",
            "EXECUTE",
        },
    }


def apply_response(incident, response):
    """
    Record a response decision without performing destructive actions.
    """
    incident["response"] = {
        "mode": response["mode"],
        "action": response["action"],
        "rationale": response["rationale"],
        "executed": False,
        "approval_required": response["approval_required"],
    }

    return incident
