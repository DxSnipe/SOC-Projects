from datetime import datetime, timezone


def parse_timestamp(timestamp):
    """Convert a Wazuh timestamp into a timezone-aware datetime."""
    if not timestamp:
        return None

    try:
        normalized = timestamp.replace("+0000", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def get_process_guid(alert):
    """Extract ProcessGuid from common Wazuh/Sysmon locations."""
    data = alert.get("data", {})
    win = data.get("win", {})
    eventdata = win.get("eventdata", {})

    candidates = [
        data.get("ProcessGuid"),
        data.get("process_guid"),
        data.get("processguid"),
        eventdata.get("ProcessGuid"),
        eventdata.get("processGuid"),
        eventdata.get("process_guid"),
        eventdata.get("processguid"),
    ]

    full_log = alert.get("full_log", "")

    if "ProcessGuid" in full_log:
        parts = full_log.split("ProcessGuid", 1)[1]
        parts = parts.lstrip(" =:")
        return parts.split()[0].strip(",;")

    for value in candidates:
        if value:
            return value

    # Sysmon ProcessGuid can also appear inside the
    # Windows event message.
    message = (
        win.get("system", {}).get("message", "")
    )

    if "ProcessGuid:" in message:
        parts = message.split("ProcessGuid:", 1)[1]
        return parts.splitlines()[0].strip()

    return None

def get_correlation_iocs(alert):
    """Extract simple correlation indicators from a parsed alert."""
    data = alert.get("data", {})

    indicators = set()

    for field in ("srcip", "dstip"):
        value = data.get(field)
        if value:
            indicators.add(value)

    return indicators


def correlation_reasons(alert_a, alert_b, time_window=60):
    """
    Determine why two alerts may belong to the same activity.

    Returns a list of evidence-based correlation reasons.
    """
    reasons = []

    # Strongest signal: ProcessGuid
    process_a = get_process_guid(alert_a)
    process_b = get_process_guid(alert_b)

    if process_a and process_b and process_a == process_b:
        reasons.append("same ProcessGuid")

    # Agent correlation
    agent_a = alert_a.get("agent", {}).get("id")
    agent_b = alert_b.get("agent", {}).get("id")

    same_agent = (
        agent_a is not None
        and agent_b is not None
        and agent_a == agent_b
    )

    # Time correlation
    time_a = parse_timestamp(alert_a.get("timestamp"))
    time_b = parse_timestamp(alert_b.get("timestamp"))

    close_in_time = False

    if time_a and time_b:
        difference = abs((time_a - time_b).total_seconds())
        close_in_time = difference <= time_window

        if close_in_time:
            reasons.append(
                f"within {time_window}s time window"
            )

    # Shared source/destination IOC
    iocs_a = get_correlation_iocs(alert_a)
    iocs_b = get_correlation_iocs(alert_b)

    shared_iocs = iocs_a.intersection(iocs_b)

    if shared_iocs:
        reasons.append(
            f"shared IOC: {', '.join(sorted(shared_iocs))}"
        )

    # Same agent + close timing is meaningful
    if same_agent and close_in_time:
        reasons.append("same agent with close timing")

    return reasons


def correlate_alerts(alerts, time_window=60):
    """
    Group alerts that have evidence suggesting related activity.

    Each group contains:
    - alerts: alerts considered related
    - reasons: correlation evidence supporting the group
    """
    groups = []
    assigned = set()

    for index, alert in enumerate(alerts):
        if index in assigned:
            continue

        group = [alert]
        group_reasons = set()

        assigned.add(index)

        for other_index in range(index + 1, len(alerts)):
            if other_index in assigned:
                continue

            reasons = correlation_reasons(
                alert,
                alerts[other_index],
                time_window=time_window
            )

            if reasons:
                group.append(alerts[other_index])
                assigned.add(other_index)
                group_reasons.update(reasons)

        groups.append({
            "alerts": group,
            "reasons": sorted(group_reasons)
        })

    return groups
