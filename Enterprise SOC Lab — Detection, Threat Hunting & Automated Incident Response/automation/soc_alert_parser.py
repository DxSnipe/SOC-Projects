import argparse
import ipaddress
import json
import re
from pathlib import Path

from enrichment.ioc_enricher import enrich_iocs
from alert_correlator import correlate_alerts
from incident_engine import build_incident


DEFAULT_ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"
DEFAULT_OUTPUT_DIR = "./output"


def extract_iocs(alert):
    raw_alert = json.dumps(alert)

    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    # Broad IPv6 candidates. They are validated below with ipaddress.
    ipv6_pattern = (
        r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}"
        r"[0-9A-Fa-f:.]+(?![\w:])"
    )

    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    md5_pattern = r"\b[a-fA-F0-9]{32}\b"

    url_pattern = r"https?://[^\s\"'<>]+"

    domain_pattern = (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}\b"
    )

    # These are common executable/file extensions.
    # They should not be treated as network domains.
    excluded_file_extensions = {
        "exe",
        "dll",
        "sys",
        "ps1",
        "psm1",
        "bat",
        "cmd",
        "msi",
        "scr",
        "tmp",
        "log",
    }

    # Extract IPv4 addresses.
    ipv4_candidates = re.findall(ipv4_pattern, raw_alert)

    # Do not treat the Wazuh agent's own infrastructure IP
    # as a threat IOC simply because it appears in alert metadata.
    agent_ip = alert.get("agent", {}).get("ip")

    ipv4 = []
    for ip in ipv4_candidates:
        if ip == agent_ip:
            continue

        try:
            ipaddress.ip_address(ip)
            ipv4.append(ip)
        except ValueError:
            continue

    # Extract and validate IPv6 addresses.
    ipv6_candidates = re.findall(ipv6_pattern, raw_alert)

    ipv6 = []

    for candidate in ipv6_candidates:
        try:
            address = ipaddress.ip_address(candidate)

            if address.version == 6:
                ipv6.append(candidate)

        except ValueError:
            continue

    # Extract domains while filtering executable/file names.
    domains = []

    for domain in re.findall(domain_pattern, raw_alert):
        tld = domain.rsplit(".", 1)[-1].lower()

        if tld not in excluded_file_extensions:
            domains.append(domain.lower())

    return {
        "ipv4": sorted(set(ipv4)),
        "ipv6": sorted(set(ipv6)),
        "sha256": sorted(
            set(re.findall(sha256_pattern, raw_alert))
        ),
        "sha1": sorted(
            set(re.findall(sha1_pattern, raw_alert))
        ),
        "md5": sorted(
            set(re.findall(md5_pattern, raw_alert))
        ),
        "urls": sorted(
            set(re.findall(url_pattern, raw_alert))
        ),
        "domains": sorted(set(domains)),
    }


def extract_original_log(alert):
    """
    Preserve the most useful raw event evidence.

    Wazuh alerts may provide full_log directly, while
    Windows/Sysmon events can store the event message under
    data.win.system.message.
    """

    full_log = alert.get("full_log")

    if full_log:
        return full_log

    message = (
        alert.get("data", {})
        .get("win", {})
        .get("system", {})
        .get("message")
    )

    return message


def parse_alert(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    mitre = rule.get("mitre", {})

    iocs = extract_iocs(alert)
    enrichment = enrich_iocs(iocs)

    return {
        "timestamp": alert.get("timestamp"),
        "alert_id": alert.get("id"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "description": rule.get("description"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "source_ip": data.get("srcip"),
        "source_port": data.get("srcport"),
        "source_user": data.get("srcuser"),
        "destination_ip": data.get("dstip"),
        "destination_port": data.get("dstport"),
        "destination_user": data.get("dstuser"),
        "mitre": {
            "techniques": mitre.get("technique", []),
            "tactics": mitre.get("tactic", []),
        },
        "full_log": extract_original_log(alert),
        "iocs": iocs,
        "enrichment": enrichment,
    }


def classify_ip(ip):
    if not ip:
        return None

    try:
        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            return "loopback"

        if address.is_private:
            return "private"

        if address.is_global:
            return "public"

        return "other"

    except ValueError:
        return "invalid"


def load_risk_config(config_file):
    with open(config_file, "r", encoding="utf-8") as f:
        return json.load(f)


def calculate_risk(result, config):
    score = 0
    factors = []

    scores = config["scores"]
    thresholds = config["thresholds"]

    description = (result["description"] or "").lower()

    techniques = [
        technique.lower()
        for technique in result["mitre"]["techniques"]
    ]

    # ---------------------------------------------------------
    # WAZUH ALERT SEVERITY
    # ---------------------------------------------------------
    # Wazuh level is an important signal, but it does NOT
    # automatically determine the final SOC risk rating.
    wazuh_level = result.get("rule_level")

    if isinstance(wazuh_level, int):
         if wazuh_level >= 12:
            points = scores.get("wazuh_high_level", 0)

            if points:
                score += points
                factors.append(
                    f"+{points} High Wazuh alert level ({wazuh_level})"
                )

         elif wazuh_level >= 8:
            points = scores.get("wazuh_medium_level", 0)

            if points:
                score += points
                factors.append(
                    f"+{points} Elevated Wazuh alert level ({wazuh_level})"
                )

    # ---------------------------------------------------------
    # AUTHENTICATION / BRUTE FORCE BEHAVIOR
    # ---------------------------------------------------------
    if "brute force" in techniques:
        points = scores["brute_force"]
        score += points
        factors.append(
            f"+{points} Brute Force technique"
        )

    if "authentication" in description and (
        "failure" in description
        or "failed" in description
    ):
        points = scores["authentication_failure"]
        score += points
        factors.append(
            f"+{points} Authentication failure"
        )

    # ---------------------------------------------------------
    # NETWORK CONTEXT
    # ---------------------------------------------------------
    # Public IPs may represent external communication.
    # Private and loopback addresses do not add risk by themselves.
    network_ip = (
        result["destination_ip"]
        or result["source_ip"]
    )

    ip_context = classify_ip(network_ip)

    if ip_context == "public":
        points = scores["public_network"]
        score += points
        factors.append(
            f"+{points} Public network address"
        )

    # ---------------------------------------------------------
    # EXECUTION BEHAVIOR
    # ---------------------------------------------------------
    # Encoded PowerShell is treated as a stronger signal
    # instead of double-counting ordinary PowerShell activity.
    if (
        "encoded" in description
        and "powershell" in description
    ):
        points = scores["encoded_powershell"]
        score += points
        factors.append(
            f"+{points} Encoded PowerShell"
        )

    elif "powershell" in description:
        points = scores["powershell"]
        score += points
        factors.append(
            f"+{points} PowerShell activity"
        )

    # ---------------------------------------------------------
    # FILE DROP / INGRES TOOL TRANSFER
    # ---------------------------------------------------------
    if "executable file dropped" in description:
        points = scores.get("file_drop", 2)
        score += points
        factors.append(
            f"+{points} Executable file dropped"
        )

    if "ingress tool transfer" in techniques:
        points = scores.get("ingress_tool_transfer", 0)

        if points:
            score += points
            factors.append(
                f"+{points} Ingress Tool Transfer technique"
            )

    # ---------------------------------------------------------
    # IOC PRESENCE
    # ---------------------------------------------------------
    if result["iocs"]["sha256"]:
        points = scores["sha256"]
        score += points
        factors.append(
            f"+{points} SHA256 observable"
        )

    if result["iocs"]["urls"]:
        points = scores["url"]
        score += points
        factors.append(
            f"+{points} URL observable"
        )

    # ---------------------------------------------------------
    # FINAL RISK CLASSIFICATION
    # ---------------------------------------------------------
    if score >= thresholds["high"]:
        rating = "HIGH"

    elif score >= thresholds["medium"]:
        rating = "MEDIUM"

    else:
        rating = "LOW"

    return {
        "score": score,
        "rating": rating,
        "factors": factors,
    }


def load_alerts(alert_file):
    path = Path(alert_file)

    if not path.is_file():
        raise FileNotFoundError(
            f"Alert file not found: {alert_file}"
        )

    with path.open("r", encoding="utf-8") as file:
        content = file.read().strip()

    if not content:
        return []

    # Support a single JSON object or JSON array.
    try:
        parsed = json.loads(content)

        if isinstance(parsed, dict):
            return [parsed]

        if isinstance(parsed, list):
            return parsed

    except json.JSONDecodeError:
        pass

    # Support Wazuh JSON Lines / NDJSON.
    alerts = []

    for line in content.splitlines():
        if not line.strip():
            continue

        try:
            alert = json.loads(line)

            if isinstance(alert, dict):
                alerts.append(alert)

        except json.JSONDecodeError:
            continue

    return alerts


def create_markdown_report(result):
    techniques = (
        ", ".join(result["mitre"]["techniques"])
        or "None"
    )

    tactics = (
        ", ".join(result["mitre"]["tactics"])
        or "None"
    )

    ips = (
        ", ".join(result["iocs"]["ipv4"])
        or "None"
    )

    ipv6 = (
        ", ".join(result["iocs"]["ipv6"])
        or "None"
    )

    hashes = (
        ", ".join(result["iocs"]["sha256"])
        or "None"
    )

    urls = (
        ", ".join(result["iocs"]["urls"])
        or "None"
    )

    domains = (
        ", ".join(result["iocs"]["domains"])
        or "None"
    )

    risk = result["risk"]

    risk_factors = "\n".join(
        f"- {factor}"
        for factor in risk["factors"]
    ) or "- No risk factors identified"

    lines = [
        "# SOC Alert Report",
        "",
        "## Alert Summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Timestamp | {result['timestamp']} |",
        f"| Alert ID | {result['alert_id']} |",
        f"| Rule ID | {result['rule_id']} |",
        f"| Wazuh Level | {result['rule_level']} |",
        f"| Description | {result['description']} |",
        f"| Agent | {result['agent_name']} |",
        f"| Agent IP | {result['agent_ip']} |",
        "",
        "## Network",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Source IP | {result['source_ip']} |",
        f"| Source Port | {result['source_port']} |",
        f"| Destination IP | {result['destination_ip']} |",
        f"| Destination Port | {result['destination_port']} |",
        "",
        "## Users",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Source User | {result['source_user']} |",
        f"| Destination User | {result['destination_user']} |",
        "",
        "## MITRE ATT&CK",
        "",
        f"**Techniques:** {techniques}",
        "",
        f"**Tactics:** {tactics}",
        "",
        "## Extracted Observables",
        "",
        "### IPv4",
        "",
        ips,
        "",
        "### IPv6",
        "",
        ipv6,
        "",
        "### Domains",
        "",
        domains,
        "",
        "### SHA256",
        "",
        hashes,
        "",
        "### URLs",
        "",
        urls,
        "",
        "## Original Log",
        "",
        "```text",
        str(result["full_log"] or ""),
        "```",
        "",
        "## Risk Assessment",
        "",
        f"**Risk Score:** {risk['score']}",
        "",
        f"**Risk Rating:** {risk['rating']}",
        "",
        "**Risk Factors:**",
        "",
        risk_factors,
        "",
        "## Analyst Note",
        "",
        "Extracted observables are not automatically malicious.",
        "They require contextual validation and, where appropriate,",
        "threat-intelligence enrichment before response decisions.",
        "",
    ]

    return "\n".join(lines)


def save_output(result, output_dir):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    json_file = output_path / "alert.json"
    markdown_file = output_path / "incident_report.md"

    with json_file.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    report = create_markdown_report(result)

    with markdown_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        file.write(report)

    print("\n=== OUTPUT GENERATED ===")
    print(f"JSON report:     {json_file}")
    print(f"Markdown report: {markdown_file}")


def save_incident(incident, output_dir):
    """
    Save a structured incident as JSON and Markdown.
    """

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    json_file = output_path / "incident.json"
    markdown_file = output_path / "incident.md"

    with json_file.open("w", encoding="utf-8") as file:
        json.dump(incident, file, indent=4)

    lines = [
        "# SOC Incident",
        "",
        f"**Incident ID:** {incident['incident_id']}",
        "",
        f"**Status:** {incident['status']}",
        "",
        f"**Severity:** {incident['severity']}",
        "",
        f"**Title:** {incident['title']}",
        "",
        "## Summary",
        "",
        incident["summary"],
        "",
        "## Risk",
        "",
        f"**Score:** {incident['risk'].get('score')}",
        "",
        f"**Rating:** {incident['risk'].get('rating')}",
        "",
        "## MITRE ATT&CK",
        "",
        "**Techniques:** "
        f"{', '.join(incident['mitre']['techniques']) or 'None'}",
        "",
        "**Tactics:** "
        f"{', '.join(incident['mitre']['tactics']) or 'None'}",
        "",
        "## Correlation",
        "",
        "**Related alerts:** "
        f"{incident['correlation']['related_alert_count']}",
        "",
        "**Reasons:**",
        "",
    ]

    for reason in incident["correlation"]["reasons"]:
        lines.append(f"- {reason}")

    lines.extend([
        "",
        "## Evidence",
        "",
        "```text",
        str(incident["evidence"]["full_log"] or ""),
        "```",
        "",
        "## Analyst Assessment",
        "",
        "**Classification:** "
        f"{incident['analyst_assessment']['classification']}",
        "",
        "**Compromise confirmed:** "
        f"{incident['analyst_assessment']['compromise_confirmed']}",
        "",
        "## Recommended Action",
        "",
        incident["recommended_action"],
        "",
    ])

    with markdown_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        file.write("\n".join(lines))

    print("\n=== INCIDENT GENERATED ===")
    print(f"Incident JSON:     {json_file}")
    print(f"Incident Markdown: {markdown_file}")


def print_alert(result):
    print("\n=== SOC AUTOMATED TRIAGE ===")
    print(f"Time:        {result['timestamp']}")
    print(f"Alert ID:    {result['alert_id']}")
    print(f"Rule:        {result['rule_id']}")
    print(f"Level:       {result['rule_level']}")
    print(f"Description: {result['description']}")
    print(f"Agent:       {result['agent_name']}")
    print(f"Agent IP:    {result['agent_ip']}")

    print("\n--- Network ---")
    print(f"Source IP:   {result['source_ip']}")
    print(f"Source Port: {result['source_port']}")
    print(f"Dest IP:     {result['destination_ip']}")
    print(f"Dest Port:   {result['destination_port']}")

    print("\n--- Users ---")
    print(f"Source User: {result['source_user']}")
    print(f"Dest User:   {result['destination_user']}")

    print("\n--- MITRE ATT&CK ---")
    print(
        f"Techniques:  "
        f"{', '.join(result['mitre']['techniques']) or 'None'}"
    )
    print(
        f"Tactics:     "
        f"{', '.join(result['mitre']['tactics']) or 'None'}"
    )

    print("\n--- Extracted IOCs ---")
    print(
        f"IPv4:        "
        f"{', '.join(result['iocs']['ipv4']) or 'None'}"
    )
    print(
        f"IPv6:        "
        f"{', '.join(result['iocs']['ipv6']) or 'None'}"
    )
    print(
        f"Domains:     "
        f"{', '.join(result['iocs']['domains']) or 'None'}"
    )
    print(
        f"SHA256:      "
        f"{', '.join(result['iocs']['sha256']) or 'None'}"
    )
    print(
        f"URLs:        "
        f"{', '.join(result['iocs']['urls']) or 'None'}"
    )

    print("\n--- IOC Enrichment ---")

    for ip in result["enrichment"]["ips"]:
        print(
            f"IP:          {ip['observable']} | "
            f"Scope: {ip['scope']} | "
            f"Valid: {ip['valid']} | "
            f"Hostname: {ip['hostname'] or 'None'}"
        )

    for domain in result["enrichment"]["domains"]:
        print(
            f"Domain:      {domain['observable']}"
        )

    for url in result["enrichment"]["urls"]:
        print(
            f"URL:         {url['observable']}"
        )

    for hash_item in result["enrichment"]["hashes"]:
        print(
            f"{hash_item['hash_type'].upper()}: "
            f"{hash_item['observable']}"
        )

    print("\n--- Risk Assessment ---")
    print(
        f"Score:       {result['risk']['score']}"
    )
    print(
        f"Rating:      {result['risk']['rating']}"
    )

    print("Factors:")

    if result["risk"]["factors"]:
        for factor in result["risk"]["factors"]:
            print(f"  {factor}")
    else:
        print("  None")

    print("\n--- Original Log ---")
    print(result["full_log"] or "None")


def create_incident_from_alerts(alerts, config):
    """
    Parse, enrich, score, correlate, and build an incident
    candidate from a collection of Wazuh alerts.
    """

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


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Portable Wazuh SOC alert parser and IOC extractor"
        )
    )

    parser.add_argument(
        "--alert-file",
        default=DEFAULT_ALERT_FILE,
        help="Path to Wazuh alerts.json"
    )

    parser.add_argument(
        "--latest",
        action="store_true",
        help="Process the latest Wazuh alert"
    )

    parser.add_argument(
        "--incident",
        action="store_true",
        help=(
            "Create an incident candidate from the latest "
            "Wazuh alerts"
        )
    )

    parser.add_argument(
        "--rule",
        help="Process the latest alert matching a Wazuh rule ID"
    )

    parser.add_argument(
        "--output",
        action="store_true",
        help="Save JSON and Markdown reports"
    )

    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for generated reports"
    )

    args = parser.parse_args()

    try:
        alerts = load_alerts(args.alert_file)

    except (
        FileNotFoundError,
        PermissionError
    ) as error:
        print(f"Error: {error}")
        return

    if not alerts:
        print("No valid Wazuh alerts found.")
        return

    if args.rule:
        selected_alert = None

        for alert in reversed(alerts):
            if (
                alert.get("rule", {}).get("id")
                == args.rule
            ):
                selected_alert = alert
                break

        if selected_alert is None:
            print(
                f"No alert found for rule {args.rule}."
            )
            return

    else:
        selected_alert = alerts[-1]

    config_path = "config/risk_config.json"
    config = load_risk_config(config_path)

    if args.incident:
        incident = create_incident_from_alerts(
            alerts,
            config
        )

        if incident is None:
            print(
                "No incident candidate could be created."
            )
            return

        print("\n=== AUTOMATED INCIDENT ===")
        print(
            f"Incident ID: {incident['incident_id']}"
        )
        print(
            f"Severity:    {incident['severity']}"
        )
        print(
            f"Status:      {incident['status']}"
        )
        print(
            f"Title:       {incident['title']}"
        )
        print(
            f"Related:     "
            f"{incident['correlation']['related_alert_count']}"
        )

        print("\nCorrelation evidence:")

        for reason in incident["correlation"]["reasons"]:
            print(f"  - {reason}")

        save_incident(
            incident,
            args.output_dir
        )

        return

    result = parse_alert(selected_alert)

    risk = calculate_risk(
        result,
        config
    )

    result["risk"] = risk

    print_alert(result)

    if args.output:
        save_output(
            result,
            args.output_dir
        )


if __name__ == "__main__":
    main()
