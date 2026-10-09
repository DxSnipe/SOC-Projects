# Enterprise SOC Lab — Detection, Threat Hunting & Automated Incident Response

A hands-on SOC lab demonstrating security monitoring, incident investigation, detection engineering, threat hunting, and Python-based SOC automation using Wazuh, Sysmon, Windows, and Linux.

## Project Overview

This project simulates practical SOC workflows, from investigating security alerts to documenting findings and generating response recommendations.

**Key highlights**
- Investigated and documented 10 security incidents.
- Conducted 5 threat-hunting investigations.
- Developed 5 incident response playbooks.
- Built Python automation for alert parsing, correlation, IOC enrichment, incident generation, and audit logging.
- Tested a simulated response workflow against a Wazuh alert.
- Identified detection gaps involving process relationships and network-event correlation.

## Technology Stack

`Wazuh` · `Sysmon` · `Windows` · `Linux` · `Python` · `JSON` · `MITRE ATT&CK`

## Project Structure

| Directory | Purpose |
|---|---|
| `incidents/` | Incident tickets, evidence, and incident register |
| `detection-engineering/` | Detection logic and detection improvement work |
| `threat-hunting/` | Five documented threat hunts |
| `ioc-enrichment/` | IOC analysis and enrichment |
| `automation/` | Python SOC automation and tests |
| `playbooks/` | Incident response procedures |
| `shift-handover/` | Shift handover documentation |
| `reports/` | SOC metrics and investigation summaries |

## Automation Workflow

```text
Wazuh Alerts
     ↓
Alert Parser
     ↓
Correlation & IOC Enrichment
     ↓
Incident Generation
     ↓
Response Recommendation
     ↓
Audit Logging
```

The response workflow supports simulated decision-making. The documented validation did not execute destructive response actions.

## Key Findings

The investigations identified opportunities to improve detection of suspicious parent-child process relationships and correlation between process execution, DNS queries, and outbound network activity.

These gaps are documented as improvement opportunities and should not be considered resolved until changes are implemented and validated.

## Validation

- 10 incident investigations documented
- 5 threat hunts completed
- 5 response playbooks documented
- 27 core Python tests passed during development
- One live Wazuh alert processed through the automation workflow in simulation mode

## Documentation

- [Incident Register](incidents/README.md)
- [10-Incident SOC Summary](reports/10-INCIDENT-SOC-SUMMARY.md)
- [SOC Metrics](reports/SOC_METRICS.md)
- [Shift Handover](shift-handover/SHIFT_HANDOVER.md)
- [Incident Response Playbooks](playbooks/README.md)

## Scope and Limitations

This is a defensive security lab using controlled validation and investigation. No real-world compromise was established by the documented investigations. Automated risk scores support triage and do not replace analyst judgment.

---

**Focus:** Security Operations · Incident Response · Detection Engineering · Threat Hunting · SOC Automation
