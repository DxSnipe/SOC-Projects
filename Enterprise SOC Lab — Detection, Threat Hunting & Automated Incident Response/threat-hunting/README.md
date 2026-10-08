# Threat Hunting

This directory documents retrospective threat-hunting activities performed against telemetry generated during the Project SOC simulation.

## Methodology

Each hunt follows:

1. Define a hunting hypothesis
2. Identify relevant telemetry
3. Search the available data
4. Correlate related events
5. Investigate suspicious findings
6. Determine the activity classification
7. Document hunting value and detection gaps

## Hunts

| ID | Hunt | Primary Telemetry |
|---|---|---|
| HUNT-001 | Windows Authentication Anomalies | Security 4625/4624 |
| HUNT-002 | PowerShell Execution | Sysmon EID 1 |
| HUNT-003 | Persistence Mechanisms | Scheduled Tasks / Services |
| HUNT-004 | Outbound Network Behavior | Sysmon EID 3/22 |
| HUNT-005 | Process Tree Anomalies | Sysmon EID 1 |

## Key Findings

The hunts demonstrated:

- Authentication correlation
- PowerShell process analysis
- Persistence investigation
- Network/process attribution
- Process-tree analysis
- False-positive identification
- Detection-gap identification

## Analyst Principle

Threat hunting is hypothesis-driven investigation.

Suspicious indicators do not automatically represent malicious activity. Context, correlation, and supporting evidence are required before determining maliciousness or compromise.
