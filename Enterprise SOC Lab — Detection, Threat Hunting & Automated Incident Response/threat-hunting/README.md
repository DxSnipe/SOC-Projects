# Threat Hunting

This directory documents proactive threat-hunting activities performed against the Project SOC environment.

## Hunting Methodology

Each hunt follows:

1. Define hypothesis
2. Identify relevant telemetry
3. Query the environment
4. Investigate suspicious results
5. Determine whether activity is benign or suspicious
6. Document findings
7. Identify detection gaps

## Hunts

| Hunt | Objective | Primary Telemetry |
|---|---|---|
| HUNT-001 | Suspicious PowerShell | Sysmon EID 1 |
| HUNT-002 | Authentication anomalies | Windows Security |
| HUNT-003 | Persistence mechanisms | Scheduled Tasks |
| HUNT-004 | Network behavior | TCP connections / Sysmon |

## Analyst Principle

Threat hunting is hypothesis-driven investigation.

A suspicious indicator is not automatically malicious.
Findings require contextual investigation and supporting evidence.
