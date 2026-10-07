# Detection Engineering

This directory contains detection improvements developed from the Project SOC incident simulation.

## Objective

Convert observed detection gaps into practical SOC detections.

## Detection Catalog

| ID | Detection | Source |
|---|---|---|
| DET-001 | Document Application → PowerShell | Sysmon EID 1 |
| DET-002 | Scheduled Task → PowerShell | Task + Sysmon EID 1 |
| DET-003 | PowerShell → External HTTPS | Sysmon EID 3 |
| DET-004 | PowerShell DNS → HTTPS | Sysmon EID 1/22/3 |

## Engineering Approach

1. Identify detection gap
2. Define behavioral hypothesis
3. Identify required telemetry
4. Build detection logic
5. Test against controlled activity
6. Review false positives
7. Document analyst response

## Key Principle

Detection alerts are indicators for investigation.

An alert does not automatically mean malicious activity.
Context, correlation, and supporting evidence are required before determining incident severity or maliciousness.
