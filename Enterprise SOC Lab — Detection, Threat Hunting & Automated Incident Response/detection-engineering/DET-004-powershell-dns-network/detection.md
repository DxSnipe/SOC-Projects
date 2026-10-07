# DET-004 — PowerShell DNS → HTTPS Behavioral Chain

## Objective

Identify PowerShell processes that perform DNS resolution followed by outbound network communication.

## Behavioral Sequence
```
PowerShell Process
        ↓
DNS Query
        ↓
Outbound HTTPS
        ↓
Same ProcessGuid
```
## Telemetry

Sysmon:

- Event ID 1 — Process Creation
- Event ID 22 — DNS Query
- Event ID 3 — Network Connection

## Correlation Key

ProcessGuid

## MITRE ATT&CK

T1059.001 — PowerShell

T1071.001 — Web Protocols

## Original Detection Gap

INC-010 demonstrated that Sysmon captured:

PowerShell → DNS → HTTPS

using the same ProcessGuid.

However, dedicated Wazuh correlation for the DNS and network events was not demonstrated.

## Analyst Investigation

Check:

- DNS domain
- Destination IP
- Process command line
- Parent process
- User
- Frequency
- Domain reputation
- Previous connections
- Related file activity

## Important

A DNS → HTTPS chain does NOT automatically establish C2.

Maliciousness requires additional evidence.

## Expected Severity

Medium

Escalate when combined with suspicious infrastructure, encoded commands, persistence, or additional malicious behavior.
