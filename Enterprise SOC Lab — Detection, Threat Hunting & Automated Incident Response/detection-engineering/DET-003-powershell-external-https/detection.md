# DET-003 — PowerShell External HTTPS Connection

## Objective

Detect PowerShell establishing outbound HTTPS connections.

## Trigger

Sysmon Event ID 3 where:

- Image = powershell.exe or pwsh.exe
- Protocol = TCP
- Destination Port = 443
- Initiated = true

## MITRE ATT&CK

T1071.001 — Web Protocols

T1059.001 — PowerShell

## Detection Logic
```
PowerShell
    ↓
Outbound TCP
    ↓
Destination Port 443
    ↓
Investigate destination
```
## Original Detection Gap

INC-007 demonstrated that Sysmon successfully captured PowerShell → HTTPS traffic but Wazuh did not generate a dedicated alert.

## Analyst Response

Investigate:

- Destination IP
- Destination hostname
- DNS history
- Process command line
- Process parent
- User
- Frequency
- First-seen destination
- Related processes

## Important

An HTTPS connection is not automatically malicious.

Context is required before classification.

## Expected Severity

Low to Medium

Increase severity when combined with suspicious process execution or known malicious infrastructure.
