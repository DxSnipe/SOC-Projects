# INC-010 — PowerShell DNS + HTTPS Communication

## Incident Information

- **Severity:** Informational / Low
- **Status:** Closed
- **Classification:** Benign Controlled Validation / Detection Gap
- **Host:** SOC-Windows
- **Process:** powershell.exe
- **ProcessGuid:** `{73915500-f93f-6ac5-1902-000000007700}`
- **DNS:** example.com
- **Destination:** 104.20.23.154:443

## Summary

A controlled PowerShell process performed DNS resolution followed by HTTPS communication.

The behavior was generated to validate a C2-like behavioral detection chain.

## Investigation

Sysmon recorded:

```text
ProcessCreate
    ↓
DNS Query
    ↓
HTTPS Connection
```

All three events were associated with the same PowerShell ProcessGuid.

The DNS query resolved example.com and the process established a TCP connection to '104.20.23.154:443'.

Wazuh detected the PowerShell execution through rule 92027 and a related temporary file through rule 92213.

No dedicated Wazuh Event ID 22 or Event ID 3 alert was demonstrated for this exact ProcessGuid.

## Detection Assessment

### Detection Gap Identified.

Sysmon successfully captured the behavioral chain, but Wazuh did not provide dedicated correlated DNS/network detections for the exact activity.

## Important Finding

The behavior was C2-like but C2 was not established.
The destination was benign and no malicious payload or compromise was identified.

## Response
No containment was required.

## Closure
The DNS → HTTPS behavioral chain was successfully captured and investigated. The incident identified an opportunity to improve network and DNS correlation in Wazuh.

## Status: Closed
