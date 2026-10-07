# INC-003 — Suspicious PowerShell Execution

## Incident Information

- **Severity:** Medium
- **Status:** Closed
- **Classification:** True Positive — Controlled Detection Validation
- **Host:** SOC-Windows
- **Process:** powershell.exe
- **Wazuh Rule:** 92027
- **Related Rule:** 92213
- **MITRE ATT&CK:** T1059.001 — PowerShell

## Summary

A hidden PowerShell process spawned another PowerShell instance.

The activity was generated to validate PowerShell process detection.

## Investigation

Sysmon Event ID 1 recorded:

- Image: powershell.exe
- User: Administrator
- Integrity: High
- Parent Image: powershell.exe
- Command included `-NoProfile -WindowStyle Hidden`
- ProcessGuid: `{73915500-a11f-6ac4-6101-000000007600}`

Wazuh generated rule 92027 for the PowerShell process behavior.

A related Sysmon Event ID 11 was also observed under rule 92213.

## Response

No containment was performed because this was controlled validation activity.

## Detection Assessment

**Successful.**

PowerShell execution was successfully detected and correlated.

## Closure

The behavior was confirmed as controlled detection-validation activity. No malicious payload or compromise was established.

**Status: Closed**
