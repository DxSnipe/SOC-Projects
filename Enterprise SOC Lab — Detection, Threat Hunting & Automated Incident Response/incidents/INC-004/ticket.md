# INC-004 — Encoded PowerShell

## Incident Information

- **Severity:** Medium
- **Status:** Closed
- **Classification:** True Positive — Controlled Detection Validation
- **Host:** SOC-Windows
- **Process:** powershell.exe
- **Wazuh Rule:** 92057
- **MITRE ATT&CK:** T1059.001 — PowerShell

## Summary

PowerShell executed a Base64-encoded command.

The activity was intentionally generated to validate detection of encoded PowerShell execution.

## Investigation

Sysmon Event ID 1 recorded:

- Image: powershell.exe
- User: Administrator
- Integrity: High
- PID: 5644
- Parent Image: powershell.exe
- Command used `-EncodedCommand`

The encoded command decoded to:

`Write-Output "PROJECT-ENCODED-POWERSHELL"`

Wazuh rule 92057 correctly identified the encoded PowerShell behavior.

## Response

No containment was required because the command was benign and intentionally generated.

## Detection Assessment

**Successful.**

The encoded PowerShell behavior was correctly detected.

## Closure

The encoded command was confirmed as controlled validation activity. No malicious payload or compromise was identified.

**Status: Closed**
