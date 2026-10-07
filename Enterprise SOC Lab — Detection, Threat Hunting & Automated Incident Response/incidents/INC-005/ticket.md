# INC-005 — Document Application → PowerShell

## Incident Information

- **Severity:** Medium
- **Status:** Closed
- **Classification:** True Positive — Controlled Detection Validation
- **Host:** SOC-Windows
- **Parent Process:** soffice.bin
- **Child Process:** powershell.exe
- **MITRE ATT&CK:** T1059.001 — PowerShell

## Summary

LibreOffice Writer spawned a PowerShell process.

This behavior was generated to validate parent-child process analysis.

## Investigation

Sysmon Event ID 1 recorded:

- Parent Image: `soffice.bin`
- Child Image: `powershell.exe`
- User: Administrator
- Integrity: High
- Command: `Write-Output PROJECT-OFFICE-CHILD-TEST`

The process relationship was:

`LibreOffice → soffice.bin → powershell.exe`

Wazuh did not generate a dedicated alert for this exact PowerShell Event ID 1.

A related Event ID 11 alert was observed.

## Detection Assessment

**Detection Gap Identified.**

Sysmon successfully recorded the suspicious parent-child relationship, but Wazuh did not provide a dedicated detection for this exact behavior.

## Response

No containment was required because the activity was controlled validation.

## Closure

The process chain was successfully captured and investigated. A detection-engineering improvement was identified for future work.

**Status: Closed**
