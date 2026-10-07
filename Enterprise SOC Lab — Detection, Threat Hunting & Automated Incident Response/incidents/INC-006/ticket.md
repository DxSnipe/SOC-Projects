# INC-006 — Scheduled Task Persistence

## Incident Information

- **Severity:** Medium
- **Status:** Closed
- **Classification:** True Positive — Controlled Detection Validation
- **Host:** SOC-Windows
- **Task:** Project--Persistence-Test
- **MITRE ATT&CK:** Scheduled Task/Job Persistence

## Summary

A temporary Windows Scheduled Task was created to validate persistence-related investigation.

The task executed PowerShell.

## Investigation

The scheduled task was configured with:

- Task: `Project--Persistence-Test`
- Action: powershell.exe
- Command: `Write-Output PROJECT-PERSISTENCE-TEST`
- Run result: `0`

Sysmon Event ID 1 recorded the resulting PowerShell execution.

The PowerShell ProcessGuid was also associated with a Wazuh Event ID 11 alert.

## Important Finding

The Sysmon process event alone did not prove scheduled-task persistence.

The scheduled-task configuration and resulting process execution were correlated to establish the behavior.

## Response

The temporary scheduled task was deleted after validation.

## Detection Assessment

**Partially Successful.**

Execution telemetry was captured, but dedicated scheduled-task creation telemetry was not configured.

## Closure

The persistence mechanism was successfully validated and removed. No malicious persistence remained.

**Status: Closed**
