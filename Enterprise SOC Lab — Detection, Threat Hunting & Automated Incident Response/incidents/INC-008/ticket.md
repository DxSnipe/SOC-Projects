# INC-008 — Windows Service Persistence

## Incident Information

- **Severity:** Medium
- **Status:** Closed
- **Classification:** True Positive — Controlled Detection Validation
- **Host:** SOC-Windows
- **Service:** Project-Svc
- **Account:** LocalSystem

## Summary

A temporary Windows service was created and configured to execute PowerShell.

The activity was performed to validate service-persistence investigation.

## Investigation

The service was configured with:

- Service: `Project-Svc`
- Display Name: Service Persistence Test
- Startup Type: Manual
- Start Account: LocalSystem
- Binary/Command: powershell.exe

An attempt to start the service failed because the configured executable did not implement the required Windows service interface.

## Important Finding

Service configuration does not prove successful execution.

The service existed and was configured for persistence, but the PowerShell payload did not successfully execute as a Windows service.

## Response

The test service was removed after validation.

## Detection Assessment

**Investigation Successful.**

The persistence configuration was identified and the execution failure was correctly documented.

## Closure

The temporary service was removed. No persistent malicious service remained.

**Status: Closed**
