# HUNT-003 — Persistence Mechanisms

## Hunt Hypothesis

Persistence mechanisms may exist even when the resulting process execution does not generate a dedicated persistence alert.

## Data Sources

- Windows Scheduled Tasks
- Windows Service configuration
- Sysmon Event ID 1
- Wazuh alerts

## Hunt Scope

Windows endpoint: `SOC-Windows`

## Findings

Two persistence mechanisms were investigated:

1. Scheduled Task
2. Windows Service

### Scheduled Task

A temporary scheduled task named: `Project--Persistence-Test` was configured to execute PowerShell.

The task successfully executed during the controlled validation.

Sysmon captured the resulting PowerShell process.

### Windows Service

A temporary service named: `Project-Svc` was created and configured to execute PowerShell under `LocalSystem`.

The service failed to execute because the configured executable did not implement the required Windows service interface.

## Investigation Assessment

The scheduled task demonstrated successful persistence-related execution.

The Windows service demonstrated that persistence configuration does not necessarily mean successful payload execution.

## Hunt Assessment

**Controlled Persistence Activity**

No unknown or unauthorized persistent mechanism was identified.

## Hunting Value

The hunt demonstrated the importance of examining both:

- Persistence configuration
- Resulting process execution

rather than assuming that a process event alone proves persistence.

## Conclusion

The persistence mechanisms identified during the hunt were known controlled activity. Both were removed after validation.
