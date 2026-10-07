# DET-002 — Scheduled Task → PowerShell

## Objective

Detect PowerShell execution associated with Windows Scheduled Tasks.

## Detection Logic
```
Scheduled Task Creation/Modification
        ↓
PowerShell Execution
        ↓
Correlate task and process information
```
## Relevant Telemetry

- Scheduled Task creation/modification
- Task action
- Task name
- User
- Sysmon Event ID 1
- PowerShell command line

## MITRE ATT&CK

T1053.005 — Scheduled Task/Job: Scheduled Task

T1059.001 — PowerShell

## Original Detection Gap

INC-006 demonstrated PowerShell execution from a scheduled task, but the current Sysmon configuration did not directly monitor scheduled-task creation.

## Analyst Response

Review:

- Task name
- Author
- Run-as account
- Action
- PowerShell command
- Creation time
- Process tree
- Persistence behavior

## False Positive Considerations

- Windows maintenance tasks
- Software updates
- Enterprise management tools
- Backup software
- Administrative automation

## Expected Severity

Medium to High depending on task origin and command.
