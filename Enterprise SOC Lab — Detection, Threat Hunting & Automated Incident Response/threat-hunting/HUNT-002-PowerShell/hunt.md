# HUNT-002 — PowerShell Execution Hunting

## Hunt Hypothesis

PowerShell process creation may reveal suspicious execution, encoded commands, hidden execution, or unusual parent-child 
relationships that require investigation.

## Data Sources

- Sysmon Event ID 1
- Wazuh PowerShell detections
- Process command lines
- Parent-child process relationships

## Hunt Scope

Windows endpoint: `SOC-Windows`

## Findings

Multiple PowerShell executions were reviewed from the Project telemetry.

The hunt identified several behaviors of interest:

- PowerShell spawned by PowerShell
- Encoded PowerShell execution
- PowerShell spawned from LibreOffice
- PowerShell launched through a scheduled task
- PowerShell performing network activity

## Process Analysis

PowerShell activity was evaluated using:

- Image
- Parent Image
- Command Line
- User
- Integrity Level
- ProcessGuid
- ParentProcessGuid

The process relationships provided additional context beyond the PowerShell command line itself.

## Important Finding

Not every PowerShell execution was malicious.

For example, PowerShell execution associated with security-tool activity demonstrated that command-line indicators such as
`-NoProfile` alone are insufficient to classify a process as malicious.

## Hunt Assessment

**Mixed — Suspicious Behaviors Identified, No Additional Compromise Established**

Several PowerShell behaviors warranted investigation, but the activity was controlled validation activity.

## Hunting Value

The hunt demonstrated the importance of process ancestry and execution context when evaluating PowerShell.

## Conclusion

PowerShell process telemetry provided useful visibility into execution behavior and highlighted areas where additional behavior-based
detection could improve coverage.
