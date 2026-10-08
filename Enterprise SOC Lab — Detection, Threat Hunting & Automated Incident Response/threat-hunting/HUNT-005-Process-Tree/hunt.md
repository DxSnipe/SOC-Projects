# HUNT-005 — Process Tree Anomalies

## Hunt Hypothesis

Unusual parent-child process relationships may reveal execution chains that are more suspicious than the individual processes themselves.

## Data Sources

- Sysmon Event ID 1
- ProcessGuid
- ParentProcessGuid
- Parent Image
- Child Image
- Command Line

## Hunt Scope

Windows endpoint: `SOC-Windows`

## Process Chains Reviewed

### PowerShell → PowerShell

Observed during controlled PowerShell validation.

### LibreOffice → PowerShell

Observed:

`soffice.bin → powershell.exe`

This relationship was investigated because document applications spawning PowerShell can represent suspicious execution behavior.

### Scheduled Task → PowerShell

A scheduled task resulted in PowerShell execution.

The process ancestry was correlated with the scheduled-task configuration.

### Wazuh Agent → PowerShell

PowerShell was also observed as a child of:

`wazuh-agent.exe`

The command performed a local account-state query.

This was assessed as expected security-tool activity.

## Hunt Assessment

**No additional malicious process chain identified.**

Several process relationships were worthy of investigation, but contextual analysis distinguished controlled or legitimate activity from suspicious behavior.

## Hunting Value

The hunt demonstrated that process ancestry can provide critical context that is not visible from a command line alone.

Important investigation fields included:

- Parent Image
- Child Image
- Command Line
- User
- Integrity Level
- ProcessGuid
- ParentProcessGuid

## Conclusion

Process-tree analysis successfully differentiated expected security-tool activity from suspicious execution patterns and identified opportunities for improved behavioral detection.
