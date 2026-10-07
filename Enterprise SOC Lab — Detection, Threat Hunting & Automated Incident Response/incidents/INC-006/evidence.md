# Evidence — INC-006

## Evidence Sources

- Windows Scheduled Task configuration
- Sysmon Event ID 1
- Wazuh Event ID 11 alert
- Host: SOC-Windows

## Key Observations

Scheduled Task:

`Project--Persistence-Test`

Configuration:

- Action: powershell.exe
- Command: `Write-Output PROJECT-PERSISTENCE-TEST`
- Result: 0

## Process Evidence

Sysmon recorded the resulting PowerShell execution.

The PowerShell ProcessGuid was also associated with a Wazuh Event ID 11 alert.

## Investigation

The scheduled-task configuration established the persistence mechanism.

Sysmon established the resulting process execution.

The process event alone was not treated as proof of scheduled-task persistence.

## Response

The temporary scheduled task was deleted after validation.

## Conclusion

Controlled persistence validation completed successfully.
No malicious persistence remained.
