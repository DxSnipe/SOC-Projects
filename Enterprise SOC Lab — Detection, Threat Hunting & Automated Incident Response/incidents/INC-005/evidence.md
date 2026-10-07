# Evidence — INC-005

## Evidence Sources

- Sysmon Event ID 1
- Wazuh alerts
- Host: SOC-Windows

## Key Observations

Process chain:

`LibreOffice → soffice.bin → powershell.exe`

PowerShell command:

`Write-Output PROJECT4-OFFICE-CHILD-TEST`

## Process Evidence

- Parent Image: `soffice.bin`
- Child Image: `powershell.exe`
- User: Administrator
- Integrity: High

## Detection

Sysmon successfully recorded the parent-child relationship.

Wazuh did not generate a dedicated alert for this exact PowerShell Event ID 1.

A related Event ID 11 alert was observed.

## Conclusion

The behavior was successfully captured but identified a detection gap in Wazuh.

## Evidence Handling

Relevant process-tree information was retained for future detection engineering.
