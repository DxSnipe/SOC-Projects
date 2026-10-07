# Evidence — INC-003

## Evidence Sources

- Sysmon Event ID 1
- Wazuh Rule 92027
- Wazuh Rule 92213
- Host: SOC-Windows

## Key Observations

- Process: powershell.exe
- User: Administrator
- Integrity: High
- Parent: powershell.exe
- Command used: `-NoProfile -WindowStyle Hidden`
- ProcessGuid: `{73915500-a11f-6ac4-6101-000000007600}`

## Detection

Wazuh Rule 92027 detected:

`Powershell process spawned powershell instance`

A related Event ID 11 was also observed under Rule 92213.

## Investigation

The process relationship and command line confirmed the expected PowerShell behavior.

## Conclusion

Controlled PowerShell detection-validation activity.
No malicious payload or compromise was established.

## Evidence Handling

Only relevant process and detection fields were retained.
