# Evidence — INC-004

## Evidence Sources

- Sysmon Event ID 1
- Wazuh Rule 92057
- Host: SOC-Windows

## Key Observations

- Process: powershell.exe
- PID: 5644
- User: Administrator
- Integrity: High
- Parent: powershell.exe
- Technique: `-EncodedCommand`

## Encoded Command

The Base64 command decoded to:

`Write-Output "PROJECT4-ENCODED-POWERSHELL"`

## Detection

Wazuh Rule 92057 identified the encoded PowerShell execution.

## Investigation

The encoded command was decoded and confirmed to contain a benign test instruction.

## Conclusion

Controlled detection-validation activity.
No malicious payload or compromise was identified.

## Evidence Handling

The encoded command and relevant process metadata were retained for investigation.
