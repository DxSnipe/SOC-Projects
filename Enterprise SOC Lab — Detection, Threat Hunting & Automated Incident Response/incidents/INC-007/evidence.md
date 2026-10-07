# Evidence — INC-007

## Evidence Sources

- Sysmon Event ID 3
- Wazuh alert search
- Host: SOC-Windows

## Key Observations

- Process: powershell.exe
- Protocol: TCP
- Source IP: 172.31.5.141
- Destination IP: 104.20.23.154
- Destination Port: 443
- Initiated: True
- Destination: example.com

## Detection

Sysmon successfully recorded the PowerShell network connection.

No dedicated Wazuh alert was identified for the exact network event.

## Investigation

The connection was generated using:

`Invoke-WebRequest -Uri "https://example.com"`

The destination was a known benign test destination.

## Detection Assessment

**Detection Gap**

Sysmon provided network telemetry, but Wazuh did not promote the event into a dedicated alert.

## Conclusion

Benign controlled network validation.
No malicious communication was established.
