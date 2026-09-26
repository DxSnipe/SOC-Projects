# Detection Matrix

| ID | Detection | Telemetry | Sigma Rule | MITRE ATT&CK | Validation |
|---|---|---|---|---|---|
| 01 | Suspicious PowerShell Encoded Command | Sysmon Event ID 1 | `01-suspicious-powershell-encoded-command.yml` | T1059.001 — PowerShell | Manual validation against controlled encoded PowerShell execution |
| 02 | PowerShell Network Connection | Sysmon Event ID 3 | `02-powershell-network-connection.yml` | T1105 — Ingress Tool Transfer context | Validated against observed PowerShell TCP connection |
| 03 | PowerShell File Creation | Sysmon Event ID 11 | `03-powershell-file-creation.yml` | T1105 — Ingress Tool Transfer context | Validated against observed PowerShell-created file |
| 04 | PowerShell Network ? File Correlation | Sysmon Event ID 3 + Event ID 11 | `04-powershell-network-file-correlation.yml` | T1105 — Ingress Tool Transfer context | Manually validated using shared ProcessGuid and five-minute window |
| 05 | Windows Failed Network Logon | Security Event ID 4625 | `05-windows-failed-logon.yml` | T1110 — Brute Force | Validated against repeated failed network logons |
