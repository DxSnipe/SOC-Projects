# PowerShell Network and File Activity Investigation

## 1. Objective

Investigate PowerShell network activity followed by file creation using Sysmon telemetry and Sigma detection logic.

## 2. Detection Coverage

Sigma Rules:

- `02-powershell-network-connection.yml`
- `03-powershell-file-creation.yml`
- `04-powershell-network-file-correlation.yml`

Telemetry:

- Sysmon Event ID 3 — Network Connection
- Sysmon Event ID 11 — File Creation

MITRE ATT&CK:

- T1105 — Ingress Tool Transfer

## 3. Test Activity

A controlled PowerShell network request was made to:

`https://example.com`

The response was written to:

`C:\SOC-Project3\download-test-3.html`

The downloaded HTML file was not executed.

The activity was intentionally generated for detection testing.

## 4. Sysmon Event ID 3 — Network Connection

Observed telemetry:

- Event ID: `3`
- UtcTime: `2026-09-26 08:18:18.451`
- ProcessGuid: `{73915500-7bf3-6ab7-3801-000000006f00}`
- ProcessId: `6300`
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Protocol: `tcp`
- Initiated: `true`
- Destination IP: `104.20.23.154`
- Destination Port: `443`

## 5. Sysmon Event ID 11 — File Creation

Observed telemetry:

- Event ID: `11`
- UtcTime: `2026-09-26 08:18:19.828`
- ProcessGuid: `{73915500-7bf3-6ab7-3801-000000006f00}`
- ProcessId: `6300`
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Target Filename: `C:\SOC-Project3\download-test-3.html`

## 6. Event Correlation

The Event ID 3 and Event ID 11 records share the same:

- ProcessGuid
- ProcessId
- PowerShell image

Event ID 3 occurred at:

`08:18:18.451`

Event ID 11 occurred at:

`08:18:19.828`

Time difference:

`1.377 seconds`

The observed sequence therefore falls within the Sigma correlation rule's five-minute window.

## 7. Detection Logic

### Network Detection

The network Sigma rule identifies TCP connections initiated by PowerShell.

### File Creation Detection

The file-creation Sigma rule identifies files created by PowerShell.

### Correlation

The correlation rule requires:

1. PowerShell network connection
2. Followed by PowerShell file creation
3. Same `ProcessGuid`
4. Within five minutes

The observed telemetry satisfies these conditions.

## 8. Assessment

The activity was intentionally generated for detection testing and is benign in this laboratory scenario.

The destination was `example.com`, and the resulting HTML file was not executed.

However, PowerShell network activity followed by file creation can warrant investigation in a production environment when the destination, user, URL, parent process, or created file is unexpected.

## 9. False Positive Considerations

Potential legitimate activity includes:

- Administrative PowerShell scripts
- Software deployment
- Configuration management
- Automation
- Scripts retrieving legitimate web content

## 10. Evidence

- `evidence/02-powershell-network-event3.txt`
- `evidence/03-powershell-file-event11.txt`
- `evidence/04-powershell-network-file-correlation.txt`

## 11. Validation

The underlying Sysmon Event ID 3 and Event ID 11 telemetry was successfully generated and verified.

The correlation conditions were manually validated using the shared `ProcessGuid` and event timestamps.

A Sigma correlation engine was not used for runtime execution.

## 12. Conclusion

The laboratory successfully demonstrated how PowerShell network activity and subsequent file creation can be detected and correlated using Sysmon telemetry and Sigma detection logic.
