# Windows Threat Detection Engineering with Sysmon & Sigma

A hands-on SOC detection engineering project focused on detecting and investigating suspicious Windows activity using **Sysmon** and **Sigma**.

## Detections

- Suspicious PowerShell Encoded Commands
- PowerShell Network Connections
- PowerShell File Creation
- PowerShell Network → File Correlation
- Windows Failed Network Logons

## Tools

**Sysmon · Sigma · Windows Security Logs · MITRE ATT&CK**

## Project Structure

```text
├── Sigma/          # Detection rules
├── evidence/       # Collected telemetry
├── investigation/  # Investigation notes
├── DETECTION-MATRIX.md
└── README.md
```
## Objective

Build and validate practical Windows detections using endpoint telemetry and document the investigation process.
