# INC-007 — Suspicious Outbound Connection / Detection Gap

## Incident Information

- **Severity:** Low / Informational
- **Status:** Closed
- **Classification:** Benign Controlled Validation / Detection Gap
- **Host:** SOC-Windows
- **Process:** powershell.exe
- **Destination:** 104.20.23.154:443
- **MITRE ATT&CK:** Network behavior validation

## Summary

PowerShell generated an HTTPS connection to example.com.

The activity was performed to validate Sysmon network telemetry and determine whether Wazuh would generate a corresponding alert.

## Investigation

Sysmon Event ID 3 recorded:

- Image: powershell.exe
- Protocol: TCP
- Source: 172.31.5.141
- Destination: 104.20.23.154
- Destination Port: 443
- Initiated: True

No dedicated Wazuh alert was identified for the exact network event.

## Detection Assessment

**Detection Gap Identified.**

Sysmon successfully captured the network connection, but Wazuh did not promote the event into a dedicated alert.

## Response

No containment was performed because the destination was a known benign test destination.

## Closure

The network telemetry pipeline was validated and a Wazuh network-detection gap was documented for future detection engineering.

**Status: Closed**
