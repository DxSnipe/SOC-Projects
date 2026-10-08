# HUNT-004 — Outbound Network Behavior

## Hunt Hypothesis

Unexpected outbound network connections may indicate command-and-control, remote access, or suspicious application behavior.

## Data Sources

- Sysmon Event ID 3
- Sysmon Event ID 22
- Windows TCP connections
- Process attribution

## Hunt Scope

Windows endpoint: `SOC-Windows`

## Findings

PowerShell network activity was identified during the Project telemetry review.

One controlled activity produced:

- Process: `powershell.exe`
- Source: `172.31.5.141`
- Destination: `104.20.23.154`
- Destination Port: `443`
- Protocol: TCP

DNS activity for `example.com` was also observed in the PowerShell C2-like validation.

## Process Correlation

The DNS and network events were associated with the same PowerShell ProcessGuid during the controlled validation.

This produced the behavioral chain:

PowerShell
→ DNS Query
→ HTTPS Connection

## Baseline Review

Other established HTTPS connections were also examined.

Connections owned by:

- `StartMenuExperienceHost.exe`
- `svchost.exe`

were not treated as malicious based solely on their HTTPS connections.

## Hunt Assessment

**No confirmed malicious network activity identified.**

The PowerShell DNS-to-HTTPS chain was suspicious from a behavioral perspective but did not establish C2 because the destination was benign and no malicious payload was identified.

## Hunting Value

The hunt demonstrated why process attribution and behavioral correlation are more useful than treating all external HTTPS connections as suspicious.

## Conclusion

No confirmed C2 activity was identified.

A network/DNS correlation detection gap was identified for future detection engineering.
