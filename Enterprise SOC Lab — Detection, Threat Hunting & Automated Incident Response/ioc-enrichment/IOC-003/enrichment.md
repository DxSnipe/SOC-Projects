# IOC-003 — 104.20.23.154

## Observable

- **Type:** IPv4 Address
- **Value:** `104.20.23.154`
- **Process:** powershell.exe
- **Destination Port:** 443
- **Activity:** HTTPS communication

## Source Context

The address was observed during controlled PowerShell network testing against `example.com`.

Sysmon recorded:

- Event ID 3
- Protocol: TCP
- Initiated: True
- Destination Port: 443

## Enrichment

The IP should be evaluated using:

- WHOIS/RDAP
- ASN
- Reverse DNS
- Threat-intelligence reputation
- Historical reputation

## Contextual Assessment

The connection was associated with a controlled request to `example.com`.

The presence of the IP in the lab does not establish malicious communication or C2.

## Analyst Decision

**Classification: Benign Controlled Observable**

No blocking action is justified from this evidence alone.
