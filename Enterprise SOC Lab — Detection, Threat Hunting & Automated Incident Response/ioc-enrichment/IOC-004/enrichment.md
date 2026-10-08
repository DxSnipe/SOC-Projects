# IOC-004 — example.com

## Observable

- **Type:** Domain
- **Value:** `example.com`
- **Activity:** DNS resolution and HTTPS request
- **Process:** powershell.exe

## Source Context

The domain was intentionally used during Project 4 network and C2-like behavior validation.

Sysmon recorded DNS and network activity associated with the PowerShell process.

## Enrichment

Domain enrichment can include:

- WHOIS/RDAP
- DNS records
- Domain age
- Reputation
- Passive DNS
- Threat-intelligence feeds

## Contextual Assessment

The domain was intentionally selected as a benign test destination.

The DNS → HTTPS sequence therefore does not establish C2.

## Analyst Decision

**Classification: Benign / Controlled Test Domain**

No containment or blocking action is required.

## SOC Lesson

Behavior that resembles C2 must still be validated against the destination's identity, reputation, process context, and additional endpoint evidence.
