# IOC Enrichment

This directory contains the enrichment and contextual analysis of
observables identified during the Project 4 SOC simulation.

## Objective

Evaluate IP addresses, domains, hashes, and other observables using
threat intelligence and surrounding security telemetry.

## Workflow

```text
Observable
    ↓
Identify & Enrich
    ↓
Reputation / Context
    ↓
Correlate With Telemetry
    ↓
Analyst Assessment
    ↓
Response Decision
```

## Observables

| ID | Observable | Type | Related Activity |
|---|---|---|---|
| IOC-001 | `152.58.87.10` | IPv4 | Windows authentication failures |
| IOC-002 | `127.0.0.1` | IPv4 | Linux SSH validation |
| IOC-003 | `104.20.23.154` | IPv4 | PowerShell HTTPS |
| IOC-004 | `example.com` | Domain | DNS + HTTPS validation |

## Enrichment Sources

- WHOIS / RDAP
- DNS information
- ASN / ownership
- Threat-intelligence reputation
- Abuse reports
- Endpoint telemetry

## Analyst Principle
An observable is not automatically malicious.
IOC reputation must be evaluated together with process, authentication, DNS, network, and other available security context before making a response decision.

## Outcome
The enrichment phase demonstrates the ability to:
- Extract observables from investigations
- Enrich security indicators
- Correlate intelligence with endpoint activity
- Assess risk using context
- Support informed response decisions
