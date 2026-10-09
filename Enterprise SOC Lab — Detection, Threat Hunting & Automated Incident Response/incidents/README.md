# Incident Investigation Index

This directory contains ten documented SOC incident investigations. Each incident has its own folder containing an incident ticket and supporting evidence notes.

## Incident Register

| Incident | Investigation |
|---|---|
| [INC-001](INC-001/ticket.md) | Multiple Windows Logon Failures |
| [INC-002](INC-002/ticket.md) | Failed Logons and Account Lockout |
| [INC-003](INC-003/ticket.md) | Suspicious PowerShell Execution |
| [INC-004](INC-004/ticket.md) | Encoded PowerShell |
| [INC-005](INC-005/ticket.md) | Document Application Spawning PowerShell |
| [INC-006](INC-006/ticket.md) | Scheduled Task Persistence |
| [INC-007](INC-007/ticket.md) | Suspicious Outbound Connection |
| [INC-008](INC-008/ticket.md) | Windows Service Persistence |
| [INC-009](INC-009/ticket.md) | Linux SSH Brute Force / Invalid User |
| [INC-010](INC-010/ticket.md) | Possible C2-Like Behavior |

## Folder Structure

Each incident folder contains:

- `ticket.md` — incident details, investigation, assessment, and disposition.
- `evidence.md` — supporting evidence and relevant observations.

## Investigation Principles

- Base conclusions on recorded evidence.
- Distinguish controlled validation from suspected or confirmed malicious activity.
- Do not treat an alert or suspicious indicator alone as proof of compromise.
- Document detection gaps and investigative limitations.
- Record response actions and closure rationale.

## Related Documentation

- [10-Incident SOC Summary](../reports/10-INCIDENT-SOC-SUMMARY.md)
- [SOC Metrics](../reports/SOC_METRICS.md)

---

**Scope:** Defensive SOC lab investigations. No real-world compromise was established by the documented investigations.
