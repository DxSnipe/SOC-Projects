# SOC Metrics — Project 4

## Incident Volume

| Metric | Value |
|---|---:|
| Total incidents | 10 |
| Closed | 10 |
| Open | 0 |
| Escalated | 0 |
| High/Critical | 0 |
| Medium | 7 |
| Low/Informational | 3 |

## Incident Outcomes

| Outcome | Count |
|---|---:|
| Controlled validation / true positive | 7 |
| Benign validation / detection gap | 3 |
| Confirmed compromise | 0 |

## Detection Engineering Findings

| Finding | Status |
|---|---|
| Document → PowerShell correlation | Improvement identified |
| Sysmon network correlation | Improvement identified |
| DNS + Process + Network C2 correlation | Improvement identified |

## Threat Hunting

| Hunt | Status |
|---|---|
| Windows Authentication Anomalies | Complete |
| PowerShell Execution | Complete |
| Persistence Mechanisms | Complete |
| Outbound Network Behavior | Complete |
| Process Tree Anomalies | Complete |

## Automation

- Alert ingestion: Complete
- IOC extraction: Complete
- IOC enrichment: Complete
- Risk scoring: Complete
- Alert correlation: Complete
- Incident generation: Complete
- SOAR decisioning: Complete
- Audit logging: Complete
