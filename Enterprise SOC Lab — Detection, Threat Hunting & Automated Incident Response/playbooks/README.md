# Incident Response Playbooks

Practical investigation guides for common security events covered in this SOC lab.

## Available Playbooks

| ID | Playbook | Focus |
|---|---|---|
| PB-001 | [Windows Brute Force](PB-001-Windows-Brute-Force.md) | Investigating repeated Windows authentication failures |
| PB-002 | [Suspicious PowerShell](PB-002-Suspicious-PowerShell.md) | Reviewing suspicious PowerShell execution and command-line evidence |
| PB-003 | [Persistence](PB-003-Persistence.md) | Investigating persistence-related activity, including scheduled tasks and services |
| PB-004 | [Suspicious Network / C2](PB-004-Suspicious-Network-C2.md) | Assessing suspicious outbound connections and possible command-and-control indicators |
| PB-005 | [Linux SSH Brute Force](PB-005-Linux-SSH-Brute-Force.md) | Investigating repeated SSH authentication failures and invalid-user attempts |

## Investigation Workflow

1. **Validate:** Confirm the alert and identify the affected host, account, and timeframe.
2. **Collect evidence:** Review relevant SIEM, endpoint, process, authentication, and network telemetry.
3. **Correlate:** Connect related events and distinguish suspicious behavior from confirmed compromise.
4. **Assess impact:** Determine the scope of activity and document uncertainties.
5. **Recommend response:** Propose proportionate containment or remediation actions, subject to authorization.
6. **Document:** Record findings, actions taken, outstanding tasks, and final disposition.

## Scope and Safety

These playbooks support defensive investigation and response planning.

- An alert or suspicious indicator alone does not establish compromise.
- Response actions must be proportionate to the evidence.
- Destructive or disruptive actions require appropriate authorization.
- Findings and limitations should be documented accurately.

---

**Focus:** SOC Investigation · Incident Response · Evidence Collection · Escalation
