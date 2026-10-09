# SOC Shift Handover

## Shift Overview

**Environment:** Enterprise SOC Detection, Threat Hunting & Automated Incident Response Lab  
**Shift:** Day → Night  
**Analyst Role:** SOC L1 / L2  
**Platform:** Wazuh + Sysmon + Windows + Linux

---

## Incident Status

| Incident | Description | Severity | Status | Classification |
|---|---|---:|---|---|
| INC-001 | Windows Logon Failures | Medium | Closed | True Positive - Controlled Validation |
| INC-002 | Account Lockout | Medium | Closed | True Positive - Controlled Validation |
| INC-003 | Suspicious PowerShell | Medium | Closed | True Positive - Controlled Validation |
| INC-004 | Encoded PowerShell | Medium | Closed | True Positive - Controlled Validation |
| INC-005 | Document → PowerShell | Medium | Closed | Controlled Validation / Detection Gap |
| INC-006 | Scheduled Task Persistence | Medium | Closed | True Positive - Controlled Validation |
| INC-007 | Outbound Network Activity | Low/Info | Closed | Benign Validation / Detection Gap |
| INC-008 | Windows Service Persistence | Medium | Closed | True Positive - Controlled Validation |
| INC-009 | Linux SSH Brute Force | Medium | Closed | True Positive - Controlled Validation |
| INC-010 | C2-like Behavior | Low/Info | Closed | Benign Validation / Detection Gap |

---

## Current Open Incidents

**None.**

All simulated incidents have been investigated, documented and closed.

---

## Detection Gaps

### 1. Document Application → PowerShell
Endpoint telemetry captured the process relationship, but dedicated Wazuh correlation was limited.

**Recommendation:** Create a dedicated detection for suspicious document/application child processes.

### 2. Network Detection Correlation
Sysmon network events were available for some PowerShell activity but were not consistently correlated by Wazuh.

**Recommendation:** Improve process/network correlation using ProcessGuid and network telemetry.

### 3. Potential C2 Correlation
DNS, process and network events were available but required stronger multi-event correlation.

**Recommendation:** Correlate process creation + DNS + network activity before assigning a C2 classification.

---

## Threat Hunting Completed

- HUNT-001 — Windows Authentication Anomalies
- HUNT-002 — PowerShell Execution
- HUNT-003 — Persistence Mechanisms
- HUNT-004 — Outbound Network Behavior
- HUNT-005 — Process Tree Anomalies

---

## Automation Status

Python SOC automation successfully demonstrated:

- Wazuh alert ingestion
- IOC extraction
- IOC enrichment
- Risk scoring
- Alert correlation
- Automated incident creation
- SOAR response decision
- Audit logging

The automation was validated against a real Wazuh Rule 92213 alert.

---

## Important Analyst Notes

- Wazuh severity should not automatically determine incident severity.
- Encoding alone does not establish malicious PowerShell activity.
- A suspicious network connection does not automatically establish C2.
- Service persistence must be assessed for successful execution.
- Legitimate authentication activity must be separated from brute-force activity.
- Detection gaps should be documented rather than hidden.

---

## Recommended Next Actions

1. Improve document → PowerShell detection coverage.
2. Improve Sysmon network event correlation.
3. Develop stronger process/DNS/network correlation.
4. Continue periodic threat hunting.
5. Review detection rules for false-positive reduction.
6. Maintain incident and response documentation.

---

## Handover Status

**All incidents:** Closed  
**Outstanding containment:** None  
**Outstanding investigation:** None  
**Known detection gaps:** 3  
**Recommended follow-up:** Detection engineering and correlation improvements

---

## Handover Statement

The environment is stable at shift handover. All current simulated incidents have been investigated and documented. No confirmed compromise remains open. The next analyst should prioritize the documented detection gaps and continue monitoring for related activity.
