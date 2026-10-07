# INC-009 — Linux SSH Brute-Force Attempt

## Incident Information

- **Severity:** Medium
- **Status:** Closed
- **Classification:** True Positive — Controlled Detection Validation
- **Host:** Ubuntu Wazuh Manager
- **Account:** fake-soc-user
- **Source:** 127.0.0.1
- **Wazuh Rules:** 5710 → 5712
- **MITRE ATT&CK:** T1110 — Brute Force
- **SSH Technique:** T1021.004 — SSH

## Summary

Multiple SSH authentication attempts were generated against a non-existent Linux user.

Ten attempts were observed within a short period.

## Investigation

Linux authentication logs recorded:

`Invalid user fake-soc-user from 127.0.0.1`

Wazuh generated:

- Rule 5710 — Attempt to login using a non-existent user
- Rule 5712 — SSH brute-force correlation

No successful authentication occurred.

Legitimate SSH sessions for the `ubuntu` account were observed separately and were excluded from the incident scope.

## Response

No containment was required because this was controlled laboratory activity.

## Detection Assessment

**Successful.**

Wazuh successfully detected the invalid-user attempts and correlated them into a brute-force alert.

## Closure

The controlled SSH brute-force behavior was successfully detected. No compromise occurred.

**Status: Closed**
