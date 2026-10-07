# INC-002 — Repeated Failed Logons → Account Lockout

## Incident Information

- **Severity:** Medium
- **Status:** Closed
- **Classification:** True Positive — Controlled Detection Validation
- **Host:** SOC-Windows
- **Account:** Administrator
- **Source IP:** 152.58.87.10
- **Event ID:** 4625
- **Wazuh Rule:** 60204
- **MITRE ATT&CK:** T1110 — Brute Force

## Summary

Multiple failed authentication attempts were generated against the Administrator account, resulting in an account lockout.

Ten failed attempts were observed between 11:56:55 and 11:57:46.

## Investigation

The failed authentication events contained:

- Logon Type: 3
- Status: 0xC000006D
- SubStatus: 0xC000006A
- Source: 152.58.87.10

A subsequent SYSTEM logon was observed, but it was Logon Type 5 and was not related to a successful attacker login.

No successful compromise was established.

## Response

No containment was required because the activity was intentionally generated in the lab.

The temporary test activity was stopped after the account-lockout behavior was validated.

## Detection Assessment

**Successful.**

The authentication-failure correlation successfully identified the repeated failures.

## Closure

The account-lockout behavior was successfully validated. No evidence of successful compromise was identified.

**Status: Closed**
