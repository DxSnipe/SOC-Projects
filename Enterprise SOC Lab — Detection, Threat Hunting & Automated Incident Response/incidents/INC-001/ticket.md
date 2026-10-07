# INC-001 — Multiple Windows Logon Failures

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

Wazuh detected multiple failed Windows authentication attempts against the Administrator account.

A total of 10 failed logon attempts were observed within the configured correlation window.

## Investigation

Windows Security Event ID 4625 confirmed:

- Target account: Administrator
- Source: 152.58.87.10
- Logon Type: 3
- Authentication: NTLM
- Status: 0xC000006D
- SubStatus: 0xC000006A

Wazuh correlated the repeated failures and generated rule 60204.

No successful compromise was established.

## Response

No containment was performed because this was a controlled laboratory validation.

## Detection Assessment

**Successful.**

The existing Wazuh authentication correlation correctly identified the repeated failed logons.

## Closure

The activity was confirmed as controlled detection-validation activity. No compromise or additional malicious activity was identified.

**Status: Closed**
