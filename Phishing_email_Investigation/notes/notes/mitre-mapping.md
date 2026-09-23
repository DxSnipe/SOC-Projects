# PHISH-001 — MITRE ATT&CK Mapping

## Technique 1 — T1566.002: Phishing: Spearphishing Link

**Tactic:** Initial Access

**Evidence:**
- The email contains the URL:
  https://bit.ly/3vF9xKz
- The subject uses an account-security lure:
  "[Action Required] Unusual sign-in activity on your account"
- The message impersonates a Microsoft account/security team.

**Assessment:**
The email uses a link-based phishing mechanism intended to direct the recipient to an external web resource.

**Confidence:** High

---

## Technique 2 — T1036.005: Masquerading: Match Legitimate Name or Location

**Tactic:** Defense Evasion

**Evidence:**
- Display name:
  "Microsoft Account Team"
- Sender address:
  noreply@microsoftonline-verify.com
- The sender domain uses Microsoft-related terminology.

**Assessment:**
The sender identity attempts to resemble a legitimate Microsoft account/security communication.

This technique is mapped as supporting evidence for impersonation. The evidence does not establish that the attacker successfully bypassed a specific security control.

**Confidence:** Medium

---

## Techniques NOT Mapped

The following techniques were intentionally not mapped because the available evidence does not prove them:

- Credential dumping
- Valid Accounts
- Command and Scripting Interpreter
- Malware execution
- User execution
- Account compromise
- Data exfiltration

No endpoint or post-click evidence is currently available to establish these activities.

---

## MITRE Summary

| Technique | Name | Evidence | Confidence |
|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | Bitly URL in phishing email | High |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Microsoft impersonation | Medium |

The mapping is limited to behaviors supported by the available evidence. Additional techniques should only be added if further evidence is discovered.
