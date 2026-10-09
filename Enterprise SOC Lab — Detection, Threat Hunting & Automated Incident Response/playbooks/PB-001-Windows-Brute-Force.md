# PB-001 — Windows Brute Force Response

## Trigger
Multiple Windows authentication failures from the same source, account or host.

## L1 Triage
1. Identify source IP.
2. Identify targeted account.
3. Review failure count and time window.
4. Check Logon Type.
5. Search for successful authentication after failures.
6. Determine whether the activity is expected.

## Investigation
- Review Windows Security events.
- Correlate failed and successful logons.
- Check affected accounts and hosts.
- Determine whether account lockout occurred.
- Identify related authentication activity.

## Scope
Determine:
- Source host/IP
- Target account
- Additional affected endpoints
- Additional successful authentications

## Response
If malicious activity is confirmed:
- Escalate.
- Consider account containment/reset.
- Block or investigate source as appropriate.
- Preserve evidence.

If benign:
- Document the reason.
- Tune detection if necessary.

## Closure Criteria
Close when activity is explained, scope is established and required response actions are complete.

## MITRE ATT&CK
T1110 — Brute Force
