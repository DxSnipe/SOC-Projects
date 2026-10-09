# PB-005 — Linux SSH Brute Force Response

## Trigger
Repeated failed SSH authentication or invalid-user attempts against a Linux system.

## L1 Triage
1. Identify source IP.
2. Identify targeted username.
3. Count failures.
4. Establish time window.
5. Review successful SSH logins.
6. Separate legitimate administrative activity from suspicious activity.

## Investigation
Review:
- SSH authentication logs
- Wazuh alerts
- Source IP
- Target accounts
- Successful sessions
- Sudo activity
- Process activity following successful authentication

## Scope
Determine:
- Accounts targeted
- Hosts affected
- Successful authentications
- Source infrastructure
- Additional suspicious activity

## Response
If malicious:
- Escalate.
- Consider account containment.
- Review authorized keys and credentials.
- Consider source blocking according to policy.
- Preserve evidence.

If benign:
- Document legitimate activity.
- Close or tune detection.

## Closure Criteria
Close when authentication activity is explained, successful access is assessed and required actions are complete.

## MITRE ATT&CK
T1110 — Brute Force
