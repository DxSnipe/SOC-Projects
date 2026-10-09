# PB-003 — Persistence Detection Response

## Trigger
Detection of a new or modified scheduled task, service, startup mechanism or other persistence mechanism.

## L1 Triage
1. Identify persistence mechanism.
2. Identify creator process/user.
3. Record command or executable.
4. Determine creation time.
5. Determine whether the mechanism executed.
6. Establish whether it is authorized.

## Investigation
Review:
- Process creation
- Task/service configuration
- Parent-child relationships
- File creation
- User context
- Related network activity
- Other persistence mechanisms

## Scope
Search for:
- Same executable
- Same command
- Same account
- Same persistence mechanism
- Other affected endpoints

## Response
If malicious:
- Escalate.
- Disable/remove persistence after authorization.
- Preserve evidence.
- Investigate associated processes/files.

If benign:
- Document the legitimate purpose.
- Close or tune detection.

## Closure Criteria
Close once the persistence mechanism, origin, execution status and required response are documented.

## MITRE ATT&CK
T1053.005 — Scheduled Task/Job: Scheduled Task
T1543.003 — Windows Service
