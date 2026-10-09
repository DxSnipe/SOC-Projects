# PB-002 — Suspicious PowerShell Response

## Trigger
PowerShell execution involving suspicious command-line parameters, encoding, unusual parent processes, downloaded content or abnormal child processes.

## L1 Triage
1. Identify PowerShell executable.
2. Capture command line.
3. Identify parent process.
4. Identify user and host.
5. Check encoded or obfuscated content.
6. Review surrounding process activity.

## Investigation
- Decode encoded PowerShell where appropriate.
- Review Sysmon ProcessCreate events.
- Build the process tree.
- Check file creation.
- Check network activity.
- Search for persistence mechanisms.
- Map relevant behavior to MITRE ATT&CK.

## Scope
Determine whether the same behavior occurred:
- On other hosts
- Under other accounts
- With other processes
- Against additional destinations

## Response
If malicious:
- Escalate.
- Consider endpoint containment.
- Preserve process/file/network evidence.
- Remove persistence after authorization.

If benign:
- Document the explanation.
- Tune detection if appropriate.

## Closure Criteria
Close after the PowerShell activity is explained and scope/response are documented.

## MITRE ATT&CK
T1059.001 — PowerShell
T1027 — Obfuscated/Compressed Files and Information
