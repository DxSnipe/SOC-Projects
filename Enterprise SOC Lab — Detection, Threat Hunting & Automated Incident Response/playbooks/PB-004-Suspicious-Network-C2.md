# PB-004 — Suspicious Network / Potential C2 Response

## Trigger
Unexpected outbound DNS, HTTP/HTTPS or other network communication associated with a suspicious process.

## L1 Triage
1. Identify source host.
2. Identify process and ProcessGuid.
3. Identify destination IP/domain.
4. Record destination port/protocol.
5. Review DNS activity.
6. Determine whether the destination is expected.

## Investigation
Correlate:
- Process creation
- DNS queries
- Network connections
- File creation
- PowerShell activity
- Authentication activity

Look for repeated communication, unusual destinations, suspicious parent processes or downloaded files.

## Scope
Determine whether:
- Other hosts contacted the destination.
- Other processes contacted the destination.
- Similar DNS activity occurred.
- Related files or persistence exist.

## Response
Do not label C2 solely from a network connection.

If malicious behavior is established:
- Escalate.
- Consider network/endpoint containment.
- Preserve network and process evidence.

If benign:
- Document the destination and business/lab context.
- Record detection gaps.

## Closure Criteria
Close after the destination, initiating process, scope and classification are established.

## MITRE ATT&CK
T1071.001 — Web Protocols
T1059.001 — PowerShell
