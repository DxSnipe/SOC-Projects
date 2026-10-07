# Evidence — INC-002

## Evidence Sources

- Windows Security Event ID 4625
- Windows account-lockout state
- Wazuh Rule 60204
- Host: SOC-Windows

## Key Observations

- 10 failed authentication attempts
- Time range: 11:56:55–11:57:46
- Account: Administrator
- Source IP: 152.58.87.10
- Logon Type: 3
- Status: 0xC000006D
- SubStatus: 0xC000006A
- Account subsequently became locked

## Authentication Review

A later Event ID 4624 was identified as:

- Account: SYSTEM
- Logon Type: 5
- Source IP: -

This was a service logon and was not treated as a successful attacker authentication.

## Detection

Wazuh successfully correlated the repeated failed logons.

## Conclusion

Account-lockout behavior was successfully validated.
No successful compromise was established.

## Evidence Handling

Unrelated legitimate authentication activity was excluded from incident scope.
