# Evidence — INC-001

## Evidence Sources

- Windows Security Event ID 4625
- Wazuh Rule 60204
- Host: SOC-Windows

## Key Observations

- 10 failed authentication attempts
- Target account: Administrator
- Source IP: 152.58.87.10
- Logon Type: 3
- Authentication: NTLM
- Status: 0xC000006D
- SubStatus: 0xC000006A

## Detection

Wazuh rule 60204 correlated the repeated Windows authentication failures.

## Investigation

The failures originated from the same source and targeted the same account within the configured correlation window.

No successful compromise was established.

## Conclusion

Controlled SOC detection-validation activity.

## Evidence Handling

Only relevant investigation fields were retained for portfolio documentation.
