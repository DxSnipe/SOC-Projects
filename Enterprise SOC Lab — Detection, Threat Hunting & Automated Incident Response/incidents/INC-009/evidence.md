# Evidence — INC-009

## Evidence Sources

- `/var/log/auth.log`
- SSH authentication logs
- Wazuh Rule 5710
- Wazuh Rule 5712
- Host: Ubuntu Wazuh Manager

## Key Observations

- Account: fake-soc-user
- Source: 127.0.0.1
- Attempts: 10
- Result: Invalid user
- Successful authentication: None

## Detection

Wazuh generated:

- Rule 5710 — SSH login attempt using non-existent user
- Rule 5712 — SSH brute-force correlation

## Investigation

Authentication logs repeatedly recorded:

`Invalid user fake-soc-user from 127.0.0.1`

The activity was correlated into a brute-force detection.

Legitimate `ubuntu` SSH sessions from 152.58.87.10 were reviewed separately and excluded from incident scope.

## Conclusion

Controlled Linux SSH brute-force validation.

No successful authentication or compromise was identified.
