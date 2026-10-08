# HUNT-001 — Windows Authentication Anomalies

## Hunt Hypothesis

Repeated Windows authentication failures may indicate credential-access activity or attempted unauthorized access.

## Data Sources

- Windows Security Event ID 4625
- Windows Security Event ID 4624
- Wazuh authentication alerts
- Windows account state

## Hunt Scope

Windows endpoint: `SOC-Windows`

## Findings

Multiple Event ID 4625 failures were identified against the `Administrator` account.

Observed characteristics:

- Source IP: `152.58.87.10`
- Target Account: `Administrator`
- Logon Type: `3`
- Authentication: `NTLM`
- Status: `0xC000006D`
- SubStatus: `0xC000006A`

Multiple failures occurred within short time windows.

## Correlation

The failed authentication activity was correlated by Wazuh and generated the existing authentication detection.

The surrounding authentication activity was reviewed for evidence of successful authentication.

A later Event ID 4624 was identified as:

- Account: `SYSTEM`
- Logon Type: `5`
- Source IP: `-`

This was determined to be a local service logon rather than a successful remote authentication associated with the failed attempts.

## Hunt Assessment

**Controlled / Known Activity**

The authentication pattern was consistent with the controlled Project validation activity.

No evidence of successful compromise was identified.

## Hunting Value

The hunt demonstrated that authentication anomalies can be investigated independently of the initial alert by correlating:

- Failure frequency
- Source IP
- Target account
- Logon type
- Authentication method
- Subsequent successful logons
- Account state

## Conclusion

No additional compromise was identified during the retrospective authentication hunt.

The existing Wazuh authentication correlation was validated as effective for this behavior.
