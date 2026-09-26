# Windows Failed Network Logon Investigation

## 1. Objective

Investigate failed Windows network logon attempts using Security Event ID 4625 and Sigma detection logic.

## 2. Detection

Sigma Rule:

`05-windows-failed-logon.yml`

Telemetry:

- Windows Security Event ID 4625
- Logon Type 3 — Network

MITRE ATT&CK:

- T1110 — Brute Force

## 3. Observed Activity

Multiple failed network logon events were observed against the `Administrator` account.

The events reported:

- Failure Reason: `Unknown user name or bad password`
- Logon Type: `3`
- Authentication Package: `NTLM`
- Source Network Address: `152.58.114.63`
- Target Account: `Administrator`

## 4. Repeated Authentication Failures

A sequence of Event ID 4625 records was observed from the same source address.

Observed timestamps include:

- `10:39:48`
- `10:39:51`
- `10:39:53`
- `10:39:55`
- `10:39:57`
- `10:39:59`
- `10:40:01`

The repeated failures occurred over a short time interval and targeted the same account.

## 5. Event Details

### Event ID

`4625 — An account failed to log on`

### Logon Type

`3 — Network`

### Target Account

`Administrator`

### Failure Reason

`Unknown user name or bad password`

### Source

`152.58.114.63`

### Authentication

`NTLM`

## 6. Detection Logic

The Sigma rule matches:

1. Windows Security Event ID `4625`
2. Network Logon Type `3`
3. Failure reason indicating an invalid username or password

The observed events satisfy these conditions.

## 7. Investigation Assessment

The repeated failed authentication events from the same source address within a short period provide telemetry consistent with a credential-attack pattern and warrant investigation.

The available Event ID 4625 telemetry alone does not establish that the activity was malicious.

Additional investigation in a production environment would include:

- Source IP reputation and ownership
- Authentication success/failure history
- Targeted accounts
- Additional authentication events
- Host and user context
- Timing and frequency of attempts
- Any successful logon following the failures

## 8. False Positive Considerations

Potential legitimate causes include:

- Users entering incorrect credentials
- Automated services using outdated credentials
- Misconfigured applications
- Administrative activity

## 9. Evidence

- `evidence/04-windows-4625-failed-logon.txt`
- `evidence/04-windows-4625-validation.txt`

## 10. Validation

The Sigma detection logic was manually validated against the observed Windows Security Event ID 4625 telemetry.

Multiple matching events were confirmed from the same source address.

A Sigma runtime engine was not used for execution of the rule.

## 11. Conclusion

The laboratory successfully demonstrated detection and investigation of repeated failed network authentication events using Windows Security Event ID 4625 and Sigma detection logic.

The investigation highlights how individual authentication failures can be correlated by an analyst to identify patterns requiring further investigation.
