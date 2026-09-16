# SOC Investigation Timeline

## Purpose

This timeline documents the sequence of authentication-related
events observed during the controlled Windows brute-force
simulation.

The timeline is based on Windows Security events and Wazuh alerts
observed during the investigation.

---

## Timeline

| Stage | Event / Alert | Description | Significance |
|---|---|---|---|
| 1 | Event ID `4625` | Failed authentication attempt against `Administrator` | Establishes failed authentication activity |
| 2 | Multiple `4625` events | Repeated failed authentication attempts were observed | Indicates repeated password attempts |
| 3 | Wazuh Rule `60204` | `Multiple Windows Logon Failures` — Level `10` | Wazuh detected and correlated the repeated failures |
| 4 | Event ID `4740` | Administrator account became locked out | Indicates the authentication failures reached the account lockout threshold |
| 5 | Event ID `4624` | Successful authentication involving `Administrator` was observed | Establishes that a later authentication succeeded |
| 6 | Investigation | Successful `4624` had Logon Type `3` | Indicates a network logon rather than Logon Type `10` RDP |

---

## Authentication Activity

### Failed Authentication

The primary failed-logon activity generated Event ID `4625`.

Observed characteristics included:

```text
Target Account: Administrator
Source IP: 152.58.114.63
Logon Type: 3
Logon Process: NtLmSsp
Authentication Package: NTLM
Status: 0xc000006d
Sub-Status: 0xc000006a
```
The status and sub-status values indicate an invalid authentication attempt involving an incorrect password.

# Wazuh Detection

The repeated failures resulted in the following Wazuh alert:

Rule ID: 60204
Rule Level: 10
Description: Multiple Windows Logon Failures
Agent: SOC-Windows
Target Account: Administrator
Source IP: 152.58.114.63

This confirmed that the Windows endpoint was successfully sending
authentication telemetry to Wazuh and that the detection logic was
working as expected.

# Account Lockout

Following the repeated authentication failures, the
Administrator account became locked out.

The corresponding Windows account-lockout event was:
```text
Event ID: 4740
```
Wazuh also generated a Level 9 alert associated with the account
lockout.

The lockout is an important escalation point in the investigation
because it demonstrates that the authentication failures had a
direct effect on the target account.

# Successful Authentication

A subsequent Event ID 4624 was observed involving:
```text
Target Account: Administrator
Source IP: 152.58.114.63
Logon Type: 3
Logon Process: NtLmSsp
Authentication Package: NTLM
```
### Important Interpretation

The successful authentication was Logon Type 3.

Logon Type 3 represents a network logon.

It is different from Logon Type 10, which represents a
RemoteInteractive/RDP logon.

Therefore, this event should be documented as a successful network
authentication rather than automatically being labeled a successful
RDP login.

# Investigation Sequence
```text
              Authentication Attempts
                       |
                       v
                Event ID 4625
                 Failed Logon
                       |
                       v
              Multiple Failures
                       |
                       v
              Wazuh Rule 60204
                  Level 10
                       |
                       v
                Event ID 4740
                Account Lockout
                       |
                       v
                Event ID 4624
             Successful Logon
                 Logon Type 3
```
# Investigation Logic
```text
ALERT
  |
  v
Multiple Windows Logon Failures
  |
  v
Identify:
  - Source IP
  - Target account
  - Number of failures
  - Logon type
  - Authentication package
  |
  v
CORRELATE
  |
  +--> 4625 Failed Logons
  |
  +--> 4740 Account Lockout
  |
  +--> 4624 Successful Logon
  |
  v
ASSESS
  |
  +--> Expected activity?
  |
  +--> Repeated authentication failures?
  |
  +--> Account locked?
  |
  +--> Successful authentication afterward?
  |
  v
DOCUMENT
```
# Investigation Conclusion

The timeline demonstrates a complete authentication-monitoring scenario in the controlled lab:

- Failed authentication events were generated.
- Multiple failures were detected by Wazuh.
- Wazuh generated Rule 60204 at Level 10.
- The Administrator account was subsequently locked out.
- A later successful authentication was observed.
- The successful authentication was Logon Type 3, not Logon Type 10.

The evidence supports the simulated password-guessing/brute-force scenario.

The available telemetry alone does not establish malicious intent or prove that 
the later successful authentication resulted directly from the preceding failed attempts.
