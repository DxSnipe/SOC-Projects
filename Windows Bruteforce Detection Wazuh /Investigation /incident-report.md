# SOC Incident Report

## Incident Title

Windows Brute Force / Repeated Authentication Failure Investigation

---

## 1. Summary

A controlled authentication attack simulation was performed
against a Windows Server Administrator account to validate
Windows authentication monitoring and Wazuh detection capabilities.

Multiple failed authentication attempts generated Windows
Security Event ID `4625` events.

Wazuh successfully collected the events and generated Rule
`60204` at Level `10` with the description:

```text  ```
Multiple Windows Logon Failures Continued authentication failures resulted in an account lockout, generating Event ID 4740.

A subsequent successful authentication, Event ID 4624, was also observed.

The successful authentication had Logon Type 3, representing a network logon. Therefore, the available evidence does not establish that the successful authentication was an RDP session
or that it resulted directly from the preceding failed attempts.

The entire activity was intentionally generated in a controlled lab environment for SOC investigation and detection testing.

# 2. Incident Classification

| Field                     | Value                            |
| ------------------------- | -------------------------------- |
| Incident Type             | Authentication Attack Simulation |
| Category                  | Brute Force / Password Guessing  |
| Environment               | Controlled SOC Lab               |
| Detection Platform        | Wazuh                            |
| Severity                  | High                             |
| Status                    | Investigated                     |
| Detection Rule            | `60204`                          |
| Detection Level           | `10`                             |
| Primary Event             | `4625`                           |
| Lockout Event             | `4740`                           |
| Successful Authentication | `4624`                           |

# 3. Affected Asset

| Field                  | Value             |
| ---------------------- | ----------------- |
| Host                   | `EC2AMAZ-V1OPH8C` |
| Operating System       | Windows Server    |
| Target Account         | `Administrator`   |
| Wazuh Agent            | `SOC-Windows`     |
| Authentication Package | NTLM              |

# 4. Source Information

| Field           | Value           |
| --------------- | --------------- |
| Source IP       | `152.58.114.63` |
| Source Hostname | `DxSnipe`       |
| Simulation Host | Kali Linux      |

The source address was observed by the Windows endpoint during the authentication events.

Because this was a controlled lab, the source address represents the system used to generate the simulation traffic and should not
be treated as a malicious indicator outside the context of this lab.

# 5. Detection
Wazuh generated the following alert:
```text 
Rule ID: 60204
Rule Level: 10
Description: Multiple Windows Logon Failures
Agent: SOC-Windows
```
The detection was triggered by repeated Windows authentication failure events.

The underlying Windows Security Event ID was:
```text 
4625 — An account failed to log on
```

# 6. Evidence Collected

## Event ID 4625 — Failed Logon

Observed fields included:
```text
Target Username: Administrator
Source IP: 152.58.114.63
Logon Type: 3
Workstation Name: DxSnipe
Logon Process: NtLmSsp
Authentication Package: NTLM
Status: 0xc000006d
Sub-Status: 0xc000006a
```
The observed status and sub-status indicate an authentication failure associated with an incorrect password.
Multiple failed authentication events were observed.

## Event ID 4740 — Account Lockout

The repeated authentication failures resulted in the Administrator account being locked out.
The corresponding Windows event was:
```text
4740 — A user account was locked out
```
Wazuh also generated a Level 9 account-lockout alert.
This provided additional evidence that the repeated authentication attempts affected the target account.

## Event ID 4624 — Successful Logon

A subsequent successful authentication was observed:
```text
Target Username: Administrator
Source IP: 152.58.114.63
Logon Type: 3
Logon Process: NtLmSsp
Authentication Package: NTLM
```
Logon Type 3 represents a network logon.

It is different from Logon Type 10, which represents RemoteInteractive/RDP authentication.

Therefore, the event is documented as a successful network authentication rather than automatically being classified as successful RDP access.

# 7. Timeline
```text
Repeated Authentication Attempts
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
   Successful Network Logon
```

# 8. Investigation

The alert was investigated by examining the authentication
events associated with the target account and source address.

The investigation focused on:

Target account
Source IP
Number of failed attempts
Authentication type
Logon type
Authentication package
Failure status
Account lockout
Subsequent successful authentication

The repeated 4625 events established that multiple authentication attempts against the Administrator account
had failed.

The Wazuh Rule 60204 confirmed that the repeated failures were detected and correlated by the SIEM.

The subsequent 4740 event demonstrated that the account became locked out.

A later 4624 event demonstrated that a successful network authentication occurred.

# 9. False-Positive Analysis

The activity was intentionally generated as part of a controlled security lab.

Therefore, the behavior was expected within the lab environment.

In a production SOC environment, repeated authentication failures could have several explanations, including:

User repeatedly entering an incorrect password
Misconfigured service credentials
Scheduled task using an outdated password
Application authentication failure
Administrator activity
Password guessing
Brute-force activity

The analyst should therefore investigate the source, target, frequency, timing, authentication type, and surrounding activity before determining the nature of the event.

For this lab, the Wazuh alert is considered a true positive for the behavior the detection was designed to identify:
multiple Windows authentication failures.

# 10. MITRE ATT&CK Mapping

## T1110 — Brute Force

The simulated activity involved repeated authentication attempts against a Windows account.

## T1110.001 — Password Guessing

The authentication attempts involved repeated incorrect passwords against the same Administrator account.

Other T1110 sub-techniques were not mapped because the available evidence did not demonstrate password cracking, password spraying, or credential stuffing.

# 11. Impact Assessment

Observed effects:

Multiple failed authentication attempts
Wazuh security alert
Administrator account lockout
Subsequent successful network authentication

The available telemetry does not independently establish:

Successful compromise
Credential theft
Data access
Persistence
Lateral movement
Privilege escalation

Therefore, the investigation should not claim compromise solely from the observed authentication events.

# 12. Response

In a production environment, analyst could:

Validate whether the source IP is authorized.
Confirm whether the target account should be used for
remote authentication.
Review the number and frequency of failed attempts.
Investigate related 4625, 4740, and 4624 events.
Determine whether the successful authentication was expected.
Review endpoint telemetry for suspicious activity following
successful authentication.
Escalate to L2/Incident Response if unauthorized access or
compromise is suspected.
Reset or disable affected credentials according to the
organization's incident-response policy if compromise is
confirmed.

# 13. Final Assessment

The controlled simulation successfully demonstrated a complete SOC detection and investigation workflow.

The investigation established:

Windows generated authentication failure events.
Wazuh successfully collected the events.
Multiple failed logons triggered Rule 60204.
The Administrator account was subsequently locked out.
A later successful network authentication was observed.
The successful event was Logon Type 3, not Logon Type 10.

The evidence supports the simulated brute-force/password-guessing behavior.

The available telemetry does not independently establish malicious intent or prove that the later successful authentication resulted directly from the preceding failed attempts.

















