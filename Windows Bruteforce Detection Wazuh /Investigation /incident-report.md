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






























