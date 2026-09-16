# Windows Authentication Event Analysis

## Purpose

This document analyzes the Windows Security events observed during
the controlled brute-force simulation and the corresponding Wazuh
alerts.

The primary events investigated were:

- Event ID 4625 — Failed Logon
- Event ID 4740 — Account Lockout
- Event ID 4624 — Successful Logon

The objective was to determine what happened, identify the relevant
authentication indicators, correlate the events, and document the
limitations of the available evidence.

---

# 1. Event ID 4625 — Failed Logon

## Description

Event ID 4625 is generated when a Windows logon attempt fails.

During the controlled simulation, multiple failed authentication
attempts were generated against the Windows `Administrator` account.

These events were successfully collected by the Wazuh agent and
displayed in the Wazuh dashboard.

## Observed Fields
```text
| Field                  | Observed Value |
| Event ID               |      4625      |
| Target Username        | Administrator  |
| Source IP              | 152.58.114.63  |
| Logon Type             | 3              |
| Workstation Name       | DxSnipe        |
| Logon Process          | NtLmSsp        |
| Authentication Package | NTLM           |
| Status                 | 0xc000006d     |
| Sub-Status             | 0xc000006a     |
| Subject Logon ID       | 0x0            |
| Target Logon ID        | 0xe00be7       |
| Process ID             | 728            |
```

### Field Analysis

## Administrator

The authentication attempts targeted the local Windows
Administrator account.

## Source IP 
```text
152.58.114.63
```
This was the source address observed by Windows for the
authentication activity.

Because this project was conducted in a controlled lab,
the address represents the source used during the simulation
and should not automatically be treated as a malicious IOC.

## Logon Type 
```text
3
```
Logon Type 3 represents a Network Logon.

This is important because Logon Type 3 is different from
Logon Type 10, which represents a RemoteInteractive/RDP logon.

Therefore, these particular 4625 events should not automatically
be described as RDP authentication failures solely from the
Logon Type field.

## Workstation Name 
```text
DxSnipe
```
The workstation name recorded by Windows for the authentication
attempt was DxSnipe.

## Logon Process 
```text
NtLmSsp
```
NtLmSsp indicates that the NTLM Security Support Provider
was involved in the authentication process.

## Authentication Package
```text
NTLM
```
The authentication used the NTLM authentication package.

## Status
```text
0xc000006d
```
This status indicates that the logon request was not accepted
because the authentication information was invalid.

## Sub-Status
```text
0xc000006a
```
This sub-status is associated with an incorrect password.

The combination of the status and sub-status therefore provides
useful evidence that the failed authentication involved an
invalid password.

# 2. Wazuh Detection

Multiple failed Windows authentication events were correlated
by Wazuh.

The following alert was observed:

| Field          | Value                           |
|----------------|---------------------------------|
| Rule ID        | 60204                           |
| Rule Level     | 10                              |
| Description    | Multiple Windows Logon Failures |
| Agent          | SOC-Windows                     |
| Target Account | Administrator                   |
| Source IP      | 152.58.114.63                   |


The alert demonstrated that Wazuh was receiving the Windows
Security events and detecting repeated authentication failures.

# 3. Event ID 4740 — Account Lockout

## Description

Event ID 4740 indicates that a Windows account was locked out.

During the simulation, repeated authentication attempts resulted
in an account lockout involving the Administrator account.

Wazuh generated a corresponding account-lockout alert.

The observed Wazuh alert was reported as:

User Account Locked Out
Rule Level: 9

The lockout provided additional evidence that the repeated
authentication activity exceeded the configured account
lockout threshold.

# 4. Event ID 4624 — Successful Logon

## Description

Event ID 4624 indicates that a logon was successfully completed.

A subsequent successful authentication involving the same
Administrator account and source IP was observed.

Observed Fields:

| Field                  | Observed Value |
|------------------------|----------------|
| Event ID               |  4624          |
| Target Username        |  Administrator |
| Source IP              |  152.58.114.63 |
| Logon Type             |  3             |
| Workstation Name       |  DxSnipe       |
| Logon Process          |  NtLmSsp       |
| Authentication Package |  NTLM          |


The successful authentication had:
```text
Logon Type = 3
```
Logon Type 3 represents a network logon.

It is not Logon Type 10, which represents a
RemoteInteractive/RDP logon.

Therefore, although RDP activity was used during portions of
the lab, the available 4624 event itself does not establish
that this particular successful authentication was an RDP
session.

# 5. Event Correlation

The relevant sequence observed during the investigation was:
```text
Authentication Attempts
          |
          v
Event ID 4625
Failed Logon
          |
          v
Multiple Failed Logons
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
The events were correlated using common authentication
attributes such as:

Username
Source IP
Authentication package
Logon process
Logon type
Target system
Timestamp

# 6. SOC Interpretation

The repeated failed authentication events triggered the Wazuh
multiple-logon-failure detection.

Because the activity was intentionally generated as part of the
controlled lab, the alert represents a true positive for the
detection behavior.

The activity is consistent with password-guessing/brute-force
behavior in the lab.

However, the available events alone do not establish malicious
intent in a real-world environment.

The subsequent 4624 event also should not automatically be
interpreted as a successful RDP compromise because its Logon Type
was 3.

A SOC analyst would therefore continue investigating the surrounding
authentication activity and endpoint telemetry before determining
whether unauthorized access occurred.

# 7. Key Investigation Findings

1. Windows auditing successfully generated Event ID 4625.
2. Wazuh successfully collected the Windows Security events.
3. Wazuh correlated repeated failed logons.
4. Wazuh generated Rule ID 60204 at Level 10.
5. The Administrator account was subsequently locked out.
6. A later Event ID 4624 was observed.
7. The successful authentication had Logon Type 3.
8. NTLM was used for the observed authentication events.
9. The failed authentication events included status 0xc000006d and sub-status 0xc000006a.
10. The evidence supports the simulated brute-force/password-guessing scenario but does not independently establish malicious intent or successful compromise.
