# Wazuh Detection — Multiple Windows Logon Failures

## Purpose

This document describes the Wazuh detection used to identify repeated Windows authentication failures 
during the controlled brute-force simulation.

The detection demonstrates how Windows Security events can be collected, analyzed, and correlated by Wazuh 
to generate a SOC alert.

---

## Detection Summary

| Field | Value |
|---|---|
| SIEM | Wazuh |
| Agent | `SOC-Windows` |
| Detection Rule | `60204` |
| Rule Level | `10` |
| Description | Multiple Windows Logon Failures |
| Primary Windows Event | `4625` |
| Target Account | `Administrator` |
| Source IP | `152.58.114.63` |

---

# Detection Flow

```text
Windows Authentication Attempt
            |
            v
Windows Security Event
            |
            v
Event ID 4625
Failed Logon
            |
            v
Wazuh Agent
            |
            v
Wazuh Manager
            |
            v
Detection / Correlation
            |
            v
Rule 60204
Level 10
            |
            v
SOC Alert
```
# Triggering Event
```text
Event ID: 4625
Description: An account failed to log on
```
The failed authentication activity included:
```text
Target User: Administrator
Source IP: 152.58.114.63
Logon Type: 3
Logon Process: NtLmSsp
Authentication Package: NTLM
Status: 0xc000006d
Sub-Status: 0xc000006a
```
The repeated occurrence of these failed authentication events
was detected by Wazuh.

# Wazuh Alert

The resulting Wazuh alert was:
```text
Rule ID: 60204
Rule Level: 10
Description: Multiple Windows Logon Failures
```
This alert indicates that Wazuh identified multiple Windows
logon failures associated with the monitored endpoint.

# Detection Logic

The detection is based on identifying repeated failed Windows
authentication events rather than treating a single failed
authentication as a brute-force attack.

Conceptually:
```text
Single 4625
    |
    +--> Could be normal user error
    |
    v
Repeated 4625 events
    |
    +--> Investigate frequency
    +--> Investigate source
    +--> Investigate target account
    +--> Investigate logon type
    |
    v
Multiple Windows Logon Failures
    |
    v
Wazuh Rule 60204
```
This distinction is important for SOC operations because a
single failed password does not necessarily represent malicious
activity.

# Important Event Fields for Triage

A SOC analyst should examine the following fields when
investigating this alert:

| Field                       | Purpose                                              |
| --------------------------- | ---------------------------------------------------- |
| `timestamp`                 | Establishes when the authentication occurred         |
| `targetUserName`            | Identifies the targeted account                      |
| `ipAddress`                 | Identifies the observed source address               |
| `logonType`                 | Identifies the type of authentication                |
| `workstationName`           | Identifies the workstation associated with the event |
| `logonProcessName`          | Shows the Windows logon process                      |
| `authenticationPackageName` | Identifies the authentication package                |
| `failureReason`             | Provides the authentication failure reason           |
| `status`                    | Provides the Windows authentication status           |
| `subStatus`                 | Provides additional failure information              |


# Logon Type Analysis

The observed failed authentication events included:
```text
Logon Type: 3
```
Logon Type 3 represents a network logon.

This is different from:
```text
Logon Type: 10
```
which represents a RemoteInteractive/RDP logon.

Therefore, the detection itself should not be described as an "RDP brute-force detection" solely 
because RDP was used elsewhere during the lab.

The detection is more accurately described as a:

## Windows authentication failure / brute-force detection.

# Correlated Events

The investigation also identified related authentication events:
```text
4625
Failed Logon
   |
   v
60204
Multiple Windows Logon Failures
   |
   v
4740
Account Lockout
   |
   v
4624
Successful Logon
```
These events provide additional context for the SOC analyst.

The 4624 event observed later had Logon Type 3, so it should be documented as a successful network 
authentication rather than automatically being classified as successful RDP access.

# Alert Triage

When this alert fires in a real SOC environment, an L1 analyst
would investigate:

## 1. Source

Determine the source IP and whether it belongs to:

An authorized workstation
A known administrator
A server
A VPN
A jump host
An unknown system

## 2. Target

Determine:
Which account was targeted
Whether the account is privileged
Whether the account should be remotely accessible

## 3. Frequency

Review:
Number of failed attempts
Time interval between attempts
Whether failures are continuous
Whether multiple accounts are targeted

## 4. Authentication Type

Review:
Logon Type
Authentication package
Logon process

## 5. Correlation

Search for related:

4625 Failed Logon
4740 Account Lockout
4624 Successful Logon

## 6. Follow-up Activity

If a successful authentication occurs after repeated failures,
investigate activity associated with that session.

# Lab Result

The detection successfully demonstrated the complete path:
```text
Windows Endpoint
       |
       v
Security Event 4625
       |
       v
Wazuh Agent
       |
       v
Wazuh Manager
       |
       v
Rule 60204
       |
       v
Level 10 Alert
       |
       v
SOC Investigation
```
The alert was intentionally generated in a controlled lab environment.

Therefore, the alert is a true positive for the simulated authentication-failure behavior.

# Detection Limitations

The detection identifies repeated authentication failures, but the alert alone does not prove:

Malicious intent
Successful compromise
Credential theft
RDP access
Persistence
Lateral movement

Additional telemetry and investigation are required to establish
what happened after the authentication attempts.

As SOC analyst we should:
```text
Detect
  ↓
Validate
  ↓
Correlate
  ↓
Investigate
  ↓
Determine impact
  ↓
Escalate or close
```
