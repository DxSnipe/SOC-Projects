# Windows Brute Force Detection & Investigation Using Wazuh

## Overview

This project demonstrates a SOC investigation of suspiciousWindows authentication activity using Wazuh SIEM.

A controlled lab environment was used to generate repeated authentication failures against a Windows Administrator account.
The resulting Windows Security events were collected by Wazuh, correlated, detected, and investigated.

The project demonstrates the complete SOC workflow:

1. Windows Security event generation
2. Event ID 4625 analysis
3. Wazuh log collection
4. Wazuh detection and alerting
5. Multiple failed-logon investigation
6. 4740 Account lockout investigation
7. Successful authentication analysis
8. False-positive analysis
9. MITRE ATT&CK mapping
10. Incident reporting

## Lab Architecture

```text
Kali Linux
    |
    | Authentication attempts
    v
Windows Server
    |
    | Windows Security Events
    v
Wazuh Agent
    |
    v
Wazuh Manager
    |
    | Detection / Correlation
    v
SOC Analyst
    |
    +--> Alert Triage
    +--> Event Investigation
    +--> Timeline Analysis
    +--> MITRE ATT&CK Mapping
    +--> Incident Report
```


# Environment

| Component                 | Technology                 |
| ------------------------- | -------------------------- |
| Attack / Simulation Host  | Kali Linux                 |
| Target                    | Windows Server             |
| SIEM                      | Wazuh                      |
| Log Source                | Windows Security Event Log |
| Agent                     | Wazuh Windows Agent        |
| Authentication            | NTLM                       |
| Primary Event             | 4625                       |
| Lockout Event             | 4740                       |
| Successful Authentication | 4624                       |


# Detection

Wazuh generated an alert for repeated Windows authentication failures.

Rule ID: 60204

Rule Level: 10

Description: Multiple Windows Logon Failures

The underlying Windows events were verified directly on the Windows endpoint.

# Key Windows Events

Event ID 4625 — Failed Logon

Multiple failed authentication attempts were observed against the Administrator account.

Important fields included:

Target username
Source IP
Logon type
Workstation name
Logon process
Authentication package
Failure reason
Status
Sub-status

## Event ID 4740 — Account Lockout

Repeated authentication failures resulted in an account lockout involving the Administrator account.

## Event ID 4624 — Successful Logon

A subsequent successful authentication was observed:

Target User: Administrator
Source IP: 152.58.114.63
Logon Type: 3
Logon Process: NtLmSsp
Authentication Package: NTLM

The observed Logon Type was 3, which represents a network logon. It was not Logon Type 10 (RemoteInteractive/RDP).

Therefore, the evidence does not independently establish that the successful authentication was an RDP session.

# Investigation Summary

The investigation followed this sequence:

```text
Multiple authentication attempts
            |
            v
Event ID 4625
Failed authentication
            |
            v
Multiple failures
            |
            v
Wazuh Rule 60204
Level 10 Alert
            |
            v
Event ID 4740
Account Lockout
            |
            v
Event ID 4624
Successful Network Authentication
```

The Wazuh detection was classified as a True Positive for the behavior the detection rule was designed to identify 
multiple Windows logon failures

The observed activity is consistent with password-guessing / brute-force behavior in this controlled lab.

However, the available telemetry alone does not establish malicious intent or prove that the later successful authentication 
resulted directly from the preceding failed attempts.

# MITRE ATT&CK

## T1110 — Brute Force

The simulated activity involved repeated authentication attempts against a Windows account.

## T1110.001 — Password Guessing

Multiple password attempts were made against the same Administrator account.

Other Brute Force sub-techniques were not mapped because the available evidence did not demonstrate password cracking,
password spraying, or credential stuffing.

# Indicators Observed

| Indicator        | Value             |
| ---------------- | ----------------- |
| Source IP        | 152.58.114.63     |
| Target Account   | Administrator     |
| Target Host      | EC2AMAZ-V1OPH8C   |
| Authentication   | NTLM              |
| Failed Event     | 4625              |
| Lockout Event    | 4740              |
| Successful Event | 4624              |
| Wazuh Rule       | 60204             |


# Project Structure

```text
windows-bruteforce-detection-wazuh/
|
├── README.md
|
├── architecture/
|
├── screenshots/
|
├── investigation/
|   ├── incident-report.md
|   ├── timeline.md
|   └── event-analysis.md
|
├── detection/
|   └── wazuh-detection.md
|
└── mitre/
    └── mitre-mapping.md
```

# Skills Demonstrated

1. SOC alert triage
2. Windows Security Event analysis
3. Event ID 4625 investigation
4. Event ID 4624 analysis
5. Event ID 4740 analysis
6. Wazuh SIEM
7. Log correlation
8. Authentication analysis
9. IOC identification
10. False-positive analysis
11. MITRE ATT&CK mapping
12. Incident documentation
13. Security investigation
                          
