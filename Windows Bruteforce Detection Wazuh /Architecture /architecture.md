# Lab Architecture

## Windows Brute Force Detection & Investigation Using Wazuh

```text
                 SOC LAB
                    |
                    |
              Kali Linux
           Simulation Host
                    |
                    | Authentication Attempts
                    v
          +-------------------+
          |   Windows Server  |
          |   EC2AMAZ-V1OPH8C |
          +-------------------+
                    |
                    | Windows Security Events
                    | 4625 / 4740 / 4624
                    v
          +-------------------+
          |   Wazuh Agent     |
          |    SOC-Windows    |
          +-------------------+
                    |
                    | Security Telemetry
                    v
          +-------------------+
          |   Wazuh Manager   |
          +-------------------+
                    |
                    | Detection / Correlation
                    v
          +-------------------+
          |    Wazuh SIEM     |
          |                   |
          | Rule 60204 Level 10|
          +-------------------+
                    |
                    v
             SOC Analyst
                    |
        +-----------+-----------+
        |           |           |
        v           v           v
      Triage   Investigation  Timeline
        |           |           |
        +-----------+-----------+
                    |
                    v
             MITRE ATT&CK
                    |
                    v
             Incident Report
```
# Data Flow
```text
Authentication Attempt
        ↓
Windows Security Event
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Detection Rule
        ↓
Wazuh Alert
        ↓
SOC Investigation
        ↓
Incident Documentation
```
# Detection

The primary Wazuh detection observed during the lab was:
```text
Rule ID: 60204
Rule Level: 10
Description: Multiple Windows Logon Failures
```




