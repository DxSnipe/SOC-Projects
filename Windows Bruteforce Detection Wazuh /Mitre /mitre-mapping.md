# MITRE ATT&CK Mapping

## Purpose

This document maps the observed authentication activity from the controlled Windows brute-force 
simulation to the MITRE ATT&CK framework.

The mapping is based on the Windows Security events and Wazuh alerts observed during 
the investigation.

---

# T1110 — Brute Force

## Technique

**T1110 — Brute Force**

## Observed Behavior

Repeated authentication attempts were generated against the Windows `Administrator` account.

The activity resulted in multiple Event ID `4625` failed-logon events.

Wazuh subsequently generated:

```text
Rule ID: 60204
Rule Level: 10
Description: Multiple Windows Logon Failures
```
# Evidence
```text
Event ID: 4625
Target Account: Administrator
Source IP: 152.58.114.63
Status: 0xc000006d
Sub-Status: 0xc000006a
```
The repeated authentication failures are consistent with the Brute Force technique in the 
controlled lab scenario.

# T1110.001 — Password Guessing

## Technique

### T1110.001 — Password Guessing

## Observed Behavior

The simulation involved repeated attempts to authenticate to the same Windows account using 
different authentication credentials.

The failed authentication events included:
```text
Target Account: Administrator
Status: 0xc000006d
Sub-Status: 0xc000006a
```
The sub-status 0xc000006a indicates an incorrect password.

The activity therefore provides evidence consistent with password guessing within the controlled lab.

# Why Other T1110 Sub-Techniques Were Not Mapped

The MITRE ATT&CK Brute Force technique contains several sub-techniques.

This investigation does not provide sufficient evidence to map the activity to all of them.

## T1110.002 — Password Cracking

Not mapped.

The investigation did not demonstrate offline password cracking, hash cracking, or password-recovery activity.

## T1110.003 — Password Spraying

Not mapped.

The observed activity focused on the Administrator account.
The evidence does not demonstrate attempts against multiple accounts using a common password.

## T1110.004 — Credential Stuffing

Not mapped.

The investigation did not demonstrate the use of previously compromised username/password pairs from another source.

# Authentication Type Consideration
The observed failed authentication events included:
```text
Logon Type: 3
Authentication Package: NTLM
Logon Process: NtLmSsp
```
Logon Type 3 represents a network logon.

A separate RDP authentication test produced Logon Type 10, which represents RemoteInteractive/RDP authentication.

The primary detection is therefore mapped to the authentication failure/brute-force behavior rather than being described as an
RDP-specific technique.

# Supporting Windows Events

The investigation also observed:
```text
4625 → Failed Logon
4740 → Account Lockout
4624 → Successful Logon
```
These events provide supporting evidence for the authentication timeline but do not themselves change the primary MITRE mapping.

The later 4624 event had:
```text
Logon Type: 3
Authentication Package: NTLM
```
Therefore, the event is documented as a successful network authentication.

# Evidence-to-Technique Mapping

| Evidence                      | Observation                              | ATT&CK Mapping                     |
| ----------------------------- | ---------------------------------------- | ---------------------------------- |
| Multiple `4625` events        | Repeated failed authentication           | T1110                              |
| Incorrect-password sub-status | Password attempts failed                 | T1110.001                          |
| Wazuh Rule `60204`            | Multiple Windows logon failures detected | Supporting detection evidence      |
| `4740`                        | Account lockout occurred                 | Supporting authentication evidence |
| `4624`                        | Successful authentication later observed | Supporting timeline evidence       |

# Confidence and Limitations

## High-confidence observations

### The lab directly demonstrated:

Repeated authentication failures
Targeting of the Administrator account
Incorrect-password authentication failures
Wazuh detection of multiple failures Account lockout
A subsequent successful network authentication 

# Limitations

The telemetry collected in this lab does not independently establish:

Real-world malicious intent
Credential theft
Successful compromise caused by the simulated attempts
Persistence
Lateral movement
Privilege escalation
Data access

The MITRE mapping therefore remains limited to the behavior directly demonstrated by the controlled simulation.

# Final Mapping
```text
Observed Behavior
       |
       v
Repeated Authentication Attempts
       |
       v
Multiple Windows 4625 Events
       |
       v
Incorrect Password
       |
       v
MITRE ATT&CK
       |
       +---- T1110
       |
       +---- T1110.001
```
### Primary Technique: T1110 — Brute Force

### Sub-Technique: T1110.001 — Password Guessing





