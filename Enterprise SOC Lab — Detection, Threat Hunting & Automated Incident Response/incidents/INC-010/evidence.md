# Evidence — INC-010

## Evidence Sources

- Sysmon Event ID 1
- Sysmon Event ID 22
- Sysmon Event ID 3
- Wazuh alerts
- Host: SOC-Windows

## Key Observations

PowerShell ProcessGuid:

`{73915500-f93f-6ac5-1902-000000007700}`

Behavioral chain:

`PowerShell`
↓
`DNS Query: example.com`
↓
`HTTPS: 104.20.23.154:443`

## Sysmon Evidence

- Event ID 1: PowerShell execution
- Event ID 22: DNS query for example.com
- Event ID 3: TCP connection to 104.20.23.154:443

The events were associated with the same PowerShell ProcessGuid.

## Detection

Wazuh detected the PowerShell execution through Rule 92027.

A related Event ID 11 alert was also observed.

No dedicated Wazuh Event ID 22 or Event ID 3 detection was demonstrated for this ProcessGuid.

## Investigation

The behavior resembled a C2-like communication chain, but C2 was **not established**.

The destination was benign and no malicious payload or compromise was identified.

## Detection Assessment

**Detection Gap**

Improved DNS and network correlation could provide stronger behavioral detection.

## Conclusion

Benign controlled validation demonstrating a PowerShell → DNS → HTTPS behavioral chain.
