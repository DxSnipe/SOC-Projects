# PowerShell Encoded Command Investigation

## 1. Objective

Investigate a PowerShell process creation event containing the `-EncodedCommand` parameter using Sysmon Event ID 1 telemetry.

## 2. Detection

Sigma Rule:
`01-suspicious-powershell-encoded-command.yml`

Telemetry:
- Sysmon Event ID 1 — Process Creation

MITRE ATT&CK:
- T1059.001 — PowerShell

## 3. Test Activity

A controlled PowerShell process was launched with an encoded command:

`-NoProfile -EncodedCommand`

The encoded command decoded to:

`Write-Output "SOC-TEST-ENCODED"`

The test was intentionally benign and performed to validate the detection.

## 4. Observed Telemetry

### Process

- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `EC2AMAZ-V1OPH8C\Administrator`
- Integrity Level: High

### Command Line

The process command line contained:

`-NoProfile -EncodedCommand`

### Parent Process

- Parent Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

### Sysmon

- Event ID: 1 — Process Create

## 5. Detection Logic

The Sigma rule matches:

1. PowerShell or PowerShell Core process image.
2. Command line containing an encoded-command parameter.

Both conditions were satisfied by the observed Sysmon telemetry.

## 6. Assessment

The detection was successfully validated using a controlled benign test.

Encoded PowerShell commands can reduce command-line readability and therefore warrant investigation when observed unexpectedly. The laboratory event itself was benign and intentionally generated for detection testing.

## 7. False Positive Considerations

Potential legitimate uses include:

- Administrative scripts
- Enterprise automation
- Software deployment
- Other authorized PowerShell automation

## 8. Evidence

`evidence/01-encoded-powershell-event.txt`

## 9. Validation

The Sigma detection logic was manually validated against the observed Sysmon Event ID 1 telemetry.

A Sigma runtime engine was not used for execution of the rule.

## 10. Conclusion

The detection successfully identified a PowerShell process containing the `-EncodedCommand` parameter in controlled laboratory telemetry.
