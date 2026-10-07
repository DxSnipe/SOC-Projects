# DET-001 — Document Application → PowerShell

## Objective

Detect PowerShell execution spawned by document-processing applications.

## Trigger

Sysmon Event ID 1 where:

- Image = powershell.exe
- Parent Image belongs to a document-processing application

Examples:

- WINWORD.EXE
- EXCEL.EXE
- POWERPNT.EXE
- soffice.bin

## MITRE ATT&CK

T1059.001 — PowerShell

## Detection Logic
```
Document Application
        ↓
PowerShell
        ↓
Investigate command line and user context
```
## Original Detection Gap

INC-005 demonstrated that Sysmon captured: 'soffice.bin → powershell.exe' but Wazuh did not generate a dedicated detection.

## Analyst Response

Review:

- Parent process
- Command line
- User
- Integrity level
- Child process
- Network activity
- File creation

## False Positive Considerations

Legitimate:

- Office macros
- Administrative automation
- Approved scripts
- Enterprise document workflows

## Expected Severity

Medium

Severity should be adjusted according to command line, user context, and follow-on behavior.
