# Evidence — INC-008

## Evidence Sources

- Windows Service configuration
- Windows Service Manager
- Host: SOC-Windows

## Key Observations

Service:

`Project-Svc`

Configuration:

- Display Name: Service Persistence Test
- Startup Type: Manual
- Start Account: LocalSystem
- Binary/Command: powershell.exe

## Investigation

The service was successfully created and configured to execute PowerShell.

An attempt to start the service failed because the configured executable did not implement the required Windows service interface.

## Important Finding

Service configuration does not prove successful execution.

The persistence mechanism existed, but the configured PowerShell payload did not successfully execute as a Windows service.

## Response

The temporary service was deleted after validation.

## Conclusion

Service-persistence investigation completed.
No persistent malicious service remained.
