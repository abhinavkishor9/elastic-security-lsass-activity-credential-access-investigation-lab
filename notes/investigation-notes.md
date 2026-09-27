# Investigation Notes — Credential Access: LSASS Activity

## Investigation Summary

This investigation examined LSASS activity on `DESKTOP-9MMM37V` using local Windows commands and Elastic endpoint telemetry.

The objective was to establish LSASS visibility, generate controlled process-enumeration activity, investigate related telemetry, and determine whether the available evidence demonstrated credential-access behavior.

No LSASS memory dumping or credential extraction was performed.

## Endpoint Validation

Local Windows inspection identified:

```text
Process: lsass
PID: 1320
```

The following command was used:

```powershell
Get-Process -Name lsass | Select-Object Id, ProcessName
```

Observed:

```text
Id: 1320
ProcessName: lsass
```

The process was also queried with:

```powershell
Get-Process -Name lsass
```

and:

```powershell
Get-Process -Name lsass | Select-Object Id, ProcessName, Path
```

## Tasklist Validation

The command:

```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
```

returned:

```text
lsass.exe
PID: 1320
Session Name: Services
Session: 0
```

This confirmed the same LSASS PID through a second Windows process-enumeration method.

## Elastic LSASS Query

The following ES|QL query was executed:

```esql
FROM logs-*
| WHERE process.name == "lsass.exe"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
```

Result:

```text
30 documents processed
```

Observed examples included:

```text
Sep 27, 2026 @ 05:35:42.146
lsass.exe
PID: 1320
Executable: C:\Windows\System32\lsass.exe
Parent PID: 1144
Parent Name: -
```

and:

```text
Sep 27, 2026 @ 05:35:42.135
lsass.exe
PID: 1320
Executable: C:\Windows\System32\lsass.exe
Parent PID: 1144
Parent Name: -
```

## LSASS Process Consistency

The local process inspection and Elastic telemetry both identified:

```text
lsass.exe
PID 1320
```

This provided consistent process identification across the endpoint and SIEM views.

## Parent Metadata

Elastic displayed:

```text
Parent PID: 1144
```

for some LSASS events while the parent process name field was:

```text
-
```

No parent process name was inferred from the PID.

This was recorded as incomplete process metadata.

## Benign Enumeration Activity

The controlled enumeration command:

```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
```

was executed to produce known-good telemetry.

Elastic later showed:

```text
Sep 27, 2026 @ 05:39:33.580
```

with:

```text
Process: tasklist.exe
PID: 12144
Parent: pwsh.exe
Parent PID: 30212
User: Dell
```

The command-line telemetry corresponded to the `tasklist` enumeration activity.

## `tasklist.exe` Hunting

The query used was:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*tasklist*"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
```

Result:

```text
1 document processed
```

This demonstrated that Elastic captured the process used for benign LSASS enumeration.

## PowerShell LSASS Hunt

A second investigation searched PowerShell process command lines:

```esql
FROM logs-*
| WHERE process.name IN ("powershell.exe", "pwsh.exe")
| WHERE process.command_line LIKE "*lsass*"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
```

No matching PowerShell event was returned.

This result was treated as a telemetry/query observation and not as proof that no PowerShell-based LSASS reference existed.

## Credential Access Investigation

The investigation did not identify evidence of:

```text
LSASS memory dumping
Credential extraction
Credential theft
```

The activity that was directly observed consisted of:

```text
LSASS process visibility
+
Benign process enumeration
+
Elastic process telemetry
```

## Evidence Assessment

### Observed

- `lsass.exe` with PID `1320`.
- Repeated LSASS events in Elastic.
- `C:\Windows\System32\lsass.exe` executable path.
- Parent PID information without a corresponding displayed parent process name.
- `tasklist.exe` process telemetry.
- `pwsh.exe → tasklist.exe` relationship for the controlled enumeration.
- Zero results from the PowerShell LSASS command-line hunt.

### Confirmed

- LSASS is running on the endpoint.
- Elastic captures LSASS process telemetry.
- The controlled enumeration command executed.
- Elastic captured the `tasklist.exe` activity.
- No credential-dumping technique was performed.

### Unknown

- The reason the LSASS parent PID was available without a parent process name.
- Whether additional LSASS-related activity existed outside the queried telemetry.
- Whether the current dataset exposes complete process-access telemetry for LSASS.

## Analyst Assessment

The available evidence does not demonstrate credential theft.

The investigation confirms LSASS visibility and benign enumeration activity, but there is no direct evidence of a process opening LSASS for credential dumping or extracting credentials.

The distinction is important:

```text
LSASS observed
    ≠
LSASS accessed maliciously
    ≠
Credentials stolen
```

## MITRE ATT&CK

### T1003.001 — OS Credential Dumping: LSASS Memory

The technique was considered as an investigation target.

No LSASS memory dump was performed.

## Conclusion

The investigation successfully validated LSASS visibility in Elastic and correlated a controlled `tasklist.exe` enumeration with its PowerShell parent.

The missing PowerShell LSASS search result and incomplete LSASS parent metadata were documented as telemetry limitations.

No credential-access or credential-theft activity was demonstrated by the evidence collected.
