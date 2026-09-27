# Timeline — Credential Access: LSASS Activity

## Investigation Timeline

| Time | Activity | Process / Artifact | Evidence / Notes |
|---|---|---|---|
| Initial validation | Local LSASS inspection | `lsass.exe` | PID `1320` confirmed locally |
| Initial validation | Process enumeration | `tasklist.exe` | `lsass.exe` shown with PID `1320` |
| 05:30:22.703 | Elastic LSASS telemetry | `lsass.exe` | PID `1320`, executable `C:\Windows\System32\lsass.exe` |
| 05:35:42.135 | Elastic LSASS telemetry | `lsass.exe` | PID `1320`, parent PID `1144`, parent name not displayed |
| 05:35:42.146 | Elastic LSASS telemetry | `lsass.exe` | PID `1320`, executable `C:\Windows\System32\lsass.exe` |
| 05:39:33.580 | Controlled enumeration telemetry | `tasklist.exe` | PID `12144`, parent `pwsh.exe`, parent PID `30212` |
| Investigation | PowerShell LSASS hunt | `powershell.exe` / `pwsh.exe` | No matching documents returned |
| Investigation | Agent validation | `Elastic Agent` | Status remained Healthy |

## Initial LSASS Validation

The endpoint was checked using:

```powershell
Get-Process -Name lsass | Select-Object Id, ProcessName
```

Observed:

```text
PID: 1320
Process: lsass
```

A second enumeration method was:

```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
```

Observed:

```text
lsass.exe
PID: 1320
Session Name: Services
Session: 0
```

## 05:30:22 — Elastic LSASS Telemetry

Elastic recorded:

```text
Sep 27, 2026 @ 05:30:22.703
```

with:

```text
Process: lsass.exe
PID: 1320
Executable: C:\Windows\System32\lsass.exe
```

This established that the running LSASS process was visible in Elastic.

## 05:35:42 — Repeated LSASS Telemetry

Additional LSASS events were recorded:

```text
05:35:42.135
05:35:42.146
```

The events continued to show:

```text
Process: lsass.exe
PID: 1320
```

Some records also showed:

```text
Parent PID: 1144
```

while the parent process name field was not populated.

The missing parent name was documented rather than inferred.

## 05:39:33 — Benign `tasklist.exe` Enumeration

Elastic recorded:

```text
Sep 27, 2026 @ 05:39:33.580
```

Observed:

```text
Process: tasklist.exe
PID: 12144
Parent: pwsh.exe
Parent PID: 30212
User: Dell
```

This event corresponded to the controlled process-enumeration activity.

## PowerShell LSASS Hunt

The following query was performed:

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

This was recorded as a telemetry/query limitation.

## Credential-Access Assessment

The timeline establishes:

```text
LSASS present
    ↓
PID 1320 confirmed
    ↓
Elastic LSASS telemetry observed
    ↓
Benign tasklist enumeration performed
    ↓
tasklist.exe telemetry captured
    ↓
PowerShell LSASS hunt returned no results
    ↓
No credential dumping demonstrated
```

## Final Assessment

The investigation confirmed that LSASS was running and visible in Elastic endpoint telemetry.

Benign process enumeration using `tasklist.exe` was also captured and correlated with its PowerShell parent.

No evidence demonstrated LSASS memory dumping, credential extraction, malicious LSASS access, or confirmed credential theft.

The missing PowerShell LSASS result and incomplete parent-process metadata were documented as telemetry limitations.
