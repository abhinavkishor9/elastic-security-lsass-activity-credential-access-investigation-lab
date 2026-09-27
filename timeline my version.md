# Timeline 

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

