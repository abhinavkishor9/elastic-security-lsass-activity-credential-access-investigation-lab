# Elastic Security Lab 08 — Credential Access: LSASS Activity

## Overview

This lab investigates **LSASS activity** from a Windows endpoint security perspective using Elastic Security and Elastic Defend.

The Local Security Authority Subsystem Service (`lsass.exe`) is a critical Windows security process. Because credential-access techniques can target LSASS, a SOC analyst should know how to identify LSASS activity, validate its process context, and investigate processes that reference or interact with it.

This lab was intentionally kept **benign and telemetry-focused**. No LSASS memory dumping, credential extraction, credential-dumping tools, or malicious payloads were used.

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | Windows 10 Pro 22H2 |
| Host | `DESKTOP-9MMM37V` |
| User | `Dell` |
| Elastic Platform | Elastic Security Serverless |
| Endpoint Integration | Elastic Defend |
| Elastic Agent | `9.5.4` |
| Agent Policy | `Windows-SOC-Lab` |
| Investigation Interface | Discover / ES|QL |
| Shell | PowerShell 7.6.6 |
| Time Range | Last 15 minutes |

## Objectives

- Identify the running LSASS process.
- Validate the LSASS process locally and through Elastic telemetry.
- Investigate process identifiers and executable information.
- Generate benign LSASS-related process enumeration activity.
- Search Elastic for the resulting process telemetry.
- Examine whether PowerShell commands referencing LSASS are visible.
- Investigate the availability of LSASS-related process-access telemetry.
- Distinguish normal LSASS presence from actual credential-access behavior.
- Document telemetry limitations and zero-result searches.
- Apply an evidence-based approach to credential-access investigations.

## Scenario

A SOC analyst is reviewing a Windows endpoint for possible credential-access activity involving LSASS.

The analyst first validates that `lsass.exe` is running and identifies its process ID. Elastic endpoint telemetry is then queried to establish whether the process is visible and whether repeated LSASS process events are being collected.

To generate known benign telemetry, the analyst uses Windows process-enumeration commands:

```powershell
Get-Process -Name lsass | Select-Object Id, ProcessName
```

and:

```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
```

The investigation then checks whether these activities and any PowerShell commands referencing LSASS can be identified in Elastic.

## Local LSASS Validation

The LSASS process was identified locally with PID:

```text
1320
```

The following command was used:

```powershell
Get-Process -Name lsass
```

The process was also queried with:

```powershell
Get-Process -Name lsass | Select-Object Id, ProcessName, Path
```

and:

```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
```

The `tasklist` output showed:

```text
lsass.exe
PID: 1320
Session Name: Services
Session: 0
```

## Elastic LSASS Telemetry

The following ES|QL query was used:

```esql
FROM logs-*
| WHERE process.name == "lsass.exe"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
```

Elastic returned:

```text
30 documents processed
```

Observed LSASS events included:

```text
Sep 27, 2026 @ 05:35:42.146
Sep 27, 2026 @ 05:35:42.135
Sep 27, 2026 @ 05:30:22.703
```

The observed process information included:

```text
Process: lsass.exe
PID: 1320
Executable: C:\Windows\System32\lsass.exe
```

This confirmed that Elastic was receiving repeated LSASS process telemetry.

## Process Metadata

Some returned LSASS events showed:

```text
Parent PID: 1144
```

while the displayed parent process name was:

```text
-
```

This was treated as incomplete process metadata.

No parent-process name was inferred from the parent PID.

## Benign Process Enumeration

The following command was executed:

```powershell
Get-Process -Name lsass | Select-Object Id, ProcessName
```

The result identified:

```text
1320 lsass
```

The following command was also executed:

```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
```

This returned:

```text
lsass.exe
PID: 1320
```

## Elastic `tasklist.exe` Telemetry

The following ES|QL query was used:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*tasklist*"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
```

Elastic returned one event:

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

This provided endpoint evidence for the benign LSASS enumeration command.

## PowerShell LSASS Search

A focused hunt was performed with:

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

This was documented as a query result and telemetry limitation rather than evidence that no LSASS-related PowerShell activity existed.

## Credential Access Assessment

The lab distinguishes between:

```text
LSASS process exists
```

and:

```text
A process accessed LSASS for credential theft
```

The first condition was confirmed.

The second condition was **not demonstrated**.

No LSASS memory dump or credential extraction activity was performed.

## Key Findings

### Observed

- `lsass.exe` was running with PID `1320`.
- Local Windows commands successfully enumerated LSASS.
- Elastic returned 30 LSASS process documents.
- LSASS executable telemetry showed `C:\Windows\System32\lsass.exe`.
- Some LSASS events contained parent PID information without a displayed parent process name.
- `tasklist.exe` was captured in Elastic.
- The controlled `tasklist.exe` event had `pwsh.exe` as its parent.
- A PowerShell/pwsh LSASS command-line search returned zero results.
- The Elastic Agent remained healthy.

### Confirmed

- LSASS was present on the endpoint.
- Elastic captured repeated LSASS process telemetry.
- Benign LSASS enumeration was performed.
- Elastic captured the associated `tasklist.exe` activity.
- No credential extraction was performed.

### Not Demonstrated

- LSASS memory dumping
- Credential extraction
- Credential theft
- Malicious LSASS access
- Malware execution
- Persistence
- Privilege escalation
- Command-and-control
- Confirmed endpoint compromise

## Telemetry Limitations

The investigation identified two important telemetry limitations:

1. Some LSASS process events contained a parent PID without a corresponding parent-process name.
2. The PowerShell LSASS command-line query returned zero documents.

These limitations were documented rather than resolved through assumption.

## Investigation Principle

The investigation followed:

```text
LSASS Process
      |
      v
Process Metadata
      |
      v
Related Enumeration Activity
      |
      v
Potential Accessing Process
      |
      v
Command Line
      |
      v
Surrounding Activity
      |
      v
Evidence-Based Assessment
```

The presence of LSASS alone is not evidence of credential theft.

## MITRE ATT&CK

### T1003.001 — OS Credential Dumping: LSASS Memory

This technique was investigated from a **detection and analysis perspective**.

The controlled lab did not perform LSASS memory dumping or credential extraction.

## Final Assessment

Elastic provided clear visibility into the running LSASS process and captured benign `tasklist.exe` enumeration activity associated with the investigation.

The available telemetry did not demonstrate LSASS memory access or credential dumping. The zero-result PowerShell search and incomplete parent-process metadata were documented as telemetry limitations.

The lab therefore demonstrates how a SOC analyst can investigate LSASS activity without confusing normal LSASS operation or benign enumeration with confirmed credential theft.
