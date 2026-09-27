# Troubleshooting Notes 

## Issue 1 — PowerShell LSASS Hunt Returned 0 Results

### Query

```esql
FROM logs-*
| WHERE process.name IN ("powershell.exe", "pwsh.exe")
| WHERE process.command_line LIKE "*lsass*"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

### Result

```text
0 documents processed
```

### Investigation

The endpoint successfully ran LSASS enumeration commands, and Elastic captured `tasklist.exe`.

Therefore, the zero-result PowerShell query did not indicate that Elastic telemetry was completely unavailable.

### Resolution

The result was documented as a telemetry/query limitation.

The successful `tasklist.exe` event became the primary evidence for the controlled enumeration activity.

### Lesson

A zero-result query should not automatically be interpreted as proof that the activity did not occur.

---

## Issue 2 — LSASS Parent Process Name Was Missing

Elastic returned LSASS events containing:

```text
Parent PID: 1144
Parent Name: -
```

### Investigation

The parent PID was retained as an observed field.

The parent process name was not inferred.

### Lesson

When telemetry contains a process ID without the corresponding process name, document the missing field instead of reconstructing the relationship through assumption.

---

## Issue 3 — Distinguishing LSASS Presence from LSASS Credential Access

The endpoint consistently showed:

```text
lsass.exe
PID 1320
```

This is expected for a running Windows system.

### Lesson

The existence of LSASS does not demonstrate credential theft.

A credential-access investigation requires evidence involving an accessing process and relevant behavior.

---

## Issue 4 — Using `tasklist.exe` for Safe LSASS Enumeration

The controlled command was:

```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
```

The command only enumerates the process.

Elastic captured:

```text
tasklist.exe
```

with:

```text
Parent: pwsh.exe
Parent PID: 30212
User: Dell
```

### Lesson

Benign process enumeration can be used to validate endpoint visibility without dumping memory or extracting credentials.

---

## Issue 5 — Local and Elastic PID Validation

Local Windows commands reported:

```text
lsass.exe
PID 1320
```

Elastic also reported:

```text
lsass.exe
PID 1320
```

### Lesson

Comparing local host evidence with SIEM telemetry is useful for validating that the correct endpoint process is being investigated.

---

## Issue 6 — Elastic Returned Repeated LSASS Events

The LSASS process query returned:

```text
30 documents processed
```

Multiple events showed the same:

```text
lsass.exe
PID 1320
```

### Interpretation

Repeated process events were treated as endpoint telemetry for the running process rather than separate credential-access incidents.

### Lesson

Multiple events for a system process do not automatically represent multiple security incidents.

---

## Issue 7 — PowerShell Search and `tasklist.exe` Search Produced Different Results

The `tasklist.exe` query returned:

```text
1 document
```

while the PowerShell LSASS command-line query returned:

```text
0 documents
```

### Investigation

This demonstrated that telemetry visibility can vary by event type and field content.

### Lesson

Different queries can legitimately produce different results from the same user activity.

Investigate the fields that are actually populated rather than assuming all process activity exposes identical metadata.

---

## Issue 8 — Time Range

The investigation used:

```text
Last 15 minutes
```

This was appropriate for the controlled activity.

The investigation should ensure that the time range includes:

```text
Local enumeration
+
Elastic process event
```

When a recent event is unexpectedly missing, temporarily expand the time range and repeat the query.

---

