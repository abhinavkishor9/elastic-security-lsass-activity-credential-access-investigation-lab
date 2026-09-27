# elastic-security-lsass-activity-credential-access-investigation-lab
## Overview

lsass.exe is a critical Windows security process associated with authentication and security-related operations. From a SOC perspective, activity involving LSASS deserves careful investigation because credential-access techniques can target it.

The investigation model is:

LSASS Process
    ↓
Process Access
    ↓
Accessing Process
    ↓
User Context
    ↓
Access Details
    ↓
Command Line
    ↓
Executable Path
    ↓
Surrounding Activity
    ↓
Assessment

The important distinction is:

lsass.exe exists
        ≠
credential theft

and:

a process references lsass.exe
        ≠
confirmed credential dumping

The analyst needs supporting telemetry showing which process accessed LSASS and what kind of access was requested.

This lab investigates Windows Data Protection API (DPAPI) artifacts and related endpoint telemetry using PowerShell, Sysmon, and Wazuh.

The investigation focuses on identifying DPAPI-related artifacts within a Windows user profile, reviewing related process activity, and correlating endpoint events using process image, command line, parent process, user context, integrity level, and timestamp.

The investigation follows an evidence-first approach. The presence of a DPAPI artifact, a credential-related keyword, or a process such as `net.exe` is not treated as proof of malicious activity. Each observation must be correlated with additional evidence before reaching a conclusion.

---

## Lab Objectives

The objectives of this lab are to:

- Investigate Windows DPAPI-related artifacts from a user profile and determine what they reveal about the endpoint.
- Identify and document DPAPI-related directories, files, and cryptographic locations associated with the Windows user and system.
- Use PowerShell to collect relevant filesystem and registry evidence without modifying the underlying artifacts.
- Analyze Sysmon process creation telemetry for activity associated with DPAPI, credential, protection, vault, and LSASS-related keywords.
- Investigate `net.exe` activity reported by Wazuh and determine what the exact command line reveals about the process execution.
- Correlate the process image, command line, parent process, user context, integrity level, and timestamp for relevant endpoint events.
- Distinguish normal Windows security artifacts from activity that may require further investigation.
- Understand the limitations of keyword-based searches and identify how they can produce legitimate matches and false positives.
- Build a chronological view of relevant process and artifact activity using Sysmon and Wazuh telemetry.
- Preserve investigation findings in structured evidence files for later review and reproducibility.
- Apply an evidence-first investigation methodology by separating confirmed observations from assumptions and unconfirmed hypotheses.
- Determine whether the collected telemetry is sufficient to support a conclusion of suspicious DPAPI activity or credential theft.
  
---

## Lab Scenario

A SOC analyst is investigating a Windows endpoint for signs of **suspicious service creation** that could potentially provide persistence. The analyst wants to determine whether a newly created service is simply a controlled administrative configuration or an artifact that requires further investigation.

A temporary Windows Service named `ElasticLab07` is created using `sc.exe`. The service is configured with the following properties:

```text
Service Name: ElasticLab07
Display Name: Elastic Lab 07 Test Service
Binary Path: C:\Windows\System32\cmd.exe /c exit
Start Type: Demand Start
Service Account: LocalSystem
```

The analyst validates the service through Windows Service Manager and examines its configuration in the corresponding Registry location under:

```text
HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07
```

Elastic telemetry is then used to investigate the `sc.exe` activity associated with creating and querying the service. The investigation focuses on:

- The process responsible for service creation
- Parent process and process ID information
- Command-line arguments
- Service binary path and startup configuration
- Service account
- Availability of corresponding Registry telemetry
- Whether the configured service binary can be independently observed as executing

During the investigation, Elastic successfully captures the `sc.exe` creation and configuration activity, while the Registry-focused query does not return a matching event. Some process records also contain incomplete metadata.

The analyst therefore separates **locally confirmed service configuration** from **telemetry actually observed in Elastic**, and does not infer service execution where direct process evidence is unavailable.

The controlled service is deleted after the investigation. Its removal is verified through Windows Service Manager and the associated Registry path.

The scenario is designed to demonstrate how a SOC analyst investigates **Windows Service creation as a potential persistence mechanism** while distinguishing service configuration, process telemetry, execution evidence, and telemetry limitations.

---

## Baseline

Before creating the test service, the analyst checked:

```powershell
Get-Service -Name "ElasticLab07" -ErrorAction SilentlyContinue
```

No existing `ElasticLab07` service was found.

A sample of existing Windows services was also reviewed to provide environmental context.

## Service Creation

The following command created the controlled service:

```powershell
sc.exe create ElasticLab07 binPath= "C:\Windows\System32\cmd.exe /c exit" start= demand DisplayName= "Elastic Lab 07 Test Service"
```

Windows returned:

```text
[SC] CreateService SUCCESS
```

## Service Configuration

The service was inspected with:

```powershell
sc.exe qc ElasticLab07
```

Observed configuration:

```text
SERVICE_NAME: ElasticLab07
TYPE: 10 WIN32_OWN_PROCESS
START_TYPE: 3 DEMAND_START
ERROR_CONTROL: 1 NORMAL
BINARY_PATH_NAME: C:\Windows\System32\cmd.exe /c exit
DISPLAY_NAME: Elastic Lab 07 Test Service
SERVICE_START_NAME: LocalSystem
```

The service was also checked with:

```powershell
Get-Service -Name "ElasticLab07" | Select-Object Name, DisplayName, Status, StartType
```

Observed:

```text
Name         : ElasticLab07
DisplayName  : Elastic Lab 07 Test Service
Status       : Stopped
StartType    : Manual
```

## Service State

The detailed service query showed:

```text
Status: Ready
Run As User: Dell
Task To Run: N/A
```

For the Windows Service configuration itself, `sc.exe qc` reported:

```text
SERVICE_START_NAME: LocalSystem
```

The investigation therefore records the service configuration exactly as reported by Windows rather than assuming the interactive user context represents the service account.

## Elastic Process Telemetry

The following ES|QL query was used to locate activity associated with the service name:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*ElasticLab07*"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

Elastic returned process events for `sc.exe`.

### Service Creation Event

Observed:

```text
Sep 26, 2026 @ 05:54:16.453
```

Process:

```text
sc.exe
```

PID:

```text
29604
```

Parent:

```text
pwsh.exe
```

Parent PID:

```text
33488
```

The command line contained:

```text
sc.exe create ElasticLab07
```

The executable path was:

```text
C:\Windows\System32\sc.exe
```

## Service Query Activity

Additional `sc.exe` activity was captured.

Observed:

```text
Sep 26, 2026 @ 05:55:46.557
```

Process:

```text
sc.exe
```

PID:

```text
33872
```

Parent:

```text
pwsh.exe
```

Parent PID:

```text
33488
```

The command line contained:

```text
sc.exe qc ElasticLab07
```

This demonstrates that Elastic captured service-management activity performed from PowerShell.

## Binary Path Investigation

A focused search for the service binary path was performed:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*cmd.exe /c exit*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

Elastic returned one result associated with:

```text
sc.exe
```

The command line referenced the service creation operation.

This provided process-level evidence that the service was configured using the intended binary path.

## Registry Investigation

The service configuration was also examined locally at:

```text
HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07
```

The following command was used:

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07"
```

Observed:

```text
Type: 16
Start: 3
ErrorControl: 1
ImagePath: C:\Windows\System32\cmd.exe /c exit
DisplayName: Elastic Lab 07 Test Service
ObjectName: LocalSystem
```

The Registry key itself was also verified.

## Elastic Registry Hunt

A Registry query was attempted:

```esql
FROM logs-*
| WHERE registry.key LIKE "*CurrentControlSet*Services*"
| WHERE registry.value LIKE "*ElasticLab07*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
```

No Registry telemetry matching those conditions was returned.

The local Registry evidence therefore remains authoritative for the configuration that was actually present on the endpoint, while the absence of Elastic Registry results is documented as a telemetry limitation.

## Service Execution

The service was configured as:

```text
DEMAND_START
```

and:

```text
STOPPED
```

The controlled service was not used to execute a malicious payload.

The investigation therefore focused primarily on:

```text
Service Creation
Service Configuration
Service Account
Binary Path
Elastic sc.exe Telemetry
```

rather than attempting unnecessary service execution.

## Key Findings

### Observed

- `ElasticLab07` was created successfully.
- The service was configured as `DEMAND_START`.
- The service status was `STOPPED`.
- The binary path was `C:\Windows\System32\cmd.exe /c exit`.
- The service display name was `Elastic Lab 07 Test Service`.
- The configured service account was `LocalSystem`.
- Elastic captured the `sc.exe create` activity.
- Elastic captured subsequent `sc.exe query` and `sc.exe qc` activity.
- The `ElasticLab07` Registry hunt returned no results in Elastic.
- Local Registry inspection confirmed the service configuration.
- The service was successfully deleted.

### Confirmed

- The controlled Windows Service existed.
- The service configuration was validated locally.
- The service creation command was captured by Elastic.
- The service management process was `sc.exe`.
- The service configuration referenced the intended executable path.
- The service was removed during remediation.

### Not Demonstrated

- Malicious service execution
- Malware execution
- Credential theft
- Privilege escalation
- Command-and-control
- Defense evasion
- Confirmed endpoint compromise

## Telemetry Limitations

The investigation identified several telemetry limitations:

- The Registry-specific Elastic query returned zero documents.
- Some `sc.exe` events contained incomplete PID, parent-process, or command-line fields.
- The service configuration was therefore validated primarily through local Windows commands.
- Service configuration evidence does not automatically prove that the configured binary executed.
- The process that created the service should not automatically be treated as the eventual service process.


## MITRE ATT&CK

### T1543.003 — Create or Modify System Process: Windows Service

The controlled activity demonstrates Windows Service creation and configuration.

The ATT&CK mapping describes the mechanism demonstrated by the lab and does not indicate that the controlled service itself was malicious.

## Remediation

The controlled service was removed using:

```powershell
sc.exe delete ElasticLab07
```

Windows returned:

```text
[SC] DeleteService SUCCESS
```

Post-deletion verification was performed with:

```powershell
Get-Service -Name "ElasticLab07" -ErrorAction SilentlyContinue
```

and:

```powershell
sc.exe query ElasticLab07
```

The service query returned:

```text
The specified service does not exist as an installed service.
```

The Registry was also checked:

```powershell
Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07"
```

Result:

```text
False
```

