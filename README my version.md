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

## Host Information

- Hostname: `DESKTOP-9MMM37V`
- User: `desktop-9mmm37v\dell`
- User Profile: `C:\Users\Dell`
- Domain: `WORKGROUP`
- Domain Role: `0`
- Wazuh Agent ID: `001`
- Wazuh Agent Name: `DESKTOP-9MMM37V`
- Investigation Directory: `C:\DPAPILab\Evidence`

---

## DPAPI Artifact Investigation

The primary user-level DPAPI location investigated was:

`C:\Users\Dell\AppData\Roaming\Microsoft\Protect`

The directory existed and contained:

- A user SID-named directory
- `CREDHIST`

The observed SID-named directory was:

`S-1-5-21-51198790-337801975-3228388354-1001`

The presence of these artifacts confirms that DPAPI-related material exists within the user profile.

However, these artifacts are not sufficient to establish credential theft or malicious DPAPI access.

---

## Machine Cryptographic Artifacts

The investigation also examined:

`C:\ProgramData\Microsoft\Crypto`

The following entries were observed:

- `PCPKSP`
- `RSA`

These locations were documented as part of the Windows cryptographic environment.

Their presence alone was not treated as suspicious.

---

## Registry Investigation

The investigation checked:

`HKCU:\Software\Microsoft\Cryptography`

It also checked:

`HKCU:\Software\Microsoft\Protect`

The `HKCU:\Software\Microsoft\Protect` path returned `False`.

This was documented as a negative finding rather than treated as an investigation failure.

---

## Sysmon Investigation

Sysmon Event ID `1` process creation events were searched for the following terms:

- `dpapi`
- `protect`
- `cryptprotect`
- `credential`
- `vault`
- `lsass`

The search returned four matching process creation events.

Observed timestamps included:

- `27-09-2026 05:54:01`
- `27-09-2026 05:56:13`
- `27-09-2026 05:58:21`
- `27-09-2026 05:58:21`

These events demonstrate that process telemetry matched the investigation keywords.

They do not, by themselves, prove that a process was performing credential theft or malicious DPAPI operations.

---

## Wazuh `net.exe` Investigation

Wazuh reported a process event involving:

`C:\Windows\SysWOW64\net.exe`

The exact command line was:

`net.exe accounts`

Additional event information included:

- Company: `Microsoft Corporation`
- Description: `Net Command`
- Integrity Level: `System`
- Original File Name: `net.exe`
- Parent Process: `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe`

The command line was particularly important because the investigation should focus on what `net.exe` actually executed rather than treating every occurrence of `net.exe` as malicious.

The parent process was also reviewed because process ancestry can provide important context.

---

## Evidence Assessment

### Confirmed

- The endpoint contains a DPAPI user-profile directory.
- A user SID-named DPAPI directory exists.
- `CREDHIST` exists within the DPAPI location.
- Machine-level cryptographic directories exist.
- Sysmon process creation events matched DPAPI-related investigation keywords.
- Wazuh recorded execution of `net.exe`.
- The observed `net.exe` command line was `net.exe accounts`.
- The Wazuh event identified `wazuh-agent.exe` as the parent process.

### Not Confirmed

The available evidence does not establish:

- Credential theft.
- DPAPI secret extraction.
- Malicious DPAPI decryption.
- LSASS credential dumping.
- Confirmed account compromise.
- Malicious persistence.
- Confirmed attacker activity.

---

## MITRE ATT&CK Mapping

The investigation has potential relevance to credential-access techniques involving Windows credential stores and protected credentials.

Potentially relevant techniques include:

- **T1555 - Credentials from Password Stores**
- **T1555.004 - Credentials from Password Stores: Windows Credential Manager**
- **T1003 - OS Credential Dumping**

These techniques are included as investigative considerations rather than confirmed detections.

The presence of DPAPI artifacts or credential-related keywords is not sufficient to claim that any of these techniques were successfully executed.

Further behavioral evidence would be required.

---


## Evidence Collected

The investigation generated the following evidence files:

- `Host-Identity.txt`
- `DPAPI-Profile-Artifacts.txt`
- `DPAPI-Registry-Artifacts.txt`
- `DPAPI-Timeline.txt`
- `Sysmon-DPAPI-ProcessActivity.txt`
- `Investigation-Summary.txt`

---

