# 🛡️ WN11-CC-000066 – Command line data must be included in process creation events

## Summary
In this task, I configured Windows to log the **full command line used when processes start**, rather than only recording the program name.  
This improves investigative visibility by allowing defenders to see exactly what commands were executed, which is critical for detecting malicious PowerShell usage, attacker tooling, and living-off-the-land techniques.

<img width="1891" height="565" alt="image" src="https://github.com/user-attachments/assets/42d82bf7-d6fc-4c8e-a6f3-52b756a05b4c" />

## What it’s about?
This STIG requires command-line logging to be enabled for process creation events.  
I implemented this configuration so Windows records the **exact command and arguments** used whenever a process starts.

By default, Windows may only log that applications such as `powershell.exe` or `cmd.exe` executed. After applying this configuration, logs also include the full command line, revealing what actions were actually performed.

This visibility is important because attackers frequently use legitimate Windows tools that appear harmless unless their command arguments are inspected.

## Why it’s a security risk if disabled?
During assessment, I identified that without command-line logging enabled, security monitoring would only show that a process started, not what it executed.

Example:

Without logging:
```

powershell.exe started

```

With logging enabled:
```

powershell.exe -enc SiLeNTyXA... (encoded malware payload)

````

Without command-line data, malicious activity can blend into normal system behaviour, making investigations and threat hunting significantly more difficult.

---

## Step 1 — Check current state

### 1) Verify Process Creation auditing is enabled (required prerequisite)

I first validated whether process auditing was enabled, since command-line logging depends on Security Event ID 4688 being generated.

```powershell
auditpol /get /subcategory:"Process Creation"
````

Expected:

```
Process Creation    Success and Failure
```

The system initially showed auditing was not enabled, meaning process execution events were not being fully logged.

<img width="685" height="146" alt="image" src="https://github.com/user-attachments/assets/a0b3e9b5-0c6c-4ecc-94c5-559ca7914c22" />

---

### 2) Verify the registry path exists

Next, I checked whether the required policy registry location was configured.

```powershell
$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
Test-Path $path
```

<img width="1067" height="76" alt="image" src="https://github.com/user-attachments/assets/20981d1e-15aa-4e82-87b5-0355e4c561c8" />

* `False` → system not configured
* `True` → proceed to validation

---

### 3) Check required policy value

I then verified whether command-line logging was already enforced.

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object ProcessCreationIncludeCmdLine_Enabled
```

<img width="1082" height="125" alt="image" src="https://github.com/user-attachments/assets/6b5cd9b2-e6dd-4f1b-8bc6-da8fc9b807aa" />

Expected:

```
ProcessCreationIncludeCmdLine_Enabled = 1
```

---

## Findings

During assessment, process creation auditing and command-line logging were not fully enabled.
This resulted in reduced visibility into executed commands and a **non-compliant STIG configuration**.

---

## Step 2 — Remediation

### 1) Enable Process Creation auditing

To generate the required security events, I enabled auditing for process creation:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

<img width="983" height="63" alt="image" src="https://github.com/user-attachments/assets/15cd3f58-64c6-4cdc-89f2-090c31776ba1" />

This ensures Windows produces Security Event ID 4688 whenever a process starts.

---

### 2) Enable command-line logging via PowerShell

I then enforced the STIG policy by configuring the registry value responsible for command-line capture.

```powershell
$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $path -Force | Out-Null

New-ItemProperty -Path $path `
-Name ProcessCreationIncludeCmdLine_Enabled `
-PropertyType DWord `
-Value 1 -Force | Out-Null

Get-ItemProperty -Path $path | Select-Object ProcessCreationIncludeCmdLine_Enabled
```

<img width="1002" height="277" alt="image" src="https://github.com/user-attachments/assets/8a5226fb-1c2e-4b24-8b41-843d94ae3cee" />

This configuration forces Windows to include full command-line arguments in process creation logs.

---

## Step 3 — Verification

### 1) Verify registry value

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' |
  Select-Object ProcessCreationIncludeCmdLine_Enabled
```

<img width="1068" height="153" alt="image" src="https://github.com/user-attachments/assets/b362d3a3-868e-45f2-a3be-d3eaa7a16ad4" />

Expected:

```
ProcessCreationIncludeCmdLine_Enabled = 1
```

---

### 2) Functional verification (event evidence)

To confirm operational effectiveness, I generated process activity and reviewed Security logs:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 5 |
  Select-Object TimeCreated, Id, Message
```

<img width="901" height="212" alt="image" src="https://github.com/user-attachments/assets/929d7285-d9a6-484b-8e28-b0a2ac5e6147" />

Event ID **4688** entries now include command-line details, confirming successful enforcement.

---

## Result

I successfully enabled command-line auditing for process creation events.
The system now records detailed execution telemetry, significantly improving detection capability, investigation accuracy, and incident response visibility.

This configuration allows analysts to identify malicious scripting, encoded commands, reconnaissance activity, and attacker tooling that would otherwise appear legitimate.

---

## STIG Status

* **STIG ID:** WN11-CC-000066
* **Status:** Compliant
* **Remediation Method:** PowerShell audit policy configuration and registry enforcement
* **Impact:** Improved defensive visibility through enhanced process execution logging

---

## MITRE ATT&CK Mapping

### Primary:

**T1059 – Command and Scripting Interpreter**
Command-line logging exposes malicious PowerShell, CMD, and scripting activity used by attackers.

### Secondary:

**T1082 – System Information Discovery**
Reconnaissance commands become visible in logs.

**T1016 – System Network Configuration Discovery**
Network discovery commands and arguments can be identified during investigations.
