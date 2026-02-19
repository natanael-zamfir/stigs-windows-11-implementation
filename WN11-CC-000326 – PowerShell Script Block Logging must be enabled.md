# 🛡️ WN11-CC-000326 – PowerShell Script Block Logging must be enabled

## Summary
In this task, I enabled PowerShell Script Block Logging to ensure PowerShell script content executed on the system is recorded, improving visibility and investigation capability for command execution activity.

<img width="1797" height="553" alt="image" src="https://github.com/user-attachments/assets/bc475b59-afb0-44eb-bd7a-9137e76858f2" />

## What it’s about?
This STIG requires **PowerShell Script Block Logging** to be enabled so Windows records the actual PowerShell script content executed on the system.

PowerShell is widely used for legitimate administration but is also heavily abused during attacks. By enabling script block logging, I ensured that executed script content can be captured and reviewed during investigations.

## Why it’s a security risk if disabled?
If Script Block Logging is disabled, PowerShell activity may execute with limited visibility. Attackers can run commands, download payloads, or perform reconnaissance with reduced traceability, making detection and incident response significantly more difficult.

---

## Step 1 — Check current state

### 1) Verify policy registry path

I first checked whether the Script Block Logging policy location existed.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
Test-Path $path
````

If the key does not exist, the policy has not been configured and the system is treated as non-compliant.

---

### 2) Check Script Block Logging configuration

I then verified whether the required policy value was present.

```powershell
Get-ItemProperty -Path $path -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
```

Interpretation:

* No output → value not configured
* `EnableScriptBlockLogging = 1` → enabled and compliant

---

## Findings

During assessment, the policy key and/or required value was not configured.
Because Script Block Logging was not explicitly enforced, the system was considered **non-compliant**.

---

## Step 2 — Remediation

### 1) Create or enforce policy registry configuration

I configured the required policy registry path and enabled Script Block Logging.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $path -Force | Out-Null

New-ItemProperty -Path $path `
-Name EnableScriptBlockLogging `
-PropertyType DWord `
-Value 1 -Force | Out-Null
```

Why this setting:

* `EnableScriptBlockLogging = 1` forces Windows to log executed PowerShell script blocks, improving detection and forensic visibility.

---

## Step 3 — Verification

### 1) Verify policy value

```powershell
Get-ItemProperty -Path $path | Select-Object EnableScriptBlockLogging
```

<img width="1071" height="136" alt="image" src="https://github.com/user-attachments/assets/eb2650ca-f7c7-4ef9-b455-26fe589963b4" />

This confirms Script Block Logging is enabled.

---

### 2) Confirm policy path existence

```powershell
Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
```

<img width="1067" height="111" alt="image" src="https://github.com/user-attachments/assets/1723106e-ba96-45d8-bee0-fddda2710c39" />

---

## Result

<img width="1076" height="622" alt="image" src="https://github.com/user-attachments/assets/85d5f625-d153-4c9b-86b5-ba92fd65521d" />

PowerShell Script Block Logging is now enforced through policy configuration.
Executed PowerShell script content can be recorded, improving detection capability and enabling deeper investigation of PowerShell-based activity.

---

## STIG Status

* **STIG ID:** WN11-CC-000326
* **Status:** Compliant
* **Remediation Method:** Registry policy configuration via PowerShell
* **Impact:** Improved auditing and threat-hunting visibility for PowerShell execution

---

## MITRE ATT&CK Mapping

### Primary:

**T1059.001 – Command and Scripting Interpreter: PowerShell**
Script block logging provides visibility into executed PowerShell scripts.

### Secondary:

**T1082 — System Information Discovery**
Discovery commands executed through PowerShell become visible.

**T1016 — System Network Configuration Discovery**
Network enumeration activity can be captured through logged scripts.

**T1105 – Ingress Tool Transfer**
PowerShell download activity used to retrieve tools or payloads can be recorded.
