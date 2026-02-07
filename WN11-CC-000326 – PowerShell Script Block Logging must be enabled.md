# 🛡️ WN11-CC-000326 – PowerShell Script Block Logging must be enabled
<img width="1797" height="553" alt="image" src="https://github.com/user-attachments/assets/bc475b59-afb0-44eb-bd7a-9137e76858f2" />

# What it’s about?
This STIG turns on **PowerShell Script Block Logging**, which records PowerShell script content that runs on the system.
So if a script (good or malicious) executes, Windows can log the **actual script text** to help defenders investigate what happened.

# Why it’s a security risk if disabled?
PowerShell is commonly abused in cyber attacks because it’s built into Windows and very powerful.
If Script Block Logging is **off**, attackers can run PowerShell commands with **much less traceability**, making detection and incident response harder.

---

## Step 1 — Check current state

### 1) Verify Path

As I couldn't find the key within this path visibly, I verified if it exists using PowerShell.
The policy registry key didn’t exist yet because it hadn’t been configured. Policy keys under HKLM:\SOFTWARE\Policies\... only appear after being created.

```powershell
PS C:\WINDOWS\system32> $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
>> Test-Path $path
>>
False
```
In this case, the device is → **Non-compliant** as the key doesn't exist. 

---

### 2) Check if the policy is enabled directly through PowerShell

```powershell
Get-ItemProperty -Path $path -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
```
Because it is a policy, we want to check if it's true or false. 1 = enabled, 0 = not enabled.
If the command gives no output, the key value is missing (which I expect since I manually tried to find the key).

* No output → value missing (not configured)
* `EnableScriptBlockLogging : 1` → enabled (compliant)

## Findings

The policy key doesn't exist, which indicates the setting was **not configured** and therefore it is not compliant.

---

## Step 2 — Remediation

### 1) Create the missing registry key

```powershell
PS C:\WINDOWS\system32> $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
>> New-Item -Path $path -Force | Out-Null
```

Since the key didn’t exist, I created it.

* `-Force` guarantees the creation/override 
* `Out-Null` hides “created successfully” output

---

### 2) Create/overwrite the required DWORD value

```powershell
New-ItemProperty -Path $path -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null
```

* Here the `EnableScriptBlockLogging` policy switch is set to 1
* `DWord` the key type
* `Value 1` = **Enabled**
* `-Force` overwrites wrong values if present

---

## Step 3 — Verification

### 1) Verifying the path to policy and the item property

```powershell
Get-ItemProperty -Path $path | Select-Object EnableScriptBlockLogging
```
The policy has been successfully enabled, making the device compliant.

<img width="1071" height="136" alt="image" src="https://github.com/user-attachments/assets/eb2650ca-f7c7-4ef9-b455-26fe589963b4" />

---

### 2) Confirm the policy and key exist

```powershell
Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
```

<img width="1067" height="111" alt="image" src="https://github.com/user-attachments/assets/1723106e-ba96-45d8-bee0-fddda2710c39" />


---

## Result
<img width="1076" height="622" alt="image" src="https://github.com/user-attachments/assets/85d5f625-d153-4c9b-86b5-ba92fd65521d" />

PowerShell Script Block Logging is now enabled and compliant.
This improves detection and investigation of PowerShell-based attacks by recording script content.

---

## STIG Status

* **STIG ID:** WN11-CC-000326
* **Status:** Compliant
* **Remediation Method:** PowerShell registry policy enforcement
* **Impact:** Better auditing and threat-hunting visibility for PowerShell activity

---

## MITRE ATT&CK Mapping

### Primary:
**T1059.001 – Command and Scripting Interpreter: PowerShell**
Attackers use PowerShell to run commands, recon, persistence, and payload execution.

### Secondary:
**T1082 — System Information Discovery**
System information discovery about the device.

**T1016 — System Network Configuration Discovery**
System network conf. discovery about the device's network info.

**T1105 – Ingress Tool Transfer**
Attackers use PowerShell to download additional tools/payloads from the network or internet.

This control helps defenders detect and investigate malicious PowerShell activity by logging what was executed.

