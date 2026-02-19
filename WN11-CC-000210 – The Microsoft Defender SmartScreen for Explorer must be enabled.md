# 🛡️ WN11-CC-000210 – The Microsoft Defender SmartScreen for Explorer must be enabled

## Summary
In this task, I enabled Microsoft Defender SmartScreen for Explorer to ensure downloaded files and applications are checked for reputation and blocked when identified as unsafe, reducing the risk of users executing malicious content.

<img width="1837" height="796" alt="image" src="https://github.com/user-attachments/assets/c3d750c4-e8a9-4892-b485-e46029714034" />

## What it’s about?
This STIG requires **Microsoft Defender SmartScreen for Explorer** to be enabled so Windows evaluates files downloaded from the internet and warns or blocks execution if they appear suspicious or untrusted.

SmartScreen provides a reputation-based protection layer that helps prevent execution of commonly used malware delivery methods such as fake installers, malicious downloads, and social-engineering payloads.

## Why it’s a security risk if disabled?
If SmartScreen is disabled, users may execute unknown or malicious files without strong warnings or blocking controls.  
This increases exposure to malware execution, credential theft, and ransomware attacks delivered through phishing or malicious downloads.

---

## Step 1 — Check current state

### 1) Verify the policy registry path exists

I first verified whether the SmartScreen policy registry location was configured.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
Test-Path $path
````

<img width="857" height="62" alt="image" src="https://github.com/user-attachments/assets/378bb438-f61b-4e7b-bd1b-154dddaf1a6c" />

* `False` → policy not configured (non-compliant)
* `True` → proceed to value validation

---

### 2) Check SmartScreen configuration values

I then reviewed the policy values controlling SmartScreen enforcement.

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object EnableSmartScreen, ShellSmartScreenLevel
```

Required configuration:

* `EnableSmartScreen = 1` → SmartScreen enabled
* `ShellSmartScreenLevel = Block` → prevents users from bypassing warnings

---

## Findings

During assessment, the required policy values were either missing or not configured as required.
Because SmartScreen enforcement was not explicitly applied through policy, the system was treated as **non-compliant**.

---

## Step 2 — Remediation

### 1) Configure SmartScreen policy

I configured the required registry policy settings to enable SmartScreen and enforce blocking behaviour.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
New-Item -Path $path -Force | Out-Null

New-ItemProperty -Path $path -Name EnableSmartScreen     -PropertyType DWord  -Value 1       -Force | Out-Null
New-ItemProperty -Path $path -Name ShellSmartScreenLevel -PropertyType String -Value 'Block' -Force | Out-Null

Get-ItemProperty -Path $path | Select-Object EnableSmartScreen, ShellSmartScreenLevel
```

Why these settings:

* `EnableSmartScreen = 1` enables SmartScreen protection in Explorer
* `ShellSmartScreenLevel = Block` enforces the strongest protection level and prevents bypass

---

## Step 3 — Verification

### 1) Verify policy configuration

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' |
  Select-Object EnableSmartScreen, ShellSmartScreenLevel
```

Expected compliant configuration:

* `EnableSmartScreen = 1`
* `ShellSmartScreenLevel = Block`

<img width="1077" height="316" alt="image" src="https://github.com/user-attachments/assets/f1690e34-edf7-49cb-8b86-7d5e4952174c" />

---

## Result

Microsoft Defender SmartScreen for Explorer is now enforced through policy configuration and set to **Block**, preventing users from bypassing warnings when attempting to run suspicious downloads.

This reduces the likelihood of malicious file execution and strengthens protection against socially engineered malware delivery.

---

## STIG Status

* **STIG ID:** WN11-CC-000210
* **Status:** Compliant
* **Remediation Method:** Registry policy enforcement via PowerShell
* **Impact:** Reduced risk of executing malicious or untrusted downloaded applications

---

## MITRE ATT&CK Mapping

### Primary:

**T1204 – User Execution**
SmartScreen helps prevent users from executing malicious files delivered through deception or fake installers.

### Secondary:

**T1566 – Phishing**
Malicious downloads delivered through phishing campaigns may be blocked or strongly warned against.

**T1189 – Drive-by Compromise**
Downloaded payloads from compromised websites can be blocked based on reputation analysis.
