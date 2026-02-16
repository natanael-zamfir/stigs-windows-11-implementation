# 🛡️ WN11-CC-000210 – The Microsoft Defender SmartScreen for Explorer must be enabled

<img width="1837" height="796" alt="image" src="https://github.com/user-attachments/assets/c3d750c4-e8a9-4892-b485-e46029714034" />

# What it’s about?
This STIG enables **Microsoft Defender SmartScreen for Explorer**, which checks files and apps downloaded from the internet and warns or blocks them if they look suspicious or untrusted.
It helps stop users from running common “fake installer” malware (e.g., crypto wallet updates, cracked software, fake support tools).

# Why it’s a security risk if disabled?
If SmartScreen is **disabled**, users are more likely to run unknown or malicious files without strong warnings.
That increases the chance of malware execution, credential theft, and ransomware, especially from social engineering and scam download links.

---

## Step 1 — Check current state

### 1) Verify the policy registry path exists
Policy keys under `HKLM:\SOFTWARE\Policies\...` only appear after being created. If the key doesn’t exist, the setting is not configured.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
Test-Path $path
````

<img width="857" height="62" alt="image" src="https://github.com/user-attachments/assets/378bb438-f61b-4e7b-bd1b-154dddaf1a6c" />

* `False` → **Non-compliant** (policy not configured)
* `True` → continue checking required values

---

### 2) Check if SmartScreen is enabled and set to Block

This checks the exact policy values the STIG requires.

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Select-Object EnableSmartScreen, ShellSmartScreenLevel
```

Expected values:

* `EnableSmartScreen = 1` → SmartScreen enabled
* `ShellSmartScreenLevel = Block` → Warn and prevent bypass (blocks users from ignoring the warning)

---

## Findings

Before configuration, the required policy values were not present or not set as required, which results in **non-compliance**.

---

## Step 2 — Remediation

### 1) Configure SmartScreen policy via PowerShell

The following commands ensure the policy registry key exists and set the required values.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
New-Item -Path $path -Force | Out-Null

New-ItemProperty -Path $path -Name EnableSmartScreen     -PropertyType DWord  -Value 1       -Force | Out-Null
New-ItemProperty -Path $path -Name ShellSmartScreenLevel -PropertyType String -Value 'Block' -Force | Out-Null

Get-ItemProperty -Path $path | Select-Object EnableSmartScreen, ShellSmartScreenLevel
```

Why these settings:

* `EnableSmartScreen = 1` turns SmartScreen on for Explorer
* `ShellSmartScreenLevel = Block` enforces the strongest setting (warn and prevent bypass)

---

## Step 3 — Verification

### 1) Verify the policy values are set correctly

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' |
  Select-Object EnableSmartScreen, ShellSmartScreenLevel
```

Expected compliant output:

* `EnableSmartScreen` = `1`
* `ShellSmartScreenLevel` = `Block`

<img width="1077" height="316" alt="image" src="https://github.com/user-attachments/assets/f1690e34-edf7-49cb-8b86-7d5e4952174c" />

---

## Result

Microsoft Defender SmartScreen for Explorer is now enabled and configured to **Block**, preventing users from bypassing warnings.
This reduces the chance of executing malicious downloads and improves protection against scam installers.

**Note:**
SmartScreen helps stop people from running shady downloads, but attackers can still get in through stolen passwords, unpatched software, or built-in tools like PowerShell.
It should be combined with Defender protections, least privilege, patching, and good logging to a SIEM.

---

## STIG Status

* **STIG ID:** WN11-CC-000210
* **Status:** Compliant
* **Remediation Method:** PowerShell registry policy enforcement
* **Impact:** Reduced risk of malicious file execution from downloaded and untrusted applications

---

## MITRE ATT&CK Mapping

### Primary:

**T1204 – User Execution**
Attackers rely on a user running a malicious file (e.g., “wallet update.exe”). SmartScreen helps prevent execution of suspicious or untrusted downloads.

### Secondary:

**T1566 – Phishing**
Phishing often delivers links to malicious downloads. SmartScreen helps block or strongly warn before execution.

**T1189 – Drive-by Compromise**
If a user downloads and runs a payload from a malicious or compromised site, SmartScreen can help block that downloaded executable based on reputation.
