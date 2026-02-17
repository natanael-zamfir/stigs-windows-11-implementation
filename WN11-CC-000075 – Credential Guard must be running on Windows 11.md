# 🛡️ WN11-CC-000075 – Credential Guard must be running on Windows 11 (domain-joined)

## Summary
Credential Guard keeps your Windows login secrets in a protected area so malware can’t easily steal them from memory (LSASS). LSASS is the Windows process that verifies logins and manages user credentials.

A domain-joined PC is connected to a company network, so stolen credentials are more valuable.

My PC isn’t domain-joined, so this STIG is **NA** for me even though I set the policy (learning purposes only).


<img width="1816" height="904" alt="Screenshot 2026-02-17 185015" src="https://github.com/user-attachments/assets/9ca43b09-d951-47f4-b630-34f851df97e6" />

# What it’s about?
This STIG requires **Credential Guard** to be running on domain-joined Windows 11 systems. Credential Guard uses VBS to isolate credential material so attackers can’t easily steal passwords, hashes, or Kerberos tickets from memory.

# Why it’s a security risk if disabled?
If Credential Guard is **not running**, attackers who gain admin access can attempt credential dumping from memory (LSASS). That often leads to account takeover, identity theft, and lateral movement across a network. 

---

## Step 1 — Check current state

### 1) Confirm Credential Guard is running (PowerShell method)
Run PowerShell as Administrator:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning
````

<img width="1048" height="134" alt="Screenshot 2026-02-17 185222" src="https://github.com/user-attachments/assets/4bb3bc39-3c11-4aba-a180-a1a2803f231c" />

Expected:

* `SecurityServicesRunning` includes `1` (Credential Guard). Example: `{1,2}`

Observed:

* `SecurityServicesRunning = {0}` (Credential Guard not running)

---

### 2) Verify the policy registry path exists (policy enforcement evidence)

Policy keys under `HKLM:\SOFTWARE\Policies\...` only appear after being created.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
Test-Path $path
```

<img width="852" height="60" alt="Screenshot 2026-02-17 185328" src="https://github.com/user-attachments/assets/86ccf27c-8906-4d8c-a3b9-9589132fbbb6" />

* `False` → policy not configured
* `True` → continue checking required values

---

### 3) Check required policy value (registry)

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object LsaCfgFlags
```

<img width="796" height="121" alt="Screenshot 2026-02-17 185358" src="https://github.com/user-attachments/assets/b573eb5e-b4e8-466a-8961-8173d6d7590c" />

Expected:

* `LsaCfgFlags = 1` (Enabled with UEFI lock)

---

## Findings

Credential Guard was **not running** (`SecurityServicesRunning = {0}`) and the policy value `LsaCfgFlags` was not present before configuration. This STIG applies to **domain-joined** Windows 11 systems; this device is not domain-joined, so the control is **Not Applicable (NA)** in this environment.

---

## Step 2 — Remediation

### 1) Configure Credential Guard policy via PowerShell (registry policy enforcement)

Note: Credential Guard depends on VBS/UEFI/Secure Boot and compatible hardware. A reboot is typically required.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
New-Item -Path $path -Force | Out-Null

# Enable Credential Guard with UEFI lock (STIG value)
New-ItemProperty -Path $path -Name LsaCfgFlags -PropertyType DWord -Value 1 -Force | Out-Null

Get-ItemProperty -Path $path | Select-Object LsaCfgFlags
```

<img width="1037" height="217" alt="Screenshot 2026-02-17 185505" src="https://github.com/user-attachments/assets/70dd4781-1a27-42b2-aee7-9e33b6cd5c30" />

Why this setting:

* `LsaCfgFlags = 1` enforces Credential Guard enabled with UEFI lock (tamper-resistant option)

---

### 2) Reboot required

Credential Guard generally requires a restart to start and report as running.

---

## Step 3 — Verification

### 1) Verify policy value is set

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' |
  Select-Object LsaCfgFlags
```

<img width="1014" height="139" alt="Screenshot 2026-02-17 185545" src="https://github.com/user-attachments/assets/cbcd5c5b-a98a-4f78-8aed-e32696c8b606" />

Expected:

* `LsaCfgFlags = 1`

---

### 2) Verify Credential Guard is running

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning
```

<img width="1052" height="135" alt="image" src="https://github.com/user-attachments/assets/a8ba7d9b-90fc-4d2d-8dc8-23f8cdb9b365" />

Expected:

* `SecurityServicesRunning` includes `1`

Observed:

* `SecurityServicesRunning = {0}`

---

## Result

Credential Guard policy was successfully configured (`LsaCfgFlags = 1`), however **Credential Guard is not running** on this device (`SecurityServicesRunning = {0}`), so the system does **not** meet the intended protection outcome.

This STIG is scoped to **domain-joined Windows 11 systems**. On this device, `DomainJoined: NO` and `AzureAdJoined: NO`, so the requirement is **Not Applicable (NA)** for this standalone system.

Practical impact: without Credential Guard running, an attacker who gains local admin/SYSTEM could have an easier time attempting **credential dumping from memory (LSASS)** compared to a properly supported and configured domain-joined Windows 11 enterprise build.

---

## STIG Status

* **STIG ID:** WN11-CC-000075
* **Status:** NA (Not Applicable) – Device is not domain-joined
* **Remediation Method:** Policy value set via PowerShell; Credential Guard not running on this device
* **Impact:** Credential Guard protection is not active on this device

---

## MITRE ATT&CK Mapping

### Primary:

**T1003 – OS Credential Dumping**
Credential Guard mitigates credential dumping by isolating credential material from the normal OS.

### Secondary:

**T1550 – Use Alternate Authentication Material**
Reducing theft of hashes/tickets makes pass-the-hash and related abuse harder.

**T1078 – Valid Accounts**
Protecting credentials helps prevent attackers from obtaining and using valid accounts.
