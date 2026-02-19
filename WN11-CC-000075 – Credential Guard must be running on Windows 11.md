# 🛡️ WN11-CC-000075 – Credential Guard must be running on Windows 11 (domain-joined)

## Summary
In this task, I configured Credential Guard policy to protect Windows authentication secrets by isolating credentials from the normal operating system memory. Credential Guard protects LSASS, the Windows process responsible for verifying logins and managing user credentials.  
Because this device is not domain-joined, the STIG requirement is **Not Applicable (NA)** in this environment.

<img width="1816" height="904" alt="Screenshot 2026-02-17 185015" src="https://github.com/user-attachments/assets/9ca43b09-d951-47f4-b630-34f851df97e6" />

## What it’s about?
This STIG requires **Credential Guard** to be running on domain-joined Windows 11 systems. Credential Guard uses Virtualization-Based Security (VBS) to isolate credential material so attackers cannot easily extract passwords, hashes, or Kerberos tickets from memory.

## Why it’s a security risk if disabled?
If Credential Guard is not running, attackers who gain administrative privileges may attempt credential dumping from LSASS memory.  
This can lead to account compromise, privilege escalation, and lateral movement across enterprise environments.

---

## Step 1 — Check current state

### 1) Verify Credential Guard runtime status

I checked whether Credential Guard security services were running.

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning
````

<img width="1048" height="134" alt="Screenshot 2026-02-17 185222" src="https://github.com/user-attachments/assets/4bb3bc39-3c11-4aba-a180-a1a2803f231c" />

Expected:

* `SecurityServicesRunning` includes `1` (Credential Guard active)

Observed:

* Credential Guard was not running.

---

### 2) Verify policy registry path

I confirmed whether the Device Guard policy registry location existed.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
Test-Path $path
```

<img width="852" height="60" alt="Screenshot 2026-02-17 185328" src="https://github.com/user-attachments/assets/86ccf27c-8906-4d8c-a3b9-9589132fbbb6" />

* `False` → policy not configured
* `True` → proceed to value validation

---

### 3) Verify Credential Guard policy value

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object LsaCfgFlags
```

<img width="796" height="121" alt="Screenshot 2026-02-17 185358" src="https://github.com/user-attachments/assets/b573eb5e-b4e8-466a-8961-8173d6d7590c" />

Expected configuration:

* `LsaCfgFlags = 1` (Credential Guard enabled with UEFI lock)

---

## Findings

Credential Guard was not running during assessment, and the required policy value was not previously configured.
This STIG applies specifically to **domain-joined Windows 11 systems**. Because this device is not domain-joined, the control is considered **Not Applicable (NA)** in this environment.

---

## Step 2 — Remediation

### 1) Configure Credential Guard policy

I configured the required registry policy to enable Credential Guard.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
New-Item -Path $path -Force | Out-Null

New-ItemProperty -Path $path `
-Name LsaCfgFlags `
-PropertyType DWord `
-Value 1 -Force | Out-Null

Get-ItemProperty -Path $path | Select-Object LsaCfgFlags
```

<img width="1037" height="217" alt="Screenshot 2026-02-17 185505" src="https://github.com/user-attachments/assets/70dd4781-1a27-42b2-aee7-9e33b6cd5c30" />

Why this setting:

* `LsaCfgFlags = 1` enables Credential Guard with UEFI lock, providing tamper-resistant protection.

---

### 2) Apply configuration

A system reboot was performed because Credential Guard requires restart and compatible hardware/VBS support before becoming active.

---

## Step 3 — Verification

### 1) Verify policy value

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' |
  Select-Object LsaCfgFlags
```

<img width="1014" height="139" alt="Screenshot 2026-02-17 185545" src="https://github.com/user-attachments/assets/cbcd5c5b-a98a-4f78-8aed-e32696c8b606" />

Expected:

* `LsaCfgFlags = 1`

---

### 2) Verify Credential Guard runtime status

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning
```

<img width="1052" height="135" alt="image" src="https://github.com/user-attachments/assets/a8ba7d9b-90fc-4d2d-8dc8-23f8cdb9b365" />

Expected:

* `SecurityServicesRunning` includes `1`

Observed:

* Credential Guard was not running on this standalone system.

---

## Result

Credential Guard policy was successfully configured; however, Credential Guard is not running on this device.
Because the system is not domain-joined, the STIG requirement is **Not Applicable (NA)** for this environment.

Without Credential Guard actively running, credential material is not isolated by VBS, meaning credential dumping protections associated with enterprise deployments are not present.

---

## STIG Status

* **STIG ID:** WN11-CC-000075
* **Status:** NA (Not Applicable) – Device is not domain-joined
* **Remediation Method:** Registry policy configured via PowerShell
* **Impact:** Credential Guard protection not active on this standalone device

---

## MITRE ATT&CK Mapping

### Primary:

**T1003 – OS Credential Dumping**
Credential Guard mitigates credential dumping by isolating authentication secrets.

### Secondary:

**T1550 – Use Alternate Authentication Material**
Reducing access to hashes and tickets limits credential reuse attacks.

**T1078 – Valid Accounts**
Protecting credentials reduces attacker ability to authenticate using legitimate accounts.
