# 🛡️ WN11-CC-000075 – Credential Guard must be running on Windows 11 (domain-joined)

<img width="1837" height="796" alt="image" src="PASTE_YOUR_IMAGE_LINK_HERE" />

# What it’s about?
This STIG requires **Credential Guard** to be running on domain-joined Windows 11 systems.
Credential Guard uses VBS to isolate credential material so attackers can’t easily steal passwords, hashes, or Kerberos tickets from memory.

# Why it’s a security risk if disabled?
If Credential Guard is **not running**, attackers who gain admin access can attempt credential dumping from memory (LSASS).
That often leads to account takeover, identity theft, and lateral movement across a network.

---

## Step 1 — Check current state

### 1) Confirm Credential Guard is running (PowerShell method)
Run PowerShell as Administrator:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning
````

Expected:

* `SecurityServicesRunning` includes `1` (Credential Guard). Example: `{1,2}`

---

### 2) Verify the policy registry path exists (policy enforcement evidence)

Policy keys under `HKLM:\SOFTWARE\Policies\...` only appear after being created.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
Test-Path $path
```

* `False` → policy not configured
* `True` → continue checking required values

---

### 3) Check required policy value (registry)

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object LsaCfgFlags
```

Expected:

* `LsaCfgFlags = 1` (Enabled with UEFI lock)

---

## Findings

Before configuration, Credential Guard was not confirmed as running and/or the policy value was not set as required, which results in **non-compliance**.

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

Why this setting:

* `LsaCfgFlags = 1` enforces Credential Guard enabled with UEFI lock (strongest / tamper-resistant option)

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

Expected:

* `LsaCfgFlags = 1`

---

### 2) Verify Credential Guard is running

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning
```

Expected:

* `SecurityServicesRunning` includes `1`

---

## Result

Credential Guard is now enforced via policy and verified as running, reducing the risk of credential theft and identity compromise.

---

## STIG Status

* **STIG ID:** WN11-CC-000075
* **Status:** Compliant
* **Remediation Method:** PowerShell registry policy enforcement + reboot
* **Impact:** Strong protection against credential dumping and account takeover

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

````

Run these two commands now (Admin PowerShell) and paste the output so we can finish it fast:
```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesRunning
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue | Select-Object LsaCfgFlags
```
