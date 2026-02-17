# 🛡️ WN11-CC-000070 – Virtualization-based Security must be enabled - Secure Boot with Direct Memory Access (DMA) Protection
Virtualization-based Security must be enabled on Windows 11 with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.

<img width="1812" height="851" alt="image" src="https://github.com/user-attachments/assets/49174bc0-4f21-49a5-8ef8-edbe0378fb44" />

# What it’s about?
This STIG enables **Virtualization-based Security (VBS)**, which uses hardware virtualization to isolate sensitive security processes from the normal Windows environment.
VBS is the platform that supports protections like **Credential Guard** and **Hypervisor-Enforced Code Integrity (HVCI / Memory Integrity)**.

# Why it’s a security risk if disabled?
If VBS is **disabled**, Windows loses a major layer of memory isolation.
That makes credential theft and kernel-level attacks easier, which can lead to account takeover, identity theft, and deeper compromise.

---

## Step 1 — Check current state

### 1) Check VBS is running
Run PowerShell as Administrator:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, RequiredSecurityProperties
````

<img width="1076" height="142" alt="image" src="https://github.com/user-attachments/assets/f11a7d1c-16fc-42a3-b0c8-9fb12fe0cfb1" />

Expected values:

* `RequiredSecurityProperties` includes `2` (Secure Boot). Example: `{1,2}`
* If configured for DMA Protection, it will also include `3`. Example: `{1,2,3}`
* `VirtualizationBasedSecurityStatus` must be `2` (Running)

---

### 2) Verify the policy registry path exists

Policy keys under `HKLM:\SOFTWARE\Policies\...` only appear after being created. If the key doesn’t exist, the setting is not configured.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
Test-Path $path

Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures
```

<img width="877" height="118" alt="image" src="https://github.com/user-attachments/assets/4db8f110-fd07-414f-82e0-afa812477618" />

* `False` → policy not configured
* `True` → continue checking required values

Expected values:

* `EnableVirtualizationBasedSecurity = 1`
* `RequirePlatformSecurityFeatures = 1` (Secure Boot) or `3` (Secure Boot + DMA Protection)

---

### 3) Check if Secure Boot is enabled in Windows

```powershell
Confirm-SecureBootUEFI
```

<img width="1048" height="63" alt="image" src="https://github.com/user-attachments/assets/fd62ed78-468b-405a-9004-fd95cf3730e7" />

Expected:

* `True` = Secure Boot on
* `False` = Secure Boot off (won’t meet Secure Boot requirement)

---

### 4) Check if the Windows hypervisor is running

This is useful because VBS typically requires the hypervisor to start.

```powershell
(Get-CimInstance Win32_ComputerSystem).HypervisorPresent
```

<img width="882" height="60" alt="image" src="https://github.com/user-attachments/assets/69a93eb5-7c58-4cc1-a4b3-d6df6ccc8e20" />

Expected:

* `True` when the hypervisor is running.
- On my system, HypervisorPresent was False, so I enabled the hypervisor and rebooted.

---

## Findings

Before configuration, the Device Guard policy key and required values were not present, and VBS was not running, which resulted in **non-compliance**.

---

## Step 2 — Remediation

### 1) Configure VBS policy via PowerShell (registry policy enforcement)

These commands ensure the policy key exists and enforce the required values.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
New-Item -Path $path -Force | Out-Null

# Enable VBS
New-ItemProperty -Path $path -Name EnableVirtualizationBasedSecurity -PropertyType DWord -Value 1 -Force | Out-Null

# Platform security level:
# 1 = Secure Boot only
# 3 = Secure Boot + DMA Protection
New-ItemProperty -Path $path -Name RequirePlatformSecurityFeatures -PropertyType DWord -Value 3 -Force | Out-Null

Get-ItemProperty -Path $path | Select-Object EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures
```

<img width="1077" height="273" alt="image" src="https://github.com/user-attachments/assets/f5a22fb9-fadb-483a-90c7-8110495b7838" />

Why these settings:

* `EnableVirtualizationBasedSecurity = 1` turns on VBS policy
* `RequirePlatformSecurityFeatures = 3` enforces Secure Boot + DMA Protection (stronger). Use `1` if DMA Protection is not available.

---

### 2) Reboot required

VBS typically requires a restart to fully enable and report as “Running”.

---

## Step 3 — Verification

### 1) Verify the policy values are set

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' |
  Select-Object EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures
```

<img width="1072" height="127" alt="image" src="https://github.com/user-attachments/assets/d3e18c9d-7305-4888-b840-3d923805c5af" />

Expected:

* `EnableVirtualizationBasedSecurity = 1`
* `RequirePlatformSecurityFeatures = 1` or `3`

---

### 2) Verify VBS is running

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, RequiredSecurityProperties
```

<img width="880" height="183" alt="image" src="https://github.com/user-attachments/assets/631cab3c-15b7-45e2-81ce-7c4cc27739b2" />

Expected:

* `VirtualizationBasedSecurityStatus = 2` (Running)
* `RequiredSecurityProperties` includes `2` (Secure Boot)

---

## Result

VBS is now enforced via policy and verified as running with the required platform security properties (Secure Boot, optionally DMA Protection).

---

## STIG Status

* **STIG ID:** WN11-CC-000070
* **Status:** Compliant
* **Remediation Method:** PowerShell registry policy enforcement + reboot
* **Impact:** Stronger memory isolation and a foundation for Credential Guard and HVCI

---

## MITRE ATT&CK Mapping

### Primary:

**T1003 – OS Credential Dumping**
VBS supports protections (especially when paired with Credential Guard) that reduce the effectiveness of credential dumping from memory.

### Secondary:

**T1055 – Process Injection**
Memory isolation and protected security services help reduce certain injection and tampering outcomes.
