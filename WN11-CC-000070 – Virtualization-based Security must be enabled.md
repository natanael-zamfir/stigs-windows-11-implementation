# 🛡️ WN11-CC-000070 – Virtualization-based Security must be enabled (Secure Boot with DMA Protection)

## Summary
In this task, I enabled Virtualization-based Security (VBS) to isolate sensitive security processes using hardware virtualization, strengthening protection against credential theft and kernel-level attacks.

<img width="1812" height="851" alt="image" src="https://github.com/user-attachments/assets/49174bc0-4f21-49a5-8ef8-edbe0378fb44" />

## What it’s about?
This STIG requires **Virtualization-based Security (VBS)** to be enabled with platform security configured to **Secure Boot** or **Secure Boot with Direct Memory Access (DMA) Protection**.

VBS uses the Windows hypervisor to isolate critical security components from the normal operating system environment.  
It provides the security foundation for protections such as **Credential Guard** and **Hypervisor-Enforced Code Integrity (HVCI / Memory Integrity)**.

## Why it’s a security risk if disabled?
If VBS is disabled, sensitive security components run within the normal OS memory space, making them more accessible to attackers.

Without this isolation layer, credential theft, kernel tampering, and advanced privilege escalation attacks become easier to perform.

---

## Step 1 — Check current state

### 1) Verify VBS runtime status

I checked whether Virtualization-based Security was running and whether required platform protections were present.

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, RequiredSecurityProperties
````

<img width="1076" height="142" alt="image" src="https://github.com/user-attachments/assets/f11a7d1c-16fc-42a3-b0c8-9fb12fe0cfb1" />

Expected:

* `VirtualizationBasedSecurityStatus = 2` (Running)
* `RequiredSecurityProperties` includes:

  * `2` → Secure Boot
  * optionally `3` → DMA Protection

---

### 2) Verify policy registry configuration

I confirmed whether Device Guard policy settings were configured.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
Test-Path $path

Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures
```

<img width="877" height="118" alt="image" src="https://github.com/user-attachments/assets/4db8f110-fd07-414f-82e0-afa812477618" />

Required configuration:

* `EnableVirtualizationBasedSecurity = 1`
* `RequirePlatformSecurityFeatures = 1` (Secure Boot) or `3` (Secure Boot + DMA Protection)

---

### 3) Verify Secure Boot status

```powershell
Confirm-SecureBootUEFI
```

<img width="1048" height="63" alt="image" src="https://github.com/user-attachments/assets/fd62ed78-468b-405a-9004-fd95cf3730e7" />

Expected:

* `True` → Secure Boot enabled

---

### 4) Verify hypervisor presence

Because VBS depends on the Windows hypervisor, I confirmed whether it was active.

```powershell
(Get-CimInstance Win32_ComputerSystem).HypervisorPresent
```

<img width="882" height="60" alt="image" src="https://github.com/user-attachments/assets/69a93eb5-7c58-4cc1-a4b3-d6df6ccc8e20" />

Expected:

* `True` when the hypervisor is running.

---

## Findings

During assessment, required Device Guard policy values were not configured and VBS was not running, resulting in **non-compliance**.

---

## Step 2 — Remediation

### 1) Configure VBS policy

I configured registry policy settings to enable Virtualization-based Security and enforce platform security requirements.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
New-Item -Path $path -Force | Out-Null

New-ItemProperty -Path $path `
-Name EnableVirtualizationBasedSecurity `
-PropertyType DWord `
-Value 1 -Force | Out-Null

# Platform security level:
# 1 = Secure Boot
# 3 = Secure Boot + DMA Protection
New-ItemProperty -Path $path `
-Name RequirePlatformSecurityFeatures `
-PropertyType DWord `
-Value 3 -Force | Out-Null

Get-ItemProperty -Path $path |
  Select-Object EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures
```

<img width="1077" height="273" alt="image" src="https://github.com/user-attachments/assets/f5a22fb9-fadb-483a-90c7-8110495b7838" />

Why these settings:

* `EnableVirtualizationBasedSecurity = 1` enables VBS enforcement
* `RequirePlatformSecurityFeatures = 3` enforces Secure Boot with DMA Protection (strongest supported configuration)

---

### 2) Apply configuration

A system reboot was performed because VBS requires restart before reporting as active.

---

## Step 3 — Verification

### 1) Verify policy configuration

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' |
  Select-Object EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures
```

<img width="1072" height="127" alt="image" src="https://github.com/user-attachments/assets/d3e18c9d-7305-4888-b840-3d923805c5af" />

Expected:

* `EnableVirtualizationBasedSecurity = 1`
* `RequirePlatformSecurityFeatures = 1` or `3`

---

### 2) Verify VBS runtime status

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, RequiredSecurityProperties
```

<img width="880" height="183" alt="image" src="https://github.com/user-attachments/assets/631cab3c-15b7-45e2-81ce-7c4cc27739b2" />

Expected:

* `VirtualizationBasedSecurityStatus = 2` (Running)
* `RequiredSecurityProperties` includes Secure Boot (and optionally DMA Protection)

---

## Result

Virtualization-based Security is now enforced through policy configuration and verified as running with the required platform security protections enabled.

This establishes hardware-backed memory isolation and strengthens protection against credential theft and kernel-level attacks.

---

## STIG Status

* **STIG ID:** WN11-CC-000070
* **Status:** Compliant
* **Remediation Method:** Registry policy enforcement via PowerShell + reboot
* **Impact:** Stronger memory isolation and security foundation for Credential Guard and HVCI

---

## MITRE ATT&CK Mapping

### Primary:

**T1003 – OS Credential Dumping**
VBS supports protections that reduce effectiveness of credential dumping attacks.

### Secondary:

**T1055 – Process Injection**
Isolated security services help reduce certain memory tampering and injection techniques.
