# 🛡️ WN11-CC-000038 – WDigest Authentication must be disabled

## Summary

This STIG makes sure Windows does not keep your password sitting in memory after you log in.
Older authentication methods like WDigest could store credentials in readable form, which attackers can steal if they gain high privileges on the machine.
By disabling it, even if an attacker compromises the system, they cannot easily recover real user passwords from memory.


<img width="1833" height="466" alt="image" src="https://github.com/user-attachments/assets/55e55285-1a96-466f-bfa3-a588dc4db376" />

# What it’s about?
This STIG disables **WDigest Authentication credential caching**.  
When WDigest is enabled, Windows may store user credentials in **plaintext inside LSASS memory**. LSASS is the Windows process that verifies logins and manages user credentials.
If an attacker gains administrative or SYSTEM access, those credentials can be extracted directly from memory.

# Why it’s a security risk if disabled (WDigest enabled)?
If WDigest is enabled, plaintext credentials may be exposed in memory.  
Attackers commonly dump LSASS to recover usernames and passwords, allowing identity theft, account takeover, and lateral movement across the environment.

---

## Step 1 — Check current state

### 1) Verify the registry path exists

Policy configuration is controlled through the registry location below.

```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'
Test-Path $path
````

<img width="1031" height="58" alt="image" src="https://github.com/user-attachments/assets/a3d3e0fc-aa85-4a10-b98a-abbdc07c9e28" />

* `False` → key missing (treat as **non-compliant** until confirmed)
* `True` → continue checking required value

---

### 2) Check required value (WDigest must be disabled)

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object UseLogonCredential
```

<img width="933" height="143" alt="image" src="https://github.com/user-attachments/assets/6cd9aaec-e8ff-4a65-823b-25c498dfb7f5" />

Expected value:

* `UseLogonCredential = 0`

---

## Findings

Before configuration, WDigest was not confirmed as disabled, resulting in **non-compliance** with the STIG requirement.

---

## Step 2 — Remediation

### 1) Disable WDigest via PowerShell

The following commands create the required registry key (if missing) and enforce the secure configuration.

```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'
New-Item -Path $path -Force | Out-Null

New-ItemProperty -Path $path -Name UseLogonCredential -PropertyType DWord -Value 0 -Force | Out-Null

Get-ItemProperty -Path $path | Select-Object UseLogonCredential
```

<img width="981" height="227" alt="image" src="https://github.com/user-attachments/assets/a223fcc6-ee15-4d87-95cf-bf38fa00a2bf" />

Why this setting:

* `UseLogonCredential = 0` prevents WDigest from storing plaintext credentials in LSASS memory.

---

## Step 3 — Verification

### 1) Verify the value is set correctly

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' |
  Select-Object UseLogonCredential
```

<img width="1047" height="152" alt="image" src="https://github.com/user-attachments/assets/f896fa41-4d0e-4ec8-b511-838905dbfa11" />

Expected compliant output:

* `UseLogonCredential = 0`

---

## Result

WDigest authentication is now disabled through registry policy enforcement.
This prevents plaintext credentials from being cached in memory and reduces the effectiveness of credential-dumping attacks targeting LSASS.

In real environments, attackers frequently attempt credential harvesting early after gaining privilege escalation. Disabling WDigest removes an easy method of obtaining reusable credentials and helps limit lateral movement.

---

## STIG Status

* **STIG ID:** WN11-CC-000038
* **Status:** Compliant
* **Remediation Method:** Registry configuration via PowerShell
* **Impact:** Reduced risk of plaintext credential exposure and credential dumping attacks

---

## MITRE ATT&CK Mapping

### Primary:

**T1003 – OS Credential Dumping**
Disabling WDigest prevents plaintext credentials from being available during LSASS memory dumping.

### Secondary:

**T1550 – Use Alternate Authentication Material**
Reducing available credential material makes pass-the-hash and credential reuse harder.

**T1078 – Valid Accounts**
Limiting credential theft reduces attacker ability to authenticate using legitimate accounts.
