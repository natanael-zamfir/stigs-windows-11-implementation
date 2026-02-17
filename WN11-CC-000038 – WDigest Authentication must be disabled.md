# 🛡️ WN11-CC-000038 – WDigest Authentication must be disabled

## Summary

In this task, I ensured Windows does not retain user passwords in memory after authentication.  
Legacy authentication mechanisms such as WDigest can store credentials in readable form, which attackers may extract if they gain elevated privileges.  

By disabling WDigest, the system no longer exposes plaintext credentials in memory, reducing the risk of password theft even if the host becomes compromised.

<img width="1833" height="466" alt="image" src="https://github.com/user-attachments/assets/55e55285-1a96-466f-bfa3-a588dc4db376" />

# What it’s about?
This STIG requires disabling **WDigest authentication credential caching**.

When WDigest is enabled, Windows may store user credentials in **plaintext within LSASS memory**.  
LSASS (Local Security Authority Subsystem Service) is the Windows process responsible for verifying logins and managing authentication credentials.

If an attacker gains administrative or SYSTEM-level access, they can target LSASS memory to extract usernames and passwords directly.

# Why it’s a security risk if disabled (WDigest enabled)?
If WDigest remains enabled, plaintext credentials may be exposed in memory.  
Attackers frequently dump LSASS during post-exploitation to recover credentials, enabling identity theft, account takeover, and lateral movement across systems.

---

## Step 1 — Check current state

### 1) Verify the registry path exists

I first validated whether the policy registry location responsible for WDigest configuration was present.

```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'
Test-Path $path
````

<img width="1031" height="58" alt="image" src="https://github.com/user-attachments/assets/a3d3e0fc-aa85-4a10-b98a-abbdc07c9e28" />

* `False` → treated as **non-compliant** until configuration is confirmed
* `True` → proceed to value validation

---

### 2) Check required value (WDigest must be disabled)

I then verified whether credential caching was already disabled.

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object UseLogonCredential
```

<img width="933" height="143" alt="image" src="https://github.com/user-attachments/assets/6cd9aaec-e8ff-4a65-823b-25c498dfb7f5" />

Expected value:

* `UseLogonCredential = 0`

---

## Findings

During assessment, the UseLogonCredential registry value was not present.  
Because the setting was not explicitly enforced by policy, the system was treated as non-compliant under STIG requirements.

---

## Step 2 — Remediation

### 1) Disable WDigest via PowerShell

I enforced the secure configuration by creating the registry key (if required) and explicitly disabling credential caching.

```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'
New-Item -Path $path -Force | Out-Null

New-ItemProperty -Path $path -Name UseLogonCredential -PropertyType DWord -Value 0 -Force | Out-Null

Get-ItemProperty -Path $path | Select-Object UseLogonCredential
```

<img width="981" height="227" alt="image" src="https://github.com/user-attachments/assets/a223fcc6-ee15-4d87-95cf-bf38fa00a2bf" />

Why this setting:

* `UseLogonCredential = 0` prevents Windows from storing plaintext credentials inside LSASS memory.

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

WDigest authentication was successfully disabled through registry policy enforcement.
The system no longer caches plaintext credentials in memory, reducing exposure to credential-dumping attacks targeting LSASS.

Since attackers commonly attempt credential harvesting shortly after privilege escalation, removing this capability helps limit credential reuse and lateral movement opportunities.

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
Disabling WDigest prevents plaintext credentials from being available during LSASS memory extraction.

### Secondary:

**T1550 – Use Alternate Authentication Material**
Reducing available credential material limits pass-the-hash and credential reuse techniques.

**T1078 – Valid Accounts**
Limiting credential theft reduces attacker ability to authenticate using legitimate accounts.
