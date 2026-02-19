# 🛡️ WN11-SO-000205 – LanMan authentication level must be NTLMv2 only (Refuse LM/NTLM)

<img width="1826" height="507" alt="image" src="https://github.com/user-attachments/assets/b11146fc-e38d-4f08-8bd0-716168f0437f" />

## Summary

In this task, I enforced modern authentication standards by configuring Windows to accept **NTLMv2 authentication only** while refusing older LM and NTLM protocols.
This reduces the risk of credential cracking and authentication downgrade attacks by preventing the system from using legacy authentication methods that are considered insecure.

### RDP Example

When you use **RDP**, the remote computer still needs to verify who you are before allowing access.

* You connect to another PC using RDP.
* You enter your **username and password**.
* The remote machine verifies your identity using a Windows authentication method.

Windows attempts to use the strongest available authentication method first.  
If that cannot be used (which can happen when connecting by IP address, across networks, or to older systems), Windows may fall back to **NTLM authentication**.  
NTLMv2 is primarily used as a fallback authentication method when stronger mechanisms cannot be negotiated (Keberos).

Without this STIG:

```
RDP login → fallback → weak NTLM/LM → easier for attackers to crack
```

With this STIG:

```
RDP login → fallback allowed ONLY to NTLMv2 (stronger authentication)
```

This ensures that even when fallback authentication occurs, Windows refuses weaker legacy methods and uses a more secure protocol.


# What it’s about?
This STIG requires the LAN Manager authentication level to be configured so the system **only sends NTLMv2 responses** and refuses older authentication mechanisms.

LM and early NTLM protocols use weak cryptographic protections and are vulnerable to password cracking and replay attacks.  
By enforcing NTLMv2-only authentication, the system ensures stronger credential protection during authentication processes.

# Why it’s a security risk if disabled?
If LM or NTLM authentication is allowed, attackers can target weaker authentication exchanges that are significantly easier to crack offline.

Legacy authentication increases risk because attackers may:
- capture authentication hashes
- perform brute-force or dictionary attacks
- downgrade authentication to weaker protocols
- reuse compromised credentials for lateral movement

---

## Step 1 — Check current state

### 1) Verify the registry path exists

I first confirmed that the Local Security Authority (LSA) configuration path was present.

```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Test-Path $path
````
<img width="995" height="67" alt="image" src="https://github.com/user-attachments/assets/4f4659fe-300e-488a-a001-d42074745f45" />

* `False` → Non-compliant (unexpected; LSA configuration should exist)
* `True` → proceed to value validation

---

### 2) Check required authentication level

I then verified the currently configured LAN Manager authentication level.

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object LmCompatibilityLevel
```
<img width="1072" height="120" alt="image" src="https://github.com/user-attachments/assets/33061927-ba72-4f9e-97da-e7cc25fdea3b" />

Expected:

```
LmCompatibilityLevel = 5
```

Meaning:

```
Send NTLMv2 response only. Refuse LM & NTLM authentication methods.
```

The value was not configured, therefore the system was considered non-compliant.

---

## Findings

During assessment, the required authentication level was either not configured or not set to the required value.
Because NTLMv2-only enforcement was not explicitly applied, the system was treated as **non-compliant** with STIG requirements.

---

## Step 2 — Remediation

### 1) Enforce NTLMv2-only authentication

I configured the system to refuse legacy authentication protocols and enforce NTLMv2 responses.

```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

New-ItemProperty -Path $path `
-Name LmCompatibilityLevel `
-PropertyType DWord `
-Value 5 -Force | Out-Null

Get-ItemProperty -Path $path | Select-Object LmCompatibilityLevel
```
<img width="731" height="277" alt="image" src="https://github.com/user-attachments/assets/b07cd91d-b4e4-424f-bd2e-c084d41eb7c5" />

Why this setting:

* `LmCompatibilityLevel = 5` enforces:

  * NTLMv2 authentication only
  * Refusal of LM and NTLM authentication attempts

This prevents authentication downgrade attacks and removes support for weak legacy protocols.

---

## Step 3 — Verification

### 1) Verify configuration value

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
  Select-Object LmCompatibilityLevel
```
<img width="917" height="142" alt="image" src="https://github.com/user-attachments/assets/c2b139b9-49fe-4f64-b693-85c561d10668" />

Expected:

```
LmCompatibilityLevel = 5
```

This confirms NTLMv2-only authentication enforcement.

---

## Result

The system is now configured to require NTLMv2 authentication and refuse LM and NTLM protocols.
This strengthens authentication security by preventing weak credential exchanges and reducing exposure to password cracking and replay attacks.

Enforcing modern authentication standards limits attacker ability to obtain usable credential material and improves overall defensive posture.

---

## STIG Status

* **STIG ID:** WN11-SO-000205
* **Status:** Compliant
* **Remediation Method:** Registry configuration via PowerShell
* **Impact:** Stronger authentication security and reduced credential theft risk

---

## MITRE ATT&CK Mapping

### Primary:

**T1110 – Brute Force**
Removing weaker LM/NTLM authentication reduces opportunities for password cracking attacks.

### Secondary:

**T1550 – Use Alternate Authentication Material**
Stronger authentication requirements reduce credential reuse and downgrade opportunities.

**T1078 – Valid Accounts**
Hardening authentication makes it more difficult for attackers to obtain usable credentials for legitimate account access.
