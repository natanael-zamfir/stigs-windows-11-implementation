# 🛡️ WN11-CC-000155 – Solicited Remote Assistance must not be allowed

## Summary
In this task, I disabled Solicited Remote Assistance to prevent users from inviting external parties to remotely control the system, reducing exposure to social engineering attacks and unauthorized remote access.

<img width="1792" height="523" alt="image" src="https://github.com/user-attachments/assets/17fae7e4-0c8c-4b1b-bf82-274715c2fb59" />

## What it’s about?
This STIG requires **Solicited Remote Assistance** to be disabled.  
Remote Assistance allows a user to invite another person to remotely connect and interact with their system.

While intended for support scenarios, this feature is frequently abused in social engineering scams where attackers impersonate IT support or trusted organizations to gain remote access.

## Why it’s a security risk?
Attackers may convince a user to request remote help and approve a connection.  
Once access is granted, the attacker can interact with the system as if physically present, allowing credential theft, malware installation, and further compromise.

---

## Step 1 — Check current state

### 1) Verify registry policy configuration

I reviewed the registry location responsible for Remote Assistance policy enforcement.

```

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services

```

The required registry value:

```

fAllowToGetHelp

````

Compliance interpretation:

* Value missing → Non-compliant (policy not enforced)
* `fAllowToGetHelp = 1` → Remote Assistance allowed (Non-compliant)
* `fAllowToGetHelp = 0` → Remote Assistance disabled (Compliant)

### Findings

During assessment, the required policy value was not configured, therefore the system was treated as **non-compliant**.

---

## Step 2 — Remediation

### 1) Enforce Remote Assistance restriction

I configured the required registry policy to disable Solicited Remote Assistance.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

New-Item -Path $path -Force | Out-Null

New-ItemProperty -Path $path `
-Name fAllowToGetHelp `
-PropertyType DWord `
-Value 0 -Force | Out-Null
````

Why this setting:

* `fAllowToGetHelp = 0` disables Solicited Remote Assistance and prevents users from granting remote control access.

### 2) Apply configuration

A system restart was performed to ensure policy enforcement was applied.

---

## Step 3 — Verification

### 1) Verify registry configuration

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' |
  Select-Object fAllowToGetHelp
```

Expected compliant configuration:

```
fAllowToGetHelp = 0
```
<img width="1045" height="130" alt="image" src="https://github.com/user-attachments/assets/76206d5f-2112-4ca7-8488-6a90a3606546" />

---

## Result

Solicited Remote Assistance is now disabled through policy configuration.
Users can no longer invite external parties to remotely control the system, reducing risk from social engineering attacks and unauthorized interactive access.

---

## STIG Status

* **STIG ID:** WN11-CC-000155
* **Status:** Compliant
* **Remediation Method:** Registry policy enforcement
* **Impact:** Reduced attack surface and prevention of unauthorized remote control access

---

## MITRE ATT&CK Mapping

### Primary:

**T1021 – Remote Services**
Attackers may abuse legitimate remote access services to gain system access.

### Secondary:

**T1566 – Phishing**
Social engineering may be used to convince users to allow remote access.

**T1078 – Valid Accounts**
Attackers operating through approved remote access appear as legitimate users.
