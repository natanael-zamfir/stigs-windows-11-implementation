# 🛡️WN11-CC-000155 – Solicited Remote Assistance must not be allowed

<img width="1792" height="523" alt="image" src="https://github.com/user-attachments/assets/17fae7e4-0c8c-4b1b-bf82-274715c2fb59" />

# What it’s about?
This STIG implementation disables Windows Remote Assistance when a user asks someone else (or is being forced) to connect remotely to their machine.
This is a very common social engineering scam: fake IT support, help desk or bank representative. Commonly used against the elderly or non-technical users.

# Why it’s a security risk?
An attacker convinces a user to request help. The User clicks **Allow**, as they are unaware of the attack.
Once the attacker has remote control they can steal credentials, install malware and move laterally within the network.

---

## Step 1 — Check current state

1. Press `Win + R`
2. Type `regedit` and press Enter
3. Navigate to the following registry path:
   ```
   HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
   ```
4. Inspect the registry value:

- Value does not exist → **Non-compliant**
- `fAllowToGetHelp = 1` → **Non-compliant**
- `fAllowToGetHelp = 0` → **Compliant**

### Findings
The system was found to be **non-compliant**, as the policy was not configured.

---

## Step 2 — Remediation

1. A new **DWORD (32-bit) Value** was created under the `Terminal Services` registry key.
2. The value was named according to STIG requirements:
   ```
   fAllowToGetHelp
   ```
3. The value was set to:
   ```
   0
   ```
   This disables Solicited Remote Assistance.
4. The system was restarted to ensure the policy was applied.

---

## Result

Solicited Remote Assistance is disabled at the system level.  
Users can no longer invite external parties to remotely control the machine, reducing exposure to social engineering attacks and unauthorized remote access.

---

## STIG Status

- **STIG ID:** WN11-CC-000155  
- **Status:** Compliant  
- **Remediation Method:** Registry policy enforcement  
- **Impact:** Reduced attack surface and prevention of unauthorized remote control

<img width="1172" height="705" alt="image" src="https://github.com/user-attachments/assets/6376f176-53a8-410b-9951-79861ab161d6" />

---

## MITRE ATT&CK Mapping

**T1021 – Remote Services**
What it is:
Attackers gain access to a system by using legitimate remote access services instead of exploiting software bugs.

**T1566 – Phishing**
What it is:
Attackers use social engineering to trick users into performing actions that grant access or execute malicious activity.

**T1078 – Valid Accounts**
What it is:
Attackers use legitimate credentials or approved access to operate as a trusted user.

This control mitigates social engineering based remote access by preventing users from granting interactive remote control to unauthorized parties.

