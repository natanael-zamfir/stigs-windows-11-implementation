# 🛡️ WN11-AU-000030 – Audit Security Group Management must be enabled (Success)

## Summary
In this task, I enabled auditing for Security Group Management events to ensure changes to security groups and group membership are recorded. This provides visibility and accountability when permissions or privileged access are modified.

---

## What it’s about?
This STIG requires Windows to audit the **Security Group Management** subcategory within the **Account Management** audit policy.

Security Group Management auditing records successful events such as:

- creating or deleting security groups
- modifying security group properties or membership
- adding or removing users from groups

Because group membership directly controls permissions and privilege levels, these events are critical for tracking access changes on a system.

---

## Why it’s a security risk if disabled?
If Security Group Management auditing is disabled, permission or privilege changes can occur without an audit trail.

Attackers commonly modify group memberships after gaining access in order to:

- escalate privileges
- maintain persistence
- grant hidden administrative access

Without logging enabled, investigators cannot reliably determine when access rights were changed or which account performed the action.

---

## Step 1 — Check current state

### 1) Verify Security Group Management auditing

I verified the audit subcategory configuration using AuditPol:

```powershell
AuditPol /get /subcategory:"Security Group Management"
````

<img width="828" height="120" alt="image" src="https://github.com/user-attachments/assets/12f09b1f-8411-44c3-b1b1-8148feef17f5" />

Required configuration:

```
Security Group Management    Success
```

Interpretation:

* Success enabled → Compliant
* No Auditing → Non-compliant

---

## Findings

Security Group Management auditing was already configured to record successful events, meeting the STIG requirement.

---

## Step 2 — Remediation

### 1) Enforce Security Group Management auditing (if required)

If the system were non-compliant, the following command would enforce the required configuration:

```powershell
AuditPol /set /subcategory:"Security Group Management" /success:enable
```
<img width="957" height="56" alt="image" src="https://github.com/user-attachments/assets/afbf0e25-2824-47c6-b2e6-a784e5abf19a" />

Why this setting:

* Records when security groups are created, modified, or deleted
* Logs group membership changes that may indicate privilege escalation or unauthorized access modification

---

## Step 3 — Verification

### 1) Confirm audit policy configuration

```powershell
AuditPol /get /subcategory:"Security Group Management"
```
<img width="853" height="121" alt="image" src="https://github.com/user-attachments/assets/c735d26d-7739-47f7-b265-653757ee407f" />

Expected compliant output:

```
Security Group Management    Success
```

This confirms successful auditing of group management activity is enabled.

---

## Result

Security Group Management auditing is enabled and functioning as required.
The system records successful changes to security groups and membership, improving accountability and enabling investigators to track privilege modifications and access control changes.

---

## STIG Status

* **STIG ID:** WN11-AU-000030
* **Status:** Compliant
* **Remediation Method:** Advanced Audit Policy configuration via AuditPol
* **Impact:** Improved visibility into privilege and permission changes

---

## MITRE ATT&CK Mapping

### Primary:

**T1098 – Account Manipulation**
Attackers may modify group memberships to escalate privileges or maintain persistence.

### Secondary:

**T1078 – Valid Accounts**
Unauthorized group changes can grant attackers legitimate privileged access.

**T1069 – Permission Groups Discovery**
Monitoring group changes helps detect attacker attempts to manipulate access structures.
