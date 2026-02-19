# 🛡️ WN11-CC-000327 – PowerShell Transcription must be enabled on Windows 11

## Summary
In this task, I enabled PowerShell transcription to ensure PowerShell sessions are recorded as text transcripts, improving visibility and investigation capability for command execution activity.

<img width="1816" height="541" alt="image" src="https://github.com/user-attachments/assets/b2472e42-aa63-414c-9411-9284fce21358" />

## What it’s about?
This STIG requires **PowerShell Transcription** to be enabled so that full PowerShell sessions are written to transcript files.

PowerShell is heavily used in both administration and attacks. By enabling transcription, I ensured that commands executed during a session are recorded, creating an additional forensic evidence source alongside event logs.

## Why it’s a security risk if disabled?
If transcription is disabled, PowerShell activity may only appear partially in logs or not contain enough context to understand what actions were performed.

Attackers frequently use PowerShell for reconnaissance, payload execution, and system modification. Without transcripts, post-incident investigation and timeline reconstruction become significantly harder.

---

## Step 1 — Check current state

### 1) Verify the policy registry path exists

I first checked whether the transcription policy location was configured.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
Test-Path $path
````

* `False` → policy not configured
* `True` → proceed to value validation

---

### 2) Check transcription configuration values

I then reviewed the policy values controlling transcription.

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
  Select-Object EnableTranscripting, EnableInvocationHeader, OutputDirectory
```

Required configuration:

* `EnableTranscripting = 1`
* `EnableInvocationHeader = 1`
* `OutputDirectory` set to a valid folder path

---

## Findings

During assessment, transcription policy values were either missing or not configured as required.
Because transcription was not explicitly enforced, the system was treated as **non-compliant**.

---

## Step 2 — Remediation

### 1) Configure PowerShell Transcription policy

I configured registry policy settings to enable transcription and define a dedicated transcript storage location.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
$dir  = 'C:\ProgramData\PowerShellTranscripts'

New-Item -Path $path -Force | Out-Null

New-ItemProperty -Path $path -Name EnableTranscripting    -PropertyType DWord  -Value 1 -Force | Out-Null
New-ItemProperty -Path $path -Name EnableInvocationHeader -PropertyType DWord  -Value 1 -Force | Out-Null
New-ItemProperty -Path $path -Name OutputDirectory        -PropertyType String -Value $dir -Force | Out-Null

Get-ItemProperty -Path $path | Select-Object EnableTranscripting, EnableInvocationHeader, OutputDirectory
```

Why these settings:

* `EnableTranscripting = 1` enables session transcription
* `EnableInvocationHeader = 1` records additional execution context
* `OutputDirectory` defines a consistent forensic storage location

---

## Step 3 — Verification

### 1) Verify policy values

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' |
  Select-Object EnableTranscripting, EnableInvocationHeader, OutputDirectory
```

Expected compliant configuration:

* `EnableTranscripting = 1`
* `EnableInvocationHeader = 1`
* `OutputDirectory` set to configured transcript directory

## Results

<img width="1073" height="358" alt="Screenshot 2026-02-07 165217" src="https://github.com/user-attachments/assets/84002c48-7474-4696-9ac6-343bf5f12561" />

---

### 2) Functional transcript verification

To confirm transcription was operational, I generated PowerShell activity:

```powershell
Get-Date
```

I then verified transcript directory creation:

```powershell
Get-ChildItem 'C:\ProgramData\PowerShellTranscripts' |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 5
```

Next, I reviewed transcript files inside the generated dated folder:

```powershell
Get-ChildItem 'C:\ProgramData\PowerShellTranscripts\20260207' |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 5
```

## Results

<img width="1201" height="290" alt="image" src="https://github.com/user-attachments/assets/e35db17a-645c-4feb-8476-8a11569619e1" />

Finally, I opened the most recent transcript file to confirm recorded commands:

```powershell
$latest = Get-ChildItem 'C:\ProgramData\PowerShellTranscripts\20260207' -File |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

notepad $latest.FullName
```

---

## Result

PowerShell transcription is now enforced through policy configuration.
PowerShell sessions generate transcript files containing executed commands, improving forensic visibility and supporting investigation of administrative or malicious activity.

---

## STIG Status

* **STIG ID:** WN11-CC-000327
* **Status:** Compliant
* **Remediation Method:** Registry policy configuration via PowerShell
* **Impact:** Improved monitoring and forensic evidence for PowerShell activity

---

## MITRE ATT&CK Mapping

### Primary:

**T1059.001 – Command and Scripting Interpreter: PowerShell**
Transcripts provide visibility into PowerShell-based execution activity.

### Secondary:

**T1082 — System Information Discovery**
Executed discovery commands can be confirmed through transcript records.

**T1016 — System Network Configuration Discovery**
Network enumeration performed via PowerShell becomes visible in transcripts.

**T1105 – Ingress Tool Transfer**
PowerShell download commands used to retrieve tools or payloads may be captured in transcripts.
