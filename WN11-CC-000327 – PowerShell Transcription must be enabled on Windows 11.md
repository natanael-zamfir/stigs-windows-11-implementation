# 🛡️ WN11-CC-000327 – PowerShell Transcription must be enabled on Windows 11

<img width="1816" height="541" alt="image" src="https://github.com/user-attachments/assets/b2472e42-aa63-414c-9411-9284fce21358" />

# What it’s about?
This STIG enables **PowerShell Transcription**, which creates **text transcript files** of PowerShell sessions.
These transcripts help defenders review what was executed during a session and support investigations.

# Why it’s a security risk if disabled?
PowerShell is often used in attacks for reconnaissance, downloading payloads, and running commands.
If transcription is **disabled**, you lose a useful evidence source (session transcripts), making detection and post-attack investigation harder.
WN11-CC-000327 goes hand in hand with WN11-CC-000326.

---

## Step 1 — Check current state

### 1) Verify the policy registry path exists
Policy keys under `HKLM:\SOFTWARE\Policies\...` only appear after being created. If the key doesn’t exist, the setting is not configured.

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
Test-Path $path
```

* `False` → **Non-compliant** (policy not configured)
* `True` → continue checking required values

---

### 2) Check if transcription is enabled and configured

This checks the exact policy values that control transcription.

```powershell
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Select-Object EnableTranscripting, EnableInvocationHeader, OutputDirectory
```

* `EnableTranscripting = 1` → Transcription enabled
* `EnableInvocationHeader = 1` → Adds extra context in the transcript (useful for investigations)
* `OutputDirectory` → Where transcript files are written (must be a valid folder path)

---

## Findings
Before configuration, transcription policy values were not present or not set as required, which result in **non-compliance**.

---

## Step 2 — Remediation

### 1) Configure Transcription policy via PowerShell

The following commands create the policy registry key and set the required values.

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

* `EnableTranscripting = 1` turns on transcription
* `OutputDirectory` defines where transcripts are saved
* `EnableInvocationHeader = 1` increases the usefulness of transcripts during investigations

---

## Step 3 — Verification

### 1) Verify the policy values are set correctly

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' |
  Select-Object EnableTranscripting, EnableInvocationHeader, OutputDirectory
```

Expected compliant output:

* `EnableTranscripting` = `1`
* `EnableInvocationHeader` = `1`
* `OutputDirectory` = `C:\ProgramData\PowerShellTranscripts`

## Results
<img width="1073" height="358" alt="Screenshot 2026-02-07 165217" src="https://github.com/user-attachments/assets/84002c48-7474-4696-9ac6-343bf5f12561" />

---

### 2) Testing transcript verification

A simple command was run to generate PowerShell activity:

```powershell
Get-Date
```

Confirm the transcript directory exists and PowerShell created a dated subfolder:

```powershell
Get-ChildItem 'C:\ProgramData\PowerShellTranscripts' | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

Then list transcript files inside the dated folder (in this example: `20260207`):

```powershell
Get-ChildItem 'C:\ProgramData\PowerShellTranscripts\20260207' |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 5
```
## Results 
<img width="1201" height="290" alt="image" src="https://github.com/user-attachments/assets/e35db17a-645c-4feb-8476-8a11569619e1" />

The following command opens a `.txt` transcript file which includes the "Get-Date" command tested.
```powershell
$latest = Get-ChildItem 'C:\ProgramData\PowerShellTranscripts\20260207' -File |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

notepad $latest.FullName
```
---

## STIG Status

* **STIG ID:** WN11-CC-000327
* **Status:** Compliant
* **Remediation Method:** PowerShell registry policy enforcement
* **Impact:** Improved visibility and forensic evidence for PowerShell activity

---

## MITRE ATT&CK Mapping

### Primary:

**T1059.001 – Command and Scripting Interpreter: PowerShell**
Attackers use PowerShell to execute commands and scripts.

### Secondary:

**T1082 — System Information Discovery**
Attackers may use PowerShell to gather OS/host information; transcripts help confirm executed discovery commands.

**T1016 — System Network Configuration Discovery**
Attackers may use PowerShell to enumerate adapters, IPs, DNS, and routes; transcripts provide evidence of these actions.

**T1105 – Ingress Tool Transfer**
Attackers may use PowerShell to download payloads/tools; transcripts can record these download commands if PowerShell is used.

