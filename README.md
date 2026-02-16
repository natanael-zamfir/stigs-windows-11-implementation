## Windows 11 STIG Implementations

Hands on Windows 11 STIG implementations for system hardening, defensive security best practices and mapping hardening controls to MITRE ATT&CK techniques.
<br>
References:
<ul>
  <li>
    <a href="https://www.tenable.com/audits/DISA_STIG_Microsoft_Windows_11_v2r5" target="_blank" rel="noopener noreferrer">
      DISA Microsoft Windows 11 STIG v2r5
    </a>
  </li>
  <li>
    <a href="https://stigaview.com/products/win11/v2r5/" target="_blank" rel="noopener noreferrer">
      STIGAVIEW Windows 11 STIG v2r5
    </a>
  </li>
</ul>

---

### View my full documentation covering STIG implementation and MITRE ATT&CK mappings.
[🛡️WN11-CC-000155 – Solicited Remote Assistance must not be allowed](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000155%20%E2%80%93%20Solicited%20Remote%20Assistance%20must%20not%20be%20allowed.md)
- Disables Solicited Remote Assistance to reduce social-engineering scams where a victim unknowingly grants remote access to an attacker.


[🛡️ WN11-CC-000326 – PowerShell Script Block Logging must be enabled](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000326%20%E2%80%93%20PowerShell%20Script%20Block%20Logging%20must%20be%20enabled.md)
- Enables PowerShell Script Block Logging to improve detection and post-attack investigation by recording PowerShell script block activity (extra detailed PS script blocks for improved SIEM investigation).

[🛡️ WN11-CC-000327 – PowerShell Transcription must be enabled on Windows 11](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000327%20%E2%80%93%20PowerShell%20Transcription%20must%20be%20enabled%20on%20Windows%2011.md)
- Enables PowerShell Transcription to generate session transcripts for post-attack investigation and forensic evidence of PowerShell activity, in conjunction with WN11-CC-000326.

[🛡️ WN11-CC-000210 – The Microsoft Defender SmartScreen for Explorer must be enabled](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000210%20%E2%80%93%20The%20Microsoft%20Defender%20SmartScreen%20for%20Explorer%20must%20be%20enabled.md)  
- Enables Microsoft Defender SmartScreen for Explorer to warn or block untrusted downloads, reducing risks from crypto scam payloads such as fake wallet apps and “airdrop claim” tools (also malicious “security updates” delivered via scam links).

<img width="1832" height="728" alt="image" src="https://github.com/user-attachments/assets/4a63bceb-f1eb-4e2c-9a1b-d0e4310beab9" />
