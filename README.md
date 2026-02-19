# 🖥️ Windows 11 STIG Hardening Implementations 🔐

In this project, I implemented multiple **DISA Windows 11 Security Technical Implementation Guide (STIG)** controls to harden a Windows endpoint against real-world attack techniques.

**Starting State:** Default Windows configuration with limited hardening and reduced security visibility.

**End State:** A hardened system with credential protections, enhanced logging, attack surface reduction, and improved detection capability aligned with enterprise security baselines.

#### How This Project Is Structured:

- **Platform Hardening** — Memory protection and virtualization-based security controls.
- **Credential Protection** — Safeguards preventing credential theft and authentication downgrade attacks.
- **Detection & Visibility** — Advanced logging and telemetry for threat hunting and incident response.
- **Access & Attack Surface Reduction** — Controls limiting remote access abuse and malicious execution paths.

#### Technology Utilised:
<div>
  <img src="https://img.shields.io/badge/Windows_11-0078D6?style=for-the-badge&logo=windows11&logoColor=white" />
  <img src="https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white" />
  <img src="https://img.shields.io/badge/Windows_Security-4CAF50?style=for-the-badge&logo=microsoft&logoColor=white" />
</div>

#### STIG References:
<ul>
  <li>
    <a href="https://stigaview.com/products/win11/v2r5/" target="_blank" rel="noopener noreferrer">
      STIGAVIEW Windows 11 STIG v2r5
    </a>
  </li>
  <li>
    <a href="https://www.tenable.com/audits/DISA_STIG_Microsoft_Windows_11_v2r5" target="_blank" rel="noopener noreferrer">
      DISA Microsoft Windows 11 STIG v2r5
    </a>
  </li>
</ul>

---

### View my full documentation covering STIG implementation and MITRE ATT&CK mappings.
[🛡️ WN11-CC-000070 – Virtualization-based Security must be enabled](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000070%20%E2%80%93%20Virtualization-based%20Security%20must%20be%20enabled.md)  
**(Memory Protection / Platform Security)**  
- I enabled virtualization-based security to isolate sensitive system components from memory and kernel attacks.

 

[🛡️ WN11-CC-000075 – Credential Guard must be running (Domain-joined systems)](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000075.md)  
**(Credential Protection / Authentication Security)**  
- I configured Credential Guard policies to protect login credentials in isolated memory (not applicable on this standalone system).

 

[🛡️ WN11-CC-000326 – PowerShell Script Block Logging must be enabled](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000326%20%E2%80%93%20PowerShell%20Script%20Block%20Logging%20must%20be%20enabled.md)  
**(Threat Detection / Logging & DFIR)**  
- I enabled script block logging so PowerShell commands and scripts executed on the system are fully recorded for investigation.

 

[🛡️ WN11-CC-000327 – PowerShell Transcription must be enabled on Windows 11](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000327%20%E2%80%93%20PowerShell%20Transcription%20must%20be%20enabled%20on%20Windows%2011.md)  
**(Threat Detection / Logging & DFIR)**  
- I enabled PowerShell transcription to create readable session logs that help reconstruct attacker activity.

 

[🛡️ WN11-CC-000066 – Command line data must be included in process creation events](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000066%20%E2%80%93%20Command%20line%20data%20must%20be%20included%20in%20process%20creation%20events.md)  
**(Endpoint Visibility / Process Monitoring)**  
- I configured Windows to log full command-line arguments so executed processes can be clearly investigated.

 

[🛡️ WN11-AU-000030 – Audit Security Group Management must be enabled (Success)](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-AU-000030%20%E2%80%93%20Audit%20Security%20Group%20Management%20must%20be%20enabled.md)  
**(Privilege Monitoring / Identity Security)**  
- I enabled auditing of security group changes so privilege and permission modifications are tracked.

 

[🛡️ WN11-SO-000205 – LanMan authentication level must be NTLMv2 only](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-SO-000205%20%E2%80%93%20LanMan%20authentication%20level%20must%20be%20NTLMv2%20only.md)  
**(Authentication Hardening)**  
- I enforced NTLMv2-only authentication to block weak legacy authentication protocols.

 

[🛡️ WN11-CC-000038 – WDigest Authentication must be disabled](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000038%20%E2%80%93%20WDigest%20Authentication%20must%20be%20disabled.md)  
**(Credential Protection)**  
- I disabled WDigest so passwords are not stored in memory where attackers could extract them.

 

[🛡️ WN11-CC-000210 – Microsoft Defender SmartScreen for Explorer must be enabled](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000210%20%E2%80%93%20The%20Microsoft%20Defender%20SmartScreen%20for%20Explorer%20must%20be%20enabled.md)  
**(User Protection / Malware Prevention)**  
- I enabled SmartScreen to block or warn against running suspicious downloaded files.

 

[🛡️ WN11-CC-000155 – Solicited Remote Assistance must not be allowed](https://github.com/natanael-zamfir/stigs-windows-11-implementation/blob/main/WN11-CC-000155%20%E2%80%93%20Solicited%20Remote%20Assistance%20must%20not%20be%20allowed.md)  
**(Attack Surface Reduction / Remote Access Control)**  
- I disabled Solicited Remote Assistance to prevent users from granting remote control to attackers through scams.

 

<img width="1832" height="728" alt="image" src="https://github.com/user-attachments/assets/4a63bceb-f1eb-4e2c-9a1b-d0e4310beab9" />
