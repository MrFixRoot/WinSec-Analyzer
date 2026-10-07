# Changelog

All notable changes to WinSec-Analyzer will be documented in this file.

The project is currently in early development and version numbers may change frequently as new security assessment modules and improvements are added.

---

## [v0.8] - 2026-10-07

### Added

- Interactive PowerShell console interface.
- Hacker-style ASCII banner for WinSec-Analyzer.
- Modular project structure using independent PowerShell functions.
- Main launcher script from the project root.
- Dynamic loading of PowerShell functions from the `src/functions` directory.
- Security assessment result formatting with:
  - PASS
  - WARNING
  - FAIL
  - INFO
  - ERROR
- Security findings with evidence and recommendations.
- Security scoring for supported modules.
- Risk level classification.
- Progress indicators while security checks are running.

### System Information

Added system information collection including:

- Hostname
- Windows edition
- Windows version
- Windows build number
- System architecture
- Domain or workgroup
- Manufacturer
- System model
- Current user
- Administrator status
- PowerShell version
- Last boot time
- Assessment timestamp

### Windows Firewall Assessment

Added Windows Firewall security auditing including:

- Windows Firewall service status.
- Domain profile status.
- Private profile status.
- Public profile status.
- Default inbound firewall policies.
- Firewall logging configuration.
- Firewall log size validation.
- Firewall log path validation.
- Detection of potentially exposed sensitive services.
- Firewall security score.
- Security findings and recommendations.

### Open Ports Assessment

Added TCP listening port analysis including:

- Detection of listening TCP ports.
- Local IP address.
- Local port.
- Associated process.
- Process ID.
- Associated Windows service when available.
- Known service identification.
- Interface exposure classification.
- Detection of selected sensitive ports.
- Informational and warning findings.

Sensitive services currently identified include:

- FTP
- SSH
- Telnet
- HTTP
- RPC
- NetBIOS
- HTTPS
- SMB
- Microsoft SQL Server
- MySQL
- Remote Desktop
- PostgreSQL
- WinRM HTTP
- WinRM HTTPS

### Windows Defender Assessment

Added Microsoft Defender security auditing including:

- Defender Antivirus service status.
- Antivirus enabled status.
- Real-time protection.
- Behavior monitoring.
- Downloaded file protection.
- Network Inspection System.
- Cloud-delivered protection.
- Potentially Unwanted Application protection.
- Security intelligence signature age.
- Last security intelligence update.
- Tamper Protection status when available.
- Defender operating mode.
- Defender security score.
- Security findings and recommendations.

### Interface

- Added categorized main menu.
- Added sections for:
  - System
  - Network Security
  - Endpoint Security
- Added reusable banner component.
- Added reusable section headers.
- Added reusable assessment result presentation.
- Added author information and LinkedIn profile to the console banner.

### Project

- Added MIT License.
- Added responsible-use notice.
- Added README documentation.
- Added Git branching workflow using:
  - `main`
  - `develop`
  - `feature/*`

---

## Planned

Future versions may include:

- BitLocker assessment.
- SMB security assessment.
- Remote Desktop security assessment.
- User Account Control assessment.
- Local users and administrators assessment.
- Guest account assessment.
- Password policy assessment.
- PowerShell logging assessment.
- Windows Audit Policy assessment.
- Windows Update assessment.
- Network configuration assessment.
- Security control correlation.
- CIS Benchmark mappings.
- NIST CSF mappings.
- MITRE ATT&CK mappings.
- JSON reporting.
- CSV reporting.
- HTML security reports.