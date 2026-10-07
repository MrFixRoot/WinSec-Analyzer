# Changelog

All notable changes to **WinSec-Analyzer** will be documented in this file.

WinSec-Analyzer is currently in early development. Features, security checks,
scoring methods, and output formats may change as the project evolves.

---

# [v0.8] - 2026-10-07

## Added

### Core

- Modular PowerShell architecture.
- Automatic loading of functions from `src/functions`.
- Root launcher script for starting WinSec-Analyzer without navigating to `src`.
- Validation of required functions before starting the application.
- Interactive console interface.
- Progress indicators while security checks are running.
- Reusable assessment result presentation.
- Per-module security scoring.
- Risk level classification.
- Security findings with:
  - Status
  - Severity
  - Evidence
  - Recommendation

### Result States

WinSec-Analyzer currently supports:

- `PASS`
- `WARNING`
- `FAIL`
- `INFO`
- `ERROR`

---

## Interface

- Added hacker-style WinSec ASCII banner.
- Added WinSec-Analyzer version display.
- Added `mrRoot` author identity.
- Added LinkedIn profile to the console banner.
- Added categorized main menu.
- Added centered menu section titles.
- Added reusable section headers.

Current menu categories:

- `SYSTEM`
- `NETWORK SECURITY`
- `ENDPOINT SECURITY`
- `WINDOWS HARDENING`
- `IDENTITY & ACCESS`

---

# Security Modules

## System Information

Added Windows system information collection.

Collected information includes:

- Hostname
- Operating system
- Windows version
- Build number
- Architecture
- Domain or workgroup
- Manufacturer
- Computer model
- Current user
- Administrator status
- PowerShell version
- Last boot time
- Assessment timestamp

---

## Windows Firewall

Added Windows Firewall security assessment.

Checks include:

- Windows Firewall service status.
- Domain profile status.
- Private profile status.
- Public profile status.
- Default inbound policies.
- Firewall logging configuration.
- Firewall log size.
- Firewall log path.
- Default outbound policy information.
- Detection of potentially exposed sensitive services.
- Sensitive inbound firewall rules.
- Firewall security score.
- Security findings and recommendations.

### Firewall Improvements

- Firewall logging issues are reported as `WARNING` instead of automatically
  being treated as critical failures.
- Potentially exposed services are identified for future correlation with
  listening ports and service configuration.

---

## Open Ports

Added TCP listening port assessment.

Collected information includes:

- Local IP address.
- Listening TCP port.
- Associated process.
- Process ID.
- Associated Windows service when available.
- Known service identification.
- Interface exposure classification.
- Sensitive port detection.

Currently recognized sensitive services include:

- FTP
- SSH
- Telnet
- HTTP
- RPC Endpoint Mapper
- NetBIOS
- HTTPS
- SMB
- Microsoft SQL Server
- MySQL
- Remote Desktop
- PostgreSQL
- WinRM HTTP
- WinRM HTTPS

Open Ports is currently treated primarily as an informational assessment and
does not directly affect the global security posture score.

---

## Windows Defender

Added Microsoft Defender security assessment.

Checks include:

- Microsoft Defender Antivirus service.
- Antivirus enabled status.
- Real-time protection.
- Behavior monitoring.
- Downloaded file protection.
- Network Inspection System.
- Cloud-delivered protection.
- Potentially Unwanted Application protection.
- Security intelligence signature age.
- Last security intelligence update.
- Tamper Protection when available.
- Defender operating mode.
- Defender security score.
- Security findings and recommendations.

---

## BitLocker

Added BitLocker security assessment.

Checks include:

- BitLocker protection status.
- Operating system volume encryption.
- Encryption percentage.
- Encryption method.
- BitLocker key protectors.
- Recovery protector availability.
- Trusted Platform Module status.
- Additional BitLocker volumes.
- BitLocker security score.

### Security Considerations

- WinSec-Analyzer does not display or store BitLocker recovery passwords.
- Recovery protector presence is detected without exposing recovery secrets.
- BitLocker checks may require Administrator privileges.

---

## SMB Security

Added SMB security assessment.

Checks include:

- SMBv1 server protocol.
- SMBv1 Windows optional feature.
- SMBv2 / SMBv3 support.
- SMB server signing.
- SMB client signing.
- Insecure SMB guest logons.
- Rejection of unencrypted SMB access.
- SMB server encryption configuration.
- SMB share enumeration.
- SMB security score.
- Security findings and recommendations.

### Informational SMB Data

- Existing non-administrative SMB shares can be reported.
- SMB encryption settings are shown for review without automatically being
  treated as a failure.

---

## Local Users & Administrators

Added local identity and privileged account assessment.

Checks include:

- Built-in Administrator account status.
- Built-in Guest account status.
- Enabled local accounts requiring passwords.
- Local administrator password requirements.
- Administrator group membership integrity.
- Detection of unresolved or orphaned administrator principals.
- Non-expiring administrator password review.
- Inactive local administrator review.
- Administrator LastLogon visibility.
- Local user inventory.
- Local Administrators group inventory.
- Principal source identification where available.

### Localization Support

Built-in accounts and groups are identified by SID rather than display name,
allowing the checks to work on Windows installations using different languages.

Examples:

- Built-in Administrator RID: `500`
- Built-in Guest RID: `501`
- Built-in Administrators group SID: `S-1-5-32-544`

### Identity Scoring

The security score focuses on objective controls such as:

- Built-in Administrator status.
- Guest account status.
- Password requirements for enabled local accounts.
- Password requirements for local administrators.
- Administrator membership integrity.

Context-dependent findings such as inactive administrators or non-expiring
passwords are reported for review without automatically reducing the score.

---

# Changed

- Removed the combined **Full Security Assessment** screen.
- Each security module now presents its own independent assessment.
- Each module can display:
  - Security controls table
  - Security findings
  - Summary
  - Security score
  - Risk level
- Improved console organization to avoid overly crowded assessment output.
- Security modules remain independent to allow future correlation without
  tightly coupling individual checks.
- Error states that prevent a control from being evaluated should not be
  interpreted automatically as security failures.

---

# Project Structure

Current project structure follows a modular approach:

```text
WinSec-Analyzer/
│
├── CHANGELOG.md
├── LICENSE
├── README.md
├── run.ps1
│
├── src/
│   ├── winsec-analyzer.ps1
│   │
│   └── functions/
│       ├── Get-SystemInfo.ps1
│       ├── Show-AssessmentResults.ps1
│       ├── Show-Banner.ps1
│       ├── Show-MainMenu.ps1
│       ├── Show-SectionHeader.ps1
│       ├── Test-BitLocker.ps1
│       ├── Test-LocalUsersAdministrators.ps1
│       ├── Test-OpenPorts.ps1
│       ├── Test-SMB.ps1
│       ├── Test-WindowsDefender.ps1
│       └── Test-WindowsFirewall.ps1
│
└── tests/
```

---

# Development Workflow

The project currently uses the following Git workflow:

```text
feature/*
    |
    v
 develop
    |
    v
  main
```

- `main` contains the stable project version.
- `develop` contains integrated development changes.
- `feature/*` branches are used for individual features and security modules.

---

# Documentation

- Added project README.
- Added MIT License.
- Added Security and Responsible Use notice.
- Added CHANGELOG.
- Added author and LinkedIn information.

---

# Planned

Future versions may include:

- Remote Desktop security assessment.
- User Account Control assessment.
- Password policy assessment.
- PowerShell logging assessment.
- Windows Audit Policy assessment.
- Windows Update assessment.
- Network configuration assessment.
- Windows services assessment.
- Account lockout policy assessment.
- Security control correlation.
- Firewall + listening port correlation.
- SMB + TCP/445 correlation.
- RDP + TCP/3389 correlation.
- WinRM + TCP/5985/5986 correlation.
- CIS Benchmark mappings.
- CIS Controls mappings.
- NIST CSF mappings.
- MITRE ATT&CK mappings.
- JSON report generation.
- CSV report generation.
- HTML security reports.
- Improved automated testing.

---

**WinSec-Analyzer v0.8**  
**mrRoot**  
PowerShell-based Windows security auditing toolkit.
