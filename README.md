# WinSec-Analyzer

```text
██╗    ██╗██╗███╗   ██╗███████╗███████╗ ██████╗
██║    ██║██║████╗  ██║██╔════╝██╔════╝██╔════╝
██║ █╗ ██║██║██╔██╗ ██║███████╗█████╗  ██║
██║███╗██║██║██║╚██╗██║╚════██║██╔══╝  ██║
╚███╔███╔╝██║██║ ╚████║███████║███████╗╚██████╗
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝

            WinSec-Analyzer v0.8
                 mrRoot

 PowerShell-based Windows security auditing toolkit
        linkedin.com/in/normandaniell
```

**WinSec-Analyzer** is a modular PowerShell-based Windows security assessment tool designed to collect, analyze, and report security-related configuration information.

It is intended for defensive security, system administration, hardening reviews, educational use, and authorized security assessments.

**Author:** Norman Daniel L. / **mrRoot**  
**LinkedIn:** [linkedin.com/in/normandaniell](https://www.linkedin.com/in/normandaniell/)

---

## Project Status

🚧 **Early Development**

Current version: **v0.8**

WinSec-Analyzer is under active development. Security checks, scoring methods, output formats, and supported Windows configurations may change as the project evolves.

See the [CHANGELOG](CHANGELOG.md) for version history and implemented features.

---

## Objectives

WinSec-Analyzer aims to evaluate different security aspects of Windows systems.

| Security Check | Status |
|---|---|
| Operating System Information | ✅ Implemented |
| Windows Firewall Configuration | ✅ Implemented |
| Listening TCP Ports | ✅ Implemented |
| Windows Defender Status | ✅ Implemented |
| BitLocker Status | ✅ Implemented |
| SMB Configuration | ✅ Implemented |
| Local Users and Administrators | ✅ Implemented |
| User Account Control (UAC) | ⏳ Planned |
| Remote Desktop Configuration | ⏳ Planned |
| Password Policy | ⏳ Planned |
| PowerShell Security Settings | ⏳ Planned |
| Network Configuration | ⏳ Planned |
| Audit Policies | ⏳ Planned |
| Windows Update | ⏳ Planned |
| Windows Services | ⏳ Planned |

---

## Current Modules

### System Information

Collects general information about the Windows system.

Information includes:

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

### Windows Firewall

Analyzes Windows Firewall configuration and security posture.

Checks include:

- Windows Firewall service status
- Domain profile
- Private profile
- Public profile
- Default inbound policies
- Firewall logging
- Firewall log size
- Firewall log path
- Default outbound policy
- Potentially exposed sensitive services
- Sensitive inbound firewall rules
- Security findings
- Recommendations
- Firewall security score

---

### Open Ports

Enumerates listening TCP ports and identifies potentially sensitive services.

Collected information includes:

- Local address
- Local TCP port
- Associated process
- Process ID
- Associated Windows service
- Known service
- Interface exposure
- Finding status
- Severity

Currently recognized services include:

- FTP
- SSH
- Telnet
- HTTP
- HTTPS
- RPC Endpoint Mapper
- NetBIOS
- SMB
- Microsoft SQL Server
- MySQL
- PostgreSQL
- Remote Desktop
- WinRM HTTP
- WinRM HTTPS

Open Ports is currently treated primarily as an informational assessment and does not automatically reduce a security score.

---

### Windows Defender

Analyzes Microsoft Defender security configuration.

Checks include:

- Defender Antivirus service
- Antivirus enabled status
- Real-time protection
- Behavior monitoring
- Downloaded file protection
- Network Inspection System
- Cloud-delivered protection
- Potentially Unwanted Application protection
- Security intelligence signature age
- Last security intelligence update
- Tamper Protection
- Defender operating mode
- Security findings
- Recommendations
- Defender security score

---

### BitLocker

Analyzes BitLocker and operating system volume encryption.

Checks include:

- BitLocker protection status
- OS volume encryption status
- Encryption percentage
- Encryption method
- Key protectors
- Recovery protector availability
- TPM status
- Additional encrypted volumes
- Security findings
- Recommendations
- BitLocker security score

> WinSec-Analyzer does not display or store BitLocker recovery passwords.

Some BitLocker checks may require Administrator privileges.

---

### SMB Security

Analyzes Windows SMB configuration.

Checks include:

- SMBv1 server protocol
- SMBv1 Windows optional feature
- SMBv2 / SMBv3 support
- SMB server signing
- SMB client signing
- Insecure SMB guest logons
- Rejection of unencrypted SMB access
- SMB encryption configuration
- SMB share enumeration
- Security findings
- Recommendations
- SMB security score

---

### Local Users & Administrators

Analyzes local accounts and privileged local access.

Checks include:

- Built-in Administrator account status
- Built-in Guest account status
- Enabled accounts requiring passwords
- Local administrator password requirements
- Administrator group membership integrity
- Unresolved or orphaned administrator principals
- Non-expiring administrator password review
- Inactive privileged accounts
- Administrator LastLogon visibility
- Local user inventory
- Local Administrators group inventory
- Principal source identification
- Security findings
- Recommendations
- Identity security score

Built-in Windows accounts and groups are identified using SIDs rather than display names, improving compatibility with localized Windows installations.

---

## Assessment Results

Security modules use standardized result states:

| Status | Description |
|---|---|
| `PASS` | Recommended security configuration detected |
| `WARNING` | Configuration should be reviewed |
| `FAIL` | Security weakness or insecure configuration detected |
| `INFO` | Informational finding |
| `ERROR` | The security control could not be evaluated |

Scored modules may display results such as:

```text
Security Score : 82/100
Risk Level     : MODERATE
```

Errors that prevent a control from being evaluated should not automatically be interpreted as security failures.

---

## Security Score

WinSec-Analyzer uses weighted security controls for modules where scoring is appropriate.

Example:

```text
PASS    : 6
WARNING : 2
FAIL    : 1
ERROR   : 0
INFO    : 3

Security Score : 78/100
Risk Level     : MODERATE
```

Current risk levels:

```text
90 - 100   LOW
75 - 89    MODERATE
50 - 74    HIGH
0  - 49    CRITICAL
```

Informational-only modules may display:

```text
Security Score : N/A
Assessment     : INFORMATIONAL
```

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 7 recommended
- Administrator privileges recommended for full functionality

Some checks may work without elevation, while others such as BitLocker and certain security configuration queries may require Administrator privileges.

---

## Usage

Clone the repository:

```powershell
git clone https://github.com/MrFixRoot/WinSec-Analyzer
```

Enter the project directory:

```powershell
cd WinSec-Analyzer
```

Run WinSec-Analyzer from the project root:

```powershell
.\run.ps1
```

The launcher automatically starts:

```text
src\winsec-analyzer.ps1
```

---

## Main Menu

The interactive console is organized by security area.

```text
SYSTEM
[1] System Information

NETWORK SECURITY
[2] Windows Firewall
[3] Open Ports

ENDPOINT SECURITY
[4] Windows Defender
[5] BitLocker

WINDOWS HARDENING
[6] SMB Security

IDENTITY & ACCESS
[7] Local Users & Administrators

[0] Exit
```

Each assessment module presents its own:

- Security controls table
- Security findings
- Evidence
- Recommendations
- Summary
- Security score when applicable

---

## Security and Responsible Use

WinSec-Analyzer is intended for authorized security auditing, system administration, education, hardening reviews, and defensive security purposes.

Users are responsible for ensuring that they have appropriate authorization before running the tool on any system.

The authors and contributors are not responsible for misuse, unauthorized use, system modifications, data loss, service disruption, or other damages resulting from the use of this software.

WinSec-Analyzer is designed primarily as a read-only security assessment tool.

Findings should be reviewed and validated before making configuration changes to production systems.

---

## License

This project is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for details.

---

## Author

**Norman Daniel L. — mrRoot**

[LinkedIn](https://www.linkedin.com/in/normandaniell/)

---

**WinSec-Analyzer v0.8**  
PowerShell-based Windows security auditing toolkit.