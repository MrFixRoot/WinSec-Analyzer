
<div align="center">

# WinSec-Analyzer

**PowerShell-Based Windows Security Auditing & Configuration Assessment Toolkit**

[![Version](https://img.shields.io/badge/version-0.8-blue)](CHANGELOG.md)
![Status](https://img.shields.io/badge/status-active%20development-orange)
![Platform](https://img.shields.io/badge/platform-Windows-0078D4?logo=windows)
![PowerShell](https://img.shields.io/badge/PowerShell-7%20recommended-5391FE?logo=powershell&logoColor=white)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Developed by [mrRoot (MrFixRoot)](https://github.com/MrFixRoot)** · [LinkedIn](https://www.linkedin.com/in/normanlp/)

</div>

```text
██╗    ██╗██╗███╗   ██╗███████╗███████╗ ██████╗
██║    ██║██║████╗  ██║██╔════╝██╔════╝██╔════╝
██║ █╗ ██║██║██╔██╗ ██║███████╗█████╗  ██║
██║███╗██║██║██║╚██╗██║╚════██║██╔══╝  ██║
╚███╔███╔╝██║██║ ╚████║███████║███████╗╚██████╗
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝

                  WinSec-Analyzer
                Windows Security Auditor
                         mrRoot
```

---

## Overview

**WinSec-Analyzer** is an open-source Windows security auditing tool developed primarily in **PowerShell**.

The project aims to automate the assessment of Windows security configurations, identify potential security weaknesses, evaluate system hardening controls, and provide actionable recommendations to improve overall security posture.

WinSec-Analyzer is designed to help cybersecurity professionals, security auditors, system administrators, and IT professionals evaluate Windows environments using standardized security checks.

The tool focuses on five security assessment categories:

1. **System Security**
2. **Network Security**
3. **Identity & Access Security**
4. **Logging & Auditing**
5. **Services & Hardening**

The project combines system administration, security automation, and security configuration assessment within a modular and extensible architecture.

> [!NOTE]
> WinSec-Analyzer is under active development. The application framework and initial components are available, while security assessment modules, scoring, and reporting functionality are being implemented.

---

## Project Objectives

The main objectives of WinSec-Analyzer are:

- Automate Windows security configuration assessments.
- Identify insecure or potentially vulnerable configurations.
- Evaluate security controls across multiple categories.
- Collect technical evidence supporting security findings.
- Provide security recommendations based on assessment results.
- Calculate security scores for individual assessment categories.
- Classify security findings according to their severity.
- Support Windows hardening and security baseline reviews.
- Generate structured security assessment reports.
- Provide a foundation for future security framework mappings.

---

## Security Assessment Categories

WinSec-Analyzer organizes its security assessments into five categories.

### 1. System Security

Evaluates fundamental Windows security mechanisms and endpoint protection settings.

**Planned assessments:**

- Microsoft Defender Antivirus
- BitLocker Drive Encryption
- Windows Update security

**Assessment objectives:**

- Verify endpoint protection mechanisms.
- Identify disabled or weakened security controls.
- Evaluate disk encryption status.
- Review Windows security update configuration.
- Identify configurations that may expose the operating system to security risks.

### 2. Network Security

Evaluates Windows network protection mechanisms and potentially exposed services.

**Planned assessments:**

- Windows Firewall
- Open TCP ports
- Remote Desktop Protocol (RDP)
- Network security configuration

**Assessment objectives:**

- Verify Windows Firewall protection.
- Identify listening TCP ports and associated services.
- Evaluate remote access security settings.
- Detect potentially exposed network services.
- Identify network configurations that require security hardening.

### 3. Identity & Access Security

Evaluates Windows account security, authentication policies, and privileged access configurations.

**Planned assessments:**

- Local user accounts
- Local administrator accounts
- Built-in Guest account
- Password security policies
- Account lockout policies

**Assessment objectives:**

- Identify unnecessary privileged accounts.
- Evaluate local administrator membership.
- Detect insecure local account configurations.
- Verify Guest account security.
- Assess authentication and password requirements.
- Review account lockout controls.

### 4. Logging & Auditing

Evaluates security event logging and auditing configurations.

**Planned assessments:**

- Windows Audit Policy
- PowerShell security logging
- PowerShell Script Block Logging
- PowerShell Module Logging
- PowerShell Transcription

**Assessment objectives:**

- Evaluate security event collection settings.
- Identify disabled or insufficient auditing controls.
- Verify PowerShell logging configuration.
- Review mechanisms supporting security monitoring.
- Improve visibility into potentially suspicious activity.

### 5. Services & Hardening

Evaluates Windows services, legacy protocols, and system hardening configurations.

**Planned assessments:**

- SMBv1 protocol security
- Windows services configuration
- User Account Control (UAC)
- Additional Windows hardening controls

**Assessment objectives:**

- Identify unnecessary or insecure services.
- Detect legacy protocols that increase security exposure.
- Evaluate Windows hardening settings.
- Review service configurations that could weaken system security.
- Support secure configuration baseline assessments.

---

## Development Status

WinSec-Analyzer is currently in active development.

The initial project architecture, application launcher, configuration files, and foundational components have been created.

Security assessment modules are being developed and integrated into the auditing engine.

### Implementation Status

| Status | Description |
|---|---|
| ✅ Implemented | Component available in the current codebase |
| 🚧 In Development | Component under development or integration |
| ⏳ Pending | Functionality planned but not yet implemented |

### Core Components

| Feature | Status |
|---|:---:|
| Modular PowerShell project structure | ✅ |
| Application launcher | ✅ |
| Project configuration files | ✅ |
| Security check module structure | ✅ |
| Assessment engine | ⏳ |
| Security control registration | ⏳ |
| Structured assessment results | ⏳ |
| Security findings processing | ⏳ |
| Security scoring engine | ⏳ |
| Security severity classification | ⏳ |
| Report generation | ⏳ |
| TXT report export | ⏳ |
| Automated testing | ⏳ |

### Security Assessment Implementation

| Category | Security Control | Status |
|---|---|:---:|
| System Security | Microsoft Defender Antivirus | ⏳ |
| System Security | BitLocker Drive Encryption | ⏳ |
| System Security | Windows Update | ⏳ |
| Network Security | Windows Firewall | ⏳ |
| Network Security | Open TCP Ports | ⏳ |
| Network Security | Remote Desktop (RDP) | ⏳ |
| Network Security | Network Configuration | ⏳ |
| Identity & Access | Local Users & Administrators | ⏳ |
| Identity & Access | Guest Account | ⏳ |
| Identity & Access | Password Policy | ⏳ |
| Identity & Access | Account Lockout Policy | ⏳ |
| Logging & Auditing | Windows Audit Policy | ⏳ |
| Logging & Auditing | PowerShell Logging | ⏳ |
| Services & Hardening | SMBv1 Security | ⏳ |
| Services & Hardening | Windows Services | ⏳ |
| Services & Hardening | User Account Control (UAC) | ⏳ |

> [!IMPORTANT]
> Several security check files already exist as placeholders in the project structure. These files are not considered implemented until their assessment logic is completed and integrated into the auditing engine.

---

## Security Assessment Results

WinSec-Analyzer is designed to produce structured security assessment results.

Each security control will provide relevant information such as:

- Security control identifier
- Assessment category
- Control description
- Assessment status
- Severity level
- Observed configuration
- Expected configuration
- Technical evidence
- Security recommendation

### Assessment States

| Status | Description |
|---|---|
| `PASS` | The configuration meets the defined security criteria |
| `WARNING` | The configuration requires review or hardening |
| `FAIL` | An insecure configuration has been identified |
| `INFO` | Informational security finding |
| `ERROR` | The security control could not be evaluated |
| `N/A` | The security control is not applicable |

An evaluation error or non-applicable control should not automatically be classified as a security failure.

---

## Security Scoring

WinSec-Analyzer will implement a weighted scoring system to evaluate security configurations.

Each assessment category will receive an individual security score based on the evaluated controls.

The scoring system is intended to:

- Provide a standardized security assessment indicator.
- Highlight security categories requiring attention.
- Support prioritization of remediation activities.
- Facilitate comparisons between assessment results.
- Provide an overall Windows security posture indicator.

Security scores will use a **0–100 scale**, with configurable control and category weights.

Scoring rules are under development and will be managed through the project's configuration files.

A security score does not guarantee that a system is secure against every threat.

---

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or later
- PowerShell 7 recommended
- Administrator privileges recommended for comprehensive security assessments

Some security checks may require elevated privileges or specific Windows components.

---

## Installation

### Clone the Repository

```powershell
git clone https://github.com/MrFixRoot/WinSec-Analyzer.git
```

### Navigate to the Project Directory

```powershell
cd WinSec-Analyzer
```

### Run WinSec-Analyzer

```powershell
.\Start-WinSec.ps1
```

> [!NOTE]
> The application can currently be launched for development and testing. Security audits will become available as the assessment engine and individual security checks are implemented.

---

## Development Roadmap

The following improvements are planned for future versions:

- Complete Windows security assessment modules.
- Implement automated security control execution.
- Integrate the findings and scoring engines.
- Support customizable security scoring policies.
- Generate TXT, JSON, CSV, and HTML reports.
- Implement security control correlation.
- Expand Windows security hardening assessments.
- Add automated testing and compatibility validation.
- Integrate recognized cybersecurity framework references.

### Security Framework References

Future versions may associate security findings with:

| Framework | Purpose |
|---|---|
| CIS Benchmarks | Windows secure configuration recommendations |
| CIS Controls | Prioritized cybersecurity safeguards |
| NIST CSF | Cybersecurity risk management practices |
| MITRE ATT&CK | Adversary techniques and defensive context |

These references will support technical security assessments and should not be interpreted as formal compliance certification.

---

## Security & Responsible Use

WinSec-Analyzer is intended for authorized defensive security assessments, system administration, and educational purposes.

The project follows a primarily **read-only assessment approach**, focusing on analyzing security configurations without automatically modifying system settings.

Users are responsible for ensuring they have proper authorization before evaluating a Windows system.

Security findings should always be reviewed and validated before applying changes to production environments.

WinSec-Analyzer does not replace professional security audits, penetration testing, vulnerability management platforms, or continuous security monitoring.

---

## Attribution & Derivative Works

WinSec-Analyzer was originally created and developed by
**Norman López P. (mrRoot / MrFixRoot)**.

Forking, modifying, and redistributing this project is
permitted under the Apache License, Version 2.0.

Redistributed versions and derivative works must preserve
the applicable original copyright and attribution notices,
including those contained in the NOTICE file.

Original Project:
https://github.com/MrFixRoot/WinSec-Analyzer

Original Author: **Norman López P. — mrRoot**

---

## Author

**Norman López P. — mrRoot**

**GitHub:** [MrFixRoot](https://github.com/MrFixRoot)

**LinkedIn:** [normanlp](https://www.linkedin.com/in/normanlp/)

**Project Repository:** [WinSec-Analyzer](https://github.com/MrFixRoot/WinSec-Analyzer)

---

<div align="center">

**WinSec-Analyzer**

*PowerShell-Based Windows Security Auditing & Configuration Assessment Toolkit*

**Developed by mrRoot**

</div>
