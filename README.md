
<div align="center">

# WinSec-Analyzer

**PowerShell-Based Windows Security Auditing & Configuration Assessment Toolkit**

[![Version](https://img.shields.io/badge/version-0.8-blue)](https://github.com/MrFixRoot/WinSec-Analyzer)
![Status](https://img.shields.io/badge/status-active%20development-orange)
![Platform](https://img.shields.io/badge/platform-Windows-0078D4?logo=windows)
![PowerShell](https://img.shields.io/badge/PowerShell-7%20recommended-5391FE?logo=powershell&logoColor=white)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

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

**WinSec-Analyzer** is an open-source, PowerShell-based Windows security auditing toolkit designed to assess security configurations, identify potential weaknesses, collect technical evidence, and provide actionable hardening recommendations.

The project organizes its assessments into five security categories:

1. **System Security**
2. **Network Security**
3. **Identity & Access Security**
4. **Logging & Auditing**
5. **Services & Hardening**

WinSec-Analyzer is intended for system administrators, cybersecurity professionals, security auditors, and authorized defensive assessments.

> **Development status:** The application framework and project structure are available. The auditing engine, control evaluation logic, scoring, and report generation are not yet integrated.

## Security Assessment Categories

| Category | Planned assessments |
|---|---|
| **System Security** | Microsoft Defender, BitLocker, Windows Update |
| **Network Security** | Windows Firewall, listening TCP ports, Remote Desktop (RDP), network configuration |
| **Identity & Access Security** | Local users and administrators, Guest account, password policy, account lockout policy |
| **Logging & Auditing** | Windows Audit Policy, PowerShell logging, Script Block Logging, Module Logging, Transcription |
| **Services & Hardening** | SMBv1, Windows services, User Account Control (UAC), additional hardening controls |

## Implementation Status

**Status:** ✅ Implemented · 🚧 In development · ⏳ Pending

### Project Components

| Component | Status |
|---|:---:|
| Modular PowerShell project structure | ✅ |
| Application entry point (`Start-WinSec.ps1`) | ✅ |
| Configuration file scaffolding | ✅ |
| Security check module scaffolding | ✅ |
| Audit engine and check execution | ⏳ |
| Structured security findings | ⏳ |
| Weighted security scoring | ⏳ |
| TXT report export | ⏳ |
| JSON, CSV, and HTML reports | ⏳ |
| Automated unit and integration tests | ⏳ |

### Security Checks

| Category | Security Check | Status |
|---|---|:---:|
| System Security | Microsoft Defender | ⏳ |
| System Security | BitLocker | ⏳ |
| System Security | Windows Update | ⏳ |
| Network Security | Windows Firewall | ⏳ |
| Network Security | Listening TCP Ports | ⏳ |
| Network Security | Remote Desktop (RDP) | ⏳ |
| Network Security | Network Configuration | ⏳ |
| Identity & Access Security | Local Administrators | ⏳ |
| Identity & Access Security | Guest Account | ⏳ |
| Identity & Access Security | Password Policy | ⏳ |
| Identity & Access Security | Account Lockout Policy | ⏳ |
| Logging & Auditing | Audit Policy | ⏳ |
| Logging & Auditing | PowerShell Logging | ⏳ |
| Services & Hardening | SMBv1 | ⏳ |
| Services & Hardening | Windows Services | ⏳ |
| Services & Hardening | User Account Control (UAC) | ⏳ |

> Some security check files exist as placeholders. They are not classified as implemented until they perform real assessments and return structured results.

## Assessment Results and Scoring

Planned assessment results include a control ID, category, status, severity, observed and expected configurations, evidence, and remediation recommendations.

| Status | Meaning |
|---|---|
| `PASS` | The evaluated control meets the defined security criteria |
| `WARNING` | The configuration requires review |
| `FAIL` | An insecure configuration was identified |
| `INFO` | Informational result |
| `ERROR` | The control could not be evaluated |
| `N/A` | The control is not applicable |

The planned scoring engine will calculate scores on a **0–100 scale** using configurable control and category weights. An `ERROR` or `N/A` result must not automatically be treated as a failure.

## Architecture

The project separates security check collection, assessment processing, and supporting services.

| Path | Responsibility |
|---|---|
| `Start-WinSec.ps1` | Application launcher |
| `src/Core/` | Audit orchestration, findings, result model, and scoring |
| `src/Checks/` | Independent Windows security controls |
| `src/Services/` | System information, export, reporting, and logs |
| `src/CLI/` | Application controller |
| `config/` | Project metadata, security checks, and scoring configuration |
| `docs/` | Architecture and technical documentation |
| `tests/` | Unit and integration tests |
| `reports/` | Generated assessment reports |
| `logs/` | Application logs |

The goal is to keep assessment logic independent from presentation so that findings can be reused across reports and future execution modes.

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or later; **PowerShell 7 recommended**
- Administrator privileges recommended for complete assessments
- Availability of the relevant Windows management modules and services

## Installation

```powershell
git clone https://github.com/MrFixRoot/WinSec-Analyzer.git
cd WinSec-Analyzer
.\Start-WinSec.ps1
```

> The application currently launches for development and testing. Security auditing will be available after the assessment engine and security checks are integrated.

## Roadmap

- [ ] Implement and integrate security assessment modules.
- [ ] Introduce structured findings and severity classification.
- [ ] Implement configurable security scoring.
- [ ] Add TXT, JSON, CSV, and HTML reporting.
- [ ] Correlate related security controls.
- [ ] Add automated tests and compatibility validation.
- [ ] Associate findings with cybersecurity framework references.

### Planned Security Framework References

| Framework | Purpose | Status |
|---|---|:---:|
| CIS Benchmarks | Windows secure configuration guidance | ⏳ |
| CIS Controls | Prioritized cybersecurity safeguards | ⏳ |
| NIST CSF | Cybersecurity risk management | ⏳ |
| MITRE ATT&CK | Adversary technique context | ⏳ |

Framework mappings will provide technical context and do not constitute compliance certification.

## Responsible Use

WinSec-Analyzer is intended for authorized defensive security activities. It is designed primarily for read-only configuration assessment rather than automatic remediation. Review and protect collected evidence, and validate findings before making changes to production systems.

## Contributing

Contributions, bug reports, and enhancement suggestions are welcome through [GitHub Issues](https://github.com/MrFixRoot/WinSec-Analyzer/issues).

Contributors should document modified files and preserve applicable copyright and attribution notices as required by the license.

## License and Attribution

Copyright © 2026 **Norman López P. (mrRoot / MrFixRoot)**.

WinSec-Analyzer is licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for the full license text and [NOTICE](NOTICE) for original-author attribution.

Forks and derivative works may be created and distributed under the terms of Apache 2.0. Redistributors must preserve applicable copyright and attribution notices, as specified in the license. This attribution recognizes the original author; it does not imply authorship of modifications made by third parties.

## Author

**Norman López P. — mrRoot (MrFixRoot)**

- GitHub: [MrFixRoot](https://github.com/MrFixRoot)
- LinkedIn: [normanlp](https://www.linkedin.com/in/normanlp/)
- Repository: [WinSec-Analyzer](https://github.com/MrFixRoot/WinSec-Analyzer)

---

<div align="center">

**WinSec-Analyzer**

*PowerShell-Based Windows Security Auditing & Configuration Assessment Toolkit*

**Developed by mrRoot**

</div>
