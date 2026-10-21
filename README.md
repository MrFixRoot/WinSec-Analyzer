
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

## Overview

WinSec Analyzer is a Windows command-line security assessment project written primarily in PowerShell. Its purpose is to **inspect local security configuration**, organize findings by security domain, and eventually produce reports with context from recognized security frameworks.

**Strictly read-only:** WinSec Analyzer is an assessment tool, **not a system-hardening or remediation utility**. It never applies recommended fixes to the audited Windows installation. Only the computer on which the application is running may be scanned.

## Security assessment areas

| Section | Intended checks |
|---|---|
| **System Security** | Microsoft Defender, BitLocker, Windows Update |
| **Network Security** | Windows Firewall, SMBv1, Remote Desktop configuration, listening ports, network configuration |
| **Identity & Access Security** | Local administrators, Guest account, password policy |
| **Logging & Auditing** | PowerShell logging, Windows audit policy |
| **Services & Hardening** | Windows services and hardening checks |

These are catalogued **assessment targets**, not a promise that every check is enabled or fully implemented.

## Current capabilities and limitations

The repository contains a modular CLI, keyboard-driven navigation, a target registry, scanning/evaluation engines, public result models, and unit/integration test suites. A local Scan/Rescan shortcut has been displayed and exercised during development.

At the latest reviewed configuration snapshot, **all 14 check executions were disabled** pending validation, so an attempted local scan can correctly return `NO_EXECUTABLE_CHECKS`. Numeric scoring also remains **disabled** until its criteria and methodology are approved; the appropriate score state is `NOT_SCORED`.

The following are **planned / under integration**, and should not be presented as finished until tested: confirmation before every scan, device/section/control-scoped Scan/Rescan, persistent scan history, historical comparisons, remapping frameworks for past results, and complete Markdown/TXT export.

## Getting started

### Requirements

- Windows and PowerShell (compatibility target: **Windows PowerShell 5.1 and PowerShell 7.x**; validate both against your checkout).
- A local copy of the repository.
- Permission to read the relevant Windows security settings; some queries may be unavailable without appropriate privileges.

### Launch

From the repository root in PowerShell:

```powershell
.\Start-WinSec.ps1
```

Select the current local device. Navigation and available actions depend on the current screen and permission checks. A visible Scan/Rescan shortcut does **not** mean every catalog check is executable. Do not enable checks or scoring just to obtain a numeric result.

## Planned assessment workflow

1. Load the locally stored device inventory and select the current computer.
2. Choose the whole device, one security section, or one individual control.
3. Display **Scan** if no valid assessment exists for that exact scope, otherwise **Rescan**.
4. Show the actual enabled controls and request confirmation before executing.
5. Collect read-only information, evaluate with approved criteria, and save **safe public results** for the session.
6. Browse previous scans, review findings and manually actionable recommendations.
7. Export Markdown (`.md`, primary) or plain text (`.txt`, alternative) reports, with relevant framework references.

The workflow above is the approved design; availability of each step must be confirmed by tests.

## Framework references

The project's framework catalogues cover:

- **CIS Benchmarks** — Windows configuration guidance.
- **CIS Controls** — prioritized security safeguards.
- **NIST Cybersecurity Framework (CSF)** — risk-management context.
- **MITRE ATT&CK** — adversary behavior and defensive context.

Mappings provide **references and context**, not certification or a declaration of compliance. Planned exports can apply updated reference mappings to historical scan results without changing the original assessment.

## Repository layout

```text
WinSec-Analyzer/
├── Start-WinSec.ps1
├── config/          # Checks, criteria, scoring, framework catalogues
├── src/
│   ├── CLI/         # Interactive application
│   ├── Core/        # Coordination, validation and assessment models
│   ├── Checks/      # Local Windows read-only queries
│   ├── Services/    # Evidence, reporting and framework support
│   └── UI/          # Keyboard navigation, screens and renderer
├── data/            # Local inventory/session data (never commit)
├── tests/
│   ├── Unit/
│   └── Integration/
├── logs/            # Local logs (never commit)
├── reports/         # User-requested exports (never commit)
└── docs/            # Public technical documentation
```

Internal Codex working files and local assessment data are intentionally excluded from the public repository.

## Tests

The project uses native PowerShell test scripts; **Pester is not required**. Test suites are located in `tests/Unit/` and `tests/Integration/`.

Always inspect a test before running it and make sure the current configuration meets its safety prerequisites. A passing test does not by itself establish that every security control is production-ready.

## Safety and privacy

- No automatic remediation or changes to audited Windows configuration.
- Scans require explicit authorization and, in the approved workflow, confirmation.
- No automatic collection/execution at startup.
- Raw evidence must never be stored or exported without separate authorization.
- Local device inventories, scan histories, logs, exports and internal Codex documentation are not meant for publication.
- `NOT_SELECTED`, `NOT_EVALUATED` and `NOT_SCORED` are **not** statements of security compliance.

## Project documents

- [Security checks](docs/SecurityChecks.md)
- [Keyboard shortcuts](docs/KeyboardShortcuts.md)
- [Framework mappings](docs/FrameworkMappings.md)
- [License](LICENSE)
- [Attribution and notices](NOTICE)

The existing `README.md`, `LICENSE` and `NOTICE` remain public files. Review the license terms before redistributing modified versions.

## Development status

WinSec Analyzer is under active development. New features must be backed by verified read-only behavior, tests, and clear provenance before they are documented as complete.
