
<div align="center">

# WinSec-Analyzer

**PowerShell-Based Windows Security Auditing & Configuration Assessment Toolkit**

[![Version](https://img.shields.io/badge/version-0.9.0-blue)](https://github.com/MrFixRoot/WinSec-Analyzer)
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

WinSec Analyzer is a Windows command-line security assessment tool written primarily in PowerShell. It **collects local security configuration**, preserves safe records for each device and scan, and reviews those records against selected framework references. Findings include configuration warnings and manual recommendations with traceable sources.

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

The CLI provides keyboard navigation, persistent hardware identity and editable device names, confirmed device/section/control scans, public scan history and interactive findings.

**Microsoft Defender, BitLocker and Windows Update** are enabled for explicitly confirmed, read-only local scans. BitLocker inspects only the Windows volume. Windows Update reads local configuration and installed revision metadata; it does not search for, download or install updates. Other checks remain disabled pending individual validation.

Each completed scan automatically writes a separate, organized **technical Markdown snapshot per executed control**. These files retain the permitted detailed readings, including informative values and explicit unknown/unavailable states, for later manual analysis. They are separate from the selected framework findings report.

Press **F** to choose **NIST CSF, CIS Controls or MITRE ATT&CK** and review saved data with a progress indicator. The analysis considers all available permitted readings and recorded deviations using reviewed warning rules. Readings without a reviewed rule remain informational; missing data is reported as a coverage limitation. Opening Findings never runs another Windows scan.

Press **P** in Findings to export **the same selected framework view as Markdown** with warning details, reference controls, descriptions and manual recommendations. Original scan records remain unchanged. Earlier scans without detailed snapshots cannot reconstruct readings that were never saved.

Historical comparisons and broader native compatibility coverage remain under development. Framework references provide context rather than a complete compliance audit.

### Collection status and data origin

| Label | Meaning | Color |
| --- | --- | --- |
| `PENDING` | No completed collection for the requested controls | Red |
| `PARTIAL` | Some controls are missing or collection encountered errors | Yellow |
| `COMPLETE` | The requested collection finished; warnings may still exist | Green |
| `LIVE` | Results collected in this application session on the current device | Green |
| `RECORDS` | Previously stored results, or a view containing historical sources | Navy blue |

Completion describes the scan, not whether a device is secure. Framework findings retain the identity and date of each contributing scan.

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

Select the current local device. Navigation and available actions depend on the screen and permission checks. A visible Scan/Rescan shortcut does **not** mean every catalog check is executable. Leave unvalidated checks disabled.

## Assessment workflow

1. Load the locally stored device inventory and select the current computer.
2. Choose the whole device, one security section, or one individual control.
3. Display **Scan** if no valid assessment exists for that exact scope, otherwise **Rescan**.
4. Show the actual enabled controls and request confirmation before executing.
5. Collect read-only information, validate applicability, save safe public results and a technical `.md` per executed control.
6. Press **F**, select a framework and review warnings from the saved readings with visible analysis progress. Use arrows to inspect findings and **Esc** to return or cancel.
7. Press **P** to print the selected findings report as `.md`, including framework references and manual recommendations.

Scan and deletion confirmations use arrows to select **Accept / Cancel**, **Enter** to execute the selection and **Esc** to cancel. No scan runs automatically when opening or resizing a screen.

## Framework references

The project's framework catalogues cover:

- **CIS Controls** — prioritized security safeguards.
- **NIST Cybersecurity Framework (CSF)** — risk-management context.
- **MITRE ATT&CK** — adversary behavior and defensive context.

Mappings provide **references and context**, not certification or a declaration of compliance. A warning may require checking applicability, an approved exception or replacement protection. It is not proof that an attack occurred. The report records framework/rule versions, source scans and available coverage without rewriting the historical results.

## Repository layout

```text
WinSec-Analyzer/
├── Start-WinSec.ps1
├── config/          # Checks, criteria and framework catalogues
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
├── reports/         # Technical snapshots and requested findings reports (never commit)
└── docs/            # Public technical documentation
```

Internal Codex working files and local assessment data are intentionally excluded from the public repository.

## Tests

The project uses native PowerShell test scripts; **Pester is not required**. Test suites are located in `tests/Unit/` and `tests/Integration/`.

Always inspect a test before running it and make sure the current configuration meets its safety prerequisites. A passing test does not by itself establish that every security control is production-ready.

## Safety and privacy

- No automatic remediation or changes to audited Windows configuration.
- Every Scan/Rescan requires explicit confirmation of its device, scope and executable controls.
- No automatic collection/execution at startup.
- Raw evidence must never be stored or exported without separate authorization.
- Local device inventories, scan histories, logs, exports and internal Codex documentation are not meant for publication.
- Unknown/unavailable readings, unfinished collection and unselected checks are **not** failed security requirements or proof of compliance.

## Project documents

- [Security checks](docs/SecurityChecks.md)
- [Keyboard shortcuts](docs/KeyboardShortcuts.md)
- [Framework mappings](docs/FrameworkMappings.md)
- [License](LICENSE)
- [Attribution and notices](NOTICE)

The existing `README.md`, `LICENSE` and `NOTICE` remain public files. Review the license terms before redistributing modified versions.

## Development status

WinSec Analyzer is under active development. New features must be backed by verified read-only behavior, tests, and clear provenance before they are documented as complete.
