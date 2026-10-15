# WinSec Analyzer — Framework Mappings

**Version:** 0.9.0  
**Author:** mrRoot  
**Status:** Under Development

---

## 1. Overview

WinSec Analyzer supports security control mappings against four recognized cybersecurity frameworks:

| Framework | Purpose |
|---|---|
| CIS Benchmarks | Secure configuration recommendations for Windows |
| CIS Controls v8.1 | Prioritized cybersecurity safeguards |
| NIST CSF 2.0 | Cybersecurity risk management |
| MITRE ATT&CK Enterprise | Adversary techniques and defensive context |

Framework mappings provide additional context for security findings and recommendations.

**Framework references do not determine whether a security check passes or fails.** Assessment results are determined by the corresponding security check.

---

## 2. Project Architecture

### Framework configuration

The framework catalogs are stored in:

- `config/frameworks/cis-benchmarks.json`
- `config/frameworks/cis-controls.json`
- `config/frameworks/nist-csf.json`
- `config/frameworks/mitre-attack.json`

### Processing components

| Component | Responsibility |
|---|---|
| `src/Core/FrameworkMappingEngine.ps1` | Match security checks with framework references |
| `src/Core/FindingPriorityEngine.ps1` | Classify and prioritize security findings |
| `src/Services/FrameworkService.ps1` | Load and validate framework configuration files |
| `src/Core/FindingsEngine.ps1` | Process security assessment findings |
| `src/Services/ExportService.ps1` | Export assessment results and references |

### User interface

Framework information will be integrated into:

- `src/UI/Screens/Findings.ps1`
- `src/UI/Screens/Results.ps1`

The framework catalogs do not require a separate navigation section in the main dashboard.

---

## 3. Framework Mapping Structure

Each framework uses a JSON configuration containing:

- `schemaVersion`: WinSec framework catalog schema version.
- `frameworkId`: Unique framework identifier.
- `frameworkVersion`: Applicable framework version, where defined.
- `enabled`: Whether the framework is active.
- `source`: Official publication information.
- `mappings`: Relationships between WinSec security checks and framework references.
- `mappingRules`: Configuration validation and mapping requirements.

### Mapping identifiers

All framework mappings must reference a security check using its `checkId`.

The identifier must match a check defined in `config/checks.json`.

Mappings must not rely solely on human-readable check names.

### Framework-specific requirements

**CIS Benchmarks**

Mappings must identify the benchmark, its version, and the applicable recommendation. Windows platform compatibility must be considered.

**CIS Controls**

Mappings should reference specific safeguards using identifiers such as `X.Y`, where the identifier is verified against the selected CIS Controls version.

**NIST CSF**

Mappings must identify the applicable function, category, and subcategory using official NIST CSF 2.0 identifiers.

**MITRE ATT&CK**

Mappings must reference validated Enterprise ATT&CK technique or subtechnique identifiers, such as `Txxxx` or `Txxxx.xxx`.

ATT&CK references provide adversary behavior context and do not establish that an attack occurred.

---

## 4. Framework Validation

FrameworkService is responsible for:

1. Locating the JSON framework catalogs.
2. Loading their configuration.
3. Validating required structural properties.
4. Detecting missing or malformed files.
5. Identifying enabled and disabled frameworks.
6. Providing validated catalog structures to FrameworkMappingEngine.

FrameworkMappingEngine is responsible for matching check identifiers and validating supported reference formats and applicable platform requirements.

**Structural validation does not establish the correctness of a framework mapping.** Official references and the applicable framework versions must be checked before including mappings in production reports.

### Framework status

| Status | Meaning |
|---|---|
| CONFIGURED | Mapping records are present |
| UNMAPPED | No mappings have been configured |
| DISABLED | Framework integration is disabled |
| ERROR | Configuration could not be loaded or validated |

CONFIGURED does not imply that the mappings have been independently verified.

---

## 5. Finding Prioritization

FindingPriorityEngine classifies security findings using their declared severity or an explicitly assigned priority.

| Priority | Severity | Attention |
|---|---|---|
| P1 | Critical | Immediate |
| P2 | High | High |
| P3 | Medium | Medium |
| P4 | Low | Low |
| P5 | Informational | Informational |
| UNRATED | Unknown | Requires classification |

Findings are presented from highest to lowest priority.

Framework references provide context but do not automatically increase a finding's priority.

This model can later be extended with additional risk factors, provided that their weighting and source are explicitly documented.

---

## 6. Multi-Device Assessment

Framework mappings are shared across the project, while findings and scores belong to individual devices and assessment executions.

Each finding should maintain the following relationships:

| Field | Description |
|---|---|
| DeviceId | Unique device identifier |
| ScanId | Unique assessment execution identifier |
| CheckId | Security check identifier |
| FindingId | Unique finding identifier |
| Severity | Finding severity |
| Priority | Calculated or explicitly assigned priority |
| FrameworkReferences | Applicable framework mappings |
| Evidence | Collected security evidence |
| Recommendation | Recommended corrective action |

The same framework reference may apply to findings from multiple devices.

Assessment records must remain associated with their original device and execution.

---

## 7. UI Integration

### H — Security Findings

The Findings screen will display:

1. Security check and assessment status.
2. Finding priority and severity.
3. Finding description and collected evidence.
4. Recommended corrective action.
5. CIS Benchmarks references.
6. CIS Controls references.
7. NIST CSF references.
8. MITRE ATT&CK references.

Findings will be ordered by priority.

When no verified framework reference is available, the UI must not invent a mapping.

### P — Export TXT

The exported report will include:

- Device identification.
- Assessment identifier and execution date.
- Overall security score.
- Section and control scores.
- Security findings ordered by priority.
- Supporting evidence.
- Recommendations.
- Applicable framework references.

Report generation belongs to ExportService.

### Esc — Back Navigation

The Esc key must return the user to the previous screen without discarding assessment results.

Navigation behavior is managed by NavigationController.

---

## 8. Framework Maintenance

Framework catalogs must be maintained independently from security checks.

Before adding or modifying a mapping:

1. Identify the corresponding WinSec security check.
2. Verify its identifier in `config/checks.json`.
3. Locate the relevant framework publication.
4. Confirm the framework version and reference identifier.
5. Validate Windows applicability where required.
6. Add the mapping to the corresponding JSON catalog.
7. Test the mapping using FrameworkMappingEngine.
8. Verify that the finding and exported report display the intended reference.

Do not create approximate reference identifiers or unsupported relationships.

### Official sources

- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- CIS Controls: https://www.cisecurity.org/controls
- NIST CSF: https://www.nist.gov/cyberframework
- MITRE ATT&CK: https://attack.mitre.org/

---

## 10. Design Principles

WinSec Analyzer follows these principles:

- **Modularity:** Each component has a clearly defined responsibility.
- **Traceability:** Every framework reference must be linked to an identifiable security check.
- **Evidence-based reporting:** Findings must originate from actual assessment results.
- **Separation of concerns:** Framework mappings do not replace security checks or scoring logic.
- **Multi-device support:** Findings and evidence remain associated with the correct device.
- **Read-only auditing:** Security assessment functionality must not automatically modify target systems.
- **Transparency:** Missing data, unsupported checks, and incomplete mappings must be reported accurately.

---

**WinSec Analyzer — PowerShell-Based Windows Security Auditing & Configuration Assessment Toolkit**

Developed by **mrRoot**  
GitHub: https://github.com/MrFixRoot/WinSec-Analyzer
