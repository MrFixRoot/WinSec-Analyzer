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

PowerShell-based Windows security auditing toolkit.
        linkedin.com/in/normandaniell
```

**Author:** Norman Daniel L. / **mrRoot**  
**LinkedIn:** [linkedin.com/in/normandaniell](https://www.linkedin.com/in/normandaniell/)

WinSec-Analyzer is a PowerShell-based Windows security assessment tool designed to collect, analyze, and report security-related configuration information.

## Project Status

🚧 **Early Development**

## Objectives

WinSec-Analyzer aims to evaluate different security aspects of Windows systems, including:

| Security Check | Status |
|---|---|
| Operating System Information | ✅ Implemented |
| Local Users and Administrators | ⏳ Planned |
| Windows Defender Status | ✅ Implemented |
| Windows Firewall Configuration | ✅ Implemented |
| BitLocker Status | ⏳ Planned |
| User Account Control (UAC) | ⏳ Planned |
| Remote Desktop Configuration | ⏳ Planned |
| SMB Configuration | ⏳ Planned |
| PowerShell Security Settings | ⏳ Planned |
| Network Configuration | ⏳ Planned |
| Listening Ports | ✅ Implemented |
| Audit Policies | ⏳ Planned |

## Requirements

- Windows 10 / Windows 11
- PowerShell 7 recommended
- Administrator privileges may be required for some checks

## Usage

Clone the repository:

```powershell
git clone https://github.com/MrFixRoot/WinSec-Analyzer
```

Enter the project directory:

```powershell
cd WinSec-Analyzer
```

Run WinSec-Analyzer:

```powershell
.\run.ps1
```

## Security and Responsible Use

WinSec-Analyzer is intended for authorized security auditing, system administration, education, and defensive security purposes.

Users are responsible for ensuring that they have appropriate authorization before running the tool on any system.

The authors and contributors are not responsible for misuse, unauthorized use, system modifications, data loss, service disruption, or other damages resulting from the use of this software.

WinSec-Analyzer is designed primarily as a read-only security assessment tool. Findings should be reviewed and validated before making configuration changes to production systems.

## License

This project is licensed under the MIT License.

See the [LICENSE](LICENSE) file for details.

## Author

**Norman Daniel L. — mrRoot**

[LinkedIn](https://www.linkedin.com/in/normandaniell/)