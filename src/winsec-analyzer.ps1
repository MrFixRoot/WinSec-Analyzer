<#
.SYNOPSIS
    Windows Security Analyzer.

.DESCRIPTION
    WinSec-Analyzer is a PowerShell-based security auditing tool
    designed to collect and analyze security-related configuration
    information from Windows systems.

.NOTES
    Project: WinSec-Analyzer
    Author: Norman Daniel L.
    LinkedIn: https://www.linkedin.com/in/normandaniell/
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$WinSecVersion = '0.8'

# ============================================================
# PROJECT PATHS
# ============================================================

$FunctionsPath = Join-Path $PSScriptRoot 'functions'

# ============================================================
# LOAD FUNCTIONS
# ============================================================

if (-not (Test-Path $FunctionsPath)) {
    Write-Error "Functions directory not found: $FunctionsPath"
    exit 1
}

Get-ChildItem -Path $FunctionsPath -Filter '*.ps1' |
    Sort-Object Name |
    ForEach-Object {
        . $_.FullName
    }

# ============================================================
# VERIFY REQUIRED FUNCTIONS
# ============================================================

$RequiredFunctions = @(
    'Show-Banner',
    'Show-MainMenu',
    'Show-SectionHeader',
    'Show-AssessmentResults',
    'Get-SystemInfo',
    'Test-WindowsFirewall',
    'Test-OpenPorts',
    'Test-WindowsDefender',
    'Test-BitLocker',
    'Test-SMB'
    

)

foreach ($FunctionName in $RequiredFunctions) {

    if (-not (Get-Command $FunctionName -ErrorAction SilentlyContinue)) {

        Write-Error "Required function not found: $FunctionName"
        exit 1
    }
}

# ============================================================
# MAIN APPLICATION LOOP
# ============================================================

do {

    Show-MainMenu -Version $WinSecVersion

    $Selection = Read-Host "Select an option"

    switch ($Selection) {

        # ====================================================
        # OPTION 1 - SYSTEM INFORMATION
        # ====================================================

        '1' {

            Clear-Host

            Show-Banner -Version $WinSecVersion
            Show-SectionHeader -Title "SYSTEM INFORMATION"

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Collecting system information..." `
                -PercentComplete 30

            $SystemInfo = Get-SystemInfo

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Processing system information..." `
                -PercentComplete 80

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            $SystemInfo | Format-List

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 2 - WINDOWS FIREWALL
        # ====================================================

        '2' {

            Clear-Host

            Show-Banner -Version $WinSecVersion
            Show-SectionHeader -Title "WINDOWS FIREWALL"

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Analyzing Windows Firewall..." `
                -PercentComplete 25

            $FirewallResults = @(
                Test-WindowsFirewall
            )

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Processing Firewall findings..." `
                -PercentComplete 75

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            Show-AssessmentResults `
                -Title "Windows Firewall Assessment" `
                -Results $FirewallResults `
                -TableColumns @(
                    'Control',
                    'Status',
                    'Severity',
                    'Score',
                    'MaxScore'
                )

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 3 - OPEN PORTS
        # ====================================================

        '3' {

            Clear-Host

            Show-Banner -Version $WinSecVersion
            Show-SectionHeader -Title "OPEN PORTS"

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Scanning listening TCP ports..." `
                -PercentComplete 30

            $OpenPortResults = @(
                Test-OpenPorts
            )

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Analyzing exposed services..." `
                -PercentComplete 80

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            Show-AssessmentResults `
                -Title "Open Ports" `
                -Results $OpenPortResults `
                -TableColumns @(
                    'LocalAddress',
                    'LocalPort',
                    'KnownService',
                    'ProcessName',
                    'Exposure',
                    'Status',
                    'Severity'
                )

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        '4' {

            Clear-Host

            Show-Banner -Version $WinSecVersion
            Show-SectionHeader -Title "WINDOWS DEFENDER"

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Analyzing Microsoft Defender..." `
                -PercentComplete 30

            $DefenderResults = @(
                Test-WindowsDefender
            )

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Processing Defender findings..." `
                -PercentComplete 80

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            Show-AssessmentResults `
                -Title "Windows Defender" `
                -Results $DefenderResults `
                -TableColumns @(
                    'Control',
                    'Status',
                    'Severity',
                    'Score',
                    'MaxScore'
                )

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 5 - BITLOCKER
        # ====================================================

        '5' {

            Clear-Host

            Show-Banner -Version $WinSecVersion
            Show-SectionHeader -Title "BITLOCKER"

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Analyzing BitLocker..." `
                -PercentComplete 30

            $BitLockerResults = @(
                Test-BitLocker
            )

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Processing BitLocker findings..." `
                -PercentComplete 80

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            Show-AssessmentResults `
                -Title "BitLocker Assessment" `
                -Results $BitLockerResults `
                -TableColumns @(
                    'Control',
                    'Status',
                    'Severity',
                    'Score',
                    'MaxScore'
                )

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 6 - SMB SECURITY
        # ====================================================

        '6' {

            Clear-Host

            Show-Banner -Version $WinSecVersion
            Show-SectionHeader -Title "SMB SECURITY"

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Reading SMB configuration..." `
                -PercentComplete 20

            Start-Sleep -Milliseconds 250

            $SMBResults = @(
                Test-SMB
            )

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Analyzing SMB protocols..." `
                -PercentComplete 50

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Checking signing and guest authentication..." `
                -PercentComplete 75

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Evaluating SMB security posture..." `
                -PercentComplete 90

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "SMB assessment completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            Show-AssessmentResults `
                -Title "SMB Security" `
                -Results $SMBResults `
                -TableColumns @(
                    'Control',
                    'Status',
                    'Severity',
                    'Score',
                    'MaxScore'
                )

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 0 - EXIT
        # ====================================================

        '0' {
            
            Clear-Host
            Write-Host ""
            Write-Host "██╗    ██╗██╗███╗   ██╗███████╗███████╗ ██████╗" -ForegroundColor Cyan
            Write-Host "██║    ██║██║████╗  ██║██╔════╝██╔════╝██╔════╝" -ForegroundColor Cyan
            Write-Host "██║ █╗ ██║██║██╔██╗ ██║███████╗█████╗  ██║     " -ForegroundColor Cyan
            Write-Host "██║███╗██║██║██║╚██╗██║╚════██║██╔══╝  ██║     " -ForegroundColor Cyan
            Write-Host "╚███╔███╔╝██║██║ ╚████║███████║███████╗╚██████╗" -ForegroundColor Cyan
            Write-Host " ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝" -ForegroundColor Cyan

            Write-Host ""
            Write-Host "            WinSec-Analyzer v$Version" -ForegroundColor White
            Write-Host "                 mrRoot" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "PowerShell-based Windows security auditing toolkit" -ForegroundColor DarkGray
            Write-Host "      linkedin.com/in/normandaniell" -ForegroundColor DarkCyan
            Write-Host ""
            Write-Host "Exiting..."
            Write-Host ""
        }

        # ====================================================
        # INVALID OPTION
        # ====================================================

        default {

            Write-Host ""
            Write-Warning "Invalid option."

            Start-Sleep -Seconds 1
        }
    }

} while ($Selection -ne '0')