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

# ------------------------------------------------------------
# Project paths
# ------------------------------------------------------------

$FunctionsPath = Join-Path $PSScriptRoot 'functions'

# ------------------------------------------------------------
# Load functions
# ------------------------------------------------------------

Get-ChildItem -Path $FunctionsPath -Filter '*.ps1' |
    Sort-Object Name |
    ForEach-Object {

        Write-Host "Loading: $($_.Name)"

        . $_.FullName
    }

# Small pause so loading messages can be seen
Start-Sleep -Milliseconds 500

# ------------------------------------------------------------
# Main application
# ------------------------------------------------------------

do {

    Show-MainMenu

    $Selection = Read-Host "Select an option"

    switch ($Selection) {

        # ====================================================
        # OPTION 1 - SYSTEM INFORMATION
        # ====================================================

        '1' {

            Clear-Host

            Write-Host "========================================"
            Write-Host "          System Information"
            Write-Host "========================================"
            Write-Host ""

            # STEP 1
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Initializing system information scan..." `
                -PercentComplete 10

            Start-Sleep -Milliseconds 300

            # STEP 2
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Collecting Windows information..." `
                -PercentComplete 40

            Start-Sleep -Milliseconds 300

            # HERE THE REAL TOOL RUNS
            $SystemInfo = Get-SystemInfo

            # STEP 3
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Processing system information..." `
                -PercentComplete 75

            Start-Sleep -Milliseconds 300

            # STEP 4
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Scan completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 300

            # REMOVE PROGRESS BAR
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            # SHOW RESULTS
            $SystemInfo |
                Format-List

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 2 - WINDOWS FIREWALL
        # ====================================================

        '2' {

            Clear-Host

            Write-Host "========================================"
            Write-Host "       Windows Firewall Assessment"
            Write-Host "========================================"
            Write-Host ""

            # STEP 1
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Initializing Firewall assessment..." `
                -PercentComplete 10

            Start-Sleep -Milliseconds 300

            # STEP 2
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Reading Windows Firewall profiles..." `
                -PercentComplete 35

            Start-Sleep -Milliseconds 300

            # STEP 3
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Analyzing Firewall configuration..." `
                -PercentComplete 60

            # HERE THE REAL TOOL RUNS
            $FirewallResult = Test-WindowsFirewall

            # STEP 4
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Evaluating security status..." `
                -PercentComplete 85

            Start-Sleep -Milliseconds 300

            # STEP 5
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Assessment completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 300

            # REMOVE PROGRESS BAR
            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            # SHOW RESULTS
            $FirewallResult |
                Format-Table Control, Status, Severity, Score, MaxScore -AutoSize

            Write-Host ""
            Write-Host "Evidence:"
            Write-Host $FirewallResult.Evidence

            Write-Host ""
            Write-Host "Recommendation:"
            Write-Host $FirewallResult.Recommendation

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 3 - FULL SECURITY ASSESSMENT
        # ====================================================

        '3' {

            Clear-Host

            Write-Host "========================================"
            Write-Host "       Full Security Assessment"
            Write-Host "========================================"
            Write-Host ""

            $Results = @()

            # STEP 1
            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Initializing security assessment..." `
                -PercentComplete 10

            Start-Sleep -Milliseconds 300

            # STEP 2
            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Checking Windows Firewall..." `
                -PercentComplete 40

            # FIREWALL TOOL
            $Results += Test-WindowsFirewall

            # Future tools will go here:
            #
            # Write-Progress `
            #     -Activity "WinSec Security Assessment" `
            #     -Status "Checking Windows Defender..." `
            #     -PercentComplete 55
            #
            # $Results += Test-WindowsDefender

            # STEP 3
            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Processing security findings..." `
                -PercentComplete 80

            Start-Sleep -Milliseconds 300

            # STEP 4
            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Assessment completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 300

            # REMOVE PROGRESS BAR
            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Completed

            # SHOW RESULTS
            $Results |
                Format-Table Control, Status, Severity, Score, MaxScore -AutoSize

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 0 - EXIT
        # ====================================================

        '0' {

            Clear-Host

            Write-Host ""
            Write-Host "WinSec Analyzer"
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