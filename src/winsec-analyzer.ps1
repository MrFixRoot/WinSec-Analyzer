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
    'Show-MainMenu',
    'Get-SystemInfo',
    'Test-WindowsFirewall',
    'Test-OpenPorts'
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

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Initializing system information scan..." `
                -PercentComplete 10

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Collecting Windows system information..." `
                -PercentComplete 40

            $SystemInfo = Get-SystemInfo

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Processing system information..." `
                -PercentComplete 80

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "System information scan completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            Write-Host ""

            $SystemInfo | Format-List

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

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Checking Windows Firewall service..." `
                -PercentComplete 10

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Reading Firewall profiles..." `
                -PercentComplete 30

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Analyzing Firewall policies..." `
                -PercentComplete 50

            $FirewallResults = @(
                Test-WindowsFirewall
            )

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Analyzing inbound Firewall rules..." `
                -PercentComplete 75

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Calculating Firewall security score..." `
                -PercentComplete 90

            # ------------------------------------------------
            # Calculate Firewall score
            # ------------------------------------------------

            $FirewallScoredResults = @(
                $FirewallResults |
                    Where-Object {
                        $_.MaxScore -gt 0
                    }
            )

            $ObtainedPoints = (
                $FirewallScoredResults |
                    Measure-Object -Property Score -Sum
            ).Sum

            $MaximumPoints = (
                $FirewallScoredResults |
                    Measure-Object -Property MaxScore -Sum
            ).Sum

            if ($null -eq $ObtainedPoints) {
                $ObtainedPoints = 0
            }

            if ($null -eq $MaximumPoints) {
                $MaximumPoints = 0
            }

            if ($MaximumPoints -gt 0) {

                $FirewallScore = [math]::Round(
                    ($ObtainedPoints / $MaximumPoints) * 100
                )
            }
            else {

                $FirewallScore = 0
            }

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Firewall assessment completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            # ------------------------------------------------
            # Results
            # ------------------------------------------------

            Write-Host ""
            Write-Host "Firewall Security Controls"
            Write-Host "--------------------------"
            Write-Host ""

            $FirewallResults |
                Format-Table `
                    Control,
                    Status,
                    Severity,
                    Score,
                    MaxScore `
                    -AutoSize

            Write-Host ""
            Write-Host "Firewall Security Score: $FirewallScore/100"

            # ------------------------------------------------
            # Findings
            # ------------------------------------------------

            $FirewallFindings = @(
                $FirewallResults |
                    Where-Object {
                        $_.Status -eq 'FAIL' -or
                        $_.Status -eq 'WARNING' -or
                        $_.Status -eq 'ERROR'
                    }
            )

            if ($FirewallFindings.Count -gt 0) {

                Write-Host ""
                Write-Host "Security Findings"
                Write-Host "-----------------"

                foreach ($Finding in $FirewallFindings) {

                    Write-Host ""
                    Write-Host "[$($Finding.Status)] $($Finding.Control)"
                    Write-Host "Severity: $($Finding.Severity)"

                    Write-Host "Evidence:"
                    Write-Host "  $($Finding.Evidence)"

                    Write-Host "Recommendation:"
                    Write-Host "  $($Finding.Recommendation)"
                }
            }
            else {

                Write-Host ""
                Write-Host "No Firewall security findings detected."
            }

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 3 - OPEN PORTS
        # ====================================================

        '3' {

            Clear-Host

            Write-Host "========================================"
            Write-Host "          Open Ports Assessment"
            Write-Host "========================================"
            Write-Host ""

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Initializing network assessment..." `
                -PercentComplete 10

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Enumerating listening TCP ports..." `
                -PercentComplete 35

            $OpenPortResults = @(
                Test-OpenPorts
            )

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Resolving processes and Windows services..." `
                -PercentComplete 65

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Identifying sensitive services..." `
                -PercentComplete 85

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Status "Open ports assessment completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Analyzer" `
                -Completed

            # ------------------------------------------------
            # Listening ports
            # ------------------------------------------------

            Write-Host ""
            Write-Host "Listening TCP Ports"
            Write-Host "-------------------"
            Write-Host ""

            $OpenPortResults |
                Format-Table `
                    LocalAddress,
                    LocalPort,
                    KnownService,
                    ProcessName,
                    Exposure,
                    Status,
                    Severity `
                    -AutoSize

            # ------------------------------------------------
            # Open Port Findings
            # ------------------------------------------------

            $OpenPortFindings = @(
                $OpenPortResults |
                    Where-Object {
                        $_.Status -eq 'WARNING' -or
                        $_.Status -eq 'FAIL' -or
                        $_.Status -eq 'ERROR'
                    }
            )

            if ($OpenPortFindings.Count -gt 0) {

                Write-Host ""
                Write-Host "Security Findings"
                Write-Host "-----------------"

                foreach ($Finding in $OpenPortFindings) {

                    Write-Host ""
                    Write-Host "[$($Finding.Status)] $($Finding.Control) - $($Finding.KnownService)"
                    Write-Host "Severity: $($Finding.Severity)"

                    Write-Host "Process:"
                    Write-Host "  $($Finding.ProcessName) (PID $($Finding.ProcessId))"

                    Write-Host "Windows Service:"
                    Write-Host "  $($Finding.WindowsService)"

                    Write-Host "Exposure:"
                    Write-Host "  $($Finding.LocalAddress) - $($Finding.Exposure)"

                    Write-Host "Evidence:"
                    Write-Host "  $($Finding.Evidence)"

                    Write-Host "Recommendation:"
                    Write-Host "  $($Finding.Recommendation)"
                }
            }
            else {

                Write-Host ""
                Write-Host "No sensitive listening ports detected."
            }

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 4 - FULL SECURITY ASSESSMENT
        # ====================================================

        '4' {

            Clear-Host

            Write-Host "========================================"
            Write-Host "       Full Security Assessment"
            Write-Host "========================================"
            Write-Host ""

            $SystemInfo = $null
            $FirewallResults = @()
            $OpenPortResults = @()

            # ------------------------------------------------
            # Initialization
            # ------------------------------------------------

            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Initializing security assessment..." `
                -PercentComplete 5

            Start-Sleep -Milliseconds 250

            # ------------------------------------------------
            # System Information
            # ------------------------------------------------

            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Collecting system information..." `
                -PercentComplete 20

            $SystemInfo = Get-SystemInfo

            Start-Sleep -Milliseconds 250

            # ------------------------------------------------
            # Windows Firewall
            # ------------------------------------------------

            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Analyzing Windows Firewall..." `
                -PercentComplete 40

            $FirewallResults = @(
                Test-WindowsFirewall
            )

            Start-Sleep -Milliseconds 250

            # ------------------------------------------------
            # Open Ports
            # ------------------------------------------------

            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Analyzing listening TCP ports..." `
                -PercentComplete 65

            $OpenPortResults = @(
                Test-OpenPorts
            )

            Start-Sleep -Milliseconds 250

            # ------------------------------------------------
            # Calculate Security Score
            # ------------------------------------------------

            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Calculating security score..." `
                -PercentComplete 85

            # For now, Firewall controls affect the score.
            # Open Ports remains informational.

            $ScoredResults = @(
                $FirewallResults |
                    Where-Object {
                        $_.MaxScore -gt 0
                    }
            )

            $ObtainedPoints = (
                $ScoredResults |
                    Measure-Object -Property Score -Sum
            ).Sum

            $MaximumPoints = (
                $ScoredResults |
                    Measure-Object -Property MaxScore -Sum
            ).Sum

            if ($null -eq $ObtainedPoints) {
                $ObtainedPoints = 0
            }

            if ($null -eq $MaximumPoints) {
                $MaximumPoints = 0
            }

            if ($MaximumPoints -gt 0) {

                $SecurityScore = [math]::Round(
                    ($ObtainedPoints / $MaximumPoints) * 100
                )
            }
            else {

                $SecurityScore = 0
            }

            # ------------------------------------------------
            # Determine Risk Level
            # ------------------------------------------------

            if ($SecurityScore -ge 90) {

                $RiskLevel = 'LOW'
            }
            elseif ($SecurityScore -ge 75) {

                $RiskLevel = 'MODERATE'
            }
            elseif ($SecurityScore -ge 50) {

                $RiskLevel = 'HIGH'
            }
            else {

                $RiskLevel = 'CRITICAL'
            }

            # ------------------------------------------------
            # Complete progress
            # ------------------------------------------------

            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Generating assessment results..." `
                -PercentComplete 95

            Start-Sleep -Milliseconds 250

            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Status "Assessment completed" `
                -PercentComplete 100

            Start-Sleep -Milliseconds 300

            Write-Progress `
                -Activity "WinSec Security Assessment" `
                -Completed

            # =================================================
            # SYSTEM INFORMATION
            # =================================================

            Write-Host ""
            Write-Host "========================================"
            Write-Host "          System Information"
            Write-Host "========================================"
            Write-Host ""

            $SystemInfo | Format-List

            # =================================================
            # WINDOWS FIREWALL
            # =================================================

            Write-Host ""
            Write-Host "========================================"
            Write-Host "       Windows Firewall Assessment"
            Write-Host "========================================"
            Write-Host ""

            $FirewallResults |
                Format-Table `
                    Control,
                    Status,
                    Severity,
                    Score,
                    MaxScore `
                    -AutoSize

            # =================================================
            # OPEN PORTS
            # =================================================

            Write-Host ""
            Write-Host "========================================"
            Write-Host "          Open Ports Assessment"
            Write-Host "========================================"
            Write-Host ""

            $OpenPortResults |
                Format-Table `
                    LocalAddress,
                    LocalPort,
                    KnownService,
                    ProcessName,
                    Exposure,
                    Status,
                    Severity `
                    -AutoSize

            # =================================================
            # GLOBAL SECURITY SCORE
            # =================================================

            Write-Host ""
            Write-Host "========================================"
            Write-Host "          Security Assessment"
            Write-Host "========================================"
            Write-Host ""

            Write-Host "Security Score : $SecurityScore/100"
            Write-Host "Risk Level     : $RiskLevel"

            # =================================================
            # COMBINE RESULTS
            # =================================================

            $AllResults = @()

            $AllResults += $FirewallResults
            $AllResults += $OpenPortResults

            # =================================================
            # SECURITY FINDINGS
            # =================================================

            $Findings = @(
                $AllResults |
                    Where-Object {
                        $_.Status -eq 'FAIL' -or
                        $_.Status -eq 'WARNING' -or
                        $_.Status -eq 'ERROR'
                    }
            )

            Write-Host ""
            Write-Host "Security Findings"
            Write-Host "-----------------"

            if ($Findings.Count -eq 0) {

                Write-Host ""
                Write-Host "No security findings detected."
            }
            else {

                foreach ($Finding in $Findings) {

                    Write-Host ""
                    Write-Host "[$($Finding.Status)] $($Finding.Control)"
                    Write-Host "Severity: $($Finding.Severity)"

                    # -----------------------------------------
                    # Known service
                    # -----------------------------------------

                    if (
                        $Finding.PSObject.Properties.Name -contains 'KnownService'
                    ) {

                        if (
                            $Finding.KnownService -ne 'Unknown' -and
                            $Finding.KnownService -ne '-'
                        ) {

                            Write-Host "Service:"
                            Write-Host "  $($Finding.KnownService)"
                        }
                    }

                    # -----------------------------------------
                    # Process
                    # -----------------------------------------

                    if (
                        $Finding.PSObject.Properties.Name -contains 'ProcessName'
                    ) {

                        if (
                            $Finding.ProcessName -ne 'Unknown' -and
                            $Finding.ProcessName -ne '-'
                        ) {

                            Write-Host "Process:"
                            Write-Host "  $($Finding.ProcessName) (PID $($Finding.ProcessId))"
                        }
                    }

                    # -----------------------------------------
                    # Exposure
                    # -----------------------------------------

                    if (
                        $Finding.PSObject.Properties.Name -contains 'Exposure'
                    ) {

                        Write-Host "Exposure:"
                        Write-Host "  $($Finding.Exposure)"
                    }

                    # -----------------------------------------
                    # Evidence
                    # -----------------------------------------

                    Write-Host "Evidence:"
                    Write-Host "  $($Finding.Evidence)"

                    # -----------------------------------------
                    # Recommendation
                    # -----------------------------------------

                    Write-Host "Recommendation:"
                    Write-Host "  $($Finding.Recommendation)"
                }
            }

            # =================================================
            # SUMMARY
            # =================================================

            $PassCount = @(
                $AllResults |
                    Where-Object {
                        $_.Status -eq 'PASS'
                    }
            ).Count

            $WarningCount = @(
                $AllResults |
                    Where-Object {
                        $_.Status -eq 'WARNING'
                    }
            ).Count

            $FailCount = @(
                $AllResults |
                    Where-Object {
                        $_.Status -eq 'FAIL'
                    }
            ).Count

            $ErrorCount = @(
                $AllResults |
                    Where-Object {
                        $_.Status -eq 'ERROR'
                    }
            ).Count

            $InfoCount = @(
                $AllResults |
                    Where-Object {
                        $_.Status -eq 'INFO'
                    }
            ).Count

            Write-Host ""
            Write-Host "========================================"
            Write-Host "          Assessment Summary"
            Write-Host "========================================"
            Write-Host ""

            Write-Host "PASS    : $PassCount"
            Write-Host "WARNING : $WarningCount"
            Write-Host "FAIL    : $FailCount"
            Write-Host "ERROR   : $ErrorCount"
            Write-Host "INFO    : $InfoCount"

            Write-Host ""
            Write-Host "Security Score : $SecurityScore/100"
            Write-Host "Risk Level     : $RiskLevel"

            Write-Host ""
            Read-Host "Press Enter to return to the menu"
        }

        # ====================================================
        # OPTION 0 - EXIT
        # ====================================================

        '0' {

            Clear-Host

            Write-Host ""
            Write-Host "========================================"
            Write-Host "          WinSec Analyzer"
            Write-Host "========================================"
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