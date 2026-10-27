
# ============================================================
# WinSec Analyzer
# Integration Tests
#
# Component : CLI + ScanCoordinator Initialization
# Version   : 0.9.0
# Author    : mrRoot
#
# PowerShell 5.1 / 7.x
# No Pester required
#
# Security:
# - No audit execution
# - No scoring activation
# - No remote connections
# - No evidence persistence
# ============================================================

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# TEST ENVIRONMENT
# ------------------------------------------------------------

$projectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

$cliPath = Join-Path $projectRoot `
    'src/CLI/Invoke-WinSecCLI.ps1'

$coordinatorPath = Join-Path $projectRoot `
    'src/Core/ScanCoordinator.ps1'

$passed = 0
$failed = 0

function Assert-WinSecIntegration {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Description
    )

    if ($Condition) {
        Write-Host "[PASS] $Description" `
            -ForegroundColor Green

        $script:passed++
    }
    else {
        Write-Host "[FAIL] $Description" `
            -ForegroundColor Red

        $script:failed++
    }
}

Write-Host ''
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ' WINSEC ANALYZER - INTEGRATION TESTS' `
    -ForegroundColor Cyan
Write-Host ' CLI + SCAN COORDINATOR' `
    -ForegroundColor Cyan
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------
# TEST 1: Required components exist
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        (Test-Path -LiteralPath $cliPath -PathType Leaf) -and
        (Test-Path -LiteralPath $coordinatorPath -PathType Leaf)
    ) `
    -Description 'Required component files exist'

if (
    -not (Test-Path -LiteralPath $cliPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $coordinatorPath -PathType Leaf)
) {
    throw 'Required integration files are missing.'
}

# ------------------------------------------------------------
# TEST 2: CLI syntax is valid
# ------------------------------------------------------------

$tokens = $null
$parseErrors = $null

$null = [System.Management.Automation.Language.Parser]::ParseFile(
    $cliPath,
    [ref]$tokens,
    [ref]$parseErrors
)

Assert-WinSecIntegration `
    -Condition (@($parseErrors).Count -eq 0) `
    -Description 'CLI PowerShell syntax is valid'

if (@($parseErrors).Count -gt 0) {
    $parseErrors | ForEach-Object {
        Write-Host $_.Message -ForegroundColor Red
    }

    throw 'CLI syntax validation failed.'
}

# ------------------------------------------------------------
# LOAD REAL APPLICATION COMPONENTS
# ------------------------------------------------------------

. $cliPath
. $coordinatorPath
function Get-WinSecInitializationHardwareFixture { 'local:hw1-'+('d'*64) }
# CLI device discovery reloads target functions in its own scope; the alias keeps
# that provider boundary synthetic too.
Set-Alias -Name Get-WinSecLocalHardwareDeviceId -Value Get-WinSecInitializationHardwareFixture -Scope Script
function Get-CimInstance { throw 'Unexpected native query in initialization tests.' }

# ------------------------------------------------------------
# TEST 3: Coordinator initialization
# ------------------------------------------------------------

$coordinator = New-WinSecScanCoordinator `
    -ProjectRoot $projectRoot

Assert-WinSecIntegration `
    -Condition ($null -ne $coordinator) `
    -Description 'ScanCoordinator initializes successfully'

if ($null -eq $coordinator) {
    throw 'Cannot continue without ScanCoordinator.'
}

# ------------------------------------------------------------
# TEST 4: Correct component identity
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $coordinator.Component -eq 'ScanCoordinator'
    ) `
    -Description 'Coordinator identity is valid'

# ------------------------------------------------------------
# TEST 5: Security scoring is disabled
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $coordinator.ScoringEnabled -eq $false
    ) `
    -Description 'Security scoring remains disabled'

# ------------------------------------------------------------
# TEST 6: Remote execution is disabled
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $coordinator.RemoteExecution -eq $false
    ) `
    -Description 'Remote execution remains disabled'

# ------------------------------------------------------------
# TEST 7: Automatic evidence storage is disabled
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $coordinator.AutomaticEvidencePersistence -eq $false
    ) `
    -Description 'Automatic evidence persistence is disabled'

# ------------------------------------------------------------
# TEST 8: CLI reads registered devices
# ------------------------------------------------------------

$devices = @(
    Get-WinSecCLIDevices `
        -ProjectRoot $projectRoot
)

Assert-WinSecIntegration `
    -Condition ($devices.Count -ge 1) `
    -Description 'CLI loads registered devices'

# ------------------------------------------------------------
# TEST 9: Current local device exists
# ------------------------------------------------------------

$expectedLocalId = (New-WinSecLocalTarget).DeviceId

$localDevices = @(
    $devices | Where-Object {
        $_.DeviceId -ceq $expectedLocalId -and
        $_.Mode -ceq 'LOCAL' -and
        $_.Enabled -eq $true
    }
)

Assert-WinSecIntegration `
    -Condition ($localDevices.Count -eq 1) `
    -Description 'Current local device is registered once'

# ------------------------------------------------------------
# TEST 10: No unauthorized device scores
# ------------------------------------------------------------

$devicesWithScores = @(
    $devices | Where-Object {
        $null -ne $_.Score
    }
)

Assert-WinSecIntegration `
    -Condition ($devicesWithScores.Count -eq 0) `
    -Description 'Device metadata contains no trusted scores'

# ------------------------------------------------------------
# TEST 11: No scan sessions after initialization
# ------------------------------------------------------------

$history = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $coordinator
)

Assert-WinSecIntegration `
    -Condition ($history.Count -eq 0) `
    -Description 'Initialization creates no scan sessions'

# ------------------------------------------------------------
# TEST 12: Coordinator rejects unknown remote target
# ------------------------------------------------------------

$remoteRejected = $false

try {
    $null = Resolve-WinSecScanTarget `
        -Coordinator $coordinator `
        -DeviceId 'remote:WINSEC-UNKNOWN-TEST' `
        -ErrorAction Stop
}
catch {
    $remoteRejected = $true
}

Assert-WinSecIntegration `
    -Condition $remoteRejected `
    -Description 'Unknown remote target is rejected'

# ------------------------------------------------------------
# TEST 13: Separate coordinators have independent history
# ------------------------------------------------------------

$secondCoordinator = New-WinSecScanCoordinator `
    -ProjectRoot $projectRoot

$secondHistory = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $secondCoordinator
)

Assert-WinSecIntegration `
    -Condition (
        $null -ne $secondCoordinator -and
        $secondHistory.Count -eq 0 -and
        -not [object]::ReferenceEquals(
            $coordinator,
            $secondCoordinator
        )
    ) `
    -Description 'Coordinator instances are independent'

# ------------------------------------------------------------
# TEST 14: Initialization does not publish scan results
# ------------------------------------------------------------

$allHistory = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $coordinator
)

Assert-WinSecIntegration `
    -Condition ($allHistory.Count -eq 0) `
    -Description 'No assessment is published automatically'

# ------------------------------------------------------------
# RESULTS SUMMARY
# ------------------------------------------------------------

Write-Host ''
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ' INTEGRATION TEST SUMMARY' `
    -ForegroundColor Cyan
Write-Host '=========================================' `
    -ForegroundColor Cyan

Write-Host "Passed: $passed"
Write-Host "Failed: $failed"

if ($failed -gt 0) {
    Write-Host ''
    Write-Host '[FAIL] Integration validation failed.' `
        -ForegroundColor Red

    throw "$failed integration test(s) failed."
}

Write-Host ''
Write-Host '[PASS] All integration tests passed.' `
    -ForegroundColor Green

Write-Host 'ScanCoordinator initialized safely.' `
    -ForegroundColor Green

Write-Host 'No audits were executed.' `
    -ForegroundColor Green

Write-Host ''
