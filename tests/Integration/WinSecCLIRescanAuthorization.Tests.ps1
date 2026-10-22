
# ============================================================
# WinSec Analyzer
# Integration Tests - CLI Rescan Authorization
#
# Version   : 0.9.0
# Author    : mrRoot
# Component : CLI + ScanCoordinator + TargetRegistry
#
# PowerShell 5.1 / 7.x
# No Pester required
#
# Security:
# - No real audit execution
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
Write-Host ' CLI RESCAN AUTHORIZATION' `
    -ForegroundColor Cyan
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------
# VERIFY REQUIRED FILES
# ------------------------------------------------------------

foreach ($path in @($cliPath, $coordinatorPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required file not found: $path"
    }
}

# ------------------------------------------------------------
# LOAD REAL PROJECT COMPONENTS
# ------------------------------------------------------------

. $cliPath
. (Join-Path $projectRoot 'src/UI/Screens/MainMenu.ps1')
. $coordinatorPath

# ------------------------------------------------------------
# INITIALIZE REAL COORDINATOR
# ------------------------------------------------------------

$coordinator = New-WinSecScanCoordinator `
    -ProjectRoot $projectRoot

if ($null -eq $coordinator) {
    throw 'ScanCoordinator initialization failed.'
}

$devices = @(
    Get-WinSecCLIDevices `
        -ProjectRoot $projectRoot
)

$localTarget = New-WinSecLocalTarget

if ($null -eq $localTarget) {
    throw 'Local target could not be resolved.'
}

$localId = [string]$localTarget.DeviceId

$state = [pscustomobject]@{
    Screen = 'MainMenu'
    SectionIndex = 0
    SelectedDeviceId = $localId
}

# ------------------------------------------------------------
# TEST 1: LOCAL TARGET AUTHORIZATION
# ------------------------------------------------------------

$authorized = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecIntegration `
    -Condition ($authorized -eq $true) `
    -Description 'Real coordinator authorizes local target'

# ------------------------------------------------------------
# TEST 2: REMOTE TARGET REJECTION
# ------------------------------------------------------------

$state.SelectedDeviceId = 'remote:UNKNOWN-TEST'

$authorized = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecIntegration `
    -Condition ($authorized -eq $false) `
    -Description 'Remote target is rejected'

$state.SelectedDeviceId = $localId

# ------------------------------------------------------------
# TEST 3: SCREEN RESTRICTION
# ------------------------------------------------------------

$state.Screen = 'Findings'

$authorized = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecIntegration `
    -Condition ($authorized -eq $false) `
    -Description 'Rescan is blocked outside MainMenu'

$state.Screen = 'MainMenu'

# ------------------------------------------------------------
# TEST 4: DISABLED LOCAL DEVICE
# ------------------------------------------------------------

$disabledDevices = @(
    foreach ($device in $devices) {
        [pscustomobject]@{
            DeviceId = $device.DeviceId
            Mode = $device.Mode
            Enabled = $false
        }
    }
)

$authorized = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $disabledDevices `
    -Coordinator $coordinator

Assert-WinSecIntegration `
    -Condition ($authorized -eq $false) `
    -Description 'Disabled local device is rejected'

# ------------------------------------------------------------
# TEST 5: SCORING REMAINS DISABLED
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition ($coordinator.ScoringEnabled -eq $false) `
    -Description 'Production scoring remains disabled'

# ------------------------------------------------------------
# TEST 6: REMOTE EXECUTION REMAINS DISABLED
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition ($coordinator.RemoteExecution -eq $false) `
    -Description 'Remote execution remains disabled'

# ------------------------------------------------------------
# TEST 7: AUTOMATIC EVIDENCE STORAGE DISABLED
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $coordinator.AutomaticEvidencePersistence -eq $false
    ) `
    -Description 'Automatic evidence persistence is disabled'

# ------------------------------------------------------------
# TEST 8: AUTHORIZATION CREATES NO SCAN SESSIONS
# ------------------------------------------------------------

$history = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $coordinator
)

Assert-WinSecIntegration `
    -Condition ($history.Count -eq 0) `
    -Description 'Authorization creates no scan sessions'

# ------------------------------------------------------------
# TEST SUMMARY
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
    Write-Host '[FAIL] Rescan integration validation failed.' `
        -ForegroundColor Red

    throw "$failed integration test(s) failed."
}

Write-Host ''
Write-Host '[PASS] All Rescan authorization integration tests passed.' `
    -ForegroundColor Green

Write-Host 'No audits were executed.' `
    -ForegroundColor Green

Write-Host ''
