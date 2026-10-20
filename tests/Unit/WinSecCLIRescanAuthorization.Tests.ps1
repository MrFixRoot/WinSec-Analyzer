
# ============================================================
# WinSec Analyzer
# Unit Tests - CLI Rescan Authorization
#
# Version   : 0.9.0
# Author    : mrRoot
# Component : Invoke-WinSecCLI
#
# PowerShell 5.1 / 7.x
# No Pester required
#
# Tests:
# - Local device authorization
# - Remote device rejection
# - Disabled device rejection
# - Invalid screen rejection
# - Duplicate device rejection
# - Coordinator authorization
# - KeyboardController integration
#
# No real scans are executed.
# ============================================================

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# ENVIRONMENT
# ------------------------------------------------------------

$root = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

$cliPath = Join-Path $root `
    'src/CLI/Invoke-WinSecCLI.ps1'

$passed = 0
$failed = 0

function Assert-WinSecUnit {
    param(
        [bool]$Condition,
        [string]$Description
    )

    if ($Condition) {
        Write-Host "[PASS] $Description" -ForegroundColor Green
        $script:passed++
    }
    else {
        Write-Host "[FAIL] $Description" -ForegroundColor Red
        $script:failed++
    }
}

Write-Host ''
Write-Host '=========================================' -ForegroundColor Cyan
Write-Host ' WINSEC ANALYZER - UNIT TESTS' -ForegroundColor Cyan
Write-Host ' CLI RESCAN AUTHORIZATION' -ForegroundColor Cyan
Write-Host '=========================================' -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------
# TEST 1 - FILE AND SYNTAX
# ------------------------------------------------------------

if (-not (Test-Path -LiteralPath $cliPath -PathType Leaf)) {
    throw "CLI not found: $cliPath"
}

$tokens = $null
$parseErrors = $null

$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $cliPath,
    [ref]$tokens,
    [ref]$parseErrors
)

Assert-WinSecUnit `
    -Condition (@($parseErrors).Count -eq 0) `
    -Description 'CLI PowerShell syntax is valid'

if (@($parseErrors).Count -gt 0) {
    foreach ($item in $parseErrors) {
        Write-Host (
            "Line $($item.Extent.StartLineNumber): $($item.Message)"
        ) -ForegroundColor Red
    }

    throw 'CLI syntax validation failed.'
}

# ------------------------------------------------------------
# LOAD CLI WITHOUT STARTING THE APPLICATION
# ------------------------------------------------------------

. $cliPath

if (-not (
    Get-Command Test-WinSecCLIRescanEligibility `
        -CommandType Function `
        -ErrorAction SilentlyContinue
)) {
    throw 'Rescan authorization function not found.'
}

# ------------------------------------------------------------
# MOCK DEPENDENCIES
# No real registry or coordinator operations.
# ------------------------------------------------------------

$script:resolverCalls = 0
$script:resolverReject = $false

function New-WinSecLocalTarget {
    return [pscustomobject]@{
        DeviceId = 'local:UNIT-PC'
    }
}

function Resolve-WinSecScanTarget {
    param(
        [object]$Coordinator,
        [string]$DeviceId
    )

    $script:resolverCalls++

    if (
        $script:resolverReject -or
        $DeviceId -cne 'local:UNIT-PC'
    ) {
        throw 'Target rejected by test coordinator.'
    }

    return [pscustomobject]@{
        DeviceId = $DeviceId
        Mode = 'LOCAL'
    }
}

# ------------------------------------------------------------
# TEST DATA
# ------------------------------------------------------------

$coordinator = [pscustomobject]@{
    Component = 'ScanCoordinator'
}

$state = [pscustomobject]@{
    Screen = 'MainMenu'
    SelectedDeviceId = 'local:UNIT-PC'
}

$devices = @(
    [pscustomobject]@{
        DeviceId = 'local:UNIT-PC'
        Mode = 'LOCAL'
        Enabled = $true
    }
)

# ------------------------------------------------------------
# TEST 2 - VALID LOCAL DEVICE
# ------------------------------------------------------------

$script:resolverCalls = 0

$result = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecUnit `
    -Condition (
        $result -eq $true -and
        $script:resolverCalls -eq 1
    ) `
    -Description 'Valid local device is authorized'

# ------------------------------------------------------------
# TEST 3 - INVALID SCREEN
# ------------------------------------------------------------

$state.Screen = 'Findings'
$script:resolverCalls = 0

$result = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecUnit `
    -Condition (
        $result -eq $false -and
        $script:resolverCalls -eq 0
    ) `
    -Description 'Rescan is blocked outside MainMenu'

$state.Screen = 'MainMenu'

# ------------------------------------------------------------
# TEST 4 - REMOTE DEVICE
# ------------------------------------------------------------

$state.SelectedDeviceId = 'remote:OTHER-PC'
$script:resolverCalls = 0

$result = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecUnit `
    -Condition (
        $result -eq $false -and
        $script:resolverCalls -eq 0
    ) `
    -Description 'Remote device is rejected'

$state.SelectedDeviceId = 'local:UNIT-PC'

# ------------------------------------------------------------
# TEST 5 - DISABLED DEVICE
# ------------------------------------------------------------

$devices[0].Enabled = $false
$script:resolverCalls = 0

$result = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecUnit `
    -Condition (
        $result -eq $false -and
        $script:resolverCalls -eq 0
    ) `
    -Description 'Disabled local device is rejected'

$devices[0].Enabled = $true

# ------------------------------------------------------------
# TEST 6 - INVALID MODE
# ------------------------------------------------------------

$devices[0].Mode = 'REMOTE'
$script:resolverCalls = 0

$result = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecUnit `
    -Condition (
        $result -eq $false -and
        $script:resolverCalls -eq 0
    ) `
    -Description 'Non-local device mode is rejected'

$devices[0].Mode = 'LOCAL'

# ------------------------------------------------------------
# TEST 7 - NO DEVICE SELECTED
# ------------------------------------------------------------

$state.SelectedDeviceId = ''
$script:resolverCalls = 0

$result = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecUnit `
    -Condition (
        $result -eq $false -and
        $script:resolverCalls -eq 0
    ) `
    -Description 'Missing device selection is rejected'

$state.SelectedDeviceId = 'local:UNIT-PC'

# ------------------------------------------------------------
# TEST 8 - DUPLICATE DEVICE ENTRIES
# ------------------------------------------------------------

$duplicateDevices = @(
    $devices[0]
    $devices[0]
)

$script:resolverCalls = 0

$result = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $duplicateDevices `
    -Coordinator $coordinator

Assert-WinSecUnit `
    -Condition (
        $result -eq $false -and
        $script:resolverCalls -eq 0
    ) `
    -Description 'Duplicate local targets are rejected'

# ------------------------------------------------------------
# TEST 9 - NULL COORDINATOR
# ------------------------------------------------------------

$script:resolverCalls = 0

$result = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $null

Assert-WinSecUnit `
    -Condition (
        $result -eq $false -and
        $script:resolverCalls -eq 0
    ) `
    -Description 'Missing coordinator is rejected'

# ------------------------------------------------------------
# TEST 10 - COORDINATOR REJECTION
# ------------------------------------------------------------

$script:resolverReject = $true
$script:resolverCalls = 0

$result = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecUnit `
    -Condition (
        $result -eq $false -and
        $script:resolverCalls -eq 1
    ) `
    -Description 'Coordinator rejection is respected'

$script:resolverReject = $false

# ------------------------------------------------------------
# TEST 11 - KEYBOARD INTEGRATION
# ------------------------------------------------------------

$cliFunctions = @(
    $ast.FindAll({
        param($node)

        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Invoke-WinSecCLI'
    }, $true)
)

$keyboardConnected = $false

if ($cliFunctions.Count -eq 1) {

    $keyboardCalls = @(
        $cliFunctions[0].Body.FindAll({
            param($node)

            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'Get-WinSecKeyboardAction'
        }, $true)
    )

    foreach ($call in $keyboardCalls) {
        if (
            $call.Extent.Text -match
            '-EnableRescan:\$enableLocalRescan\b'
        ) {
            $keyboardConnected = $true
            break
        }
    }
}

Assert-WinSecUnit `
    -Condition $keyboardConnected `
    -Description 'KeyboardController receives authorization flag'

# ------------------------------------------------------------
# TEST 12 - NO AUDIT EXECUTION
# ------------------------------------------------------------

$auditCalls = @(
    $ast.FindAll({
        param($node)

        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-WinSecCoordinatedScan'
    }, $true)
)

Assert-WinSecUnit `
    -Condition ($auditCalls.Count -eq 0) `
    -Description 'No audit execution added in step 4'

# ------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------

Write-Host ''
Write-Host '=========================================' -ForegroundColor Cyan
Write-Host ' UNIT TEST SUMMARY' -ForegroundColor Cyan
Write-Host '=========================================' -ForegroundColor Cyan

Write-Host "Passed: $passed"
Write-Host "Failed: $failed"

if ($failed -gt 0) {
    throw "$failed unit test(s) failed."
}

Write-Host ''
Write-Host '[PASS] All Rescan authorization unit tests passed.' `
    -ForegroundColor Green
