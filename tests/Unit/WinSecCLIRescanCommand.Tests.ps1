
# ============================================================
# WinSec Analyzer
# Unit Tests - CLI Rescan Command
#
# Version   : 0.9.0
# Author    : mrRoot
# Component : Invoke-WinSecCLI
#
# PowerShell 5.1 / 7.x
# No Pester required
#
# Security:
# - No real audits
# - No remote connections
# - No evidence persistence
# - No scoring activation
# ============================================================

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# ENVIRONMENT
# ------------------------------------------------------------

$projectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

$cliPath = Join-Path $projectRoot `
    'src/CLI/Invoke-WinSecCLI.ps1'

$script:passed = 0
$script:failed = 0

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
Write-Host ' CLI RESCAN COMMAND' -ForegroundColor Cyan
Write-Host '=========================================' -ForegroundColor Cyan

# ------------------------------------------------------------
# TEST 1 - CLI SOURCE EXISTS
# ------------------------------------------------------------

$exists = Test-Path -LiteralPath $cliPath -PathType Leaf

Assert-WinSecUnit `
    -Condition $exists `
    -Description 'CLI source file exists'

if (-not $exists) {
    throw "CLI not found: $cliPath"
}

# ------------------------------------------------------------
# TEST 2 - CLI SYNTAX
# ------------------------------------------------------------

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
# LOCATE THE REAL RESCAN COMMAND BLOCK
# ------------------------------------------------------------

$cliFunctions = @(
    $ast.FindAll({
        param($node)

        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Invoke-WinSecCLI'
    }, $true)
)

if ($cliFunctions.Count -ne 1) {
    throw 'Expected exactly one Invoke-WinSecCLI function.'
}

$cliFunction = $cliFunctions[0]

$rescanBlocks = @(
    $cliFunction.Body.FindAll({
        param($node)

        if ($node -isnot [System.Management.Automation.Language.IfStatementAst]) {
            return $false
        }

        $condition = $node.Clauses[0].Item1.Extent.Text

        return (
            $condition -match 'PendingCommand' -and
            $condition -match "'Rescan'" -and
            $condition -match '\-eq\b'
        )
    }, $true)
)

# ------------------------------------------------------------
# TEST 3 - RESCAN HANDLER EXISTS ONCE
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition ($rescanBlocks.Count -eq 1) `
    -Description 'Rescan command handler exists exactly once'

if ($rescanBlocks.Count -ne 1) {
    throw 'Rescan handler missing or ambiguous.'
}

$rescanAst = $rescanBlocks[0]
$rescanText = $rescanAst.Extent.Text

# ------------------------------------------------------------
# TEST 4 - HELPER IS CALLED EXACTLY ONCE
# ------------------------------------------------------------

$helperCalls = @(
    $rescanAst.FindAll({
        param($node)

        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-WinSecCLILocalRescan'
    }, $true)
)

Assert-WinSecUnit `
    -Condition ($helperCalls.Count -eq 1) `
    -Description 'Rescan calls the local scan helper once'

# ------------------------------------------------------------
# TEST 5 - TERMINATING ERRORS ARE REQUESTED
# ------------------------------------------------------------

$usesErrorActionStop = (
    $helperCalls.Count -eq 1 -and
    $helperCalls[0].Extent.Text -match
        '(?i)-ErrorAction\s+Stop\b'
)

Assert-WinSecUnit `
    -Condition $usesErrorActionStop `
    -Description 'Scan helper uses ErrorAction Stop'

# ------------------------------------------------------------
# TEST 6 - NO DIRECT AUDIT ENGINE EXECUTION
# ------------------------------------------------------------

$unsafeCalls = @(
    $rescanAst.FindAll({
        param($node)

        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -in @(
            'Invoke-WinSecCoordinatedScan',
            'Invoke-WinSecAudit',
            'Invoke-Command',
            'Enter-PSSession',
            'New-PSSession'
        )
    }, $true)
)

Assert-WinSecUnit `
    -Condition ($unsafeCalls.Count -eq 0) `
    -Description 'CLI handler does not bypass scan coordinator'

# ------------------------------------------------------------
# PREPARE THE ACTUAL RESCAN IF-BLOCK FOR UNIT EXECUTION
# ------------------------------------------------------------

# Only the Rescan if-statement is executed.
# The interactive CLI is never started.
#
# The real local scan helper is replaced by the mock below.

$script:rescanBranch = [scriptblock]::Create($rescanText)

$script:mockCalls = 0
$script:mockShouldThrow = $false

$script:secretMarker = 'SECRET_UNIT_TEST_VALUE'

function Invoke-WinSecCLILocalRescan {
    [CmdletBinding()]
    param(
        [psobject]$State,
        [psobject]$Context,
        [switch]$ShowProgress
    )

    $script:mockCalls++

    if ($script:mockShouldThrow) {
        throw $script:secretMarker
    }

    $deviceId = [string]$State.SelectedDeviceId
    $scanId = 'scan-unit-001'

    $result = [pscustomobject]@{
        DeviceId = $deviceId
        ScanId = $scanId
        PublicProjection = $true
        ContainsRawEvidence = $false
        OverallScore = $null
        OverallStatus = 'NOT_SCORED'
    }

    $Context.PublicScans['unit-session'] = $result
    $Context.ActiveScanByDevice[$deviceId] = $scanId

    $Context.LastScanMessage = (
        'Scan completed. Security score: NOT_SCORED.'
    )

    return $result
}

function New-WinSecCommandFixture {
    param(
        [string]$Command = 'Rescan'
    )

    return [pscustomobject]@{
        State = [pscustomobject]@{
            Screen = 'MainMenu'
            SelectedDeviceId = 'local:UNIT-PC'
            PendingCommand = $Command
            PendingScope = 'Device'
        }

        Context = [pscustomobject]@{
            PublicScans = @{}
            ActiveScanByDevice = @{}
            LastScanMessage = ''
        }
    }
}

function Invoke-TestRescanBranch {
    param(
        [psobject]$State,
        [psobject]$Context
    )

    # Match variable names used by the real CLI handler.
    $navigationState = $State
    $context = $Context

    . $script:rescanBranch
}

# ------------------------------------------------------------
# TEST 7 - RESCAN EXECUTES ONCE
# ------------------------------------------------------------

$fixture = New-WinSecCommandFixture

$script:mockCalls = 0
$script:mockShouldThrow = $false

Invoke-TestRescanBranch `
    -State $fixture.State `
    -Context $fixture.Context

Assert-WinSecUnit `
    -Condition ($script:mockCalls -eq 1) `
    -Description 'Rescan executes the local helper once'

# ------------------------------------------------------------
# TEST 8 - SUCCESS CLEARS PENDING COMMAND
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $null -eq $fixture.State.PendingCommand -and
        $null -eq $fixture.State.PendingScope
    ) `
    -Description 'Successful Rescan clears pending navigation'

# ------------------------------------------------------------
# TEST 9 - SUCCESS PRESERVES PUBLIC RESULT
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $fixture.Context.PublicScans.Count -eq 1 -and
        $fixture.Context.PublicScans['unit-session'].PublicProjection -eq $true
    ) `
    -Description 'Successful Rescan preserves published result'

# ------------------------------------------------------------
# TEST 10 - SUCCESS PRESERVES ACTIVE DEVICE SCAN
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $fixture.Context.ActiveScanByDevice['local:UNIT-PC'] -ceq
            'scan-unit-001'
    ) `
    -Description 'Active ScanId remains associated with device'

# ------------------------------------------------------------
# TEST 11 - ERROR IS HANDLED SAFELY
# ------------------------------------------------------------

$fixture = New-WinSecCommandFixture

$script:mockCalls = 0
$script:mockShouldThrow = $true

$unexpectedException = $false

try {
    Invoke-TestRescanBranch `
        -State $fixture.State `
        -Context $fixture.Context
}
catch {
    $unexpectedException = $true
}

Assert-WinSecUnit `
    -Condition (
        -not $unexpectedException -and
        $script:mockCalls -eq 1 -and
        $fixture.Context.LastScanMessage -match
            'failed or was rejected'
    ) `
    -Description 'Scan failure is handled by CLI'

# ------------------------------------------------------------
# TEST 12 - ERROR DETAILS ARE NOT EXPOSED
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $fixture.Context.LastScanMessage -notmatch
            $script:secretMarker
    ) `
    -Description 'Sensitive exception details are not displayed'

# ------------------------------------------------------------
# TEST 13 - FAILURE CLEARS PENDING COMMAND
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $null -eq $fixture.State.PendingCommand -and
        $null -eq $fixture.State.PendingScope
    ) `
    -Description 'Failed Rescan clears pending navigation'

# ------------------------------------------------------------
# TEST 14 - FAILED EXECUTION PUBLISHES NOTHING
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $fixture.Context.PublicScans.Count -eq 0 -and
        $fixture.Context.ActiveScanByDevice.Count -eq 0
    ) `
    -Description 'Failed helper publishes no scan result'

# ------------------------------------------------------------
# TEST 15 - UNRELATED COMMAND IS NOT EXECUTED
# ------------------------------------------------------------

$fixture = New-WinSecCommandFixture `
    -Command 'SelectDevice'

$script:mockCalls = 0
$script:mockShouldThrow = $false

Invoke-TestRescanBranch `
    -State $fixture.State `
    -Context $fixture.Context

Assert-WinSecUnit `
    -Condition (
        $script:mockCalls -eq 0 -and
        $fixture.State.PendingCommand -eq 'SelectDevice'
    ) `
    -Description 'Rescan handler ignores unrelated commands'

# ------------------------------------------------------------
# TEST 16 - EXPORT AND SETTINGS REMAIN DISABLED
# ------------------------------------------------------------

$disabledBlocks = @(
    $cliFunction.Body.FindAll({
        param($node)

        if ($node -isnot [System.Management.Automation.Language.IfStatementAst]) {
            return $false
        }

        $condition = $node.Clauses[0].Item1.Extent.Text

        return (
            $condition -match 'PendingCommand' -and
            $condition -match "'ExportTXT'" -and
            $condition -match "'SelectSetting'"
        )
    }, $true)
)

$unsupportedCommandsSafe = $false

if ($disabledBlocks.Count -eq 1) {
    $condition = $disabledBlocks[0].Clauses[0].Item1.Extent.Text

    $unsupportedCommandsSafe = (
        $condition -notmatch "'Rescan'"
    )
}

Assert-WinSecUnit `
    -Condition $unsupportedCommandsSafe `
    -Description 'Export and settings remain disabled separately'

# ------------------------------------------------------------
# TEST 17 - NO EVIDENCE PERSISTENCE REQUEST
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $rescanText -notmatch '(?i)-PersistEvidence\b'
    ) `
    -Description 'Rescan handler does not request evidence storage'

# ------------------------------------------------------------
# TEST SUMMARY
# ------------------------------------------------------------

Write-Host ''
Write-Host '=========================================' -ForegroundColor Cyan
Write-Host ' UNIT TEST SUMMARY' -ForegroundColor Cyan
Write-Host '=========================================' -ForegroundColor Cyan

Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"

if ($script:failed -gt 0) {
    throw "$script:failed unit test(s) failed."
}

Write-Host ''
Write-Host '[PASS] All CLI Rescan command unit tests passed.' `
    -ForegroundColor Green
