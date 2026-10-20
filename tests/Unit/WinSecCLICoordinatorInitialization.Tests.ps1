
# ============================================================
# WinSec Analyzer
# Unit Tests - CLI ScanCoordinator Initialization
#
# Version   : 0.9.0
# Author    : mrRoot
# Component : Invoke-WinSecCLI
#
# PowerShell 5.1 / 7.x
# No Pester required
#
# Security:
# - No real audit execution
# - No remote connections
# - No evidence persistence
# - No scoring activation
# ============================================================

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# TEST ENVIRONMENT
# ------------------------------------------------------------

$projectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

$cliPath = Join-Path `
    $projectRoot 'src/CLI/Invoke-WinSecCLI.ps1'

$passed = 0
$failed = 0

function Assert-WinSecUnit {
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
Write-Host ' WINSEC ANALYZER - UNIT TESTS' `
    -ForegroundColor Cyan
Write-Host ' CLI / SCAN COORDINATOR INITIALIZATION' `
    -ForegroundColor Cyan
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------
# TEST 1: CLI file exists
# ------------------------------------------------------------

$exists = Test-Path `
    -LiteralPath $cliPath `
    -PathType Leaf

Assert-WinSecUnit `
    -Condition $exists `
    -Description 'CLI source file exists'

if (-not $exists) {
    throw "CLI source not found: $cliPath"
}

# ------------------------------------------------------------
# PARSE SOURCE WITHOUT EXECUTING THE CLI
# ------------------------------------------------------------

$source = [System.IO.File]::ReadAllText($cliPath)

$tokens = $null
$parseErrors = $null

$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $cliPath,
    [ref]$tokens,
    [ref]$parseErrors
)

# ------------------------------------------------------------
# TEST 2: PowerShell syntax is valid
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (@($parseErrors).Count -eq 0) `
    -Description 'CLI has valid PowerShell syntax'

if (@($parseErrors).Count -gt 0) {
    foreach ($parseError in $parseErrors) {
        Write-Host (
            'Line {0}: {1}' -f `
            $parseError.Extent.StartLineNumber,
            $parseError.Message
        ) -ForegroundColor Red
    }

    throw 'Cannot continue with invalid CLI syntax.'
}

# ------------------------------------------------------------
# TEST 3: Main CLI function exists exactly once
# ------------------------------------------------------------

$cliFunctions = @(
    $ast.FindAll({
        param($node)

        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Invoke-WinSecCLI'
    }, $true)
)

Assert-WinSecUnit `
    -Condition ($cliFunctions.Count -eq 1) `
    -Description 'Invoke-WinSecCLI is defined exactly once'

if ($cliFunctions.Count -ne 1) {
    throw 'Expected exactly one Invoke-WinSecCLI function.'
}

$cliFunction = $cliFunctions[0]
$bodyText = $cliFunction.Body.Extent.Text

# ------------------------------------------------------------
# TEST 4: Coordinator dependency is referenced
# ------------------------------------------------------------

$hasDependency = $bodyText.Contains(
    'src/Core/ScanCoordinator.ps1'
)

Assert-WinSecUnit `
    -Condition $hasDependency `
    -Description 'CLI references ScanCoordinator dependency'

# ------------------------------------------------------------
# TEST 5: Coordinator file is checked before loading
# ------------------------------------------------------------

$hasDependencyCheck = (
    $bodyText -match
    'Test-Path\s+-LiteralPath\s+\$coordinatorPath'
)

Assert-WinSecUnit `
    -Condition $hasDependencyCheck `
    -Description 'Coordinator dependency existence is checked'

# ------------------------------------------------------------
# TEST 6: Coordinator initializer is called once
# ------------------------------------------------------------

$initCalls = @(
    $cliFunction.Body.FindAll({
        param($node)

        if ($node -isnot [System.Management.Automation.Language.CommandAst]) {
            return $false
        }

        return (
            $node.GetCommandName() -eq
            'New-WinSecScanCoordinator'
        )
    }, $true)
)

Assert-WinSecUnit `
    -Condition ($initCalls.Count -eq 1) `
    -Description 'Coordinator is initialized exactly once'

# ------------------------------------------------------------
# TEST 7: ProjectRoot is supplied
# ------------------------------------------------------------

$hasProjectRoot = $false

if ($initCalls.Count -eq 1) {
    $hasProjectRoot = (
        $initCalls[0].Extent.Text -match
        '(?s)-ProjectRoot\s+\$ProjectRoot\b'
    )
}

Assert-WinSecUnit `
    -Condition $hasProjectRoot `
    -Description 'Coordinator receives project root'

# ------------------------------------------------------------
# TEST 8: Initialization precedes device loading
# ------------------------------------------------------------

$initPosition = $bodyText.IndexOf(
    '$scanCoordinator = New-WinSecScanCoordinator'
)

$devicePosition = $bodyText.IndexOf(
    '# Load device registry'
)

$correctOrder = (
    $initPosition -ge 0 -and
    $devicePosition -gt $initPosition
)

Assert-WinSecUnit `
    -Condition $correctOrder `
    -Description 'Coordinator initializes before device loading'

# ------------------------------------------------------------
# TEST 9: Scoring safety guard exists
# ------------------------------------------------------------

$scoringGuard = (
    $bodyText -match
    '\$scanCoordinator\.ScoringEnabled\s+-ne\s+\$false'
)

Assert-WinSecUnit `
    -Condition $scoringGuard `
    -Description 'CLI checks that scoring is disabled'

# ------------------------------------------------------------
# TEST 10: Remote execution safety guard exists
# ------------------------------------------------------------

$remoteGuard = (
    $bodyText -match
    '\$scanCoordinator\.RemoteExecution\s+-ne\s+\$false'
)

Assert-WinSecUnit `
    -Condition $remoteGuard `
    -Description 'CLI checks that remote execution is disabled'

# ------------------------------------------------------------
# TEST 11: Evidence persistence safety guard exists
# ------------------------------------------------------------

$evidenceGuard = (
    $bodyText -match
    '\$scanCoordinator\.AutomaticEvidencePersistence\s+-ne\s+\$false'
)

Assert-WinSecUnit `
    -Condition $evidenceGuard `
    -Description 'CLI checks automatic evidence persistence'

# ------------------------------------------------------------
# TEST 12: Coordinator is stored in CLI context
# ------------------------------------------------------------

$hasContextCoordinator = (
    $bodyText -match
    'ScanCoordinator\s*=\s*\$scanCoordinator\b'
)

Assert-WinSecUnit `
    -Condition $hasContextCoordinator `
    -Description 'Coordinator is stored in CLI context'

# ------------------------------------------------------------
# TEST 13: Per-device active scans are initialized
# ------------------------------------------------------------

$hasActiveScanMap = (
    $bodyText -match
    'ActiveScanByDevice\s*=\s*@\{\s*\}'
)

Assert-WinSecUnit `
    -Condition $hasActiveScanMap `
    -Description 'Per-device scan map is initialized'

# ------------------------------------------------------------
# TEST 14: Public scan storage is initialized
# ------------------------------------------------------------

$hasPublicScanMap = (
    $bodyText -match
    'PublicScans\s*=\s*@\{\s*\}'
)

Assert-WinSecUnit `
    -Condition $hasPublicScanMap `
    -Description 'Public scan collection is initialized'

# ------------------------------------------------------------
# TEST 15: Scan notification starts empty
# ------------------------------------------------------------

$hasEmptyMessage = (
    $bodyText -match
    "LastScanMessage\s*=\s*''"
)

Assert-WinSecUnit `
    -Condition $hasEmptyMessage `
    -Description 'Scan notification starts empty'

# ------------------------------------------------------------
# TEST 16: No scan starts during initialization
# ------------------------------------------------------------

$startupText = ''

if ($devicePosition -gt 0) {
    $startupText = $bodyText.Substring(
        0,
        $devicePosition
    )
}

$startupHasScanCall = (
    $startupText -match
    '(?m)^\s*(?:\$null\s*=\s*)?Invoke-WinSecCoordinatedScan\b'
)

Assert-WinSecUnit `
    -Condition (
        $devicePosition -gt 0 -and
        -not $startupHasScanCall
    ) `
    -Description 'Initialization does not execute scans'

# ------------------------------------------------------------
# TEST 17: Coordinator functions are checked
# ------------------------------------------------------------

$requiredCommands = @(
    'New-WinSecScanCoordinator'
    'Invoke-WinSecCoordinatedScan'
    'Get-WinSecCoordinatorHistory'
    'Get-WinSecCoordinatorPublicResult'
)

$allReferenced = $true

foreach ($commandName in $requiredCommands) {
    if (-not $bodyText.Contains("'$commandName'")) {
        $allReferenced = $false
    }
}

Assert-WinSecUnit `
    -Condition $allReferenced `
    -Description 'Required coordinator functions are declared'

# ------------------------------------------------------------
# TEST 18: Legacy updater is not embedded in the CLI
# ------------------------------------------------------------

$updaterFound = (
    $source.Contains('function Replace-CLIRegion') -or
    $source.Contains('function Replace-CLIText')
)

Assert-WinSecUnit `
    -Condition (-not $updaterFound) `
    -Description 'Legacy CLI updater is not embedded'

# ------------------------------------------------------------
# RESULTS SUMMARY
# ------------------------------------------------------------

Write-Host ''
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ' UNIT TEST SUMMARY' `
    -ForegroundColor Cyan
Write-Host '=========================================' `
    -ForegroundColor Cyan

Write-Host "Passed: $passed"
Write-Host "Failed: $failed"

if ($failed -gt 0) {
    Write-Host ''
    Write-Host '[FAIL] CLI unit validation failed.' `
        -ForegroundColor Red

    throw "$failed unit test(s) failed."
}

Write-Host ''
Write-Host '[PASS] All CLI initialization unit tests passed.' `
    -ForegroundColor Green
Write-Host ''
