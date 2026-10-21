
# ============================================================
# WinSec Analyzer
# Integration Tests - CLI Rescan Command
#
# Version   : 0.9.0
# Author    : mrRoot
# Component : Invoke-WinSecCLI / Rescan
#
# PowerShell 5.1 / 7.x
# No Pester required
#
# Safety:
# - Local target only
# - Production checks remain disabled; the collector is simulated
# - No scoring
# - No remote execution
# - No automatic evidence persistence
# - No project configuration modifications
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

$coordinatorPath = Join-Path $projectRoot `
    'src/Core/ScanCoordinator.ps1'

$checksPath = Join-Path $projectRoot `
    'config/checks.json'

$scoringPath = Join-Path $projectRoot `
    'config/scoring.json'

$script:passed = 0
$script:failed = 0

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

function Invoke-TestRescanCommand {
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Context
    )

    # Use the same variable names as the real CLI.
    # Only the actual Rescan command block is executed.
    # The interactive application is never started.

    $navigationState = $State
    $context = $Context

    . $script:rescanBranch
}

Write-Host ''
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ' WINSEC ANALYZER - INTEGRATION TESTS' `
    -ForegroundColor Cyan
Write-Host ' CLI RESCAN COMMAND' `
    -ForegroundColor Cyan
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------
# TEST 1 - REQUIRED FILES EXIST
# ------------------------------------------------------------

$requiredFiles = @(
    $cliPath
    $coordinatorPath
    $checksPath
    $scoringPath
)

$filesExist = $true

foreach ($path in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Host "[MISSING] $path" -ForegroundColor Red
        $filesExist = $false
    }
}

Assert-WinSecIntegration `
    -Condition $filesExist `
    -Description 'Required project files exist'

if (-not $filesExist) {
    throw 'Required integration files are missing.'
}

# ------------------------------------------------------------
# TEST 2 - VALID CLI SYNTAX
# ------------------------------------------------------------

$tokens = $null
$parseErrors = $null

$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $cliPath,
    [ref]$tokens,
    [ref]$parseErrors
)

Assert-WinSecIntegration `
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
# TEST 3 - LOCATE REAL RESCAN HANDLER
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

$rescanBlocks = @(
    $cliFunctions[0].Body.FindAll({
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

Assert-WinSecIntegration `
    -Condition ($rescanBlocks.Count -eq 1) `
    -Description 'Real Rescan handler exists exactly once'

if ($rescanBlocks.Count -ne 1) {
    throw 'Rescan handler was not found uniquely.'
}

$script:rescanBranch = [scriptblock]::Create(
    $rescanBlocks[0].Extent.Text
)

# ------------------------------------------------------------
# READ PRODUCTION CONFIGURATION
# ------------------------------------------------------------

$checksHashBefore = (
    Get-FileHash -LiteralPath $checksPath -Algorithm SHA256
).Hash

$scoringHashBefore = (
    Get-FileHash -LiteralPath $scoringPath -Algorithm SHA256
).Hash

$checksConfig = Get-Content `
    -LiteralPath $checksPath `
    -Raw `
    -Encoding UTF8 |
    ConvertFrom-Json

$scoringConfig = Get-Content `
    -LiteralPath $scoringPath `
    -Raw `
    -Encoding UTF8 |
    ConvertFrom-Json

# ------------------------------------------------------------
# TEST 4 - READ-ONLY EXECUTION POLICY
# ------------------------------------------------------------

$readOnlyPolicy = (
    $checksConfig.executionPolicy.readOnly -eq $true -and
    $checksConfig.executionPolicy.automaticRemediation -eq $false
)

Assert-WinSecIntegration `
    -Condition $readOnlyPolicy `
    -Description 'Read-only execution policy is enforced'

# ------------------------------------------------------------
# TEST 5 - ALL EXECUTABLE CHECKS DISABLED
# ------------------------------------------------------------

$enabledChecks = @(
    $checksConfig.checks | Where-Object {
        $_.execution.enabled -eq $true
    }
)

$automaticExecutionDisabled = (
    $checksConfig.executionPolicy.automaticExecutionOnStartup -eq $false -and
    $checksConfig.executionPolicy.executeOnScreenRender -eq $false
)

Assert-WinSecIntegration `
    -Condition (
        $enabledChecks.Count -eq 0 -and
        $automaticExecutionDisabled
    ) `
    -Description 'No checks or automatic scans are enabled'

# ------------------------------------------------------------
# TEST 6 - SCORING CONFIGURATION DISABLED
# ------------------------------------------------------------

$scoringDisabled = (
    $scoringConfig.enabled -eq $false -and
    $scoringConfig.activationStatus -ceq
        'PENDING_APPROVED_CRITERIA'
)

Assert-WinSecIntegration `
    -Condition $scoringDisabled `
    -Description 'Production scoring remains disabled'

# Never execute the scan if any prerequisite fails.

if (
    -not $readOnlyPolicy -or
    $enabledChecks.Count -gt 0 -or
    -not $automaticExecutionDisabled -or
    -not $scoringDisabled
) {
    throw (
        'Unsafe test environment. ' +
        'No scan was requested.'
    )
}

# ------------------------------------------------------------
# LOAD REAL APPLICATION COMPONENTS
# ------------------------------------------------------------

. $cliPath
. $coordinatorPath
. (Join-Path $PSScriptRoot '../Fixtures/ConfirmedScan.ps1')
try {

$coordinator = New-WinSecScanCoordinator `
    -ProjectRoot $projectRoot

$devices = @(
    Get-WinSecCLIDevices `
        -ProjectRoot $projectRoot
)

$localTarget = New-WinSecLocalTarget

if ($null -eq $localTarget) {
    throw 'Local target not available.'
}

$localId = [string]$localTarget.DeviceId

# ------------------------------------------------------------
# TEST 7 - COORDINATOR SECURITY
# ------------------------------------------------------------

$coordinatorSafe = (
    $null -ne $coordinator -and
    $coordinator.ScoringEnabled -eq $false -and
    $coordinator.RemoteExecution -eq $false -and
    $coordinator.AutomaticEvidencePersistence -eq $false
)

Assert-WinSecIntegration `
    -Condition $coordinatorSafe `
    -Description 'Real coordinator satisfies security restrictions'

if (-not $coordinatorSafe) {
    throw 'Unsafe coordinator configuration.'
}

# ------------------------------------------------------------
# TEST FIXTURES
# ------------------------------------------------------------

$state = [pscustomobject]@{
    Screen = 'Devices'
    DeviceIndex = 0
    SelectedDeviceId = $localId
    PendingCommand = 'Rescan'
    PendingScope = 'Device'
}

$context = [pscustomobject]@{
    ProjectRoot = $projectRoot
    ScanCoordinator = $coordinator
    Devices = @($devices)

    PublicScans = @{}
    ActiveScanByDevice = @{}

    LastScanMessage = ''

    SectionResults = @()
    ControlResults = @()
    Findings = @()

    ScanId = ''
}

# ------------------------------------------------------------
# TEST 8 - LOCAL TARGET ELIGIBILITY
# ------------------------------------------------------------

$authorized = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecIntegration `
    -Condition ($authorized -eq $true) `
    -Description 'Selected local target is authorized'

if ($authorized -ne $true) {
    throw 'Local target authorization failed.'
}

# ------------------------------------------------------------
# TEST 9 - INITIAL HISTORY EMPTY
# ------------------------------------------------------------

$initialHistory = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $coordinator
)

Assert-WinSecIntegration `
    -Condition ($initialHistory.Count -eq 0) `
    -Description 'Coordinator starts with empty history'

# ------------------------------------------------------------
# EXECUTE ONE SYNTHETIC RESCAN COMMAND
# ------------------------------------------------------------

Write-Host ''
Write-Host '[INFO] Executing one synthetic CLI Rescan command...' `
    -ForegroundColor Cyan

Invoke-TestRescanCommand `
    -State $state `
    -Context $context

# ------------------------------------------------------------
# TEST 10 - PENDING COMMAND CLEARED
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $null -eq $state.PendingCommand -and
        $null -eq $state.PendingScope
    ) `
    -Description 'Rescan clears pending command and scope'

# ------------------------------------------------------------
# TEST 11 - EXACTLY ONE RESULT PUBLISHED
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $context.PublicScans.Count -eq 1 -and
        $context.ActiveScanByDevice.Count -eq 1
    ) `
    -Description 'Rescan publishes exactly one local session'

if ($context.PublicScans.Count -ne 1) {
    throw (
        'No valid public result was published. ' +
        'Inspect the preceding test output.'
    )
}

$publicResult = @(
    $context.PublicScans.Values
)[0]

$scanId = [string]$publicResult.ScanId

# ------------------------------------------------------------
# TEST 12 - RESULT IDENTITY AND PUBLIC CONTRACT
# ------------------------------------------------------------

$publicValid = (
    $publicResult.PublicProjection -ceq $true -and
    $publicResult.ContainsRawEvidence -ceq $false -and
    $publicResult.DeviceId -ceq $localId -and
    -not [string]::IsNullOrWhiteSpace($scanId)
)

Assert-WinSecIntegration `
    -Condition $publicValid `
    -Description 'Published result belongs to local device'

# ------------------------------------------------------------
# TEST 13 - SCORING REMAINS DISABLED
# ------------------------------------------------------------

$notScored = (
    $null -eq $publicResult.OverallScore -and
    $publicResult.OverallStatus -ceq 'NOT_SCORED' -and
    $publicResult.ScoringEligible -ceq $false
)

Assert-WinSecIntegration `
    -Condition $notScored `
    -Description 'Published result remains NOT_SCORED'

# ------------------------------------------------------------
# TEST 14 - SYNTHETIC CONTROL COMPLETES
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $publicResult.ExecutionStatus -ceq
            'COMPLETED'
    ) `
    -Description 'Scan completes the synthetic control'

# ------------------------------------------------------------
# TEST 15 - CATALOG RECORDS ARE NOT EXECUTED
# ------------------------------------------------------------

$controls = @(
    $publicResult.ControlResults |
        Where-Object { $null -ne $_ }
)

$unexpectedControls = @(
    $controls | Where-Object {
        ($_.CheckId -ceq 'WSA-SYS-001' -and $_.Status -cne 'INFORMATIONAL') -or
        ($_.CheckId -cne 'WSA-SYS-001' -and $_.Status -cne 'NOT_SELECTED') -or
        [string]::IsNullOrWhiteSpace(
            [string]$_.CheckId
        )
    }
)

Assert-WinSecIntegration `
    -Condition (
        $unexpectedControls.Count -eq 0
    ) `
    -Description 'Only the synthetic control is selected'

# ------------------------------------------------------------
# TEST 16 - SCAN ASSOCIATED WITH DEVICE
# ------------------------------------------------------------

}
finally {
    Restore-WinSecConfirmedScanFixture
}

$sessionKey = '{0}:{1}{2}:{3}' -f `
    $localId.Length,
    $localId,
    $scanId.Length,
    $scanId

Assert-WinSecIntegration `
    -Condition (
        $context.PublicScans.ContainsKey($sessionKey) -and
        $context.ActiveScanByDevice[$localId] -ceq $scanId
    ) `
    -Description 'DeviceId and ScanId association is correct'

# ------------------------------------------------------------
# TEST 17 - COORDINATOR HISTORY
# ------------------------------------------------------------

$history = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $coordinator `
        -DeviceId $localId
)

$matching = @(
    $history | Where-Object {
        $_.DeviceId -ceq $localId -and
        $_.ScanId -ceq $scanId
    }
)

Assert-WinSecIntegration `
    -Condition (
        $history.Count -eq 1 -and
        $matching.Count -eq 1
    ) `
    -Description 'Coordinator contains exactly one scan session'

# ------------------------------------------------------------
# TEST 18 - NO REPEAT AFTER COMMAND CLEAR
# ------------------------------------------------------------

Invoke-TestRescanCommand `
    -State $state `
    -Context $context

$historyAfterRepeat = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $coordinator
)

Assert-WinSecIntegration `
    -Condition (
        $historyAfterRepeat.Count -eq 1 -and
        $context.PublicScans.Count -eq 1
    ) `
    -Description 'Cleared command cannot repeat the scan'

# ------------------------------------------------------------
# TEST 19 - REMOTE COMMAND REJECTED SAFELY
# ------------------------------------------------------------

$state.SelectedDeviceId = 'remote:INTEGRATION-TEST'
$context.Devices += @([pscustomobject]@{DeviceId='remote:INTEGRATION-TEST';Mode='REMOTE';Enabled=$true})
$state.DeviceIndex = $context.Devices.Count - 1
$state.PendingCommand = 'Rescan'
$state.PendingScope = 'Device'

Invoke-TestRescanCommand `
    -State $state `
    -Context $context

$historyAfterRemote = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $coordinator
)

Assert-WinSecIntegration `
    -Condition (
        $historyAfterRemote.Count -eq 1 -and
        $context.PublicScans.Count -eq 1 -and
        $null -eq $state.PendingCommand -and
        $null -eq $state.PendingScope
    ) `
    -Description 'Remote Rescan creates no additional session'

# ------------------------------------------------------------
# TEST 20 - SAFE FAILURE MESSAGE
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $context.LastScanMessage -match
            'failed or was rejected' -and
        $context.LastScanMessage -notmatch
            'Exception|StackTrace|SECRET_'
    ) `
    -Description 'Rejected scan exposes no internal error details'

# ------------------------------------------------------------
# TEST 21 - UNRELATED COMMAND NOT CONSUMED
# ------------------------------------------------------------

$state.SelectedDeviceId = $localId
$state.DeviceIndex = 0
$state.PendingCommand = 'SelectDevice'
$state.PendingScope = 'Device'

Invoke-TestRescanCommand `
    -State $state `
    -Context $context

Assert-WinSecIntegration `
    -Condition (
        $state.PendingCommand -ceq 'SelectDevice' -and
        $context.PublicScans.Count -eq 1
    ) `
    -Description 'Unrelated command remains unchanged'

# ------------------------------------------------------------
# TEST 22 - CONFIGURATION FILES UNCHANGED
# ------------------------------------------------------------

$checksHashAfter = (
    Get-FileHash -LiteralPath $checksPath -Algorithm SHA256
).Hash

$scoringHashAfter = (
    Get-FileHash -LiteralPath $scoringPath -Algorithm SHA256
).Hash

Assert-WinSecIntegration `
    -Condition (
        $checksHashBefore -ceq $checksHashAfter -and
        $scoringHashBefore -ceq $scoringHashAfter
    ) `
    -Description 'Scan does not modify project configuration'

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

Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"

if ($script:failed -gt 0) {
    throw "$script:failed integration test(s) failed."
}

Write-Host ''
Write-Host '[PASS] All CLI Rescan command integration tests passed.' `
    -ForegroundColor Green

Write-Host ''
