
# ============================================================
# WinSec Analyzer
# Integration Tests - CLI Local Rescan
#
# Version   : 0.9.0
# Author    : mrRoot
#
# Components:
# - Invoke-WinSecCLI
# - ScanCoordinator
# - TargetRegistry
# - AuditEngine
# - ResultModel
#
# PowerShell 5.1 / 7.x
# No Pester required
#
# Safety:
# - Synthetic collector only; no Windows audit
# - Only the individually validated Defender check may be enabled
# - No security scoring
# - No remote sessions
# - No automatic evidence persistence
# - No modification of project configuration
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

function Assert-WinSecRejected {
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Context,

        [Parameter(Mandatory)]
        [string]$Description
    )

    $rejected = $false

    try {
        $null = Invoke-WinSecCLILocalRescan `
            -State $State `
            -Context $Context `
            -ErrorAction Stop
    }
    catch {
        $rejected = $true
    }

    $notPublished = (
        $Context.PublicScans.Count -eq 0 -and
        $Context.ActiveScanByDevice.Count -eq 0
    )

    Assert-WinSecIntegration `
        -Condition ($rejected -and $notPublished) `
        -Description $Description
}

Write-Host ''
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ' WINSEC ANALYZER' `
    -ForegroundColor Cyan
Write-Host ' CLI LOCAL RESCAN INTEGRATION TESTS' `
    -ForegroundColor Cyan
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------
# TEST 1 - REQUIRED FILES
# ------------------------------------------------------------

$requiredFiles = @(
    $cliPath
    $coordinatorPath
    $checksPath
    $scoringPath
)

$filesAvailable = $true

foreach ($file in $requiredFiles) {
    if (-not (
        Test-Path -LiteralPath $file -PathType Leaf
    )) {
        Write-Host "[MISSING] $file" `
            -ForegroundColor Red

        $filesAvailable = $false
    }
}

Assert-WinSecIntegration `
    -Condition $filesAvailable `
    -Description 'Required project files exist'

if (-not $filesAvailable) {
    throw 'Integration prerequisites are missing.'
}

# ------------------------------------------------------------
# TEST 2 - CLI SYNTAX
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
    foreach ($item in $parseErrors) {
        Write-Host (
            "Line $($item.Extent.StartLineNumber): $($item.Message)"
        ) -ForegroundColor Red
    }

    throw 'CLI syntax validation failed.'
}

# ------------------------------------------------------------
# SAFETY PRECONDITIONS
# ------------------------------------------------------------

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
# TEST 3 - READ-ONLY EXECUTION POLICY
# ------------------------------------------------------------

$readOnly = (
    $checksConfig.executionPolicy.readOnly -eq $true -and
    $checksConfig.executionPolicy.automaticRemediation -eq $false
)

Assert-WinSecIntegration `
    -Condition $readOnly `
    -Description 'Execution policy remains read-only'

# ------------------------------------------------------------
# TEST 4 - AUTOMATIC STARTUP EXECUTION DISABLED
# ------------------------------------------------------------

$noAutomaticStartup = (
    $checksConfig.executionPolicy.automaticExecutionOnStartup -eq $false -and
    $checksConfig.executionPolicy.executeOnScreenRender -eq $false
)

Assert-WinSecIntegration `
    -Condition $noAutomaticStartup `
    -Description 'Automatic execution remains disabled'

# ------------------------------------------------------------
# TEST 5 - ONLY VALIDATED DEFENDER ENABLED
# ------------------------------------------------------------

$enabledChecks = @(
    $checksConfig.checks | Where-Object {
        $_.execution.enabled -eq $true
    }
)

Assert-WinSecIntegration `
    -Condition ($enabledChecks.Count -eq 1 -and $enabledChecks[0].checkId -ceq 'WSA-SYS-001' -and $enabledChecks[0].implementationStatus -ceq 'VALIDATED') `
    -Description 'Only validated Defender is enabled in production'

# ------------------------------------------------------------
# TEST 6 - SCORING POLICY DISABLED
# ------------------------------------------------------------

$scoringDisabled = (
    $scoringConfig.enabled -eq $false -and
    $scoringConfig.activationStatus -ceq
        'PENDING_APPROVED_CRITERIA'
)

Assert-WinSecIntegration `
    -Condition $scoringDisabled `
    -Description 'Production scoring remains unapproved'

# Never proceed to real coordination if the
# production configuration is not safe for this test.

if (
    -not $readOnly -or
    -not $noAutomaticStartup -or
    $enabledChecks.Count -ne 1 -or
    $enabledChecks[0].checkId -cne 'WSA-SYS-001' -or
    $enabledChecks[0].implementationStatus -cne 'VALIDATED' -or
    -not $scoringDisabled
) {
    throw (
        'Safety preconditions failed. ' +
        'No scan was requested.'
    )
}

# ------------------------------------------------------------
# LOAD REAL COMPONENTS
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

$localId = [string]$localTarget.DeviceId

# ------------------------------------------------------------
# TEST 7 - COORDINATOR SAFETY
# ------------------------------------------------------------

$coordinatorSafe = (
    $null -ne $coordinator -and
    $coordinator.ScoringEnabled -eq $false -and
    $coordinator.RemoteExecution -eq $false -and
    $coordinator.AutomaticEvidencePersistence -eq $false
)

Assert-WinSecIntegration `
    -Condition $coordinatorSafe `
    -Description 'Real coordinator has safe settings'

if (-not $coordinatorSafe) {
    throw 'Unsafe coordinator configuration.'
}

# ------------------------------------------------------------
# CREATE REAL CLI CONTEXT
# ------------------------------------------------------------

$state = [pscustomobject]@{
    Screen = 'Devices'
    DeviceIndex = 0
    SelectedDeviceId = $localId
}

$context = [pscustomobject]@{
    ProjectRoot = $projectRoot

    ScanCoordinator = $coordinator
    Devices = @($devices)

    ActiveScanByDevice = @{}
    PublicScans = @{}

    LastScanMessage = ''

    SectionResults = @()
    ControlResults = @()
    Findings = @()

    ScanId = ''
}

# ------------------------------------------------------------
# TEST 8 - INITIAL HISTORY IS EMPTY
# ------------------------------------------------------------

$initialHistory = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $coordinator
)

Assert-WinSecIntegration `
    -Condition ($initialHistory.Count -eq 0) `
    -Description 'New coordinator has no scan history'

# ------------------------------------------------------------
# TEST 9 - LOCAL DEVICE IS AUTHORIZED
# ------------------------------------------------------------

$authorized = Test-WinSecCLIRescanEligibility `
    -State $state `
    -Devices $devices `
    -Coordinator $coordinator

Assert-WinSecIntegration `
    -Condition ($authorized -eq $true) `
    -Description 'Real local target is authorized'

if ($authorized -ne $true) {
    throw 'Local target authorization failed.'
}

# ------------------------------------------------------------
# TEST 10 - REMOTE TARGET IS REJECTED
# ------------------------------------------------------------

$remoteState = [pscustomobject]@{
    Screen = 'MainMenu'
    SelectedDeviceId = 'remote:INTEGRATION-TEST'
}

Assert-WinSecRejected `
    -State $remoteState `
    -Context $context `
    -Description 'Remote rescan is rejected without publication'

# ------------------------------------------------------------
# TEST 11 - INVALID SCREEN IS REJECTED
# ------------------------------------------------------------

$invalidState = [pscustomobject]@{
    Screen = 'Findings'
    SelectedDeviceId = $localId
}

Assert-WinSecRejected `
    -State $invalidState `
    -Context $context `
    -Description 'Rescan outside MainMenu is rejected'

# ------------------------------------------------------------
# TEST 12 - REJECTED ACTIONS CREATE NO HISTORY
# ------------------------------------------------------------

$historyAfterRejections = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $coordinator
)

Assert-WinSecIntegration `
    -Condition ($historyAfterRejections.Count -eq 0) `
    -Description 'Rejected requests create no scan sessions'

# ------------------------------------------------------------
# EXECUTE ONE REAL COORDINATED SCAN
# ------------------------------------------------------------

# This invokes the real coordination pipeline.
#
# The confirmed fixture replaces the collector boundary.
# No native collector checks should run.
#
# No evidence persistence parameter is supplied.

Write-Host ''
Write-Host '[INFO] Requesting one local coordinated scan...' `
    -ForegroundColor Cyan

$publicResult = Invoke-WinSecCLILocalRescan `
    -State $state `
    -Context $context `
    -ErrorAction Stop

# ------------------------------------------------------------
# TEST 13 - PUBLIC RESULT RETURNED
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $null -ne $publicResult -and
        $publicResult.PublicProjection -ceq $true
    ) `
    -Description 'Synthetic scan returns a public projection'

# ------------------------------------------------------------
# TEST 14 - DEVICE AND SCAN ID VALID
# ------------------------------------------------------------

$scanId = [string]$publicResult.ScanId

$identityValid = (
    $publicResult.DeviceId -ceq $localId -and
    -not [string]::IsNullOrWhiteSpace($scanId)
)

Assert-WinSecIntegration `
    -Condition $identityValid `
    -Description 'Public result belongs to local device'

# ------------------------------------------------------------
# TEST 15 - NO NUMERIC SECURITY SCORE
# ------------------------------------------------------------

$notScored = (
    $null -eq $publicResult.OverallScore -and
    $publicResult.OverallStatus -ceq 'NOT_SCORED' -and
    $publicResult.ScoringEligible -ceq $false
)

Assert-WinSecIntegration `
    -Condition $notScored `
    -Description 'Real result remains NOT_SCORED'

# ------------------------------------------------------------
# TEST 16 - NO RAW EVIDENCE
# ------------------------------------------------------------

$noRawEvidence = (
    $publicResult.ContainsRawEvidence -ceq $false -and
    $null -eq $publicResult.PSObject.Properties['Evidence'] -and
    $null -eq $publicResult.PSObject.Properties['RawEvidence']
)

Assert-WinSecIntegration `
    -Condition $noRawEvidence `
    -Description 'Public result contains no raw evidence'

# ------------------------------------------------------------
# TEST 17 - PUBLIC RESULT STORED BY SESSION
# ------------------------------------------------------------

$sessionKey = '{0}:{1}{2}:{3}' -f `
    $localId.Length,
    $localId,
    $scanId.Length,
    $scanId

$sessionStored = (
    $context.PublicScans.ContainsKey($sessionKey) -and
    -not [object]::ReferenceEquals(
        $context.PublicScans[$sessionKey],
        $publicResult
    ) -and
    (ConvertTo-Json -InputObject $context.PublicScans[$sessionKey] -Depth 15 -Compress) -ceq
        (ConvertTo-Json -InputObject $publicResult -Depth 15 -Compress)
)

Assert-WinSecIntegration `
    -Condition $sessionStored `
    -Description 'An equal independent public result is stored by DeviceId and ScanId'

# ------------------------------------------------------------
# TEST 18 - ACTIVE SCAN IS REGISTERED
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $context.ActiveScanByDevice[$localId] -ceq $scanId
    ) `
    -Description 'Active scan belongs to selected device'

# ------------------------------------------------------------
# TEST 19 - SAFE UI MESSAGE
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $context.LastScanMessage -match 'NOT_SCORED'
    ) `
    -Description 'CLI scan message reports NOT_SCORED'

# ------------------------------------------------------------
# TEST 20 - REAL HISTORY CONTAINS EXECUTION
# ------------------------------------------------------------

$history = @(
    Get-WinSecCoordinatorHistory `
        -Coordinator $coordinator `
        -DeviceId $localId
)

$matchingHistory = @(
    $history | Where-Object {
        $_.DeviceId -ceq $localId -and
        $_.ScanId -ceq $scanId
    }
)

Assert-WinSecIntegration `
    -Condition (
        $history.Count -eq 1 -and
        $matchingHistory.Count -eq 1
    ) `
    -Description 'Coordinator records the synthetic scan session'

# ------------------------------------------------------------
# TEST 21 - SYNTHETIC CONTROL COMPLETES
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $publicResult.ExecutionStatus -ceq
        'COMPLETED'
    ) `
    -Description 'Execution completes the synthetic control'

# ------------------------------------------------------------
# TEST 22 - NO COLLECTOR RESULTS
# ------------------------------------------------------------


# ------------------------------------------------------------
# TEST 22 - NO DISABLED CHECK WAS EXECUTED
# ------------------------------------------------------------

# WinSec Analyzer preserves non-selected control records
# for traceability.
#
# Expected behavior:
# - ExecutionStatus = COMPLETED (synthetic data only)
# - Control records may exist
# - Only the synthetic control is INFORMATIONAL; all others are NOT_SELECTED
# - No production collector is invoked
#
# This test does not require ControlResults to be empty.

$controlResults = @(
    $publicResult.ControlResults |
        Where-Object { $null -ne $_ }
)

$unexpectedControls = @(
    foreach ($control in $controlResults) {

        $checkId = [string](
            Get-WinSecCLIValue `
                -InputObject $control `
                -Name 'CheckId'
        )

        $status = [string](
            Get-WinSecCLIValue `
                -InputObject $control `
                -Name 'Status'
        )

        if (
            [string]::IsNullOrWhiteSpace($checkId) -or
            ($checkId -ceq 'WSA-SYS-001' -and $status -cne 'INFORMATIONAL') -or
            ($checkId -cne 'WSA-SYS-001' -and $status -cne 'NOT_SELECTED')
        ) {
            [pscustomobject]@{
                CheckId = $checkId
                Status  = $status
            }
        }
    }
)

Write-Host ''
Write-Host '[DIAGNOSTIC] Control execution validation' `
    -ForegroundColor Cyan

Write-Host (
    'ExecutionStatus: {0}' -f
    $publicResult.ExecutionStatus
)

Write-Host (
    'Control records: {0}' -f
    $controlResults.Count
)

Write-Host (
    'Unexpected control states: {0}' -f
    $unexpectedControls.Count
)

# Display only identifiers and states.
# Never expose raw collector evidence.

foreach ($control in $unexpectedControls) {
    Write-Host (
        '[UNEXPECTED] CheckId={0} | Status={1}' -f
        $control.CheckId,
        $control.Status
    ) -ForegroundColor Red
}

$noChecksExecuted = (
    $publicResult.ExecutionStatus -ceq
        'COMPLETED' -and
    $unexpectedControls.Count -eq 0
)

# Publication ownership: mutating the CLI response cannot rewrite its cache,
# the coordinator's completed session or later scan history.
$cacheBefore = ConvertTo-Json -InputObject $context.PublicScans[$sessionKey] -Depth 15 -Compress
$coreBefore = ConvertTo-Json -InputObject (
    Get-WinSecCoordinatorPublicResult -Coordinator $coordinator -DeviceId $localId -ScanId $scanId
) -Depth 15 -Compress
$historyBefore = ConvertTo-Json -InputObject $history -Depth 10 -Compress
$publicResult.DeviceId = 'local:CHANGED-RESPONSE'
$publicResult.ControlResults[0].ScanId = 'changed-response-scan'
$publicResult.ControlResults[0].Status = 'ERROR'
$publicResult.CheckResults[0].Status = 'UNKNOWN'

Assert-WinSecIntegration -Condition (
    $cacheBefore -ceq (ConvertTo-Json -InputObject $context.PublicScans[$sessionKey] -Depth 15 -Compress) -and
    (Get-WinSecCLIActiveAssessment -State $state -Context $context).ScanId -ceq $scanId
) -Description 'Mutating the CLI response preserves cached data and subsequent public reads'

Assert-WinSecIntegration -Condition (
    $coreBefore -ceq (ConvertTo-Json -InputObject (
        Get-WinSecCoordinatorPublicResult -Coordinator $coordinator -DeviceId $localId -ScanId $scanId
    ) -Depth 15 -Compress) -and
    $historyBefore -ceq (ConvertTo-Json -InputObject @(
        Get-WinSecCoordinatorHistory -Coordinator $coordinator -DeviceId $localId
    ) -Depth 10 -Compress)
) -Description 'Mutating the CLI response preserves the coordinator session and history'

$secondResult = Invoke-WinSecCLILocalRescan -State $state -Context $context -ErrorAction Stop
Assert-WinSecIntegration -Condition (
    $secondResult.ScanId -cne $scanId -and $context.PublicScans.Count -eq 2 -and
    $context.ActiveScanByDevice[$localId] -ceq $secondResult.ScanId -and
    $cacheBefore -ceq (ConvertTo-Json -InputObject $context.PublicScans[$sessionKey] -Depth 15 -Compress) -and
    @(Get-WinSecCoordinatorHistory -Coordinator $coordinator -DeviceId $localId).Count -eq 2
) -Description 'A second confirmed synthetic scan preserves the first cached session'

}
finally {
    Restore-WinSecConfirmedScanFixture
}

Assert-WinSecIntegration `
    -Condition $noChecksExecuted `
    -Description 'No disabled check was executed'

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
Write-Host '[PASS] All CLI Local Rescan integration tests passed.' `
    -ForegroundColor Green

Write-Host ''
