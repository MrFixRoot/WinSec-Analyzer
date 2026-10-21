
# ============================================================
# WinSec Analyzer
# Integration Tests - CLI Public Scan Results
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
# - Local target only
# - Production checks remain disabled; only in-memory test metadata is simulated
# - No scoring
# - No remote sessions
# - No evidence persistence
# - No production configuration changes
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

# ------------------------------------------------------------
# ASSERTION HELPERS
# ------------------------------------------------------------

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

function Assert-WinSecAssessmentRejected {
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Context,

        [Parameter(Mandatory)]
        [string]$Description
    )

    $rejected = $false
    $assessment = $null

    try {
        $assessment = Get-WinSecCLIActiveAssessment `
            -State $State `
            -Context $Context `
            -ErrorAction Stop
    }
    catch {
        $rejected = $true
    }

    Assert-WinSecIntegration `
        -Condition (
            $rejected -and
            $null -eq $assessment
        ) `
        -Description $Description
}

function Get-TestSessionKey {
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId
    )

    return ('{0}:{1}{2}:{3}' -f `
        $DeviceId.Length,
        $DeviceId,
        $ScanId.Length,
        $ScanId)
}

Write-Host ''
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ' WINSEC ANALYZER' `
    -ForegroundColor Cyan
Write-Host ' CLI PUBLIC RESULTS INTEGRATION TESTS' `
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

foreach ($path in $requiredFiles) {
    if (-not (
        Test-Path -LiteralPath $path -PathType Leaf
    )) {
        Write-Host "[MISSING] $path" `
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
# TEST 3 - READ-ONLY POLICY
# ------------------------------------------------------------

$readOnlyPolicy = (
    $checksConfig.executionPolicy.readOnly -eq $true -and
    $checksConfig.executionPolicy.automaticRemediation -eq $false
)

Assert-WinSecIntegration `
    -Condition $readOnlyPolicy `
    -Description 'Execution policy remains read-only'

# ------------------------------------------------------------
# TEST 4 - AUTOMATIC EXECUTION DISABLED
# ------------------------------------------------------------

$automaticExecutionDisabled = (
    $checksConfig.executionPolicy.automaticExecutionOnStartup -eq $false -and
    $checksConfig.executionPolicy.executeOnScreenRender -eq $false
)

Assert-WinSecIntegration `
    -Condition $automaticExecutionDisabled `
    -Description 'Automatic execution remains disabled'

# ------------------------------------------------------------
# TEST 5 - ALL CHECKS DISABLED
# ------------------------------------------------------------

$enabledChecks = @(
    $checksConfig.checks | Where-Object {
        $_.execution.enabled -eq $true
    }
)

Assert-WinSecIntegration `
    -Condition ($enabledChecks.Count -eq 0) `
    -Description 'No executable security checks are enabled'

# ------------------------------------------------------------
# TEST 6 - SCORING DISABLED
# ------------------------------------------------------------

$scoringDisabled = (
    $scoringConfig.enabled -eq $false -and
    $scoringConfig.activationStatus -ceq
        'PENDING_APPROVED_CRITERIA'
)

Assert-WinSecIntegration `
    -Condition $scoringDisabled `
    -Description 'Security scoring remains unapproved'

# ------------------------------------------------------------
# ABORT IF SAFETY REQUIREMENTS FAIL
# ------------------------------------------------------------

if (
    -not $readOnlyPolicy -or
    -not $automaticExecutionDisabled -or
    $enabledChecks.Count -gt 0 -or
    -not $scoringDisabled
) {
    throw (
        'Safety preconditions failed. ' +
        'No coordinated scan was requested.'
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
    throw 'Local target could not be resolved.'
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
    -Description 'Coordinator security restrictions are active'

if (-not $coordinatorSafe) {
    throw 'Unsafe coordinator configuration.'
}

# ------------------------------------------------------------
# TEST 8 - LOCAL DEVICE REGISTRATION
# ------------------------------------------------------------

$localDevices = @(
    $devices | Where-Object {
        $_.DeviceId -ceq $localId -and
        $_.Mode -ceq 'LOCAL' -and
        $_.Enabled -eq $true
    }
)

Assert-WinSecIntegration `
    -Condition ($localDevices.Count -eq 1) `
    -Description 'Current local device is registered once'

if ($localDevices.Count -ne 1) {
    throw 'Local device registration is invalid.'
}

# ------------------------------------------------------------
# TEST FIXTURES
# ------------------------------------------------------------

$state = [pscustomobject]@{
    Screen = 'MainMenu'
    SelectedDeviceId = $localId
}

$context = [pscustomobject]@{
    ProjectRoot = $projectRoot
    Version = '0.9.0'

    ScanCoordinator = $coordinator
    Devices = @($devices)

    ActiveScanByDevice = @{}
    PublicScans = @{}

    SectionResults = @()
    ControlResults = @()
    Findings = @()

    ScanId = ''
    LastScanMessage = ''
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
    -Description 'New coordinator has no scan sessions'

# ------------------------------------------------------------
# EXECUTE ONE SYNTHETIC LOCAL SCAN
# ------------------------------------------------------------

# The production catalog was verified above.
# Production checks remain disabled; the collector is replaced by a synthetic fixture.
# No evidence persistence parameter is supplied.

Write-Host ''
Write-Host '[INFO] Requesting one synthetic local scan...' `
    -ForegroundColor Cyan

$publicResult = Invoke-WinSecCLILocalRescan `
    -State $state `
    -Context $context `
    -ErrorAction Stop

# ------------------------------------------------------------
# TEST 10 - PUBLIC RESULT RETURNED
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $null -ne $publicResult -and
        $publicResult.PublicProjection -ceq $true
    ) `
    -Description 'Coordinator returns a public result'

# ------------------------------------------------------------
# TEST 11 - SYNTHETIC CONTROL COMPLETES
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $publicResult.ExecutionStatus -ceq
        'COMPLETED'
    ) `
    -Description 'Execution completes the synthetic control'

# ------------------------------------------------------------
# TEST 12 - PUBLIC RESULT SAFETY
# ------------------------------------------------------------

$scanId = [string]$publicResult.ScanId

$publicSafe = (
    $publicResult.DeviceId -ceq $localId -and
    -not [string]::IsNullOrWhiteSpace($scanId) -and
    $publicResult.ContainsRawEvidence -ceq $false -and
    $null -eq $publicResult.PSObject.Properties['Evidence'] -and
    $null -eq $publicResult.PSObject.Properties['RawEvidence']
)

Assert-WinSecIntegration `
    -Condition $publicSafe `
    -Description 'Public result has safe device and scan identity'

# ------------------------------------------------------------
# TEST 13 - SESSION INDEX
# ------------------------------------------------------------

$sessionKey = Get-TestSessionKey `
    -DeviceId $localId `
    -ScanId $scanId

$sessionIndexed = (
    $context.PublicScans.ContainsKey($sessionKey) -and
    $context.ActiveScanByDevice[$localId] -ceq $scanId
)

Assert-WinSecIntegration `
    -Condition $sessionIndexed `
    -Description 'Scan is indexed by DeviceId and ScanId'

# ------------------------------------------------------------
# TEST 14 - CLI RESOLVES REAL PUBLIC ASSESSMENT
# ------------------------------------------------------------

$assessment = Get-WinSecCLIActiveAssessment `
    -State $state `
    -Context $context `
    -ErrorAction Stop

Assert-WinSecIntegration `
    -Condition (
        $null -ne $assessment -and
        $assessment.ScanId -ceq $scanId
    ) `
    -Description 'CLI selects the real active public assessment'

# ------------------------------------------------------------
# TEST 15 - CLI NEVER CALCULATES SECURITY SCORE
# ------------------------------------------------------------

Assert-WinSecIntegration `
    -Condition (
        $null -eq $assessment.OverallScore -and
        $assessment.OverallStatus -ceq 'NOT_SCORED'
    ) `
    -Description 'CLI assessment remains NOT_SCORED'

# ------------------------------------------------------------
# TEST 16 - PUBLIC CONTROL RECORDS ARE PRESERVED
# ------------------------------------------------------------

$sourceControls = @(
    $publicResult.ControlResults |
        Where-Object { $null -ne $_ }
)

$displayControls = @(
    $assessment.ControlResults |
        Where-Object { $null -ne $_ }
)

Assert-WinSecIntegration `
    -Condition (
        $displayControls.Count -eq $sourceControls.Count
    ) `
    -Description 'CLI preserves public control records'

# ------------------------------------------------------------
# TEST 17 - NO DISABLED CONTROL WAS EXECUTED
# ------------------------------------------------------------

$unexpectedControls = @(
    $displayControls | Where-Object {
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
    -Description 'All other controls remain NOT_SELECTED'

# ------------------------------------------------------------
# TEST 18 - OTHER DEVICE CANNOT ACCESS LOCAL SCAN
# ------------------------------------------------------------

}
finally {
    Restore-WinSecConfirmedScanFixture
}

$otherState = [pscustomobject]@{
    Screen = 'MainMenu'
    SelectedDeviceId = 'remote:INTEGRATION-TEST'
}

$otherAssessment = Get-WinSecCLIActiveAssessment `
    -State $otherState `
    -Context $context `
    -ErrorAction Stop

$otherControls = @(
    $otherAssessment.ControlResults |
        Where-Object { $null -ne $_ }
)

Assert-WinSecIntegration `
    -Condition (
        $otherControls.Count -eq 0 -and
        $null -eq $otherAssessment.OverallScore -and
        $otherAssessment.OverallStatus -ceq 'PENDING'
    ) `
    -Description 'Other devices cannot see local assessment records'

# ------------------------------------------------------------
# TEST 19 - MISMATCHED ACTIVE SCAN IS REJECTED
# ------------------------------------------------------------

$originalActiveScan = $context.ActiveScanByDevice[$localId]

try {
    $context.ActiveScanByDevice[$localId] = 'scan-UNKNOWN'

    Assert-WinSecAssessmentRejected `
        -State $state `
        -Context $context `
        -Description 'Unknown selected ScanId is rejected'
}
finally {
    $context.ActiveScanByDevice[$localId] = $originalActiveScan
}

# ------------------------------------------------------------
# TEST 20 - ROOT RAW EVIDENCE IS REJECTED
# ------------------------------------------------------------

$originalStoredResult = $context.PublicScans[$sessionKey]

try {
    # Copy only for the test. Do not modify coordinator
    # history or the original published result.

    $forgedResult = $originalStoredResult.PSObject.Copy()

    $forgedResult | Add-Member `
        -NotePropertyName Evidence `
        -NotePropertyValue 'SECRET-INTEGRATION-TEST'

    $context.PublicScans[$sessionKey] = $forgedResult

    Assert-WinSecAssessmentRejected `
        -State $state `
        -Context $context `
        -Description 'CLI rejects injected root evidence'
}
finally {
    $context.PublicScans[$sessionKey] = $originalStoredResult
}

# ------------------------------------------------------------
# TEST 21 - UNAPPROVED NUMERIC SCORE IS REJECTED
# ------------------------------------------------------------

try {
    $forgedResult = $originalStoredResult.PSObject.Copy()

    $forgedResult.OverallScore = 100

    $context.PublicScans[$sessionKey] = $forgedResult

    Assert-WinSecAssessmentRejected `
        -State $state `
        -Context $context `
        -Description 'CLI rejects injected numeric score'
}
finally {
    $context.PublicScans[$sessionKey] = $originalStoredResult
}

# ------------------------------------------------------------
# TEST 22 - LEGACY RECORDS REMAIN UNSCORED
# ------------------------------------------------------------

$legacyContext = [pscustomobject]@{
    Devices = @(
        [pscustomobject]@{
            DeviceId = $localId
            ScanId = 'legacy-001'
            Score = 100
            Status = 'PASS'
        }
    )

    ActiveScanByDevice = @{}
    PublicScans = @{}

    SectionResults = @()

    ControlResults = @(
        [pscustomobject]@{
            DeviceId = $localId
            ScanId = 'legacy-001'
            CheckId = 'LEGACY-CONTROL'
            Status = 'NOT_EVALUATED'
        }
    )

    Findings = @()
    ScanId = 'legacy-001'
}

$legacyAssessment = Get-WinSecCLIActiveAssessment `
    -State $state `
    -Context $legacyContext `
    -ErrorAction Stop

Assert-WinSecIntegration `
    -Condition (
        $legacyAssessment.ScanId -ceq 'legacy-001' -and
        $null -eq $legacyAssessment.OverallScore -and
        $legacyAssessment.OverallStatus -ceq 'NOT_SCORED'
    ) `
    -Description 'Legacy assessment ignores forged device score'

# ------------------------------------------------------------
# TEST 23 - REAL HISTORY CONTAINS ONE SESSION
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
    -Description 'Coordinator history preserves the confirmed synthetic scan'

# ------------------------------------------------------------
# TEST 24 - PRODUCTION CONFIGURATION UNCHANGED
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
    -Description 'Production configuration remains unchanged'

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
Write-Host '[PASS] All CLI Public Results integration tests passed.' `
    -ForegroundColor Green
Write-Host ''
