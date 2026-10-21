
# ============================================================
# WinSec Analyzer
# Unit Tests - CLI Local Rescan Execution
#
# Version   : 0.9.0
# Author    : mrRoot
# Component : Invoke-WinSecCLILocalRescan
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

$script:passed = 0
$script:failed = 0

function Assert-WinSecUnit {
    param(
        [bool]$Condition,
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
        [psobject]$State,
        [psobject]$Context,
        [string]$Description
    )

    $rejected = $false
    $beforeCalls = $script:scanCalls

    try {
        $null = Invoke-WinSecCLILocalRescan `
            -State $State `
            -Context $Context `
            -ErrorAction Stop
    }
    catch {
        $rejected = $true
    }

    $noPublication = (
        $Context.ActiveScanByDevice.Count -eq 0 -and
        $Context.PublicScans.Count -eq 0
    )

    Assert-WinSecUnit `
        -Condition ($rejected -and $noPublication) `
        -Description $Description

    return [pscustomobject]@{
        Rejected = $rejected
        ScanCallsChanged = (
            $script:scanCalls -ne $beforeCalls
        )
    }
}

# ------------------------------------------------------------
# TEST 1 - CLI SOURCE EXISTS AND PARSES
# ------------------------------------------------------------

if (-not (Test-Path -LiteralPath $cliPath -PathType Leaf)) {
    throw "CLI not found: $cliPath"
}

$tokens = $null
$parseErrors = $null

$null = [System.Management.Automation.Language.Parser]::ParseFile(
    $cliPath,
    [ref]$tokens,
    [ref]$parseErrors
)

Assert-WinSecUnit `
    -Condition (@($parseErrors).Count -eq 0) `
    -Description 'CLI PowerShell syntax is valid'

if (@($parseErrors).Count -gt 0) {
    throw 'CLI syntax validation failed.'
}

# ------------------------------------------------------------
# LOAD CLI WITHOUT STARTING INTERACTIVE MODE
# ------------------------------------------------------------

. $cliPath

if (-not (
    Get-Command Invoke-WinSecCLILocalRescan `
        -CommandType Function `
        -ErrorAction SilentlyContinue
)) {
    throw 'Invoke-WinSecCLILocalRescan was not found.'
}

# ------------------------------------------------------------
# TEST DOUBLE STATE
# ------------------------------------------------------------

$script:scanCalls = 0
$script:resolverCalls = 0
$script:resolverReject = $false
$script:scanShouldThrow = $false
$script:persistEvidenceRequested = $false

# ------------------------------------------------------------
# SIMULATED DEPENDENCIES
# ------------------------------------------------------------

function New-WinSecLocalTarget {
    return [pscustomobject]@{
        DeviceId = 'local:UNIT-PC'
        Mode = 'LOCAL'
        Enabled = $true
    }
}

function Resolve-WinSecScanTarget {
    [CmdletBinding()]
    param(
        [object]$Coordinator,
        [string]$DeviceId
    )

    $script:resolverCalls++

    if (
        $script:resolverReject -or
        $DeviceId -cne 'local:UNIT-PC'
    ) {
        throw 'Test target rejected.'
    }

    return [pscustomobject]@{
        DeviceId = $DeviceId
        Mode = 'LOCAL'
        Enabled = $true
    }
}

function Invoke-WinSecCoordinatedScan {
    [CmdletBinding()]
    param(
        [object]$Coordinator,
        [string]$DeviceId,
        [switch]$PersistEvidence,
        [scriptblock]$ConfirmAction
    )

    $script:scanCalls++

    if ($null -eq $ConfirmAction) { throw 'Missing confirmation callback.' }

    if ($PersistEvidence.IsPresent) {
        $script:persistEvidenceRequested = $true
    }

    if ($script:scanShouldThrow) {
        throw 'Simulated collector failure.'
    }

    return $script:mockPublicResult
}

# ------------------------------------------------------------
# TEST FIXTURES
# ------------------------------------------------------------

function New-TestPublicResult {
    param(
        [string]$ScanId = 'scan-unit-001',
        [string]$DeviceId = 'local:UNIT-PC'
    )

    return [pscustomobject]@{
        PublicProjection = $true
        ContainsRawEvidence = $false

        DeviceId = $DeviceId
        ScanId = $ScanId

        ScoringEligible = $false
        OverallScore = $null
        OverallStatus = 'NOT_SCORED'

        ExecutionStatus = 'NO_EXECUTABLE_CHECKS'

        ControlResults = @()
        SectionResults = @()
        Findings = @()
    }
}

function Reset-TestFixture {
    $script:resolverReject = $false
    $script:scanShouldThrow = $false
    $script:persistEvidenceRequested = $false

    $script:mockPublicResult = New-TestPublicResult

    $script:testCoordinator = [pscustomobject]@{
        Component = 'ScanCoordinator'
        ScoringEnabled = $false
        RemoteExecution = $false
        AutomaticEvidencePersistence = $false
    }

    $script:testState = [pscustomobject]@{
        Screen = 'Devices'
        DeviceIndex = 0
        SelectedDeviceId = 'local:UNIT-PC'
    }

    $script:testContext = [pscustomobject]@{
        ScanCoordinator = $script:testCoordinator

        Devices = @(
            [pscustomobject]@{
                DeviceId = 'local:UNIT-PC'
                Mode = 'LOCAL'
                Enabled = $true
            }
        )

        ActiveScanByDevice = @{}
        PublicScans = @{}
        LastScanMessage = ''
    }
}

# ------------------------------------------------------------
# TEST 2 - AUTHORIZED LOCAL SCAN
# ------------------------------------------------------------

Reset-TestFixture

$beforeCalls = $script:scanCalls

$result = Invoke-WinSecCLILocalRescan `
    -State $script:testState `
    -Context $script:testContext

Assert-WinSecUnit `
    -Condition (
        $null -ne $result -and
        $result.DeviceId -ceq 'local:UNIT-PC' -and
        $script:scanCalls -eq ($beforeCalls + 1)
    ) `
    -Description 'Authorized local scan calls coordinator once'

# ------------------------------------------------------------
# TEST 3 - PUBLIC RESULT IS STORED
# ------------------------------------------------------------

$scanId = 'scan-unit-001'
$deviceId = 'local:UNIT-PC'

$sessionKey = '{0}:{1}{2}:{3}' -f `
    $deviceId.Length,
    $deviceId,
    $scanId.Length,
    $scanId

Assert-WinSecUnit `
    -Condition (
        $script:testContext.PublicScans.ContainsKey($sessionKey) -and
        $script:testContext.PublicScans[$sessionKey].PublicProjection -eq $true
    ) `
    -Description 'Validated public result is stored by session key'

# ------------------------------------------------------------
# TEST 4 - ACTIVE SCAN IS TRACKED PER DEVICE
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $script:testContext.ActiveScanByDevice['local:UNIT-PC'] -ceq
        'scan-unit-001'
    ) `
    -Description 'Active scan is associated with DeviceId'

# ------------------------------------------------------------
# TEST 5 - NO EXECUTABLE CHECKS MESSAGE
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $script:testContext.LastScanMessage -match
        'no executable checks' -and
        $script:testContext.LastScanMessage -match
        'NOT_SCORED'
    ) `
    -Description 'No executable checks are reported safely'

# ------------------------------------------------------------
# TEST 6 - NO EVIDENCE PERSISTENCE REQUEST
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (-not $script:persistEvidenceRequested) `
    -Description 'Evidence persistence is never requested'

# ------------------------------------------------------------
# TEST 7 - SECOND SCAN PRESERVES PREVIOUS SESSION
# ------------------------------------------------------------

$script:mockPublicResult = New-TestPublicResult `
    -ScanId 'scan-unit-002'

$null = Invoke-WinSecCLILocalRescan `
    -State $script:testState `
    -Context $script:testContext

Assert-WinSecUnit `
    -Condition (
        $script:testContext.PublicScans.Count -eq 2 -and
        $script:testContext.ActiveScanByDevice['local:UNIT-PC'] -ceq
            'scan-unit-002'
    ) `
    -Description 'Second scan preserves prior session'

# ------------------------------------------------------------
# TEST 8 - REMOTE TARGET IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:testState.SelectedDeviceId = 'remote:OTHER-PC'
$script:testContext.Devices[0].DeviceId = 'remote:OTHER-PC'

$beforeCalls = $script:scanCalls

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Remote scan is rejected without publication'

Assert-WinSecUnit `
    -Condition ($script:scanCalls -eq $beforeCalls) `
    -Description 'Remote rejection prevents scan execution'

# ------------------------------------------------------------
# TEST 10 - INVALID SCREEN IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:testState.Screen = 'Findings'

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Scan outside MainMenu is rejected'

# ------------------------------------------------------------
# TEST 11 - COORDINATOR REJECTION
# ------------------------------------------------------------

Reset-TestFixture

$script:resolverReject = $true

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Coordinator authorization failure is rejected'

# ------------------------------------------------------------
# TEST 12 - SCORING ACTIVATION IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:testCoordinator.ScoringEnabled = $true

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Unauthorized scoring activation is rejected'

# ------------------------------------------------------------
# TEST 13 - REMOTE EXECUTION ACTIVATION IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:testCoordinator.RemoteExecution = $true

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Remote execution activation is rejected'

# ------------------------------------------------------------
# TEST 14 - AUTO EVIDENCE PERSISTENCE IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:testCoordinator.AutomaticEvidencePersistence = $true

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Automatic evidence persistence is rejected'

# ------------------------------------------------------------
# TEST 15 - FORGED NUMERIC SCORE IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:mockPublicResult.OverallScore = 100

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Forged numeric security score is rejected'

# ------------------------------------------------------------
# TEST 16 - RAW EVIDENCE IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:mockPublicResult |
    Add-Member -NotePropertyName Evidence `
               -NotePropertyValue 'SECRET-TEST-DATA'

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Raw evidence in public result is rejected'

# ------------------------------------------------------------
# TEST 17 - MISMATCHED DEVICE ID IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:mockPublicResult.DeviceId = 'remote:OTHER-PC'

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Mismatched result DeviceId is rejected'

# ------------------------------------------------------------
# TEST 18 - EMPTY SCAN ID IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:mockPublicResult.ScanId = ''

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Missing ScanId is rejected'

# ------------------------------------------------------------
# TEST 19 - COLLECTOR FAILURE IS NOT PUBLISHED
# ------------------------------------------------------------

Reset-TestFixture

$script:scanShouldThrow = $true

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Collector failure does not publish a result'

# ------------------------------------------------------------
# TEST 20 - MISSING PUBLIC COLLECTION IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:testContext.PublicScans = $null

$rejected = $false

try {
    $null = Invoke-WinSecCLILocalRescan `
        -State $script:testState `
        -Context $script:testContext `
        -ErrorAction Stop
}
catch {
    $rejected = $true
}

Assert-WinSecUnit `
    -Condition (
        $rejected -and
        $script:testContext.ActiveScanByDevice.Count -eq 0
    ) `
    -Description 'Uninitialized public collection is rejected'

# ------------------------------------------------------------
# TEST 21 - INVALID PUBLIC PROJECTION IS REJECTED
# ------------------------------------------------------------

Reset-TestFixture

$script:mockPublicResult.PublicProjection = $false

$null = Assert-WinSecRejected `
    -State $script:testState `
    -Context $script:testContext `
    -Description 'Invalid public projection is rejected'

# ------------------------------------------------------------
# TEST SUMMARY
# ------------------------------------------------------------

Write-Host ''
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ' UNIT TEST SUMMARY' `
    -ForegroundColor Cyan
Write-Host '=========================================' `
    -ForegroundColor Cyan

Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"

if ($script:failed -gt 0) {
    throw "$script:failed unit test(s) failed."
}

Write-Host ''
Write-Host '[PASS] All CLI Local Rescan unit tests passed.' `
    -ForegroundColor Green
Write-Host ''
