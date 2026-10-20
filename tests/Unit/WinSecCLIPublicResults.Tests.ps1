
# ============================================================
# WinSec Analyzer
# Unit Tests - CLI Public Scan Results
#
# Version   : 0.9.0
# Author    : mrRoot
# Component : Get-WinSecCLIActiveAssessment
#
# PowerShell 5.1 / 7.x
# No Pester required
#
# Security:
# - No real scans
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
    $published = $null

    try {
        $published = Get-WinSecCLIActiveAssessment `
            -State $State `
            -Context $Context `
            -ErrorAction Stop
    }
    catch {
        $rejected = $true
    }

    Assert-WinSecUnit `
        -Condition (
            $rejected -and
            $null -eq $published
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

# ------------------------------------------------------------
# TEST FIXTURES
# ------------------------------------------------------------

function New-TestPublicResult {
    param(
        [string]$DeviceId = 'local:UNIT-PC',
        [string]$ScanId = 'scan-001'
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

        SectionResults = @(
            [pscustomobject]@{
                DeviceId = $DeviceId
                ScanId = $ScanId
                SectionKey = 'SystemSecurity'
                Name = 'System Security'
                Status = 'NOT_SCORED'
                Score = $null
            }
        )

        ControlResults = @(
            [pscustomobject]@{
                DeviceId = $DeviceId
                ScanId = $ScanId
                CheckId = 'WSA-SYS-001'
                SectionKey = 'SystemSecurity'
                Status = 'NOT_SELECTED'
                Score = $null
            }
        )

        Findings = @()
    }
}

function New-TestFixture {
    param(
        [string]$DeviceId = 'local:UNIT-PC',
        [string]$ScanId = 'scan-001'
    )

    $publicResult = New-TestPublicResult `
        -DeviceId $DeviceId `
        -ScanId $ScanId

    $key = Get-TestSessionKey `
        -DeviceId $DeviceId `
        -ScanId $ScanId

    $publicScans = @{}
    $publicScans[$key] = $publicResult

    $activeScans = @{}
    $activeScans[$DeviceId] = $ScanId

    $state = [pscustomobject]@{
        Screen = 'MainMenu'
        SelectedDeviceId = $DeviceId
    }

    $context = [pscustomobject]@{
        Devices = @(
            [pscustomobject]@{
                DeviceId = $DeviceId
                Score = 100
                Status = 'PASS'
                ScanId = $ScanId
            }
        )

        ActiveScanByDevice = $activeScans
        PublicScans = $publicScans

        SectionResults = @()
        ControlResults = @()
        Findings = @()

        ScanId = ''
    }

    return [pscustomobject]@{
        State = $state
        Context = $context
        Result = $publicResult
        SessionKey = $key
    }
}

Write-Host ''
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ' WINSEC ANALYZER - UNIT TESTS' `
    -ForegroundColor Cyan
Write-Host ' CLI PUBLIC SCAN RESULTS' `
    -ForegroundColor Cyan
Write-Host '=========================================' `
    -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------
# TEST 1 - CLI FILE EXISTS
# ------------------------------------------------------------

$exists = Test-Path `
    -LiteralPath $cliPath `
    -PathType Leaf

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
            'Line {0}: {1}' -f
            $item.Extent.StartLineNumber,
            $item.Message
        ) -ForegroundColor Red
    }

    throw 'CLI syntax validation failed.'
}

# ------------------------------------------------------------
# TEST 3 - ASSESSMENT FUNCTION EXISTS EXACTLY ONCE
# ------------------------------------------------------------

$assessmentFunctions = @(
    $ast.FindAll({
        param($node)

        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-WinSecCLIActiveAssessment'
    }, $true)
)

Assert-WinSecUnit `
    -Condition ($assessmentFunctions.Count -eq 1) `
    -Description 'Assessment resolver is defined exactly once'

if ($assessmentFunctions.Count -ne 1) {
    throw 'Assessment function is missing or duplicated.'
}

# ------------------------------------------------------------
# LOAD CLI WITHOUT STARTING THE APPLICATION
# ------------------------------------------------------------

. $cliPath

# ------------------------------------------------------------
# TEST 4 - PUBLIC SCAN MAP IS USED
# ------------------------------------------------------------

$functionText = $assessmentFunctions[0].Body.Extent.Text

$publicIntegrationExists = (
    $functionText -match 'ActiveScanByDevice' -and
    $functionText -match 'PublicScans' -and
    $functionText -match 'PublicProjection'
)

Assert-WinSecUnit `
    -Condition $publicIntegrationExists `
    -Description 'Active public scan integration exists'

# ------------------------------------------------------------
# TEST 5 - VALID PUBLIC RESULT IS SELECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$assessment = Get-WinSecCLIActiveAssessment `
    -State $fixture.State `
    -Context $fixture.Context

Assert-WinSecUnit `
    -Condition (
        $null -ne $assessment -and
        $assessment.ScanId -ceq 'scan-001'
    ) `
    -Description 'Active public scan is selected'

# ------------------------------------------------------------
# TEST 6 - CONTROL RESULTS ARE AVAILABLE
# ------------------------------------------------------------

$controls = @(
    $assessment.ControlResults |
        Where-Object { $null -ne $_ }
)

Assert-WinSecUnit `
    -Condition (
        $controls.Count -eq 1 -and
        $controls[0].CheckId -ceq 'WSA-SYS-001' -and
        $controls[0].Status -ceq 'NOT_SELECTED'
    ) `
    -Description 'Public control records are preserved'

# ------------------------------------------------------------
# TEST 7 - SECTION RESULTS ARE AVAILABLE
# ------------------------------------------------------------

$sections = @(
    $assessment.SectionResults |
        Where-Object { $null -ne $_ }
)

Assert-WinSecUnit `
    -Condition (
        $sections.Count -eq 1 -and
        $sections[0].Name -ceq 'System Security'
    ) `
    -Description 'Public section records are preserved'

# ------------------------------------------------------------
# TEST 8 - SECURITY SCORE REMAINS UNAPPROVED
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $null -eq $assessment.OverallScore -and
        $assessment.OverallStatus -ceq 'NOT_SCORED'
    ) `
    -Description 'Assessment remains NOT_SCORED'

# ------------------------------------------------------------
# TEST 9 - FORGED DEVICE SCORE IS IGNORED
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $fixture.Context.Devices[0].Score -eq 100 -and
        $null -eq $assessment.OverallScore
    ) `
    -Description 'Device metadata cannot authorize scoring'

# ------------------------------------------------------------
# TEST 10 - DIFFERENT DEVICES REMAIN ISOLATED
# ------------------------------------------------------------

$fixture = New-TestFixture

$otherResult = New-TestPublicResult `
    -DeviceId 'remote:OTHER-PC' `
    -ScanId 'scan-001'

$otherKey = Get-TestSessionKey `
    -DeviceId 'remote:OTHER-PC' `
    -ScanId 'scan-001'

$fixture.Context.PublicScans[$otherKey] = $otherResult

$fixture.Context.ActiveScanByDevice['remote:OTHER-PC'] = 'scan-001'

$assessment = Get-WinSecCLIActiveAssessment `
    -State $fixture.State `
    -Context $fixture.Context

Assert-WinSecUnit `
    -Condition (
        $assessment.ScanId -ceq 'scan-001' -and
        @($assessment.ControlResults).Count -eq 1 -and
        $fixture.State.SelectedDeviceId -ceq 'local:UNIT-PC'
    ) `
    -Description 'Selected device is isolated from other devices'

# ------------------------------------------------------------
# TEST 11 - DIFFERENT EXECUTIONS REMAIN ISOLATED
# ------------------------------------------------------------

$fixture = New-TestFixture

$secondResult = New-TestPublicResult `
    -ScanId 'scan-002'

$secondResult.ControlResults[0].CheckId = 'WSA-SYS-002'

$secondKey = Get-TestSessionKey `
    -DeviceId 'local:UNIT-PC' `
    -ScanId 'scan-002'

$fixture.Context.PublicScans[$secondKey] = $secondResult

$fixture.Context.ActiveScanByDevice['local:UNIT-PC'] = 'scan-002'

$assessment = Get-WinSecCLIActiveAssessment `
    -State $fixture.State `
    -Context $fixture.Context

Assert-WinSecUnit `
    -Condition (
        $assessment.ScanId -ceq 'scan-002' -and
        @($assessment.ControlResults).Count -eq 1 -and
        $assessment.ControlResults[0].CheckId -ceq 'WSA-SYS-002'
    ) `
    -Description 'Active ScanId selects only its own execution'

# ------------------------------------------------------------
# TEST 12 - ORIGINAL SESSION IS PRESERVED
# ------------------------------------------------------------

Assert-WinSecUnit `
    -Condition (
        $fixture.Context.PublicScans.Count -eq 2 -and
        $fixture.Context.PublicScans.ContainsKey(
            $fixture.SessionKey
        ) -and
        $fixture.Context.PublicScans.ContainsKey(
            $secondKey
        )
    ) `
    -Description 'Selecting a scan preserves prior sessions'

# ------------------------------------------------------------
# TEST 13 - EMPTY ACTIVE SCAN ID IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture
$fixture.Context.ActiveScanByDevice['local:UNIT-PC'] = ''

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Empty active ScanId is rejected'

# ------------------------------------------------------------
# TEST 14 - MISSING PUBLIC SESSION IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture
$fixture.Context.PublicScans.Clear()

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Missing public session is rejected'

# ------------------------------------------------------------
# TEST 15 - NULL PUBLIC RESULT IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Context.PublicScans[$fixture.SessionKey] = $null

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Null public result is rejected'

# ------------------------------------------------------------
# TEST 16 - INVALID PUBLIC PROJECTION IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result.PublicProjection = $false

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Invalid public projection is rejected'

# ------------------------------------------------------------
# TEST 17 - MISMATCHED DEVICE ID IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result.DeviceId = 'remote:OTHER-PC'

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Mismatched DeviceId is rejected'

# ------------------------------------------------------------
# TEST 18 - MISMATCHED SCAN ID IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result.ScanId = 'scan-FORGED'

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Mismatched ScanId is rejected'

# ------------------------------------------------------------
# TEST 19 - NUMERIC OVERALL SCORE IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result.OverallScore = 100

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Unapproved overall score is rejected'

# ------------------------------------------------------------
# TEST 20 - SCORING ELIGIBILITY IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result.ScoringEligible = $true

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Unauthorized scoring eligibility is rejected'

# ------------------------------------------------------------
# TEST 21 - FORGED OVERALL STATUS IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result.OverallStatus = 'PASS'

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Forged overall PASS status is rejected'

# ------------------------------------------------------------
# TEST 22 - RAW EVIDENCE FLAG IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result.ContainsRawEvidence = $true

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Raw evidence flag is rejected'

# ------------------------------------------------------------
# TEST 23 - ROOT EVIDENCE PROPERTY IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result | Add-Member `
    -NotePropertyName Evidence `
    -NotePropertyValue 'SECRET-UNIT-TEST'

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Root evidence property is rejected'

# ------------------------------------------------------------
# TEST 24 - ROOT RAW EVIDENCE PROPERTY IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result | Add-Member `
    -NotePropertyName RawEvidence `
    -NotePropertyValue 'SECRET-UNIT-TEST'

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Root RawEvidence property is rejected'

# ------------------------------------------------------------
# TEST 25 - NESTED CONTROL EVIDENCE IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result.ControlResults[0] | Add-Member `
    -NotePropertyName Evidence `
    -NotePropertyValue 'SECRET-CONTROL-DATA'

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Nested control evidence is rejected'

# ------------------------------------------------------------
# TEST 26 - NESTED SECTION SCORE IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result.SectionResults[0].Score = 90

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Unapproved section score is rejected'

# ------------------------------------------------------------
# TEST 27 - NESTED CONTROL SCORE IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Result.ControlResults[0].Score = 100

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Unapproved control score is rejected'

# ------------------------------------------------------------
# TEST 28 - INVALID PUBLIC COLLECTION IS REJECTED
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Context.PublicScans = $null

Assert-WinSecRejected `
    -State $fixture.State `
    -Context $fixture.Context `
    -Description 'Missing public collection is rejected'

# ------------------------------------------------------------
# TEST 29 - EMPTY DEVICE SELECTION REMAINS PENDING
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.State.SelectedDeviceId = ''

$assessment = Get-WinSecCLIActiveAssessment `
    -State $fixture.State `
    -Context $fixture.Context

Assert-WinSecUnit `
    -Condition (
        $assessment.OverallStatus -ceq 'PENDING' -and
        $null -eq $assessment.OverallScore -and
        @($assessment.ControlResults | Where-Object {
            $null -ne $_
        }).Count -eq 0
    ) `
    -Description 'Missing device selection returns empty assessment'

# ------------------------------------------------------------
# TEST 30 - NO ACTIVE SCAN PRESERVES LEGACY PATH
# ------------------------------------------------------------

$fixture = New-TestFixture

$fixture.Context.ActiveScanByDevice.Clear()

$fixture.Context.ControlResults = @(
    [pscustomobject]@{
        DeviceId = 'local:UNIT-PC'
        ScanId = 'legacy-001'
        CheckId = 'LEGACY-TEST'
        Status = 'NOT_EVALUATED'
    }
)

$fixture.Context.ScanId = 'legacy-001'

$assessment = Get-WinSecCLIActiveAssessment `
    -State $fixture.State `
    -Context $fixture.Context

Assert-WinSecUnit `
    -Condition (
        $assessment.ScanId -ceq 'legacy-001' -and
        $null -eq $assessment.OverallScore -and
        @($assessment.ControlResults).Count -eq 1 -and
        $assessment.ControlResults[0].CheckId -ceq 'LEGACY-TEST'
    ) `
    -Description 'Legacy assessment remains available without scoring'

# ------------------------------------------------------------
# NESTED PUBLIC RECORD IDENTITY REGRESSIONS
# ------------------------------------------------------------

$identityCases = @(
    @{ Name = 'foreign device'; Field = 'DeviceId'; Value = 'remote:OTHER-PC' }
    @{ Name = 'foreign scan'; Field = 'ScanId'; Value = 'scan-OTHER' }
    @{ Name = 'missing device'; Field = 'DeviceId'; Remove = $true }
    @{ Name = 'missing scan'; Field = 'ScanId'; Remove = $true }
    @{ Name = 'null device'; Field = 'DeviceId'; Value = $null }
    @{ Name = 'null scan'; Field = 'ScanId'; Value = $null }
    @{ Name = 'empty device'; Field = 'DeviceId'; Value = '' }
    @{ Name = 'empty scan'; Field = 'ScanId'; Value = '' }
    @{ Name = 'numeric device'; Field = 'DeviceId'; Value = 123 }
    @{ Name = 'numeric scan'; Field = 'ScanId'; Value = 123 }
    @{ Name = 'array device'; Field = 'DeviceId'; Value = @('local:UNIT-PC') }
    @{ Name = 'array scan'; Field = 'ScanId'; Value = @('scan-001') }
    @{ Name = 'device case mismatch'; Field = 'DeviceId'; Value = 'local:unit-pc' }
    @{ Name = 'scan case mismatch'; Field = 'ScanId'; Value = 'SCAN-001' }
)

foreach ($collectionName in @('SectionResults', 'ControlResults', 'Findings')) {
    foreach ($identityCase in $identityCases) {
        $fixture = New-TestFixture

        if ($collectionName -eq 'Findings') {
            $fixture.Result.Findings = @(
                [pscustomobject]@{
                    DeviceId = 'local:UNIT-PC'
                    ScanId = 'scan-001'
                    FindingId = 'UNIT-FINDING-001'
                    CheckId = 'WSA-SYS-001'
                    Kind = 'EVALUATION_PENDING'
                    EvaluationStatus = 'NOT_EVALUATED'
                    Severity = 'UNASSIGNED'
                    Priority = 'UNASSIGNED'
                }
            )
        }

        $record = $fixture.Result.$collectionName[0]
        $field = $identityCase.Field

        if ($identityCase.Remove) {
            $record.PSObject.Properties.Remove($field)
        }
        else {
            $record.$field = $identityCase.Value
        }

        Assert-WinSecRejected `
            -State $fixture.State `
            -Context $fixture.Context `
            -Description ('{0} rejects {1}' -f $collectionName, $identityCase.Name)
    }
}

# A valid diagnostic finding is still available to the selected assessment.

$fixture = New-TestFixture
$fixture.Result.Findings = @(
    [pscustomobject]@{
        DeviceId = 'local:UNIT-PC'
        ScanId = 'scan-001'
        FindingId = 'UNIT-FINDING-001'
        CheckId = 'WSA-SYS-001'
        Kind = 'EVALUATION_PENDING'
        EvaluationStatus = 'NOT_EVALUATED'
        Severity = 'UNASSIGNED'
        Priority = 'UNASSIGNED'
    }
)

$assessment = Get-WinSecCLIActiveAssessment `
    -State $fixture.State `
    -Context $fixture.Context

Assert-WinSecUnit `
    -Condition (
        @($assessment.Findings).Count -eq 1 -and
        $assessment.Findings[0].FindingId -ceq 'UNIT-FINDING-001' -and
        $assessment.OverallStatus -ceq 'NOT_SCORED'
    ) `
    -Description 'Matching nested findings remain available without scoring'

# Rejection must not replace the active session or change navigation state.

$fixture.Result.ControlResults[0].ScanId = 'scan-OTHER'
$contextBefore = ConvertTo-Json -InputObject $fixture.Context -Depth 12 -Compress
$stateBefore = ConvertTo-Json -InputObject $fixture.State -Depth 4 -Compress

try {
    $null = Get-WinSecCLIActiveAssessment `
        -State $fixture.State `
        -Context $fixture.Context `
        -ErrorAction Stop
}
catch {
    # The rejection itself is covered by the matrix above.
}

Assert-WinSecUnit `
    -Condition (
        (ConvertTo-Json -InputObject $fixture.Context -Depth 12 -Compress) -ceq $contextBefore -and
        (ConvertTo-Json -InputObject $fixture.State -Depth 4 -Compress) -ceq $stateBefore
    ) `
    -Description 'Rejected nested identity preserves sessions and navigation'

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
Write-Host '[PASS] All CLI Public Results unit tests passed.' `
    -ForegroundColor Green
Write-Host ''
