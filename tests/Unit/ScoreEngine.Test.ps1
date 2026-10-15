
# ============================================================
# WinSec Analyzer
# Test Suite : ScoreEngine
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit tests for the security scoring engine.
#
# Methodology:
# XCCDF 1.2 Flat Unweighted (adapted)
#
# Tests:
# - Scoring policy validation
# - PASS / FAIL / ERROR / UNKNOWN
# - PENDING and excluded statuses
# - Evidence requirements
# - Assessment coverage
# - Section and device scoring
# - Duplicate check detection
# - Device and scan isolation
#
# Compatible with PowerShell 5.1+
# No administrative privileges required.
# 
# .\tests\Unit\ScoreEngine.Test.ps1
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# Resolve project paths
# ------------------------------------------------------------

$projectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)

$scoreEnginePath = Join-Path `
    -Path $projectRoot `
    -ChildPath 'src/Core/ScoreEngine.ps1'

$scoringConfigPath = Join-Path `
    -Path $projectRoot `
    -ChildPath 'config/scoring.json'

# ------------------------------------------------------------
# Validate required files
# ------------------------------------------------------------

if (-not (
    Test-Path -LiteralPath $scoreEnginePath -PathType Leaf
)) {
    throw "ScoreEngine.ps1 not found: $scoreEnginePath"
}

if (-not (
    Test-Path -LiteralPath $scoringConfigPath -PathType Leaf
)) {
    throw "scoring.json not found: $scoringConfigPath"
}

# ------------------------------------------------------------
# Load scoring engine
# ------------------------------------------------------------

. $scoreEnginePath

# ------------------------------------------------------------
# Initialize test counters
# ------------------------------------------------------------

$script:ScoreTestsPassed = 0
$script:ScoreTestsFailed = 0
$script:ScorePolicy = $null


# ------------------------------------------------------------
# Assert equality
# ------------------------------------------------------------

function Assert-WinSecScoreEqual {
    param(
        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Expected,

        [string]$Message = 'Values do not match.'
    )

    if ($Actual -ne $Expected) {

        throw (
            '{0} Expected: [{1}], Actual: [{2}]' -f `
                $Message,
                $Expected,
                $Actual
        )
    }
}


# ------------------------------------------------------------
# Assert Boolean condition
# ------------------------------------------------------------

function Assert-WinSecScoreTrue {
    param(
        [bool]$Condition,

        [string]$Message = 'Expected condition is false.'
    )

    if (-not $Condition) {
        throw $Message
    }
}


# ------------------------------------------------------------
# Assert approximate numeric value
# ------------------------------------------------------------

function Assert-WinSecScoreNear {
    param(
        [double]$Actual,

        [double]$Expected,

        [double]$Tolerance = 0.001,

        [string]$Message = 'Numeric values differ.'
    )

    if (
        [Math]::Abs($Actual - $Expected) -gt $Tolerance
    ) {

        throw (
            '{0} Expected: {1}, Actual: {2}' -f `
                $Message,
                $Expected,
                $Actual
        )
    }
}


# ------------------------------------------------------------
# Assert an operation throws an expected error
# ------------------------------------------------------------

function Assert-WinSecScoreThrows {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action,

        [string]$ExpectedMessage = ''
    )

    $exceptionCaught = $false
    $actualMessage = ''

    try {

        $null = & $Action
    }
    catch {

        $exceptionCaught = $true
        $actualMessage = $_.Exception.Message
    }

    if (-not $exceptionCaught) {
        throw 'Expected an exception, but none occurred.'
    }

    if (
        $ExpectedMessage -and
        $actualMessage -notmatch $ExpectedMessage
    ) {

        throw (
            'Unexpected exception: {0}' -f $actualMessage
        )
    }
}


# ------------------------------------------------------------
# Execute an individual unit test
# ------------------------------------------------------------

function Invoke-WinSecScoreTest {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Test
    )

    try {

        $null = & $Test

        $script:ScoreTestsPassed++

        Write-Host "[PASS] $Name" `
            -ForegroundColor Green
    }
    catch {

        $script:ScoreTestsFailed++

        Write-Host "[FAIL] $Name" `
            -ForegroundColor Red

        Write-Host (
            '       {0}' -f $_.Exception.Message
        ) -ForegroundColor DarkGray
    }
}


# ------------------------------------------------------------
# Create synthetic security check
# ------------------------------------------------------------

function New-WinSecScoreTestCheck {
    [CmdletBinding()]
    param(
        [string]$CheckId = 'TEST-CHECK-001',

        [string]$DeviceId = 'TEST-PC-01',

        [string]$ScanId = 'TEST-SCAN-001',

        [string]$SectionKey = 'SystemSecurity',

        [string]$Status = 'PASS',

        [AllowNull()]
        [object]$Evidence = $null,

        [string]$NotApplicableReason = ''
    )

    return [PSCustomObject]@{
        CheckId             = $CheckId
        DeviceId            = $DeviceId
        ScanId              = $ScanId
        SectionKey          = $SectionKey
        Status              = $Status
        Evidence            = $Evidence
        NotApplicableReason = $NotApplicableReason
    }
}


# ------------------------------------------------------------
# Create sample assessment
# ------------------------------------------------------------

function Invoke-WinSecScoreTestAssessment {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Checks = @(),

        [string]$DeviceId = 'TEST-PC-01',

        [string]$ScanId = 'TEST-SCAN-001'
    )

    return Get-WinSecSecurityScore `
        -DeviceId $DeviceId `
        -ScanId $ScanId `
        -CheckResults $Checks `
        -Policy $script:ScorePolicy
}


# ------------------------------------------------------------
# Print test suite header
# ------------------------------------------------------------

Write-Host ''
Write-Host ('=' * 55) -ForegroundColor DarkGray

Write-Host 'WINSEC ANALYZER - SCORE ENGINE UNIT TESTS' `
    -ForegroundColor Cyan

Write-Host ('=' * 55) -ForegroundColor DarkGray
Write-Host ''


# ============================================================
# GROUP 1 - SCORING POLICY
# ============================================================

Write-Host '[1] SCORING POLICY' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecScoreTest `
    -Name 'Scoring policy loads successfully' `
    -Test {

        $script:ScorePolicy = Get-WinSecScoringPolicy `
            -Path $scoringConfigPath

        Assert-WinSecScoreTrue `
            -Condition ($null -ne $script:ScorePolicy) `
            -Message 'Scoring policy was not loaded.'

        Assert-WinSecScoreEqual `
            -Actual $script:ScorePolicy.methodology.scoringModel `
            -Expected 'urn:xccdf:scoring:flat-unweighted'
    }


Invoke-WinSecScoreTest `
    -Name 'Unit weight is fixed at 1' `
    -Test {

        Assert-WinSecScoreEqual `
            -Actual $script:ScorePolicy.methodology.unitWeight `
            -Expected 1

        Assert-WinSecScoreEqual `
            -Actual $script:ScorePolicy.methodology.allowCustomWeights `
            -Expected $false
    }


Invoke-WinSecScoreTest `
    -Name 'Custom weights are rejected' `
    -Test {

        $copy = ConvertFrom-Json -InputObject (
            ConvertTo-Json `
                -InputObject $script:ScorePolicy `
                -Depth 40
        )

        $copy.methodology.unitWeight = 3

        Assert-WinSecScoreThrows `
            -Action {
                Test-WinSecScoringPolicy -Policy $copy
            } `
            -ExpectedMessage 'unit weights'
    }


Invoke-WinSecScoreTest `
    -Name 'Unsupported scoring models are rejected' `
    -Test {

        $copy = ConvertFrom-Json -InputObject (
            ConvertTo-Json `
                -InputObject $script:ScorePolicy `
                -Depth 40
        )

        $copy.methodology.scoringModel = 'CUSTOM'

        Assert-WinSecScoreThrows `
            -Action {
                Test-WinSecScoringPolicy -Policy $copy
            } `
            -ExpectedMessage 'Unsupported scoring methodology'
    }


# ============================================================
# GROUP 2 - INDIVIDUAL CHECK RESULTS
# ============================================================

Write-Host ''
Write-Host '[2] SECURITY CHECK SCORING' `
    -ForegroundColor Cyan
Write-Host ''


Invoke-WinSecScoreTest `
    -Name 'PASS with evidence receives 100 points' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'PASS' `
            -Evidence @{
                Test = 'Windows Defender enabled'
            }

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks @($check)

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected 100

        Assert-WinSecScoreEqual `
            -Actual $result.Coverage `
            -Expected 100

        Assert-WinSecScoreEqual `
            -Actual $result.Status `
            -Expected 'COMPLETE'
    }


Invoke-WinSecScoreTest `
    -Name 'FAIL receives zero points' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'FAIL' `
            -Evidence 'Security requirement not satisfied'

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks @($check)

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $result.Coverage `
            -Expected 100

        Assert-WinSecScoreEqual `
            -Actual $result.FailedCount `
            -Expected 1
    }


Invoke-WinSecScoreTest `
    -Name 'ERROR receives zero points and reduces coverage' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'ERROR'

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks @($check)

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $result.Coverage `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $result.Status `
            -Expected 'PROVISIONAL'
    }


Invoke-WinSecScoreTest `
    -Name 'UNKNOWN receives zero points and reduces coverage' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'UNKNOWN'

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks @($check)

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $result.Coverage `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $result.UnknownCount `
            -Expected 1
    }


Invoke-WinSecScoreTest `
    -Name 'PENDING does not receive a security score' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'PENDING'

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks @($check)

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected $null

        Assert-WinSecScoreEqual `
            -Actual $result.Coverage `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $result.Status `
            -Expected 'PROVISIONAL'
    }


Invoke-WinSecScoreTest `
    -Name 'Empty assessment does not generate a score' `
    -Test {

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks @()

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected $null

        Assert-WinSecScoreEqual `
            -Actual $result.Coverage `
            -Expected $null

        Assert-WinSecScoreEqual `
            -Actual $result.Status `
            -Expected 'PENDING'

        Assert-WinSecScoreEqual `
            -Actual $result.TotalChecks `
            -Expected 0
    }


# ============================================================
# GROUP 3 - EVIDENCE VALIDATION
# ============================================================

Write-Host ''
Write-Host '[3] EVIDENCE VALIDATION' -ForegroundColor Cyan
Write-Host ''


Invoke-WinSecScoreTest `
    -Name 'PASS without evidence becomes UNKNOWN' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'PASS'

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks @($check)

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $result.Coverage `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $result.CheckResults[0].Status `
            -Expected 'UNKNOWN'

        Assert-WinSecScoreEqual `
            -Actual $result.CheckResults[0].OriginalStatus `
            -Expected 'PASS'
    }


Invoke-WinSecScoreTest `
    -Name 'Whitespace evidence is not accepted for PASS' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'PASS' `
            -Evidence '   '

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks @($check)

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $result.CheckResults[0].Status `
            -Expected 'UNKNOWN'
    }


Invoke-WinSecScoreTest `
    -Name 'FAIL without evidence generates validation warning' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'FAIL'

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks @($check)

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected 0

        Assert-WinSecScoreTrue `
            -Condition (
                $result.CheckResults[0].ValidationIssue -match
                'no supporting evidence'
            ) `
            -Message 'Missing evidence warning was not generated.'
    }


# ============================================================
# GROUP 4 - SCORE AND COVERAGE CALCULATIONS
# ============================================================

Write-Host ''
Write-Host '[4] SCORE AND COVERAGE CALCULATIONS' `
    -ForegroundColor Cyan
Write-Host ''


Invoke-WinSecScoreTest `
    -Name 'Mixed assessment produces correct score and coverage' `
    -Test {

        $checks = @(
            New-WinSecScoreTestCheck `
                -CheckId 'CHECK-01' `
                -Status 'PASS' `
                -Evidence 'Verified'

            New-WinSecScoreTestCheck `
                -CheckId 'CHECK-02' `
                -Status 'FAIL' `
                -Evidence 'Noncompliant'

            New-WinSecScoreTestCheck `
                -CheckId 'CHECK-03' `
                -Status 'ERROR'

            New-WinSecScoreTestCheck `
                -CheckId 'CHECK-04' `
                -Status 'UNKNOWN'

            New-WinSecScoreTestCheck `
                -CheckId 'CHECK-05' `
                -Status 'PENDING'
        )

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks $checks

        # Score = 1 PASS / 4 scored checks = 25%
        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected 25

        # Coverage = 2 verified / 5 selected = 40%
        Assert-WinSecScoreEqual `
            -Actual $result.Coverage `
            -Expected 40

        Assert-WinSecScoreEqual `
            -Actual $result.ScoredRules `
            -Expected 4

        Assert-WinSecScoreEqual `
            -Actual $result.VerifiedChecks `
            -Expected 2

        Assert-WinSecScoreEqual `
            -Actual $result.Status `
            -Expected 'PROVISIONAL'
    }


Invoke-WinSecScoreTest `
    -Name 'NOT_APPLICABLE is excluded with a reason' `
    -Test {

        $checks = @(
            New-WinSecScoreTestCheck `
                -CheckId 'CHECK-01' `
                -Status 'PASS' `
                -Evidence 'Verified'

            New-WinSecScoreTestCheck `
                -CheckId 'CHECK-02' `
                -Status 'NOT_APPLICABLE' `
                -NotApplicableReason 'Feature not installed'
        )

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks $checks

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected 100

        Assert-WinSecScoreEqual `
            -Actual $result.Coverage `
            -Expected 100

        Assert-WinSecScoreEqual `
            -Actual $result.NotApplicableCount `
            -Expected 1
    }


Invoke-WinSecScoreTest `
    -Name 'NOT_APPLICABLE without a reason is rejected' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'NOT_APPLICABLE'

        Assert-WinSecScoreThrows `
            -Action {
                Invoke-WinSecScoreTestAssessment `
                    -Checks @($check)
            } `
            -ExpectedMessage 'requires a reason'
    }


Invoke-WinSecScoreTest `
    -Name 'MANUAL and NOT_SELECTED do not affect the score' `
    -Test {

        $checks = @(
            New-WinSecScoreTestCheck `
                -CheckId 'CHECK-01' `
                -Status 'MANUAL'

            New-WinSecScoreTestCheck `
                -CheckId 'CHECK-02' `
                -Status 'NOT_SELECTED'
        )

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks $checks

        Assert-WinSecScoreEqual `
            -Actual $result.Score `
            -Expected $null

        Assert-WinSecScoreEqual `
            -Actual $result.Coverage `
            -Expected $null

        Assert-WinSecScoreEqual `
            -Actual $result.Status `
            -Expected 'PENDING'
    }


# ============================================================
# GROUP 5 - INPUT VALIDATION
# ============================================================

Write-Host ''
Write-Host '[5] INPUT VALIDATION' -ForegroundColor Cyan
Write-Host ''


Invoke-WinSecScoreTest `
    -Name 'WARNING is rejected as unsupported scoring status' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'WARNING'

        Assert-WinSecScoreThrows `
            -Action {
                Invoke-WinSecScoreTestAssessment `
                    -Checks @($check)
            } `
            -ExpectedMessage 'Unsupported status'
    }


Invoke-WinSecScoreTest `
    -Name 'Invalid section is rejected' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -SectionKey 'InvalidSection'

        Assert-WinSecScoreThrows `
            -Action {
                Invoke-WinSecScoreTestAssessment `
                    -Checks @($check)
            } `
            -ExpectedMessage 'Invalid section'
    }


Invoke-WinSecScoreTest `
    -Name 'Missing ScanId is rejected' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -ScanId ''

        Assert-WinSecScoreThrows `
            -Action {
                Invoke-WinSecScoreTestAssessment `
                    -Checks @($check)
            } `
            -ExpectedMessage 'without ScanId'
    }


Invoke-WinSecScoreTest `
    -Name 'Duplicate CheckId is rejected' `
    -Test {

        $checks = @(
            New-WinSecScoreTestCheck `
                -CheckId 'DUPLICATE-CHECK' `
                -Evidence 'Verified A'

            New-WinSecScoreTestCheck `
                -CheckId 'DUPLICATE-CHECK' `
                -Evidence 'Verified B'
        )

        Assert-WinSecScoreThrows `
            -Action {
                Invoke-WinSecScoreTestAssessment `
                    -Checks $checks
            } `
            -ExpectedMessage 'Duplicate CheckId'
    }


# ============================================================
# GROUP 6 - DEVICE AND SCAN ISOLATION
# ============================================================

Write-Host ''
Write-Host '[6] DEVICE AND SCAN ISOLATION' `
    -ForegroundColor Cyan
Write-Host ''


Invoke-WinSecScoreTest `
    -Name 'Scores remain isolated by DeviceId' `
    -Test {

        $checks = @(
            New-WinSecScoreTestCheck `
                -CheckId 'DEFENDER' `
                -DeviceId 'TEST-PC-01' `
                -Status 'PASS' `
                -Evidence 'Enabled'

            New-WinSecScoreTestCheck `
                -CheckId 'DEFENDER' `
                -DeviceId 'TEST-PC-02' `
                -Status 'FAIL' `
                -Evidence 'Disabled'
        )

        $first = Invoke-WinSecScoreTestAssessment `
            -Checks $checks `
            -DeviceId 'TEST-PC-01'

        $second = Invoke-WinSecScoreTestAssessment `
            -Checks $checks `
            -DeviceId 'TEST-PC-02'

        Assert-WinSecScoreEqual `
            -Actual $first.Score `
            -Expected 100

        Assert-WinSecScoreEqual `
            -Actual $second.Score `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $first.TotalChecks `
            -Expected 1

        Assert-WinSecScoreEqual `
            -Actual $second.TotalChecks `
            -Expected 1
    }


Invoke-WinSecScoreTest `
    -Name 'Scores remain isolated by ScanId' `
    -Test {

        $checks = @(
            New-WinSecScoreTestCheck `
                -CheckId 'FIREWALL' `
                -ScanId 'TEST-SCAN-001' `
                -Status 'PASS' `
                -Evidence 'Enabled'

            New-WinSecScoreTestCheck `
                -CheckId 'FIREWALL' `
                -ScanId 'TEST-SCAN-002' `
                -Status 'FAIL' `
                -Evidence 'Disabled'
        )

        $first = Invoke-WinSecScoreTestAssessment `
            -Checks $checks `
            -ScanId 'TEST-SCAN-001'

        $second = Invoke-WinSecScoreTestAssessment `
            -Checks $checks `
            -ScanId 'TEST-SCAN-002'

        Assert-WinSecScoreEqual `
            -Actual $first.Score `
            -Expected 100

        Assert-WinSecScoreEqual `
            -Actual $second.Score `
            -Expected 0

        Assert-WinSecScoreEqual `
            -Actual $first.ScanId `
            -Expected 'TEST-SCAN-001'

        Assert-WinSecScoreEqual `
            -Actual $second.ScanId `
            -Expected 'TEST-SCAN-002'
    }


# ============================================================
# GROUP 7 - SECTION AND DEVICE AGGREGATION
# ============================================================

Write-Host ''
Write-Host '[7] SECTION AND DEVICE AGGREGATION' `
    -ForegroundColor Cyan
Write-Host ''


Invoke-WinSecScoreTest `
    -Name 'Overall score uses rule-level aggregation' `
    -Test {

        $checks = @(
            New-WinSecScoreTestCheck `
                -CheckId 'DEFENDER' `
                -SectionKey 'SystemSecurity' `
                -Status 'PASS' `
                -Evidence 'Enabled'

            New-WinSecScoreTestCheck `
                -CheckId 'BITLOCKER' `
                -SectionKey 'SystemSecurity' `
                -Status 'FAIL' `
                -Evidence 'Disabled'

            New-WinSecScoreTestCheck `
                -CheckId 'FIREWALL' `
                -SectionKey 'NetworkSecurity' `
                -Status 'PASS' `
                -Evidence 'Enabled'
        )

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks $checks

        # 2 passed / 3 scored = 66.67
        Assert-WinSecScoreNear `
            -Actual $result.Score `
            -Expected 66.67

        $system = @(
            $result.SectionResults | Where-Object {
                $_.Key -eq 'SystemSecurity'
            }
        )[0]

        $network = @(
            $result.SectionResults | Where-Object {
                $_.Key -eq 'NetworkSecurity'
            }
        )[0]

        Assert-WinSecScoreEqual `
            -Actual $system.Score `
            -Expected 50

        Assert-WinSecScoreEqual `
            -Actual $network.Score `
            -Expected 100

        # The overall score must NOT be the
        # average of 50 and 100 (75).

        Assert-WinSecScoreTrue `
            -Condition ($result.Score -ne 75) `
            -Message 'Section averages were used incorrectly.'
    }


Invoke-WinSecScoreTest `
    -Name 'All five sections are returned' `
    -Test {

        $check = New-WinSecScoreTestCheck `
            -Status 'PASS' `
            -Evidence 'Verified'

        $result = Invoke-WinSecScoreTestAssessment `
            -Checks @($check)

        Assert-WinSecScoreEqual `
            -Actual $result.SectionResults.Count `
            -Expected 5

        $emptySection = @(
            $result.SectionResults | Where-Object {
                $_.Key -eq 'ServicesHardening'
            }
        )[0]

        Assert-WinSecScoreEqual `
            -Actual $emptySection.Score `
            -Expected $null

        Assert-WinSecScoreEqual `
            -Actual $emptySection.Status `
            -Expected 'PENDING'
    }


# ============================================================
# FINAL TEST SUMMARY
# ============================================================

$total = (
    $script:ScoreTestsPassed +
    $script:ScoreTestsFailed
)

Write-Host ''
Write-Host ('=' * 55) -ForegroundColor DarkGray

Write-Host 'SCORE ENGINE TEST SUMMARY' `
    -ForegroundColor Cyan

Write-Host ''
Write-Host "Total tests : $total"

Write-Host "Passed      : $script:ScoreTestsPassed" `
    -ForegroundColor Green

$failureColor = 'Green'

if ($script:ScoreTestsFailed -gt 0) {
    $failureColor = 'Red'
}

Write-Host "Failed      : $script:ScoreTestsFailed" `
    -ForegroundColor $failureColor

Write-Host ''

if ($script:ScoreTestsFailed -gt 0) {

    throw (
        '{0} ScoreEngine unit test(s) failed.' -f `
            $script:ScoreTestsFailed
    )
}

Write-Host 'All ScoreEngine unit tests passed.' `
    -ForegroundColor Green

Write-Host ''
