
# ============================================================
# WinSec Analyzer
# Test Suite : Evaluation Engine Integration
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Integration tests for the Windows security evaluation
# engine and Microsoft Defender evidence collector.
#
# Includes:
# - Component availability and import
# - PowerShell syntax validation
# - Synthetic PASS and FAIL evaluations
# - Evidence identity preservation
# - Framework source and recommendation handling
# - Real Defender evidence integration
# - Missing criteria protection
# - No automatic compliance grading
# - No Windows configuration changes
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# Synthetic criteria are not actual CIS requirements.
# Real Defender evidence is never graded using fixtures.
# The suite does not modify Windows security settings.
# ============================================================

[CmdletBinding()]
param(
    [switch]$SkipLive
)

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0

$script:Root = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)

$script:EnginePath = Join-Path `
    $script:Root `
    'src/Core/EvaluationEngine.ps1'

$script:DefenderPath = Join-Path `
    $script:Root `
    'src/Checks/Defender/Test-Defender.ps1'


# ============================================================
# ASSERTIONS
# ============================================================

function Assert-Equal {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [string]$Message = 'Values differ.'
    )

    if ($null -eq $Expected) {
        if ($null -ne $Actual) {
            throw "$Message Expected null, got [$Actual]."
        }

        return
    }

    if ($null -eq $Actual -or $Actual -cne $Expected) {
        throw "$Message Expected [$Expected], got [$Actual]."
    }
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) {
        throw $Message
    }
}


# ============================================================
# TEST EXECUTION
# ============================================================

function Test-Case {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    try {
        $null = & $Action

        $script:Passed++

        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:Failed++

        Write-Host (
            "[FAIL] $Name - $($_.Exception.Message)"
        ) -ForegroundColor Red

        if ($_.ScriptStackTrace) {
            Write-Host $_.ScriptStackTrace `
                -ForegroundColor DarkGray
        }
    }
}

function Skip-Case {
    param(
        [string]$Name,
        [string]$Reason
    )

    $script:Skipped++

    Write-Host (
        "[SKIP] $Name - $Reason"
    ) -ForegroundColor Yellow
}


# ============================================================
# SUMMARY
# ============================================================

function Complete-Tests {
    $total = (
        $script:Passed +
        $script:Failed +
        $script:Skipped
    )

    Write-Host ''
    Write-Host ('=' * 60)
    Write-Host 'EVALUATION ENGINE INTEGRATION SUMMARY'
    Write-Host "TOTAL : $total"
    Write-Host "PASS  : $script:Passed"
    Write-Host "FAIL  : $script:Failed"
    Write-Host "SKIP  : $script:Skipped"
    Write-Host ('=' * 60)
    Write-Host ''

    if ($script:Failed -gt 0) {
        throw (
            "$($script:Failed) Evaluation Engine integration test(s) failed."
        )
    }

    if ($script:Skipped -gt 0) {
        Write-Host (
            'Integration completed with incomplete coverage.'
        ) -ForegroundColor Yellow
    }
    else {
        Write-Host (
            'All Evaluation Engine integration tests passed.'
        ) -ForegroundColor Green
    }
}


# ============================================================
# START TESTS
# ============================================================

Write-Host ''
Write-Host 'WinSec Analyzer - Evaluation Engine Integration'
Write-Host ''


# ============================================================
# GROUP 1 - COMPONENT VALIDATION
# ============================================================

Test-Case 'Evaluation Engine exists' {
    Assert-True (
        Test-Path $script:EnginePath -PathType Leaf
    )
}

Test-Case 'Defender collector exists' {
    Assert-True (
        Test-Path $script:DefenderPath -PathType Leaf
    )
}

if ($script:Failed -gt 0) {
    Complete-Tests
    return
}

foreach ($file in @(
    $script:EnginePath,
    $script:DefenderPath
)) {
    $name = Split-Path $file -Leaf

    Test-Case "$name parses correctly" {
        $tokens = $null
        $errors = $null

        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $file,
            [ref]$tokens,
            [ref]$errors
        )

        Assert-Equal @($errors).Count 0
    }
}

if ($script:Failed -gt 0) {
    Complete-Tests
    return
}


# ============================================================
# GROUP 2 - IMPORT COMPONENTS
# ============================================================

try {
    . (Join-Path $script:Root 'src/Core/TargetRegistry.ps1')
    . $script:EnginePath
    . $script:DefenderPath
}
catch {
    $script:Failed++

    Write-Host (
        "[FAIL] Component import - $($_.Exception.Message)"
    ) -ForegroundColor Red

    Complete-Tests
    return
}

Test-Case 'Evaluation function is available' {
    Assert-True (
        $null -ne (
            Get-Command Invoke-WinSecControlEvaluation
        )
    )
}

Test-Case 'Defender function is available' {
    Assert-True (
        $null -ne (
            Get-Command Test-WinSecDefender
        )
    )
}


# ============================================================
# GROUP 3 - SYNTHETIC INTEGRATION FIXTURES
# ============================================================

# Explicitly synthetic OS/device identity.
# No real Windows configuration is altered.

$script:FixtureControl = [pscustomobject]@{
    CheckId = 'WSA-SYS-001'
    DeviceId = 'local:INTEGRATION-FIXTURE'
    ScanId = 'FIXTURE-SCAN-001'
    Status = 'INFORMATIONAL'

    Evidence = [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:INTEGRATION-FIXTURE'
        ScanId = 'FIXTURE-SCAN-001'
        CollectionSuccessful = $true

        DefenderPreferences = [pscustomobject]@{
            PUAProtection = 0
        }
    }
}

$script:FixtureContext = [pscustomobject]@{
    DeviceId = 'local:INTEGRATION-FIXTURE'
    ScanId = 'FIXTURE-SCAN-001'
    OSFamily = 'Windows'
    OSRelease = 'TEST-RELEASE'
    Edition = 'TEST-EDITION'
    Profile = 'TEST-PROFILE'
}

$script:FixtureCriterion = [pscustomobject]@{
    CriterionId = 'INTEGRATION-LOCAL-001'
    CheckId = 'WSA-SYS-001'

    EvidencePath = 'DefenderPreferences.PUAProtection'
    Operator = 'Equals'
    ExpectedValue = 1

    Approved = $true

    Source = [pscustomobject]@{
        Framework = 'LOCAL_POLICY'
        Version = 'TEST-ONLY'
        ControlId = 'INTEGRATION-LOCAL-001'
        Title = 'Synthetic PUA comparison'
        Url = 'https://example.invalid/winsec-test'
    }

    Verification = [pscustomobject]@{
        Status = 'VERIFIED'
        ReviewedBy = 'INTEGRATION-TEST-FIXTURE'
        ReviewedAtUTC = '2025-01-01T00:00:00Z'
    }

    Applicability = [pscustomobject]@{
        OSFamily = 'Windows'
        OSRelease = 'TEST-RELEASE'
        Edition = 'TEST-EDITION'
        Profile = 'TEST-PROFILE'
    }

    Recommendation = (
        'Synthetic integration recommendation only.'
    )
}


# ============================================================
# GROUP 4 - SYNTHETIC EVALUATION
# ============================================================

Test-Case 'Synthetic evidence produces expected FAIL' {
    $r = Invoke-WinSecControlEvaluation `
        -ControlResult $script:FixtureControl `
        -Criteria @($script:FixtureCriterion) `
        -TargetContext $script:FixtureContext

    Assert-Equal $r.Status 'FAIL'
    Assert-Equal $r.FailedCriteria 1
    Assert-Equal $r.ScoringEligible $true
}

Test-Case 'Synthetic PASS and FAIL use the same contract' {
    $control = [pscustomobject]@{
        CheckId = $script:FixtureControl.CheckId
        DeviceId = $script:FixtureControl.DeviceId
        ScanId = $script:FixtureControl.ScanId
        Status = 'INFORMATIONAL'

        Evidence = [pscustomobject]@{
            CheckId = $script:FixtureControl.CheckId
            DeviceId = $script:FixtureControl.DeviceId
            ScanId = $script:FixtureControl.ScanId
            CollectionSuccessful = $true

            DefenderPreferences = [pscustomobject]@{
                PUAProtection = 1
            }
        }
    }

    $r = Invoke-WinSecControlEvaluation `
        -ControlResult $control `
        -Criteria @($script:FixtureCriterion) `
        -TargetContext $script:FixtureContext

    Assert-Equal $r.Status 'PASS'
    Assert-Equal $r.PassedCriteria 1
}

Test-Case 'Synthetic evaluation preserves identity' {
    $r = Invoke-WinSecControlEvaluation `
        -ControlResult $script:FixtureControl `
        -Criteria @($script:FixtureCriterion) `
        -TargetContext $script:FixtureContext

    Assert-Equal $r.CheckId 'WSA-SYS-001'
    Assert-Equal $r.DeviceId 'local:INTEGRATION-FIXTURE'
    Assert-Equal $r.ScanId 'FIXTURE-SCAN-001'
}

Test-Case 'Synthetic recommendation is preserved' {
    $r = Invoke-WinSecControlEvaluation `
        -ControlResult $script:FixtureControl `
        -Criteria @($script:FixtureCriterion) `
        -TargetContext $script:FixtureContext

    Assert-Equal `
        $r.Evaluations[0].Recommendation `
        'Synthetic integration recommendation only.'
}

Test-Case 'Synthetic framework source remains LOCAL_POLICY' {
    $r = Invoke-WinSecControlEvaluation `
        -ControlResult $script:FixtureControl `
        -Criteria @($script:FixtureCriterion) `
        -TargetContext $script:FixtureContext

    Assert-Equal `
        $r.Evaluations[0].Source.Framework `
        'LOCAL_POLICY'
}

Test-Case 'Synthetic evaluation rejects missing criteria' {
    $r = Invoke-WinSecControlEvaluation `
        -ControlResult $script:FixtureControl

    Assert-Equal $r.Status 'NOT_EVALUATED'
    Assert-Equal $r.ScoringEligible $false
}

Test-Case 'Synthetic evaluation rejects foreign context' {
    $context = [pscustomobject]@{
        DeviceId = 'local:OTHER-FIXTURE'
        ScanId = 'FIXTURE-SCAN-001'
        OSFamily = 'Windows'
        OSRelease = 'TEST-RELEASE'
        Edition = 'TEST-EDITION'
        Profile = 'TEST-PROFILE'
    }

    $r = Invoke-WinSecControlEvaluation `
        -ControlResult $script:FixtureControl `
        -Criteria @($script:FixtureCriterion) `
        -TargetContext $context

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoringEligible $false
}


# ============================================================
# GROUP 5 - REAL DEFENDER INTEGRATION
# ============================================================

Write-Host ''
Write-Host 'Real Defender evidence integration'
Write-Host ''

if ($SkipLive -or $env:OS -ne 'Windows_NT') {
    Skip-Case `
        'Real Defender evidence collection' `
        'Live collection was skipped or Windows is unavailable.'

    Complete-Tests
    return
}

$script:LiveResult = $null

$script:LiveDeviceId = Get-WinSecLocalHardwareDeviceId

$script:LiveScanId = (
    'EVALUATION-INTEGRATION-{0}' -f
    [guid]::NewGuid().ToString('N')
)

Test-Case 'Defender returns a structured result' {
    $results = @(
        Test-WinSecDefender `
            -DeviceId $script:LiveDeviceId `
            -ScanId $script:LiveScanId `
            -CheckId 'WSA-SYS-001'
    )

    Assert-Equal $results.Count 1

    $script:LiveResult = $results[0]

    Assert-True (
        $null -ne $script:LiveResult.Evidence
    )
}

if ($null -eq $script:LiveResult) {
    Complete-Tests
    return
}

Test-Case 'Real Defender identity is preserved' {
    Assert-Equal $script:LiveResult.CheckId 'WSA-SYS-001'
    Assert-Equal $script:LiveResult.DeviceId $script:LiveDeviceId
    Assert-Equal $script:LiveResult.ScanId $script:LiveScanId
}

Test-Case 'Real Defender remains informational or error' {
    Assert-True (
        $script:LiveResult.Status -in @(
            'INFORMATIONAL',
            'ERROR'
        )
    )
}

Test-Case 'Real Defender evidence remains ungraded' {
    Assert-Equal `
        $script:LiveResult.Evidence.ScoringEligible `
        $false

    Assert-Equal `
        $script:LiveResult.Evidence.ComplianceAssessment `
        'NOT_EVALUATED'
}

Test-Case 'Real evidence without criteria is not graded' {
    $r = Invoke-WinSecControlEvaluation `
        -ControlResult $script:LiveResult

    Assert-Equal $r.ScoringEligible $false

    Assert-True (
        $r.Status -in @(
            'NOT_EVALUATED',
            'UNKNOWN'
        )
    )

    if ($script:LiveResult.Status -eq 'ERROR') {
        Assert-Equal $r.Status 'UNKNOWN'
    }
    else {
        Assert-Equal $r.Status 'NOT_EVALUATED'
    }
}

if ($script:LiveResult.Status -eq 'INFORMATIONAL') {
    Test-Case 'Real Defender result preserves analysis areas' {
        $areas = $script:LiveResult.Evidence.Analysis.Areas

        Assert-Equal @($areas.PSObject.Properties).Count 9

        Assert-True (
            $null -ne $areas.PSObject.Properties['ThreatProtection']
        )
    }

    Test-Case 'Real PUA remains a descriptive indicator' {
        $pua = (
            $script:LiveResult.Evidence.PUAProtectionAssessment
        )

        Assert-True ($null -ne $pua)

        Assert-Equal `
            $pua.ScoringEligible `
            $false

        Assert-Equal `
            $pua.EffectiveProtectionConfirmed `
            $false
    }
}
else {
    Skip-Case `
        'Real Defender analysis areas' `
        'Defender telemetry was unavailable.'

    Skip-Case `
        'Real PUA evidence' `
        'Defender telemetry was unavailable.'
}


# ============================================================
# FINAL SUMMARY
# ============================================================

Complete-Tests
