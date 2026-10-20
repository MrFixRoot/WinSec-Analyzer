# ============================================================
# WinSec Analyzer
# Test Suite : Score and Evaluation Engine Regression
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Compatibility and security regression checks against the
# existing public APIs. This suite deliberately exposes
# known defects; do NOT change expectations to hide failures.
#
# Includes:
# - Legacy normalized-result compatibility
# - Rejection of self-declared scoring authorization
# - Expected CheckId membership, not just matching counts
# - Source and expected-value snapshot isolation
# - Disabled policy and incomplete-assessment safeguards
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# Synthetic fixtures only. No changes to Windows or project
# configuration. A FAIL here is a genuine regression to fix.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
$script:Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$script:ScorePath = Join-Path $script:Root 'src/Core/ScoreEngine.ps1'
$script:EvaluationPath = Join-Path $script:Root 'src/Core/EvaluationEngine.ps1'
$script:PolicyPath = Join-Path $script:Root 'config/scoring.json'

function Assert-WinSecRegressionTrue {
    param([bool]$Condition, [string]$Message = 'Assertion failed.')
    if (-not $Condition) { throw $Message }
}
function Assert-WinSecRegressionEqual {
    param([AllowNull()][object]$Actual, [AllowNull()][object]$Expected,
          [string]$Message = 'Values differ.')
    if ($null -eq $Expected) {
        if ($null -ne $Actual) { throw "$Message Expected null, got [$Actual]." }
        return
    }
    if ($null -eq $Actual -or $Actual -cne $Expected) {
        throw "$Message Expected [$Expected], got [$Actual]."
    }
}
function Test-WinSecRegressionCase {
    param([string]$Name, [scriptblock]$Action)
    try {
        $null = & $Action
        $script:Passed++
        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:Failed++
        Write-Host "[FAIL] $Name - $($_.Exception.Message)" -ForegroundColor Red
        if ($_.ScriptStackTrace) {
            Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
        }
    }
}

foreach ($path in @($script:ScorePath, $script:EvaluationPath, $script:PolicyPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required project file was not found: $path"
    }
}
. $script:EvaluationPath
. $script:ScorePath
$script:Policy = Get-WinSecScoringPolicy

function New-WinSecRegressionPolicy {
    $policy = $script:Policy | ConvertTo-Json -Depth 40 | ConvertFrom-Json
    $policy.enabled = $true
    $policy.activationStatus = 'ACTIVE'
    return $policy
}
function New-WinSecRegressionNormalized {
    param([string]$CheckId = 'WSA-SYS-001')
    return [pscustomobject]@{
        CheckId = $CheckId
        DeviceId = 'local:REGRESSION-PC'
        ScanId = 'SCORE-REGRESSION-001'
        SectionKey = 'SystemSecurity'
        Status = 'PASS'
        OriginalStatus = 'PASS'
        IncludedInScore = $true
        ScoreValue = 1
        Verified = $true
        EvidencePresent = $true
        ScoringEligible = $true
        ValidationIssue = ''
    }
}
function New-WinSecRegressionCriterion {
    param([string]$Operator = 'Equals', [object]$ExpectedValue = 1)
    return [pscustomobject]@{
        CriterionId = 'SYNTHETIC-REGRESSION-001'
        CheckId = 'WSA-SYS-001'
        EvidencePath = 'DefenderPreferences.PUAProtection'
        Operator = $Operator
        ExpectedValue = $ExpectedValue
        Approved = $true
        Recommendation = 'Test-only recommendation; do not apply.'
        Source = [pscustomobject]@{
            Framework = 'LOCAL_POLICY'
            Version = 'TEST-ONLY'
            ControlId = 'SYNTHETIC-REGRESSION-001'
            Title = 'Test-only policy'
            Url = 'https://example.invalid/test'
        }
        Verification = [pscustomobject]@{
            Status = 'VERIFIED'
            ReviewedBy = 'TEST-FIXTURE'
            ReviewedAtUTC = '2025-01-01T00:00:00Z'
        }
        Applicability = [pscustomobject]@{
            OSFamily = 'Windows'
            OSRelease = '11-24H2'
            Edition = 'Pro'
            Profile = 'Level1'
        }
    }
}
function Invoke-WinSecRegressionCriterion {
    param([object]$Criterion)
    $evidence = [pscustomobject]@{
        DefenderPreferences = [pscustomobject]@{ PUAProtection = 1 }
    }
    $context = [pscustomobject]@{
        OSFamily = 'Windows'; OSRelease = '11-24H2'
        Edition = 'Pro'; Profile = 'Level1'
    }
    return Invoke-WinSecCriterionEvaluation -Criterion $Criterion `
        -Evidence $evidence -TargetContext $context `
        -CheckId 'WSA-SYS-001' -DeviceId 'local:REGRESSION-PC' `
        -ScanId 'SCORE-REGRESSION-001'
}

Write-Host ''
Write-Host 'WinSec Analyzer - Score/Evaluation Regression Tests' -ForegroundColor Cyan
Write-Host ''

Test-WinSecRegressionCase 'Public Score Engine functions remain available' {
    foreach ($name in @(
        'Get-WinSecScoreField', 'Test-WinSecScoreEvidence',
        'Test-WinSecScoringPolicy', 'Get-WinSecScoringPolicy',
        'Test-WinSecScoreAuthorization', 'Get-WinSecCheckScore',
        'Get-WinSecScoreSummary', 'Get-WinSecSecurityScore'
    )) {
        Assert-WinSecRegressionTrue ($null -ne (Get-Command $name -ErrorAction SilentlyContinue)) `
            "Public function missing: $name"
    }
}

Test-WinSecRegressionCase 'Production policy stays disabled' {
    Assert-WinSecRegressionEqual $script:Policy.enabled $false
    Assert-WinSecRegressionEqual $script:Policy.schemaVersion '1.1.0'
}

Test-WinSecRegressionCase 'Legacy OriginalResult is retained in normalized checks' {
    $inputResult = [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:REGRESSION-PC'
        ScanId = 'SCORE-REGRESSION-001'
        SectionKey = 'SystemSecurity'
        Status = 'NOT_EVALUATED'
    }
    $normalized = Get-WinSecCheckScore -CheckResult $inputResult -Policy $script:Policy
    Assert-WinSecRegressionTrue ($null -ne $normalized.PSObject.Properties['OriginalResult']) `
        'OriginalResult property was removed from the legacy public result.'
    Assert-WinSecRegressionTrue ([object]::ReferenceEquals($inputResult, $normalized.OriginalResult)) `
        'Legacy OriginalResult no longer references the supplied input object.'
}

Test-WinSecRegressionCase 'Direct summary rejects fabricated PASS authorization flags' {
    $score = Get-WinSecScoreSummary `
        -CheckResults @((New-WinSecRegressionNormalized)) `
        -Policy (New-WinSecRegressionPolicy) `
        -ExpectedCheckIds @('WSA-SYS-001') -AllowScore $true
    Assert-WinSecRegressionEqual $score.Score $null `
        'Public summary must not trust self-declared Verified/ScoringEligible flags.'
    Assert-WinSecRegressionEqual $score.Status 'NOT_SCORED'
}

Test-WinSecRegressionCase 'Direct summary does not trust matching count with wrong CheckId' {
    $score = Get-WinSecScoreSummary `
        -CheckResults @((New-WinSecRegressionNormalized -CheckId 'WSA-OTHER-999')) `
        -Policy (New-WinSecRegressionPolicy) `
        -ExpectedCheckIds @('WSA-SYS-001') -AllowScore $true
    Assert-WinSecRegressionEqual $score.Score $null `
        'Expected CheckIds must match identities, not merely item count.'
}

Test-WinSecRegressionCase 'Disabled production policy rejects even fabricated flags' {
    $score = Get-WinSecScoreSummary `
        -CheckResults @((New-WinSecRegressionNormalized)) `
        -Policy $script:Policy `
        -ExpectedCheckIds @('WSA-SYS-001') -AllowScore $true
    Assert-WinSecRegressionEqual $score.Score $null
    Assert-WinSecRegressionEqual $score.Status 'NOT_SCORED'
}

Test-WinSecRegressionCase 'Summary without expected CheckIds cannot score' {
    $score = Get-WinSecScoreSummary `
        -CheckResults @((New-WinSecRegressionNormalized)) `
        -Policy (New-WinSecRegressionPolicy) -AllowScore $true
    Assert-WinSecRegressionEqual $score.Score $null
}

Test-WinSecRegressionCase 'Source is independently copied into criterion evaluation' {
    $criterion = New-WinSecRegressionCriterion
    $evaluated = Invoke-WinSecRegressionCriterion -Criterion $criterion
    Assert-WinSecRegressionEqual $evaluated.Status 'PASS'
    $evaluated.Source.ControlId = 'FORGED-CONTROL'
    Assert-WinSecRegressionEqual $criterion.Source.ControlId 'SYNTHETIC-REGRESSION-001'
}

Test-WinSecRegressionCase 'ExpectedValue array is independently copied into evaluation' {
    $criterion = New-WinSecRegressionCriterion -Operator 'In' -ExpectedValue @(1,2)
    $evaluated = Invoke-WinSecRegressionCriterion -Criterion $criterion
    Assert-WinSecRegressionEqual $evaluated.Status 'PASS'
    $evaluated.ExpectedValue[0] = 999
    Assert-WinSecRegressionEqual $criterion.ExpectedValue[0] 1 `
        'Evaluation ExpectedValue shares a mutable array with the approved criterion.'
}

Test-WinSecRegressionCase 'Actual evaluation files parse cleanly' {
    foreach ($path in @($script:ScorePath, $script:EvaluationPath)) {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $path, [ref]$tokens, [ref]$errors
        )
        Assert-WinSecRegressionEqual @($errors).Count 0 "Syntax errors in $path."
    }
}

Write-Host ''
Write-Host ('=' * 60)
Write-Host 'SCORE / EVALUATION REGRESSION TEST SUMMARY' -ForegroundColor Cyan
$total = $script:Passed + $script:Failed
Write-Host "TOTAL : $total"
Write-Host "PASS  : $script:Passed"
Write-Host "FAIL  : $script:Failed"
Write-Host ('=' * 60)
if ($script:Failed -gt 0) {
    throw "$($script:Failed) security/compatibility regression test(s) failed."
}
