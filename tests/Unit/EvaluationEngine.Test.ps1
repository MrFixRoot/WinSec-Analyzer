
# ============================================================
# WinSec Analyzer
# Test Suite : Evaluation Engine
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit tests for evidence-based security evaluation.
#
# Includes:
# - Evidence and identity validation
# - Approved criteria and verification metadata
# - Windows applicability
# - Type-safe comparisons
# - PASS, FAIL, UNKNOWN and NOT_EVALUATED
# - NOT_APPLICABLE handling
# - Duplicate criterion detection
# - Conservative scoring eligibility
# - Framework restrictions
# - Read-only behavior
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# All evidence and criteria are synthetic.
# Test approvals are fixtures, not real CIS validation.
# This suite never modifies Windows settings.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)

$script:EnginePath = Join-Path `
    $script:ProjectRoot `
    'src/Core/EvaluationEngine.ps1'

if (-not (Test-Path -LiteralPath $script:EnginePath)) {
    throw "Evaluation engine not found: $script:EnginePath"
}

. $script:EnginePath


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

function Assert-Contains {
    param(
        [AllowNull()][object]$Value,
        [string]$Pattern
    )

    Assert-True (
        [string]$Value -match $Pattern
    ) "Expected pattern: $Pattern"
}


# ============================================================
# SYNTHETIC TEST FIXTURES
# ============================================================

function New-FixtureContext {
    return [pscustomobject]@{
        DeviceId = 'local:TEST-PC'
        ScanId = 'TEST-SCAN-001'
        OSFamily = 'Windows'
        OSRelease = '11-24H2'
        Edition = 'Pro'
        Profile = 'Level1'
    }
}

function New-FixtureControl {
    param(
        [object]$Value = 1,
        [string]$Status = 'INFORMATIONAL'
    )

    return [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:TEST-PC'
        ScanId = 'TEST-SCAN-001'
        Status = $Status

        Evidence = [pscustomobject]@{
            CheckId = 'WSA-SYS-001'
            DeviceId = 'local:TEST-PC'
            ScanId = 'TEST-SCAN-001'
            CollectionSuccessful = $true

            DefenderPreferences = [pscustomobject]@{
                PUAProtection = $Value
                DisableRealtimeMonitoring = $false
            }

            DefenderStatus = [pscustomobject]@{
                AntivirusEnabled = $true
                RealTimeProtectionEnabled = $true
                AntivirusSignatureAge = 2
                AMRunningMode = 'Normal'
            }
        }
    }
}

function New-FixtureCriterion {
    param(
        [string]$Id = 'TEST-LOCAL-001',
        [string]$Path = 'DefenderPreferences.PUAProtection',
        [string]$Operator = 'Equals',
        [object]$Expected = 1
    )

    # A synthetic policy used only to test engine mechanics.
    # It is NOT a genuine CIS Benchmark criterion.

    return [pscustomobject]@{
        CriterionId = $Id
        CheckId = 'WSA-SYS-001'
        EvidencePath = $Path
        Operator = $Operator
        ExpectedValue = $Expected

        Approved = $true

        Source = [pscustomobject]@{
            Framework = 'LOCAL_POLICY'
            Version = 'TEST-ONLY'
            ControlId = $Id
            Title = 'Synthetic unit-test criterion'
            Url = 'https://example.invalid/winsec-test'
        }

        Verification = [pscustomobject]@{
            Status = 'VERIFIED'
            ReviewedBy = 'UNIT-TEST-FIXTURE'
            ReviewedAtUTC = '2025-01-01T00:00:00Z'
        }

        Applicability = [pscustomobject]@{
            OSFamily = 'Windows'
            OSRelease = '11-24H2'
            Edition = 'Pro'
            Profile = 'Level1'
        }

        Recommendation = (
            'Synthetic recommendation for unit testing only.'
        )
    }
}

function Invoke-FixtureEvaluation {
    param(
        [AllowNull()][object]$Control = $null,
        [AllowNull()][object[]]$Criteria = $null,
        [AllowNull()][object]$Context = $null
    )

    if ($null -eq $Control) {
        $Control = New-FixtureControl
    }

    if ($null -eq $Context) {
        $Context = New-FixtureContext
    }

    if ($null -eq $Criteria) {
        $Criteria = @(
            New-FixtureCriterion
        )
    }

    return Invoke-WinSecControlEvaluation `
        -ControlResult $Control `
        -Criteria $Criteria `
        -TargetContext $Context
}


# ============================================================
# TEST EXECUTOR
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


# ============================================================
# GROUP 1 - ENGINE CONTRACT
# ============================================================

Write-Host ''
Write-Host 'WinSec Analyzer - Evaluation Engine Unit Tests'
Write-Host ''

Test-Case 'Evaluation engine imports' {
    Assert-True (
        $null -ne (
            Get-Command Invoke-WinSecControlEvaluation
        )
    )
}

Test-Case 'Criterion validation function exists' {
    Assert-True (
        $null -ne (
            Get-Command Test-WinSecEvaluationCriterion
        )
    )
}

Test-Case 'Approved synthetic criterion is structurally valid' {
    $v = Test-WinSecEvaluationCriterion `
        -Criterion (New-FixtureCriterion)

    Assert-Equal $v.Valid $true
}

Test-Case 'No criteria produces NOT_EVALUATED' {
    $r = Invoke-WinSecControlEvaluation `
        -ControlResult (New-FixtureControl)

    Assert-Equal $r.Status 'NOT_EVALUATED'
    Assert-Equal $r.ScoringEligible $false
}

Test-Case 'Matching criterion produces PASS' {
    $r = Invoke-FixtureEvaluation

    Assert-Equal $r.Status 'PASS'
    Assert-Equal $r.ScoringEligible $true
    Assert-Equal $r.PassedCriteria 1
}

Test-Case 'Nonmatching criterion produces FAIL' {
    $r = Invoke-FixtureEvaluation `
        -Control (New-FixtureControl -Value 0)

    Assert-Equal $r.Status 'FAIL'
    Assert-Equal $r.FailedCriteria 1
}

Test-Case 'Evaluation preserves device and scan' {
    $r = Invoke-FixtureEvaluation

    Assert-Equal $r.CheckId 'WSA-SYS-001'
    Assert-Equal $r.DeviceId 'local:TEST-PC'
    Assert-Equal $r.ScanId 'TEST-SCAN-001'
}


# ============================================================
# GROUP 2 - COMPARISON OPERATORS
# ============================================================

Test-Case 'Equals supports numeric values' {
    $r = Invoke-FixtureEvaluation

    Assert-Equal $r.Status 'PASS'
}

Test-Case 'Equals supports boolean false' {
    $c = New-FixtureCriterion `
        -Path 'DefenderPreferences.DisableRealtimeMonitoring' `
        -Expected $false

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'PASS'
}

Test-Case 'Equals supports string values' {
    $c = New-FixtureCriterion `
        -Path 'DefenderStatus.AMRunningMode' `
        -Expected 'Normal'

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'PASS'
}

Test-Case 'String comparisons are case sensitive' {
    $c = New-FixtureCriterion `
        -Path 'DefenderStatus.AMRunningMode' `
        -Expected 'normal'

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'FAIL'
}

Test-Case 'NotEquals succeeds for different values' {
    $c = New-FixtureCriterion `
        -Operator 'NotEquals' `
        -Expected 0

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'PASS'
}

Test-Case 'NotEquals fails for identical values' {
    $c = New-FixtureCriterion `
        -Operator 'NotEquals' `
        -Expected 1

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'FAIL'
}

Test-Case 'GreaterThanOrEqual succeeds at boundary' {
    $c = New-FixtureCriterion `
        -Path 'DefenderStatus.AntivirusSignatureAge' `
        -Operator 'GreaterThanOrEqual' `
        -Expected 2

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'PASS'
}

Test-Case 'GreaterThanOrEqual fails below threshold' {
    $c = New-FixtureCriterion `
        -Path 'DefenderStatus.AntivirusSignatureAge' `
        -Operator 'GreaterThanOrEqual' `
        -Expected 3

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'FAIL'
}

Test-Case 'LessThanOrEqual succeeds at boundary' {
    $c = New-FixtureCriterion `
        -Path 'DefenderStatus.AntivirusSignatureAge' `
        -Operator 'LessThanOrEqual' `
        -Expected 2

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'PASS'
}

Test-Case 'LessThanOrEqual fails above threshold' {
    $c = New-FixtureCriterion `
        -Path 'DefenderStatus.AntivirusSignatureAge' `
        -Operator 'LessThanOrEqual' `
        -Expected 1

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'FAIL'
}

Test-Case 'In accepts a member of the list' {
    $c = New-FixtureCriterion `
        -Operator 'In' `
        -Expected @(0, 1, 2)

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'PASS'
}

Test-Case 'In fails when value is absent' {
    $c = New-FixtureCriterion `
        -Operator 'In' `
        -Expected @(0, 2)

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'FAIL'
}

Test-Case 'NotIn accepts a value outside the list' {
    $c = New-FixtureCriterion `
        -Operator 'NotIn' `
        -Expected @(0, 2)

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'PASS'
}

Test-Case 'NotIn fails for listed value' {
    $c = New-FixtureCriterion `
        -Operator 'NotIn' `
        -Expected @(0, 1)

    Assert-Equal `
        (Invoke-FixtureEvaluation -Criteria @($c)).Status `
        'FAIL'
}

Test-Case 'Numeric strings cannot silently match numbers' {
    $c = New-FixtureCriterion -Expected '1'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoringEligible $false
}

Test-Case 'Numeric comparisons support different number types' {
    $c = New-FixtureCriterion -Expected ([long]1)

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'PASS'
}


# ============================================================
# GROUP 3 - CRITERION VALIDATION
# ============================================================

Test-Case 'Unapproved criterion cannot grade' {
    $c = New-FixtureCriterion
    $c.Approved = $false

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.NotEvaluatedCriteria 1
    Assert-Equal $r.ScoringEligible $false
}

Test-Case 'Missing verification cannot grade' {
    $c = New-FixtureCriterion
    $c.Verification.Status = 'PENDING'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoringEligible $false
}

Test-Case 'Missing reviewer cannot grade' {
    $c = New-FixtureCriterion
    $c.Verification.ReviewedBy = ''

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Future review date is rejected' {
    $c = New-FixtureCriterion

    $c.Verification.ReviewedAtUTC = (
        [datetimeoffset]::UtcNow.AddDays(10).ToString('o')
    )

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'HTTP source is rejected' {
    $c = New-FixtureCriterion
    $c.Source.Url = 'http://example.invalid/test'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Invalid source URL is rejected' {
    $c = New-FixtureCriterion
    $c.Source.Url = 'not-a-valid-url'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'NIST CSF is not an independent scoring criterion' {
    $c = New-FixtureCriterion
    $c.Source.Framework = 'NIST CSF'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoringEligible $false
}

Test-Case 'MITRE ATTACK cannot directly award compliance' {
    $c = New-FixtureCriterion
    $c.Source.Framework = 'MITRE ATT&CK'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'CIS Controls cannot directly award compliance' {
    $c = New-FixtureCriterion
    $c.Source.Framework = 'CIS Controls'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Unsupported operator is rejected' {
    $c = New-FixtureCriterion
    $c.Operator = 'Execute'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Expression-like evidence paths are rejected' {
    $c = New-FixtureCriterion
    $c.EvidencePath = 'DefenderPreferences.$(Get-Process)'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Null expected value cannot grade' {
    $c = New-FixtureCriterion
    $c.ExpectedValue = $null

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Empty In list is invalid' {
    $c = New-FixtureCriterion
    $c.Operator = 'In'
    $c.ExpectedValue = @()

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Array expected for Equals is rejected' {
    $c = New-FixtureCriterion
    $c.ExpectedValue = @(1, 2)

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Wrong CheckId criterion cannot grade' {
    $c = New-FixtureCriterion
    $c.CheckId = 'WSA-SYS-999'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoringEligible $false
}


# ============================================================
# GROUP 4 - EVIDENCE VALIDATION
# ============================================================

Test-Case 'Missing evidence path produces UNKNOWN' {
    $c = New-FixtureCriterion
    $c.EvidencePath = 'DefenderPreferences.NotPresent'

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.UnknownCriteria 1
}

Test-Case 'Null evidence value produces UNKNOWN' {
    $control = New-FixtureControl
    $control.Evidence.DefenderPreferences.PUAProtection = $null

    $r = Invoke-FixtureEvaluation -Control $control

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Collector error produces UNKNOWN' {
    $control = New-FixtureControl
    $control.Status = 'ERROR'

    $r = Invoke-FixtureEvaluation -Control $control

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoringEligible $false
}

Test-Case 'CollectionSuccessful false cannot grade' {
    $control = New-FixtureControl
    $control.Evidence.CollectionSuccessful = $false

    $r = Invoke-FixtureEvaluation -Control $control

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Missing collection confirmation cannot grade' {
    $control = New-FixtureControl

    $control.Evidence.PSObject.Properties.Remove(
        'CollectionSuccessful'
    )

    $r = Invoke-FixtureEvaluation -Control $control

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Evidence from another device is rejected' {
    $control = New-FixtureControl
    $control.Evidence.DeviceId = 'local:OTHER-PC'

    $r = Invoke-FixtureEvaluation -Control $control

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoringEligible $false
}

Test-Case 'Evidence from another scan is rejected' {
    $control = New-FixtureControl
    $control.Evidence.ScanId = 'OTHER-SCAN'

    $r = Invoke-FixtureEvaluation -Control $control

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Evidence with another CheckId is rejected' {
    $control = New-FixtureControl
    $control.Evidence.CheckId = 'WSA-SYS-999'

    $r = Invoke-FixtureEvaluation -Control $control

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Missing control identity is not evaluated' {
    $control = New-FixtureControl
    $control.ScanId = ''

    $r = Invoke-FixtureEvaluation -Control $control

    Assert-Equal $r.Status 'NOT_EVALUATED'
}

Test-Case 'Unsupported collector status cannot grade' {
    $control = New-FixtureControl
    $control.Status = 'PENDING'

    $r = Invoke-FixtureEvaluation -Control $control

    Assert-Equal $r.Status 'NOT_EVALUATED'
}

Test-Case 'Collector NOT_APPLICABLE is not blindly accepted' {
    $control = New-FixtureControl
    $control.Status = 'NOT_APPLICABLE'

    $r = Invoke-FixtureEvaluation -Control $control

    Assert-Equal $r.Status 'NOT_EVALUATED'
    Assert-Equal $r.ScoringEligible $false
}


# ============================================================
# GROUP 5 - WINDOWS APPLICABILITY
# ============================================================

Test-Case 'Missing target context blocks grading' {
    $r = Invoke-WinSecControlEvaluation `
        -ControlResult (New-FixtureControl) `
        -Criteria @(
            New-FixtureCriterion
        )

    Assert-Equal $r.Status 'NOT_EVALUATED'
}

Test-Case 'Missing OS release blocks evaluation' {
    $context = New-FixtureContext
    $context.OSRelease = ''

    $r = Invoke-FixtureEvaluation -Context $context

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.NotEvaluatedCriteria 1
}

Test-Case 'Different Windows release gives NOT_APPLICABLE' {
    $context = New-FixtureContext
    $context.OSRelease = '10-22H2'

    $r = Invoke-FixtureEvaluation -Context $context

    Assert-Equal $r.Status 'NOT_APPLICABLE'
    Assert-Equal $r.ScoringEligible $false
}

Test-Case 'Different edition gives NOT_APPLICABLE' {
    $context = New-FixtureContext
    $context.Edition = 'Enterprise'

    $r = Invoke-FixtureEvaluation -Context $context

    Assert-Equal $r.Status 'NOT_APPLICABLE'
}

Test-Case 'Different benchmark profile gives NOT_APPLICABLE' {
    $context = New-FixtureContext
    $context.Profile = 'Level2'

    $r = Invoke-FixtureEvaluation -Context $context

    Assert-Equal $r.Status 'NOT_APPLICABLE'
}

Test-Case 'Case-insensitive Windows context is accepted' {
    $context = New-FixtureContext
    $context.OSFamily = 'WINDOWS'

    $r = Invoke-FixtureEvaluation -Context $context

    Assert-Equal $r.Status 'PASS'
}

Test-Case 'Target context from other device is rejected' {
    $context = New-FixtureContext
    $context.DeviceId = 'local:OTHER-PC'

    $r = Invoke-FixtureEvaluation -Context $context

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Target context from other scan is rejected' {
    $context = New-FixtureContext
    $context.ScanId = 'OTHER-SCAN'

    $r = Invoke-FixtureEvaluation -Context $context

    Assert-Equal $r.Status 'UNKNOWN'
}

Test-Case 'Missing criterion scope is rejected' {
    $c = New-FixtureCriterion
    $c.Applicability.Profile = ''

    $r = Invoke-FixtureEvaluation -Criteria @($c)

    Assert-Equal $r.Status 'UNKNOWN'
}


# ============================================================
# GROUP 6 - MULTIPLE CRITERIA
# ============================================================

Test-Case 'Two passing criteria produce PASS' {
    $a = New-FixtureCriterion -Id 'TEST-A'

    $b = New-FixtureCriterion `
        -Id 'TEST-B' `
        -Path 'DefenderStatus.AntivirusEnabled' `
        -Expected $true

    $r = Invoke-FixtureEvaluation -Criteria @($a, $b)

    Assert-Equal $r.Status 'PASS'
    Assert-Equal $r.PassedCriteria 2
    Assert-Equal $r.EvaluatedCriteria 2
}

Test-Case 'One failing criterion produces FAIL' {
    $a = New-FixtureCriterion -Id 'TEST-A'

    $b = New-FixtureCriterion `
        -Id 'TEST-B' `
        -Expected 0

    $r = Invoke-FixtureEvaluation -Criteria @($a, $b)

    Assert-Equal $r.Status 'FAIL'
    Assert-Equal $r.FailedCriteria 1
    Assert-Equal $r.PassedCriteria 1
}

Test-Case 'Unknown criterion prevents aggregate grading' {
    $a = New-FixtureCriterion -Id 'TEST-A'

    $b = New-FixtureCriterion `
        -Id 'TEST-B' `
        -Path 'DefenderStatus.MissingProperty'

    $r = Invoke-FixtureEvaluation -Criteria @($a, $b)

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoringEligible $false
    Assert-Equal $r.UnknownCriteria 1
}

Test-Case 'Observed FAIL remains visible despite UNKNOWN' {
    $a = New-FixtureCriterion `
        -Id 'TEST-A' `
        -Expected 0

    $b = New-FixtureCriterion `
        -Id 'TEST-B' `
        -Path 'DefenderStatus.MissingProperty'

    $r = Invoke-FixtureEvaluation -Criteria @($a, $b)

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.FailedCriteria 1
    Assert-Equal $r.UnknownCriteria 1

    Assert-Equal $r.Evaluations[0].Status 'FAIL'
}

Test-Case 'Invalid criterion prevents aggregate grading' {
    $a = New-FixtureCriterion -Id 'TEST-A'

    $b = New-FixtureCriterion -Id 'TEST-B'
    $b.Approved = $false

    $r = Invoke-FixtureEvaluation -Criteria @($a, $b)

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoringEligible $false
}

Test-Case 'Duplicate criterion IDs invalidate all copies' {
    $a = New-FixtureCriterion -Id 'DUPLICATE'
    $b = New-FixtureCriterion -Id 'DUPLICATE'

    $r = Invoke-FixtureEvaluation -Criteria @($a, $b)

    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.NotEvaluatedCriteria 2
    Assert-Equal $r.ScoringEligible $false

    foreach ($item in $r.Evaluations) {
        Assert-Equal $item.Status 'NOT_EVALUATED'
    }
}

Test-Case 'Applicable PASS with unrelated scope stays PASS' {
    $a = New-FixtureCriterion -Id 'TEST-A'

    $b = New-FixtureCriterion -Id 'TEST-B'
    $b.Applicability.Edition = 'Enterprise'

    $r = Invoke-FixtureEvaluation -Criteria @($a, $b)

    Assert-Equal $r.Status 'PASS'
    Assert-Equal $r.NotApplicableCriteria 1
    Assert-Equal $r.PassedCriteria 1
}

Test-Case 'Recommendations stay attached to evaluated criteria' {
    $r = Invoke-FixtureEvaluation

    Assert-Equal `
        $r.Evaluations[0].Recommendation `
        'Synthetic recommendation for unit testing only.'

    Assert-Equal `
        $r.Evaluations[0].Source.Framework `
        'LOCAL_POLICY'
}


# ============================================================
# GROUP 7 - READ-ONLY STATIC VALIDATION
# ============================================================

Test-Case 'Engine parses without syntax errors' {
    $tokens = $null
    $errors = $null

    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:EnginePath,
        [ref]$tokens,
        [ref]$errors
    )

    Assert-Equal @($errors).Count 0
}

Test-Case 'Engine has no known modification commands' {
    $tokens = $null
    $errors = $null

    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:EnginePath,
        [ref]$tokens,
        [ref]$errors
    )

    Assert-Equal @($errors).Count 0

    $forbidden = (
        '^(Set-Mp|Add-Mp|Remove-Mp|' +
        'Start-MpScan$|Update-MpSignature$|' +
        'Set-Item|New-Item|Remove-Item|' +
        'Set-Content|Add-Content|Out-File$|' +
        'Export-|Set-Service|Start-Service|' +
        'Stop-Service|Invoke-CimMethod$|' +
        'Set-CimInstance$|New-CimInstance$|' +
        'Invoke-Expression$|Start-Process$|' +
        'Invoke-Command$)'
    )

    $nodes = $ast.FindAll(
        {
            param($node)

            $node -is [System.Management.Automation.Language.CommandAst]
        },
        $true
    )

    foreach ($node in $nodes) {
        $name = $node.GetCommandName()

        Assert-True (
            -not ($name -match $forbidden)
        ) "Potentially modifying command found: $name"
    }
}


# ============================================================
# FINAL SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'EVALUATION ENGINE UNIT TEST SUMMARY' `
    -ForegroundColor Cyan
Write-Host "TOTAL : $total"
Write-Host "PASS  : $script:Passed"
Write-Host "FAIL  : $script:Failed"
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''

if ($script:Failed -gt 0) {
    throw "$($script:Failed) Evaluation Engine unit test(s) failed."
}

Write-Host 'All Evaluation Engine unit tests passed.' `
    -ForegroundColor Green
