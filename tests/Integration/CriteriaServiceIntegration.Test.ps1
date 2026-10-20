
# ============================================================
# WinSec Analyzer
# Test Suite : Criteria Service Integration
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Integration checks for the Defender collector, Criteria
# Service, and Evaluation Engine contracts.
#
# Includes:
# - Local Defender JSON catalog loading
# - Draft approval and scoring safeguards
# - Synthetic approved LOCAL_POLICY evaluation
# - Device and scan identity isolation
# - Dependency and evidence completeness checks
# - Live, read-only Defender collection (Windows only)
# - Catalog immutability verification
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# Synthetic policies are test fixtures, not verified CIS
# requirements. Never use them to grade a real device.
# Read-only audit; no changes to security settings.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)
$script:CriteriaPath = Join-Path $script:ProjectRoot 'src/Services/CriteriaService.ps1'
$script:EnginePath = Join-Path $script:ProjectRoot 'src/Core/EvaluationEngine.ps1'
$script:DefenderPath = Join-Path $script:ProjectRoot 'src/Checks/Defender/Test-Defender.ps1'
$script:CatalogPath = Join-Path $script:ProjectRoot 'config/criteria/defender.json'

# ============================================================
# ASSERTIONS AND TEST RUNNER
# ============================================================

function Assert-WinSecEqual {
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

function Assert-WinSecTrue {
    param(
        [bool]$Condition,
        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) { throw $Message }
}

function Test-WinSecCase {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )

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

function Skip-WinSecCase {
    param([string]$Name, [string]$Reason)

    $script:Skipped++
    Write-Host "[SKIP] $Name - $Reason" -ForegroundColor Yellow
}

function Complete-WinSecTests {
    $total = $script:Passed + $script:Failed + $script:Skipped

    Write-Host ''
    Write-Host ('=' * 60) -ForegroundColor DarkGray
    Write-Host 'CRITERIA SERVICE INTEGRATION TEST SUMMARY' -ForegroundColor Cyan
    Write-Host "TOTAL : $total"
    Write-Host "PASS  : $script:Passed" -ForegroundColor Green
    Write-Host "FAIL  : $script:Failed" -ForegroundColor $(if ($script:Failed) { 'Red' } else { 'Green' })
    Write-Host "SKIP  : $script:Skipped" -ForegroundColor Yellow
    Write-Host ('=' * 60) -ForegroundColor DarkGray
    Write-Host ''

    if ($script:Failed -gt 0) {
        throw "$($script:Failed) Criteria Service integration test(s) failed."
    }

    if ($script:Skipped -gt 0) {
        Write-Host 'Tests passed with incomplete live coverage (SKIP).' -ForegroundColor Yellow
    }
    else {
        Write-Host 'All Criteria Service integration tests passed.' -ForegroundColor Green
    }
}

function Copy-WinSecFixture {
    param([Parameter(Mandatory)][object]$InputObject)
    return ($InputObject | ConvertTo-Json -Depth 40 | ConvertFrom-Json)
}

# ============================================================
# SYNTHETIC FIXTURES: NOT REAL COMPLIANCE CRITERIA
# ============================================================

function New-WinSecTestControl {
    param([AllowNull()][object]$PUA = 1)

    return [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:INTEGRATION-FIXTURE'
        ScanId = 'INTEGRATION-FIXTURE-001'
        Status = 'INFORMATIONAL'
        Evidence = [pscustomobject]@{
            CheckId = 'WSA-SYS-001'
            DeviceId = 'local:INTEGRATION-FIXTURE'
            ScanId = 'INTEGRATION-FIXTURE-001'
            CollectionSuccessful = $true
            DefenderPreferences = [pscustomobject]@{
                PUAProtection = $PUA
            }
        }
    }
}

function New-WinSecTestContext {
    return [pscustomobject]@{
        DeviceId = 'local:INTEGRATION-FIXTURE'
        ScanId = 'INTEGRATION-FIXTURE-001'
        OSFamily = 'Windows'
        OSRelease = '11-24H2'
        Edition = 'Pro'
        Profile = 'Level1'
    }
}

function New-WinSecTestCatalog {
    # Approval metadata here tests the engine's mechanical contract;
    # no actual organizational approval or verification is asserted.
    $criterion = [pscustomobject]@{
        CriterionId = 'TEST-LOCAL-001'
        CheckId = 'WSA-SYS-001'
        Area = 'ThreatProtection'
        Name = 'Synthetic PUA expected value'
        EvidencePath = 'DefenderPreferences.PUAProtection'
        Operator = 'Equals'
        ExpectedValue = 1
        Approved = $true
        Recommendation = 'Synthetic recommendation; do not apply to devices.'
        Source = [pscustomobject]@{
            Framework = 'LOCAL_POLICY'
            Version = 'TEST-ONLY'
            ControlId = 'TEST-LOCAL-001'
            Title = 'Test-only criterion'
            Url = 'https://example.invalid/winsec-test'
        }
        Verification = [pscustomobject]@{
            Status = 'VERIFIED'
            ReviewedBy = 'INTEGRATION-TEST-FIXTURE'
            ReviewedAtUTC = '2025-01-01T00:00:00Z'
        }
        Applicability = [pscustomobject]@{
            OSFamily = 'Windows'
            OSRelease = '11-24H2'
            Edition = 'Pro'
            Profile = 'Level1'
        }
        ActivationDependencies = @('active-antivirus-mode')
        FrameworkMappings = [pscustomobject]@{
            CISBenchmarks = @()
            CISControls = @()
            NISTCSF = @()
            MITREATTACK = @()
        }
    }

    return [pscustomobject]@{
        CatalogId = 'WSA-INTEGRATION-FIXTURE'
        CatalogVersion = '0.9.0'
        CheckId = 'WSA-SYS-001'
        Status = 'APPROVED'
        ScoringEnabled = $true
        DeviceChangesAllowed = $false
        Criteria = @($criterion)
        ReviewOnly = @(
            [pscustomobject]@{
                Area = 'ThreatProtection'
                Name = 'Test-only observation'
                Assessment = 'REVIEW_ONLY'
            }
        )
    }
}

function Invoke-WinSecTestSelection {
    param(
        [AllowNull()][object]$Catalog = $null,
        [AllowNull()][object]$Control = $null,
        [AllowNull()][object]$Context = $null,
        [AllowNull()][System.Collections.IDictionary]$Dependencies = $null,
        [bool]$UseDefaultDependencies = $true
    )

    if ($null -eq $Catalog) { $Catalog = New-WinSecTestCatalog }
    if ($null -eq $Control) { $Control = New-WinSecTestControl }
    if ($null -eq $Context) { $Context = New-WinSecTestContext }
    if ($null -eq $Dependencies -and $UseDefaultDependencies) {
        $Dependencies = @{ 'active-antivirus-mode' = $true }
    }

    return Get-WinSecApplicableCriteria `
        -Catalog $Catalog `
        -TargetContext $Context `
        -ControlResult $Control `
        -ProjectRoot $script:ProjectRoot `
        -DependencyEvidence $Dependencies
}

Write-Host ''
Write-Host 'WinSec Analyzer - Criteria Service Integration Tests' -ForegroundColor Cyan
Write-Host ''

# ============================================================
# GROUP 1: LOCAL COMPONENTS
# ============================================================

foreach ($file in @($script:CriteriaPath, $script:EnginePath,
                     $script:DefenderPath, $script:CatalogPath)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Required WinSec Analyzer file not found: $file"
    }
}

foreach ($file in @($script:CriteriaPath, $script:EnginePath, $script:DefenderPath)) {
    $label = Split-Path $file -Leaf
    Test-WinSecCase "$label parses correctly" {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $file, [ref]$tokens, [ref]$errors
        )
        Assert-WinSecEqual @($errors).Count 0
    }
}

if ($script:Failed -gt 0) {
    Complete-WinSecTests
    return
}

try {
    . $script:EnginePath
    . $script:CriteriaPath
    . $script:DefenderPath
    $script:Catalog = Import-WinSecCriteriaCatalog `
        -ProjectRoot $script:ProjectRoot
}
catch {
    throw "Unable to import components: $($_.Exception.Message)"
}

$script:CatalogHashBefore = (Get-FileHash -LiteralPath $script:CatalogPath -Algorithm SHA256).Hash

Test-WinSecCase 'Three components expose their public functions' {
    foreach ($name in @(
        'Import-WinSecCriteriaCatalog',
        'Test-WinSecCriteriaCatalog',
        'Get-WinSecApplicableCriteria',
        'Invoke-WinSecControlEvaluation',
        'Test-WinSecDefender'
    )) {
        Assert-WinSecTrue ($null -ne (Get-Command $name -ErrorAction SilentlyContinue)) `
            "Function not found: $name"
    }
}

# ============================================================
# GROUP 2: REAL CATALOG, DRAFT BLOCKED
# ============================================================

Test-WinSecCase 'Defender catalog is structurally valid' {
    $v = Test-WinSecCriteriaCatalog -Catalog $script:Catalog
    Assert-WinSecEqual $v.Valid $true
    Assert-WinSecEqual $v.CriteriaCount 20
    Assert-WinSecEqual $v.ReviewOnlyCount 14
}

Test-WinSecCase 'Draft catalog remains ineligible for scoring' {
    $v = Test-WinSecCriteriaCatalog -Catalog $script:Catalog
    Assert-WinSecEqual $v.Status 'DRAFT_UNAPPROVED'
    Assert-WinSecEqual $v.ReadyForScoring $false
}

Test-WinSecCase 'Draft catalog cannot release rules' {
    $r = Invoke-WinSecTestSelection -Catalog $script:Catalog
    Assert-WinSecEqual $r.Status 'DRAFT_BLOCKED'
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

Test-WinSecCase 'Draft catalog keeps all review-only observations' {
    $r = Invoke-WinSecTestSelection -Catalog $script:Catalog
    Assert-WinSecEqual @($r.ReviewOnly).Count 14
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

Test-WinSecCase 'Changing catalog label does not approve draft rules' {
    $copy = Copy-WinSecFixture $script:Catalog
    $copy.Status = 'APPROVED'
    $copy.ScoringEnabled = $true

    $v = Test-WinSecCriteriaCatalog -Catalog $copy
    Assert-WinSecEqual $v.ReadyForScoring $false

    $r = Invoke-WinSecTestSelection -Catalog $copy
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

# ============================================================
# GROUP 3: SYNTHETIC END-TO-END EVALUATION
# ============================================================

Test-WinSecCase 'Synthetic approved fixture passes catalog validation' {
    $v = Test-WinSecCriteriaCatalog -Catalog (New-WinSecTestCatalog)
    Assert-WinSecEqual $v.Valid $true
    Assert-WinSecEqual $v.ReadyForScoring $true
}

Test-WinSecCase 'Synthetic prerequisites permit complete selection' {
    $r = Invoke-WinSecTestSelection
    Assert-WinSecEqual $r.Status 'READY'
    Assert-WinSecEqual $r.ScoringEligible $true
    Assert-WinSecEqual @($r.EligibleCriteria).Count 1
    Assert-WinSecEqual @($r.ReviewOnly).Count 1
}

Test-WinSecCase 'Synthetic matching evidence produces PASS' {
    $control = New-WinSecTestControl -PUA 1
    $context = New-WinSecTestContext
    $r = Invoke-WinSecTestSelection -Control $control -Context $context
    Assert-WinSecEqual $r.Status 'READY'

    $evaluation = Invoke-WinSecControlEvaluation `
        -ControlResult $control `
        -Criteria $r.EligibleCriteria `
        -TargetContext $context

    Assert-WinSecEqual $evaluation.Status 'PASS'
    Assert-WinSecEqual $evaluation.PassedCriteria 1
    Assert-WinSecEqual $evaluation.DeviceId $control.DeviceId
    Assert-WinSecEqual $evaluation.ScanId $control.ScanId
}

Test-WinSecCase 'Synthetic nonmatching evidence produces FAIL' {
    $control = New-WinSecTestControl -PUA 0
    $context = New-WinSecTestContext
    $r = Invoke-WinSecTestSelection -Control $control -Context $context
    Assert-WinSecEqual $r.Status 'READY'

    $evaluation = Invoke-WinSecControlEvaluation `
        -ControlResult $control `
        -Criteria $r.EligibleCriteria `
        -TargetContext $context

    Assert-WinSecEqual $evaluation.Status 'FAIL'
    Assert-WinSecEqual $evaluation.FailedCriteria 1
}

Test-WinSecCase 'Synthetic missing evidence produces UNKNOWN, never PASS' {
    $control = New-WinSecTestControl -PUA $null
    $context = New-WinSecTestContext
    $r = Invoke-WinSecTestSelection -Control $control -Context $context
    Assert-WinSecEqual $r.Status 'READY'

    $evaluation = Invoke-WinSecControlEvaluation `
        -ControlResult $control `
        -Criteria $r.EligibleCriteria `
        -TargetContext $context

    Assert-WinSecEqual $evaluation.Status 'UNKNOWN'
    Assert-WinSecEqual $evaluation.ScoringEligible $false
}

Test-WinSecCase 'Selection never grades when dependency is absent' {
    $r = Invoke-WinSecTestSelection -UseDefaultDependencies $false
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

Test-WinSecCase 'Selection never grades when dependency is false' {
    $r = Invoke-WinSecTestSelection `
        -Dependencies @{ 'active-antivirus-mode' = $false }
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

Test-WinSecCase 'Selection rejects textual true as dependency evidence' {
    $r = Invoke-WinSecTestSelection `
        -Dependencies @{ 'active-antivirus-mode' = 'true' }
    Assert-WinSecEqual $r.ScoringEligible $false
}

Test-WinSecCase 'Selection rejects cross-device evidence' {
    $control = New-WinSecTestControl
    $control.Evidence.DeviceId = 'local:OTHER-PC'
    $r = Invoke-WinSecTestSelection -Control $control
    Assert-WinSecEqual $r.Status 'BLOCKED'
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

Test-WinSecCase 'Selection rejects cross-scan target context' {
    $context = New-WinSecTestContext
    $context.ScanId = 'OTHER-SCAN'
    $r = Invoke-WinSecTestSelection -Context $context
    Assert-WinSecEqual $r.Status 'BLOCKED'
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

Test-WinSecCase 'Selection rejects unsupported Windows edition' {
    $context = New-WinSecTestContext
    $context.Edition = 'Enterprise'
    $r = Invoke-WinSecTestSelection -Context $context
    Assert-WinSecEqual $r.Status 'NO_ELIGIBLE_CRITERIA'
    Assert-WinSecEqual $r.ScoringEligible $false
}

Test-WinSecCase 'A partial synthetic catalog never releases a subset' {
    $catalog = New-WinSecTestCatalog
    $second = Copy-WinSecFixture $catalog.Criteria[0]
    $second.CriterionId = 'TEST-LOCAL-002'
    $second.Source.ControlId = 'TEST-LOCAL-002'
    $second.Applicability.Profile = 'Level2'
    $catalog.Criteria = @($catalog.Criteria[0], $second)

    $r = Invoke-WinSecTestSelection -Catalog $catalog
    Assert-WinSecEqual $r.Status 'PARTIAL_SELECTION_BLOCKED'
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

Test-WinSecCase 'Synthetic FAIL includes local policy source and recommendation' {
    $control = New-WinSecTestControl -PUA 0
    $context = New-WinSecTestContext
    $r = Invoke-WinSecTestSelection -Control $control -Context $context
    $e = Invoke-WinSecControlEvaluation -ControlResult $control `
        -Criteria $r.EligibleCriteria -TargetContext $context

    Assert-WinSecEqual $e.Evaluations[0].Source.Framework 'LOCAL_POLICY'
    Assert-WinSecTrue (
        -not [string]::IsNullOrWhiteSpace($e.Evaluations[0].Recommendation)
    )
    Assert-WinSecEqual $e.Evaluations[0].CriterionId 'TEST-LOCAL-001'
}

# ============================================================
# GROUP 4: LIVE DEFENDER INTEGRATION (READ-ONLY)
# ============================================================

Write-Host ''
Write-Host 'Live Defender collection (read-only)' -ForegroundColor Cyan
Write-Host ''

$script:LiveResult = $null

if ($env:OS -ne 'Windows_NT') {
    Skip-WinSecCase 'Live Defender collection' 'Windows is required.'
    Skip-WinSecCase 'Live catalog selection remains blocked' 'Windows is required.'
    Skip-WinSecCase 'Live evidence without criteria is ungraded' 'Windows is required.'
}
else {
    $liveDeviceId = 'local:{0}' -f $env:COMPUTERNAME
    $liveScanId = 'CRITERIA-INTEGRATION-{0}' -f ([guid]::NewGuid().ToString('N'))

    Test-WinSecCase 'Live Defender collector returns exactly one result' {
        $results = @(Test-WinSecDefender `
            -DeviceId $liveDeviceId `
            -ScanId $liveScanId `
            -CheckId 'WSA-SYS-001')

        Assert-WinSecEqual $results.Count 1
        $script:LiveResult = $results[0]
        Assert-WinSecEqual $script:LiveResult.CheckId 'WSA-SYS-001'
        Assert-WinSecEqual $script:LiveResult.DeviceId $liveDeviceId
        Assert-WinSecEqual $script:LiveResult.ScanId $liveScanId
        Assert-WinSecTrue ($null -ne $script:LiveResult.Evidence)
        Assert-WinSecTrue (
            $script:LiveResult.Status -in @('INFORMATIONAL', 'ERROR')
        )
    }

    if ($null -ne $script:LiveResult) {
        Test-WinSecCase 'Live Defender catalog cannot release draft criteria' {
            # This intentionally uses an unresolved OS context: the real
            # Defender catalog is DRAFT and must be rejected BEFORE any
            # OS-scope or prerequisites could lead to scoring.
            $context = [pscustomobject]@{
                DeviceId = $script:LiveResult.DeviceId
                ScanId = $script:LiveResult.ScanId
                OSFamily = 'Windows'
                OSRelease = 'UNRESOLVED'
                Edition = 'UNRESOLVED'
                Profile = 'UNRESOLVED'
            }

            $selection = Get-WinSecApplicableCriteria `
                -Catalog $script:Catalog `
                -TargetContext $context `
                -ControlResult $script:LiveResult `
                -ProjectRoot $script:ProjectRoot

            Assert-WinSecEqual $selection.Status 'DRAFT_BLOCKED'
            Assert-WinSecEqual $selection.ScoringEligible $false
            Assert-WinSecEqual @($selection.EligibleCriteria).Count 0
            Assert-WinSecEqual @($selection.ReviewOnly).Count 14
        }

        Test-WinSecCase 'Live evidence cannot be graded without criteria' {
            $evaluation = Invoke-WinSecControlEvaluation `
                -ControlResult $script:LiveResult

            Assert-WinSecEqual $evaluation.ScoringEligible $false
            Assert-WinSecEqual @($evaluation.Evaluations).Count 0

            if ($script:LiveResult.Status -eq 'ERROR') {
                Assert-WinSecEqual $evaluation.Status 'UNKNOWN'
            }
            else {
                Assert-WinSecEqual $evaluation.Status 'NOT_EVALUATED'
            }
        }
    }
    else {
        Skip-WinSecCase 'Live catalog selection remains blocked' `
            'Live Defender collector did not return a result.'
        Skip-WinSecCase 'Live evidence without criteria is ungraded' `
            'Live Defender collector did not return a result.'
    }
}

# ============================================================
# GROUP 5: READ-ONLY CATALOG GUARANTEE
# ============================================================

Test-WinSecCase 'Catalog file hash is unchanged by integration' {
    $after = (Get-FileHash -LiteralPath $script:CatalogPath -Algorithm SHA256).Hash
    Assert-WinSecEqual $after $script:CatalogHashBefore
}

Complete-WinSecTests
