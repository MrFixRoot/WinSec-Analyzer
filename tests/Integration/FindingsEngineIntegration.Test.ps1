# ============================================================
# WinSec Analyzer
# Test Suite : Findings Engine Integration
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Tests CriteriaService, EvaluationEngine and FindingsEngine
# together, with a separate read-only Defender collection.
#
# Includes:
# - Catalog approval and review-only safeguards
# - Synthetic LOCAL_POLICY end-to-end PASS/FAIL/UNKNOWN
# - Traceable findings, privacy and device identity
# - Incomplete/blocked criteria and dependencies
# - Live Microsoft Defender evidence (Windows only)
# - No data collection changes or compliance inventions
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# Approved synthetic fixtures are never run against real
# devices. Real Defender results use only the DRAFT catalog.
# Read-only audit; no changes to security settings.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0
$script:Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:FindingsPath = Join-Path $script:Root 'src/Core/FindingsEngine.ps1'
$script:EvaluationPath = Join-Path $script:Root 'src/Core/EvaluationEngine.ps1'
$script:CriteriaPath = Join-Path $script:Root 'src/Services/CriteriaService.ps1'
$script:DefenderPath = Join-Path $script:Root 'src/Checks/Defender/Test-Defender.ps1'
$script:CatalogPath = Join-Path $script:Root 'config/criteria/defender.json'

function Assert-Equal {
    param([AllowNull()][object]$Actual, [AllowNull()][object]$Expected,
          [string]$Message = 'Values differ.')
    if ($null -eq $Expected) {
        if ($null -ne $Actual) { throw "$Message Expected null; got [$Actual]." }
        return
    }
    if ($null -eq $Actual -or $Actual -cne $Expected) {
        throw "$Message Expected [$Expected]; got [$Actual]."
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message = 'Assertion failed.')
    if (-not $Condition) { throw $Message }
}

function Test-Case {
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

function Skip-Case {
    param([string]$Name, [string]$Reason)
    $script:Skipped++
    Write-Host "[SKIP] $Name - $Reason" -ForegroundColor Yellow
}

function New-FixtureControl {
    param([AllowNull()][object]$PUA = 1, [string]$Status = 'INFORMATIONAL')
    return [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:FINDINGS-FIXTURE'
        ScanId = 'FINDINGS-FIXTURE-SCAN'
        Status = $Status
        Evidence = [pscustomobject]@{
            CheckId = 'WSA-SYS-001'
            DeviceId = 'local:FINDINGS-FIXTURE'
            ScanId = 'FINDINGS-FIXTURE-SCAN'
            CollectionSuccessful = ($Status -eq 'INFORMATIONAL')
            DefenderPreferences = [pscustomobject]@{
                PUAProtection = $PUA
                SecretRawEvidence = 'SENSITIVE-EVIDENCE-FIXTURE'
            }
        }
    }
}

function New-FixtureContext {
    return [pscustomobject]@{
        DeviceId = 'local:FINDINGS-FIXTURE'
        ScanId = 'FINDINGS-FIXTURE-SCAN'
        OSFamily = 'Windows'
        OSRelease = '11-24H2'
        Edition = 'Pro'
        Profile = 'Level1'
    }
}

function New-FixtureCatalog {
    # Contract fixture only; VERIFIED does not mean real approval.
    $criterion = [pscustomobject]@{
        CriterionId = 'TEST-FINDINGS-LOCAL-001'
        CheckId = 'WSA-SYS-001'
        Area = 'ThreatProtection'
        Name = 'Synthetic PUA preference'
        EvidencePath = 'DefenderPreferences.PUAProtection'
        Operator = 'Equals'
        ExpectedValue = 1
        Approved = $true
        Recommendation = 'Synthetic recommendation - no device action.'
        Source = [pscustomobject]@{
            Framework = 'LOCAL_POLICY'
            Version = 'TEST-ONLY'
            ControlId = 'TEST-FINDINGS-LOCAL-001'
            Title = 'Synthetic assessment rule'
            Url = 'https://example.invalid/fictional-rule'
        }
        Verification = [pscustomobject]@{
            Status = 'VERIFIED'
            ReviewedBy = 'TEST-FIXTURE-ONLY'
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
        CatalogId = 'FINDINGS-INTEGRATION-FIXTURE'
        CatalogVersion = '0.9.0'
        CheckId = 'WSA-SYS-001'
        Status = 'APPROVED'
        ScoringEnabled = $true
        DeviceChangesAllowed = $false
        Criteria = @($criterion)
        ReviewOnly = @(
            [pscustomobject]@{
                Name = 'Synthetic PUA observation'
                Area = 'ThreatProtection'
                Assessment = 'REVIEW_ONLY'
                EvidencePath = 'DefenderPreferences.PUAProtection'
                ReferenceUrl = 'https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus'
            }
        )
    }
}

function Invoke-FixturePipeline {
    param([AllowNull()][object]$PUA = 1,
          [AllowNull()][System.Collections.IDictionary]$Dependencies = $null,
          [bool]$UseDefaultDependencies = $true,
          [AllowNull()][object]$Catalog = $null,
          [AllowNull()][object]$Context = $null)
    $control = New-FixtureControl -PUA $PUA
    if ($null -eq $Catalog) { $Catalog = New-FixtureCatalog }
    if ($null -eq $Context) { $Context = New-FixtureContext }
    if ($null -eq $Dependencies -and $UseDefaultDependencies) {
        $Dependencies = @{ 'active-antivirus-mode' = $true }
    }
    $selection = Get-WinSecApplicableCriteria `
        -Catalog $Catalog -TargetContext $Context `
        -ControlResult $control -ProjectRoot $script:Root `
        -DependencyEvidence $Dependencies
    $evaluation = if ($selection.Status -eq 'READY') {
        Invoke-WinSecControlEvaluation `
            -ControlResult $control -Criteria $selection.EligibleCriteria `
            -TargetContext $Context
    }
    else {
        Invoke-WinSecControlEvaluation -ControlResult $control
    }
    $findings = ConvertTo-WinSecFindings `
        -EvaluationResult $evaluation -ControlResult $control `
        -SelectionResult $selection -IncludeReviewOnly
    return [pscustomobject]@{
        Control = $control
        Selection = $selection
        Evaluation = $evaluation
        Findings = $findings
    }
}

Write-Host ''
Write-Host 'WinSec Analyzer - Findings Engine Integration Tests' -ForegroundColor Cyan
Write-Host ''

# ============================================================
# COMPONENT IMPORT AND CONTRACT
# ============================================================

foreach ($file in @($script:FindingsPath, $script:EvaluationPath,
                    $script:CriteriaPath, $script:DefenderPath,
                    $script:CatalogPath)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Required file missing: $file"
    }
}

foreach ($file in @($script:FindingsPath, $script:EvaluationPath,
                    $script:CriteriaPath, $script:DefenderPath)) {
    $label = Split-Path -Path $file -Leaf
    Test-Case "$label parses without errors" {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $file, [ref]$tokens, [ref]$errors
        )
        Assert-Equal @($errors).Count 0
    }
}

if ($script:Failed -gt 0) { throw 'Component parsing failed.' }

. $script:EvaluationPath
. $script:CriteriaPath
. $script:FindingsPath
. $script:DefenderPath

$script:CatalogHash = (Get-FileHash -LiteralPath $script:CatalogPath -Algorithm SHA256).Hash
$script:RealCatalog = Import-WinSecCriteriaCatalog -ProjectRoot $script:Root

Test-Case 'Public pipeline functions are available' {
    foreach ($name in @('Import-WinSecCriteriaCatalog', 'Get-WinSecApplicableCriteria',
                        'Invoke-WinSecControlEvaluation', 'ConvertTo-WinSecFindings',
                        'Test-WinSecDefender')) {
        Assert-True ($null -ne (Get-Command $name -ErrorAction SilentlyContinue)) `
            "Missing function: $name"
    }
}

# ============================================================
# REAL CATALOG, SYNTHETIC DEVICE (NO COMPLIANCE CLAIMS)
# ============================================================

Test-Case 'Real Defender catalog remains draft and cannot score' {
    $v = Test-WinSecCriteriaCatalog -Catalog $script:RealCatalog
    Assert-Equal $v.Valid $true
    Assert-Equal $v.Status 'DRAFT_UNAPPROVED'
    Assert-Equal $v.ReadyForScoring $false
}

Test-Case 'Real draft catalog produces CATALOG_NOT_READY' {
    $r = Invoke-FixturePipeline -Catalog $script:RealCatalog
    Assert-Equal $r.Selection.Status 'DRAFT_BLOCKED'
    Assert-Equal $r.Findings.Status 'BLOCKED'
    Assert-Equal $r.Findings.DeviationCount 0
    Assert-Equal $r.Findings.Findings[0].Kind 'CATALOG_NOT_READY'
}

Test-Case 'Real draft preserves fourteen review-only observations' {
    $r = Invoke-FixturePipeline -Catalog $script:RealCatalog
    Assert-Equal $r.Findings.ReviewItemCount 14
    Assert-Equal $r.Findings.DeviationCount 0
    foreach ($item in $r.Findings.ReviewItems) {
        Assert-Equal $item.ScoringEligible $false
    }
}

# ============================================================
# SYNTHETIC, APPROVED *FIXTURE* ONLY
# ============================================================

Test-Case 'Synthetic catalog passes structural validation' {
    $v = Test-WinSecCriteriaCatalog -Catalog (New-FixtureCatalog)
    Assert-Equal $v.Valid $true
    Assert-Equal $v.ReadyForScoring $true
}

Test-Case 'Matching synthetic evidence yields PASS and no deviation' {
    $r = Invoke-FixturePipeline -PUA 1
    Assert-Equal $r.Selection.Status 'READY'
    Assert-Equal $r.Evaluation.Status 'PASS'
    Assert-Equal $r.Findings.Status 'COMPLETE'
    Assert-Equal $r.Findings.DeviationCount 0
    Assert-Equal $r.Findings.ReviewItemCount 1
}

Test-Case 'Nonmatching synthetic evidence yields traceable FAIL finding' {
    $r = Invoke-FixturePipeline -PUA 0
    Assert-Equal $r.Selection.Status 'READY'
    Assert-Equal $r.Evaluation.Status 'FAIL'
    Assert-Equal $r.Findings.Status 'COMPLETE'
    Assert-Equal $r.Findings.DeviationCount 1
    $f = $r.Findings.Findings[0]
    Assert-Equal $f.Kind 'CONFIGURATION_DEVIATION'
    Assert-Equal $f.CriterionId 'TEST-FINDINGS-LOCAL-001'
    Assert-Equal $f.DeviceId $r.Control.DeviceId
    Assert-Equal $f.ScanId $r.Control.ScanId
    Assert-Equal $f.EvidenceReference.RawValueIncluded $false
}

Test-Case 'Synthetic deviation never invents severity or framework mappings' {
    $f = (Invoke-FixturePipeline -PUA 0).Findings.Findings[0]
    Assert-Equal $f.Severity 'UNASSIGNED'
    Assert-Equal $f.Priority 'UNASSIGNED'
    Assert-Equal $f.ScoringEligible $false
    Assert-Equal $f.FrameworkMappings.CISBenchmarks.Count 0
    Assert-Equal $f.FrameworkMappings.CISControls.Count 0
    Assert-Equal $f.FrameworkMappings.NISTCSF.Count 0
    Assert-Equal $f.FrameworkMappings.MITREATTACK.Count 0
}

Test-Case 'Missing synthetic evidence yields UNKNOWN evidence gap' {
    $r = Invoke-FixturePipeline -PUA $null
    Assert-Equal $r.Selection.Status 'READY'
    Assert-Equal $r.Evaluation.Status 'UNKNOWN'
    Assert-Equal $r.Findings.DeviationCount 0
    Assert-Equal $r.Findings.EvidenceGapCount 1
    Assert-Equal $r.Findings.Findings[0].Kind 'EVIDENCE_GAP'
}

Test-Case 'Missing dependency yields blocked selection, no deviation' {
    $r = Invoke-FixturePipeline -PUA 0 -UseDefaultDependencies $false
    Assert-Equal $r.Selection.ScoringEligible $false
    Assert-Equal $r.Findings.Status 'BLOCKED'
    Assert-Equal $r.Findings.DeviationCount 0
    Assert-Equal $r.Findings.Findings[0].Kind 'CATALOG_NOT_READY'
}

Test-Case 'False dependency yields blocked selection' {
    $r = Invoke-FixturePipeline -PUA 0 `
        -Dependencies @{ 'active-antivirus-mode' = $false }
    Assert-Equal $r.Selection.ScoringEligible $false
    Assert-Equal $r.Findings.DeviationCount 0
}

Test-Case 'Wrong Windows profile cannot generate a deviation' {
    $context = New-FixtureContext
    $context.Profile = 'Level2'
    $r = Invoke-FixturePipeline -PUA 0 -Context $context
    Assert-Equal $r.Selection.Status 'NO_ELIGIBLE_CRITERIA'
    Assert-Equal $r.Findings.Status 'BLOCKED'
    Assert-Equal $r.Findings.DeviationCount 0
}

Test-Case 'Unapproved individual criterion cannot generate a deviation' {
    $catalog = New-FixtureCatalog
    $catalog.Criteria[0].Approved = $false
    $r = Invoke-FixturePipeline -PUA 0 -Catalog $catalog
    Assert-Equal $r.Selection.ScoringEligible $false
    Assert-Equal $r.Findings.DeviationCount 0
}

Test-Case 'Synthetic report contains no raw private evidence' {
    $r = Invoke-FixturePipeline -PUA 0
    $json = $r.Findings | ConvertTo-Json -Depth 20
    Assert-True (-not $json.Contains('SENSITIVE-EVIDENCE-FIXTURE'))
    Assert-Equal $r.Findings.ReviewItems[0].RawValueIncluded $false
}

Test-Case 'Finding counts equal actual record collections' {
    $r = Invoke-FixturePipeline -PUA 0
    Assert-Equal $r.Findings.FindingCount @($r.Findings.Findings).Count
    Assert-Equal $r.Findings.ReviewItemCount @($r.Findings.ReviewItems).Count
    Assert-Equal $r.Findings.DeviationCount 1
}

# ============================================================
# REAL MICROSOFT DEFENDER - NEVER USE SYNTHETIC RULES
# ============================================================

$script:LiveResult = $null
if ($env:OS -ne 'Windows_NT') {
    Skip-Case 'Real Defender returns a collector result' 'Windows only.'
    Skip-Case 'Real Defender and draft catalog stay blocked' 'Windows only.'
    Skip-Case 'Real Defender never receives synthetic scoring rules' 'Windows only.'
}
else {
    $liveDevice = 'local:{0}' -f $env:COMPUTERNAME
    $liveScan = 'FINDINGS-LIVE-{0}' -f ([guid]::NewGuid().ToString('N'))

    Test-Case 'Real Defender returns a collector result' {
        $results = @(
            Test-WinSecDefender -DeviceId $liveDevice `
                -ScanId $liveScan -CheckId 'WSA-SYS-001'
        )
        Assert-Equal $results.Count 1
        $script:LiveResult = $results[0]
        Assert-Equal $script:LiveResult.DeviceId $liveDevice
        Assert-Equal $script:LiveResult.ScanId $liveScan
        Assert-True ($null -ne $script:LiveResult.Evidence)
    }

    if ($null -ne $script:LiveResult) {
        Test-Case 'Real Defender and draft catalog stay blocked' {
            $context = [pscustomobject]@{
                DeviceId = $script:LiveResult.DeviceId
                ScanId = $script:LiveResult.ScanId
                OSFamily = 'Windows'
                OSRelease = 'UNRESOLVED'
                Edition = 'UNRESOLVED'
                Profile = 'UNRESOLVED'
            }
            $selection = Get-WinSecApplicableCriteria `
                -Catalog $script:RealCatalog -TargetContext $context `
                -ControlResult $script:LiveResult -ProjectRoot $script:Root
            Assert-Equal $selection.Status 'DRAFT_BLOCKED'
            $evaluation = Invoke-WinSecControlEvaluation `
                -ControlResult $script:LiveResult
            $findings = ConvertTo-WinSecFindings `
                -EvaluationResult $evaluation -ControlResult $script:LiveResult `
                -SelectionResult $selection -IncludeReviewOnly
            Assert-Equal $findings.Status 'BLOCKED'
            Assert-Equal $findings.DeviationCount 0
            Assert-Equal $findings.Findings[0].Kind 'CATALOG_NOT_READY'
            Assert-Equal $findings.ReviewItemCount 14
        }
        Test-Case 'Real Defender never receives synthetic scoring rules' {
            $evaluation = Invoke-WinSecControlEvaluation `
                -ControlResult $script:LiveResult
            Assert-Equal $evaluation.ScoringEligible $false
            Assert-Equal @($evaluation.Evaluations).Count 0
            Assert-True ($evaluation.Status -in @('UNKNOWN','NOT_EVALUATED'))
        }
    }
    else {
        Skip-Case 'Real Defender and draft catalog stay blocked' 'Collector returned no result.'
        Skip-Case 'Real Defender never receives synthetic scoring rules' 'Collector returned no result.'
    }
}

Test-Case 'Original Defender catalog is unchanged after integration' {
    $after = (Get-FileHash -LiteralPath $script:CatalogPath -Algorithm SHA256).Hash
    Assert-Equal $after $script:CatalogHash
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed + $script:Skipped
Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'FINDINGS ENGINE INTEGRATION TEST SUMMARY' -ForegroundColor Cyan
Write-Host "TOTAL : $total"
Write-Host "PASS  : $script:Passed" -ForegroundColor Green
Write-Host "FAIL  : $script:Failed" -ForegroundColor $(if ($script:Failed) { 'Red' } else { 'Green' })
Write-Host "SKIP  : $script:Skipped" -ForegroundColor Yellow
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''
if ($script:Failed -gt 0) {
    throw "$($script:Failed) Findings Engine integration test(s) failed."
}
Write-Host 'Findings Engine integration tests completed.' -ForegroundColor Green
