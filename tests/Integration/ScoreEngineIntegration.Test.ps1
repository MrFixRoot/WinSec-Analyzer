# ============================================================
# WinSec Analyzer
# Test Suite : Score Engine Integration
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Integration tests for approved-criteria scoring contracts.
#
# Includes:
# - CriteriaService -> EvaluationEngine -> ScoreEngine
# - Synthetic authorized PASS / FAIL scoring
# - Active policy simulation exclusively in memory
# - Incomplete coverage and tampering safeguards
# - Real draft Defender catalog blocks scoring
# - Live read-only Defender collection (Windows only)
# - Configuration file integrity verification
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# Synthetic approvals do not imply real compliance.
# No live security settings are modified or remediated.
# The real scoring policy is never enabled by this suite.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0
$script:Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:Paths = [ordered]@{
    Score = Join-Path $script:Root 'src/Core/ScoreEngine.ps1'
    Evaluation = Join-Path $script:Root 'src/Core/EvaluationEngine.ps1'
    Criteria = Join-Path $script:Root 'src/Services/CriteriaService.ps1'
    Defender = Join-Path $script:Root 'src/Checks/Defender/Test-Defender.ps1'
    Policy = Join-Path $script:Root 'config/scoring.json'
    Catalog = Join-Path $script:Root 'config/criteria/defender.json'
}

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
        if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
    }
}
function Skip-Case {
    param([string]$Name, [string]$Reason)
    $script:Skipped++
    Write-Host "[SKIP] $Name - $Reason" -ForegroundColor Yellow
}
function Copy-Fixture {
    param([object]$Value)
    return ($Value | ConvertTo-Json -Depth 40 | ConvertFrom-Json)
}
function New-SyntheticBundle {
    param(
        [int]$PUA = 1,
        [string]$Device = 'local:INTEGRATION-TEST',
        [string]$Scan = 'SCORE-INTEGRATION-001'
    )
    $criterion = [pscustomobject]@{
        CriterionId = 'SYNTHETIC-LOCAL-001'
        CheckId = 'WSA-SYS-001'
        Area = 'ThreatProtection'
        Name = 'Synthetic PUA test criterion'
        EvidencePath = 'DefenderPreferences.PUAProtection'
        Operator = 'Equals'
        ExpectedValue = 1
        Approved = $true
        Recommendation = 'Synthetic recommendation; no real action.'
        Source = [pscustomobject]@{
            Framework = 'LOCAL_POLICY'
            Version = 'TEST-ONLY'
            ControlId = 'SYNTHETIC-LOCAL-001'
            Title = 'Synthetic criterion only'
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
    $catalog = [pscustomobject]@{
        CatalogId = 'INTEGRATION-SYNTHETIC-ONLY'
        CatalogVersion = '0.9.0'
        CheckId = 'WSA-SYS-001'
        Status = 'APPROVED'
        ScoringEnabled = $true
        DeviceChangesAllowed = $false
        Criteria = @($criterion)
        ReviewOnly = @()
    }
    $collector = [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = $Device
        ScanId = $Scan
        Status = 'INFORMATIONAL'
        SectionKey = 'SystemSecurity'
        Evidence = [pscustomobject]@{
            CheckId = 'WSA-SYS-001'
            DeviceId = $Device
            ScanId = $Scan
            CollectionSuccessful = $true
            DefenderPreferences = [pscustomobject]@{
                PUAProtection = $PUA
            }
        }
    }
    $context = [pscustomobject]@{
        DeviceId = $Device
        ScanId = $Scan
        OSFamily = 'Windows'
        OSRelease = '11-24H2'
        Edition = 'Pro'
        Profile = 'Level1'
    }
    $selection = Get-WinSecApplicableCriteria -Catalog $catalog `
        -TargetContext $context -ControlResult $collector `
        -ProjectRoot $script:Root `
        -DependencyEvidence @{ 'active-antivirus-mode' = $true }
    $evaluation = Invoke-WinSecControlEvaluation -ControlResult $collector `
        -Criteria $selection.EligibleCriteria -TargetContext $context
    return [pscustomobject]@{
        Catalog = $catalog
        Collector = $collector
        Context = $context
        Selection = $selection
        Evaluation = $evaluation
    }
}
function Invoke-IntegrationScore {
    param([object]$Bundle, [object]$Policy)
    return Get-WinSecSecurityScore -DeviceId $Bundle.Collector.DeviceId `
        -ScanId $Bundle.Collector.ScanId -Policy $Policy `
        -ExpectedCheckIds @('WSA-SYS-001') `
        -CheckResults @($Bundle.Evaluation) `
        -CriteriaSelections @($Bundle.Selection) `
        -CollectorResults @($Bundle.Collector)
}

Write-Host ''
Write-Host 'WinSec Analyzer - Score Engine Integration Tests' -ForegroundColor Cyan
Write-Host ''

foreach ($path in $script:Paths.Values) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing integration dependency: $path"
    }
}

$script:PolicyHash = (Get-FileHash -LiteralPath $script:Paths.Policy -Algorithm SHA256).Hash
$script:CatalogHash = (Get-FileHash -LiteralPath $script:Paths.Catalog -Algorithm SHA256).Hash

# ------------------------------------------------------------
# Import modules in the same process.
# ------------------------------------------------------------
. $script:Paths.Score
. $script:Paths.Evaluation
. $script:Paths.Criteria
. $script:Paths.Defender
$script:RealPolicy = Get-WinSecScoringPolicy
$script:DraftCatalog = Import-WinSecCriteriaCatalog -ProjectRoot $script:Root
$script:ActiveTestPolicy = Copy-Fixture $script:RealPolicy
$script:ActiveTestPolicy.enabled = $true
$script:ActiveTestPolicy.activationStatus = 'ACTIVE'

# ============================================================
# GROUP 1 - MODULE AND POLICY CONTRACTS
# ============================================================

Test-Case 'Integration functions are available' {
    foreach ($name in @('Get-WinSecSecurityScore', 'Get-WinSecScoringPolicy',
        'Get-WinSecApplicableCriteria', 'Invoke-WinSecControlEvaluation',
        'Test-WinSecDefender')) {
        Assert-True ($null -ne (Get-Command $name -ErrorAction SilentlyContinue)) `
            "Missing function: $name"
    }
}
Test-Case 'Real policy remains disabled' {
    Assert-Equal $script:RealPolicy.enabled $false
    Assert-Equal $script:RealPolicy.activationStatus 'PENDING_APPROVED_CRITERIA'
}
Test-Case 'Real Defender catalog cannot award compliance' {
    $v = Test-WinSecCriteriaCatalog -Catalog $script:DraftCatalog
    Assert-Equal $v.Status 'DRAFT_UNAPPROVED'
    Assert-Equal $v.ReadyForScoring $false
}
Test-Case 'Synthetic active policy is validated only in memory' {
    Assert-Equal (Test-WinSecScoringPolicy $script:ActiveTestPolicy) $true
    Assert-Equal $script:RealPolicy.enabled $false
}

# ============================================================
# GROUP 2 - FULL SYNTHETIC CHAIN
# ============================================================

$script:PassingBundle = New-SyntheticBundle -PUA 1
$script:FailingBundle = New-SyntheticBundle -PUA 0

Test-Case 'CriteriaService releases an approved synthetic criterion' {
    Assert-Equal $script:PassingBundle.Selection.Status 'READY'
    Assert-Equal $script:PassingBundle.Selection.ScoringEligible $true
    Assert-Equal @($script:PassingBundle.Selection.EligibleCriteria).Count 1
}
Test-Case 'EvaluationEngine recognizes synthetic PASS' {
    Assert-Equal $script:PassingBundle.Evaluation.Status 'PASS'
    Assert-Equal $script:PassingBundle.Evaluation.ScoringEligible $true
}
Test-Case 'EvaluationEngine recognizes synthetic FAIL' {
    Assert-Equal $script:FailingBundle.Evaluation.Status 'FAIL'
    Assert-Equal $script:FailingBundle.Evaluation.FailedCriteria 1
}
Test-Case 'Disabled real policy blocks synthetic PASS scoring' {
    $r = Invoke-IntegrationScore $script:PassingBundle $script:RealPolicy
    Assert-Equal $r.Score $null
    Assert-Equal $r.Status 'NOT_SCORED'
    Assert-Equal $r.Coverage 100
}
Test-Case 'Active in-memory policy scores synthetic PASS as 100' {
    $r = Invoke-IntegrationScore $script:PassingBundle $script:ActiveTestPolicy
    Assert-Equal $r.Score 100
    Assert-Equal $r.Coverage 100
    Assert-Equal $r.ScoringEligible $true
}
Test-Case 'Active in-memory policy scores synthetic FAIL as 0' {
    $r = Invoke-IntegrationScore $script:FailingBundle $script:ActiveTestPolicy
    Assert-Equal $r.Score 0
    Assert-Equal $r.FailedCount 1
    Assert-Equal $r.AssessmentStatus 'COMPLETE'
}
Test-Case 'Overall and section scoring agree for one synthetic check' {
    $r = Invoke-IntegrationScore $script:PassingBundle $script:ActiveTestPolicy
    $section = @($r.SectionResults | Where-Object { $_.Key -eq 'SystemSecurity' })[0]
    Assert-Equal $section.Score 100
    Assert-Equal $section.TotalChecks 1
    Assert-Equal $r.ExpectedCheckCount 1
}
Test-Case 'Incomplete expected scope suppresses synthetic score' {
    $b = $script:PassingBundle
    $r = Get-WinSecSecurityScore -DeviceId $b.Collector.DeviceId `
        -ScanId $b.Collector.ScanId -Policy $script:ActiveTestPolicy `
        -ExpectedCheckIds @('WSA-SYS-001','WSA-SYS-002') `
        -CheckResults @($b.Evaluation) `
        -CriteriaSelections @($b.Selection) `
        -CollectorResults @($b.Collector)
    Assert-Equal $r.Score $null
    Assert-Equal $r.Coverage 50
    Assert-Equal $r.NotCheckedCount 1
}
Test-Case 'Missing criteria selection suppresses score' {
    $b = $script:PassingBundle
    $r = Get-WinSecSecurityScore -DeviceId $b.Collector.DeviceId `
        -ScanId $b.Collector.ScanId -Policy $script:ActiveTestPolicy `
        -ExpectedCheckIds @('WSA-SYS-001') `
        -CheckResults @($b.Evaluation) `
        -CollectorResults @($b.Collector)
    Assert-Equal $r.Score $null
    Assert-Equal $r.UnknownCount 1
}
Test-Case 'Forged evaluation source cannot inherit approval' {
    $b = New-SyntheticBundle
    $b.Evaluation.Evaluations[0].Source.ControlId = 'FORGED-ID'
    $r = Invoke-IntegrationScore $b $script:ActiveTestPolicy
    Assert-Equal $r.Score $null
    Assert-Equal $r.UnknownCount 1
}
Test-Case 'Foreign scan cannot alter local scoring' {
    $b = $script:PassingBundle
    $other = New-SyntheticBundle -PUA 0 -Scan 'OTHER-SCAN'
    $r = Get-WinSecSecurityScore -DeviceId $b.Collector.DeviceId `
        -ScanId $b.Collector.ScanId -Policy $script:ActiveTestPolicy `
        -ExpectedCheckIds @('WSA-SYS-001') `
        -CheckResults @($b.Evaluation,$other.Evaluation) `
        -CriteriaSelections @($b.Selection,$other.Selection) `
        -CollectorResults @($b.Collector,$other.Collector)
    Assert-Equal $r.Score 100
    Assert-Equal $r.TotalChecks 1
}
Test-Case 'Cross-device evidence cannot be scored' {
    $b = New-SyntheticBundle
    $b.Collector.Evidence.DeviceId = 'local:ANOTHER-DEVICE'
    $r = Invoke-IntegrationScore $b $script:ActiveTestPolicy
    Assert-Equal $r.Score $null
    Assert-Equal $r.ScoringEligible $false
}
Test-Case 'Section result preserves DeviceId and ScanId' {
    $r = Invoke-IntegrationScore $script:PassingBundle $script:ActiveTestPolicy
    foreach ($section in $r.SectionResults) {
        Assert-Equal $section.DeviceId 'local:INTEGRATION-TEST'
        Assert-Equal $section.ScanId 'SCORE-INTEGRATION-001'
    }
}

# ============================================================
# GROUP 3 - REAL DEFENDER, NEVER GRADED
# ============================================================

if ($env:OS -eq 'Windows_NT') {
    $device = 'local:{0}' -f $env:COMPUTERNAME
    $scan = 'SCORE-LIVE-{0}' -f ([guid]::NewGuid().ToString('N'))
    $script:LiveCollector = $null

    Test-Case 'Real Defender collector returns one read-only result' {
        $results = @(Test-WinSecDefender -DeviceId $device `
            -ScanId $scan -CheckId 'WSA-SYS-001')
        Assert-Equal $results.Count 1
        $script:LiveCollector = $results[0]
        Assert-Equal $script:LiveCollector.CheckId 'WSA-SYS-001'
        Assert-True ($script:LiveCollector.Status -in @('INFORMATIONAL','ERROR'))
    }

    if ($null -ne $script:LiveCollector) {
        Test-Case 'Real draft criteria remain blocked for live evidence' {
            $context = [pscustomobject]@{
                DeviceId = $device
                ScanId = $scan
                OSFamily = 'Windows'
                OSRelease = 'UNRESOLVED'
                Edition = 'UNRESOLVED'
                Profile = 'UNRESOLVED'
            }
            $s = Get-WinSecApplicableCriteria -Catalog $script:DraftCatalog `
                -TargetContext $context -ControlResult $script:LiveCollector `
                -ProjectRoot $script:Root
            Assert-Equal $s.Status 'DRAFT_BLOCKED'
            Assert-Equal $s.ScoringEligible $false
            Assert-Equal @($s.EligibleCriteria).Count 0
        }
        Test-Case 'Real Defender produces NOT_SCORED without approved criteria' {
            $e = Invoke-WinSecControlEvaluation -ControlResult $script:LiveCollector
            $r = Get-WinSecSecurityScore -DeviceId $device -ScanId $scan `
                -Policy $script:RealPolicy -ExpectedCheckIds @('WSA-SYS-001') `
                -CheckResults @($e) -CollectorResults @($script:LiveCollector)
            Assert-Equal $r.Score $null
            Assert-Equal $r.Status 'NOT_SCORED'
            Assert-Equal $r.ScoringEligible $false
        }
    }
    else {
        Skip-Case 'Real draft criteria remain blocked for live evidence' 'Defender collector produced no result.'
        Skip-Case 'Real Defender produces NOT_SCORED without approved criteria' 'Defender collector produced no result.'
    }
}
else {
    Skip-Case 'Real Defender collector returns one read-only result' 'Windows is required.'
    Skip-Case 'Real draft criteria remain blocked for live evidence' 'Windows is required.'
    Skip-Case 'Real Defender produces NOT_SCORED without approved criteria' 'Windows is required.'
}

# ============================================================
# GROUP 4 - FILE INTEGRITY
# ============================================================

Test-Case 'Scoring policy file remains unchanged' {
    $after = (Get-FileHash -LiteralPath $script:Paths.Policy -Algorithm SHA256).Hash
    Assert-Equal $after $script:PolicyHash
}
Test-Case 'Real Defender criteria catalog remains unchanged' {
    $after = (Get-FileHash -LiteralPath $script:Paths.Catalog -Algorithm SHA256).Hash
    Assert-Equal $after $script:CatalogHash
}
Test-Case 'Original scoring policy remains disabled after tests' {
    $p = Get-WinSecScoringPolicy
    Assert-Equal $p.enabled $false
    Assert-Equal $p.activationStatus 'PENDING_APPROVED_CRITERIA'
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed + $script:Skipped
Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'SCORE ENGINE INTEGRATION TEST SUMMARY' -ForegroundColor Cyan
Write-Host "TOTAL : $total"
Write-Host "PASS  : $script:Passed"
Write-Host "FAIL  : $script:Failed"
Write-Host "SKIP  : $script:Skipped"
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''
if ($script:Failed -gt 0) { throw "$($script:Failed) Score Engine integration test(s) failed." }
Write-Host 'All executed Score Engine integration tests passed.' -ForegroundColor Green
