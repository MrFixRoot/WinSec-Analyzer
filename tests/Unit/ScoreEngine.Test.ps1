# ============================================================
# WinSec Analyzer
# Test Suite : Score Engine
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit tests for conservative, evidence-based scoring.
#
# Includes:
# - Scoring policy validation and loading
# - Draft, incomplete and unauthorized score safeguards
# - Evidence and criterion identity validation
# - Flat-unweighted scoring using synthetic approved fixtures
# - Coverage, security sections, device and scan isolation
# - Duplicate and unexpected control detection
# - PowerShell AST read-only inspection
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# All approved criteria here are synthetic TEST FIXTURES.
# They are NOT CIS requirements or real organizational approvals.
# This suite does not modify Windows security settings.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
$script:Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:EnginePath = Join-Path $script:Root 'src/Core/ScoreEngine.ps1'
$script:PolicyPath = Join-Path $script:Root 'config/scoring.json'

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
function Assert-Throws {
    param([scriptblock]$Action, [string]$Message = 'Expected an exception.')
    $raised = $false
    try { $null = & $Action } catch { $raised = $true }
    if (-not $raised) { throw $Message }
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
function Copy-Fixture {
    param([Parameter(Mandatory)][object]$Value)
    return ($Value | ConvertTo-Json -Depth 40 | ConvertFrom-Json)
}
function New-TestPolicy {
    param([bool]$Active = $false)
    $p = Copy-Fixture $script:BasePolicy
    $p.enabled = $Active
    $p.activationStatus = if ($Active) { 'ACTIVE' } else { 'PENDING_APPROVED_CRITERIA' }
    return $p
}
function New-TestCriterion {
    param([string]$CheckId = 'WSA-SYS-001', [string]$Id = 'TEST-CRIT-001')
    return [pscustomobject]@{
        CheckId = $CheckId
        CriterionId = $Id
        Approved = $true
        EvidencePath = 'DefenderPreferences.PUAProtection'
        Operator = 'Equals'
        ExpectedValue = 1
        Verification = [pscustomobject]@{
            Status = 'VERIFIED'
            ReviewedBy = 'UNIT-TEST-FIXTURE'
            ReviewedAtUTC = '2025-01-01T00:00:00Z'
        }
        Source = [pscustomobject]@{
            Framework = 'LOCAL_POLICY'
            ControlId = $Id
            Version = 'TEST-ONLY'
            Title = 'Synthetic policy only'
            Url = 'https://example.invalid/test'
        }
    }
}
function New-TestBundle {
    param(
        [string]$CheckId = 'WSA-SYS-001',
        [string]$CriterionId = 'TEST-CRIT-001',
        [ValidateSet('PASS','FAIL','UNKNOWN','NOT_EVALUATED')][string]$Status = 'PASS',
        [string]$Section = 'SystemSecurity',
        [string]$Device = 'local:TEST-PC',
        [string]$Scan = 'TEST-SCAN-001'
    )
    $criterion = New-TestCriterion -CheckId $CheckId -Id $CriterionId
    $ok = $Status -in @('PASS','FAIL')
    $entry = [pscustomobject]@{
        CriterionId = $CriterionId
        CheckId = $CheckId
        DeviceId = $Device
        ScanId = $Scan
        Status = $Status
        ScoringEligible = $ok
        EvidencePath = $criterion.EvidencePath
        Operator = $criterion.Operator
        Source = Copy-Fixture $criterion.Source
    }
    $evaluation = [pscustomobject]@{
        CheckId = $CheckId
        DeviceId = $Device
        ScanId = $Scan
        CollectorStatus = 'INFORMATIONAL'
        Status = $Status
        ScoringEligible = $ok
        Evaluations = @($entry)
        PassedCriteria = [int]($Status -eq 'PASS')
        FailedCriteria = [int]($Status -eq 'FAIL')
        EvaluatedCriteria = [int]$ok
        UnknownCriteria = [int]($Status -eq 'UNKNOWN')
        NotEvaluatedCriteria = [int]($Status -eq 'NOT_EVALUATED')
        NotApplicableCriteria = 0
    }
    $selection = [pscustomobject]@{
        CatalogId = 'TEST-CATALOG'
        CheckId = $CheckId
        DeviceId = $Device
        ScanId = $Scan
        Status = 'READY'
        ScoringEligible = $true
        CatalogCriteriaCount = 1
        MatchedCriteriaCount = 1
        ExcludedCriteria = @()
        EligibleCriteria = @($criterion)
    }
    $collector = [pscustomobject]@{
        CheckId = $CheckId
        DeviceId = $Device
        ScanId = $Scan
        SectionKey = $Section
        Status = 'INFORMATIONAL'
        Evidence = [pscustomobject]@{
            CheckId = $CheckId
            DeviceId = $Device
            ScanId = $Scan
            CollectionSuccessful = $true
            DefenderPreferences = [pscustomobject]@{ PUAProtection = 1 }
        }
    }
    return [pscustomobject]@{
        Evaluation = $evaluation
        Selection = $selection
        Collector = $collector
    }
}
function Invoke-Bundle {
    param([object]$Bundle, [object]$Policy = $script:BasePolicy)
    return Get-WinSecCheckScore -CheckResult $Bundle.Evaluation -Policy $Policy `
        -CriteriaSelection $Bundle.Selection -CollectorResult $Bundle.Collector
}
function Invoke-Device {
    param(
        [object[]]$Bundles,
        [object]$Policy = $script:BasePolicy,
        [string[]]$Expected = @('WSA-SYS-001'),
        [string]$Device = 'local:TEST-PC',
        [string]$Scan = 'TEST-SCAN-001'
    )
    return Get-WinSecSecurityScore -DeviceId $Device -ScanId $Scan `
        -CheckResults @($Bundles | ForEach-Object { $_.Evaluation }) `
        -CriteriaSelections @($Bundles | ForEach-Object { $_.Selection }) `
        -CollectorResults @($Bundles | ForEach-Object { $_.Collector }) `
        -Policy $Policy -ExpectedCheckIds $Expected
}

if (-not (Test-Path -LiteralPath $script:EnginePath -PathType Leaf)) {
    throw "Missing Score Engine: $script:EnginePath"
}
if (-not (Test-Path -LiteralPath $script:PolicyPath -PathType Leaf)) {
    throw "Missing scoring policy: $script:PolicyPath"
}
. $script:EnginePath
$script:BasePolicy = Get-WinSecScoringPolicy

Write-Host ''
Write-Host 'WinSec Analyzer - Score Engine Unit Tests' -ForegroundColor Cyan
Write-Host ''

# ============================================================
# GROUP 1 - POLICY
# ============================================================

Test-Case 'Policy loads schema 1.1.0' {
    Assert-Equal $script:BasePolicy.schemaVersion '1.1.0'
}
Test-Case 'Production scoring stays disabled' {
    Assert-Equal $script:BasePolicy.enabled $false
    Assert-Equal $script:BasePolicy.activationStatus 'PENDING_APPROVED_CRITERIA'
}
Test-Case 'Policy validation accepts disabled configuration' {
    Assert-Equal (Test-WinSecScoringPolicy $script:BasePolicy) $true
}
Test-Case 'Active synthetic policy can be validated in memory' {
    Assert-Equal (Test-WinSecScoringPolicy (New-TestPolicy -Active $true)) $true
}
Test-Case 'Unsupported schema is rejected' {
    $p = New-TestPolicy; $p.schemaVersion = '1.0.0'
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Enabled without ACTIVE is rejected' {
    $p = New-TestPolicy; $p.enabled = $true
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Non-Boolean enabled flag is rejected' {
    $p = New-TestPolicy; $p.enabled = 'true'
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Weighted methodology is rejected' {
    $p = New-TestPolicy; $p.methodology.allowSeverityWeights = $true
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Custom unit weight is rejected' {
    $p = New-TestPolicy; $p.methodology.unitWeight = 2
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Partial credit is rejected' {
    $p = New-TestPolicy; $p.methodology.allowPartialCredit = $true
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Framework-based weighting is rejected' {
    $p = New-TestPolicy; $p.methodology.allowFrameworkWeights = $true
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Missing approval safeguard is rejected' {
    $p = New-TestPolicy; $p.scoringRules.requireApprovedCriteria = $false
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Allowing provisional scores is rejected' {
    $p = New-TestPolicy; $p.scoringRules.allowProvisionalScore = $true
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Permitting remediation is rejected' {
    $p = New-TestPolicy; $p.scoringRules.automaticRemediation = $true
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Scoring UNKNOWN is rejected' {
    $p = New-TestPolicy; $p.statusDefinitions.UNKNOWN.includedInScore = $true
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Scoring ERROR is rejected' {
    $p = New-TestPolicy; $p.statusDefinitions.ERROR.scoreValue = 0
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Scoring NOT_EVALUATED is rejected' {
    $p = New-TestPolicy; $p.statusDefinitions.NOT_EVALUATED.includedInScore = $true
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Invalid coverage statuses are rejected' {
    $p = New-TestPolicy; $p.coverage.numeratorStatuses = @('PASS')
    Assert-Throws { Test-WinSecScoringPolicy $p }
}
Test-Case 'Missing policy file is rejected' {
    Assert-Throws {
        Get-WinSecScoringPolicy -Path (Join-Path $script:Root 'missing-policy.json')
    }
}

# ============================================================
# GROUP 2 - HELPERS AND AUTHORIZATION
# ============================================================

Test-Case 'Empty evidence is rejected' {
    Assert-Equal (Test-WinSecScoreEvidence $null) $false
    Assert-Equal (Test-WinSecScoreEvidence @()) $false
    Assert-Equal (Test-WinSecScoreEvidence @{}) $false
}
Test-Case 'Nonempty evidence is recognized' {
    Assert-Equal (Test-WinSecScoreEvidence 'observed') $true
}
Test-Case 'Identity validation rejects a different scan' {
    $b = New-TestBundle
    $other = Copy-Fixture $b.Selection
    $other.ScanId = 'OTHER-SCAN'
    Assert-Equal (Assert-WinSecScoreIdentity $b.Evaluation $other) $false
}
Test-Case 'Fully aligned synthetic control is authorized' {
    $b = New-TestBundle
    $r = Test-WinSecScoreAuthorization $b.Evaluation $b.Selection $b.Collector
    Assert-Equal $r.Authorized $true
}
Test-Case 'Unapproved criterion is not authorized' {
    $b = New-TestBundle
    $b.Selection.EligibleCriteria[0].Approved = $false
    Assert-Equal (Test-WinSecScoreAuthorization $b.Evaluation $b.Selection $b.Collector).Authorized $false
}
Test-Case 'Unverified criterion is not authorized' {
    $b = New-TestBundle
    $b.Selection.EligibleCriteria[0].Verification.Status = 'PENDING'
    Assert-Equal (Test-WinSecScoreAuthorization $b.Evaluation $b.Selection $b.Collector).Authorized $false
}
Test-Case 'Contextual NIST mapping cannot replace scoring source' {
    $b = New-TestBundle
    $b.Selection.EligibleCriteria[0].Source.Framework = 'NIST CSF'
    Assert-Equal (Test-WinSecScoreAuthorization $b.Evaluation $b.Selection $b.Collector).Authorized $false
}
Test-Case 'Mismatched criterion identifier is not authorized' {
    $b = New-TestBundle
    $b.Evaluation.Evaluations[0].CriterionId = 'OTHER-CRITERION'
    Assert-Equal (Test-WinSecScoreAuthorization $b.Evaluation $b.Selection $b.Collector).Authorized $false
}
Test-Case 'Mismatched original evidence identity is not authorized' {
    $b = New-TestBundle
    $b.Collector.Evidence.DeviceId = 'local:FOREIGN'
    Assert-Equal (Test-WinSecScoreAuthorization $b.Evaluation $b.Selection $b.Collector).Authorized $false
}
Test-Case 'Changed evidence path is not authorized' {
    $b = New-TestBundle
    $b.Evaluation.Evaluations[0].EvidencePath = 'Different.Property'
    Assert-Equal (Test-WinSecScoreAuthorization $b.Evaluation $b.Selection $b.Collector).Authorized $false
}
Test-Case 'READY selection is required' {
    $b = New-TestBundle
    $b.Selection.Status = 'DRAFT_BLOCKED'
    Assert-Equal (Test-WinSecScoreAuthorization $b.Evaluation $b.Selection $b.Collector).Authorized $false
}
Test-Case 'Incomplete selected criteria are not authorized' {
    $b = New-TestBundle
    $b.Selection.CatalogCriteriaCount = 2
    Assert-Equal (Test-WinSecScoreAuthorization $b.Evaluation $b.Selection $b.Collector).Authorized $false
}

# ============================================================
# GROUP 3 - NORMALIZATION
# ============================================================

Test-Case 'Synthetic PASS normalization awards one point' {
    $r = Invoke-Bundle (New-TestBundle) (New-TestPolicy -Active $true)
    Assert-Equal $r.Status 'PASS'
    Assert-Equal $r.ScoreValue 1
    Assert-Equal $r.ScoringEligible $true
}
Test-Case 'Synthetic FAIL normalization awards zero points' {
    $r = Invoke-Bundle (New-TestBundle -Status FAIL) (New-TestPolicy -Active $true)
    Assert-Equal $r.Status 'FAIL'
    Assert-Equal $r.ScoreValue 0
    Assert-Equal $r.ScoringEligible $true
}
Test-Case 'Bare PASS without selection becomes UNKNOWN' {
    $b = New-TestBundle
    $r = Get-WinSecCheckScore -CheckResult $b.Evaluation `
        -Policy (New-TestPolicy -Active $true) -CollectorResult $b.Collector
    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoreValue $null
}
Test-Case 'Bare FAIL without evidence becomes UNKNOWN' {
    $b = New-TestBundle -Status FAIL
    $r = Get-WinSecCheckScore -CheckResult $b.Evaluation `
        -Policy (New-TestPolicy -Active $true) -CriteriaSelection $b.Selection
    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoringEligible $false
}
Test-Case 'Collector section is preserved' {
    $b = New-TestBundle -Section IdentityAccess
    Assert-Equal (Invoke-Bundle $b).SectionKey 'IdentityAccess'
}
Test-Case 'Unsupported section throws' {
    $b = New-TestBundle -Section InvalidSection
    Assert-Throws { Invoke-Bundle $b }
}
Test-Case 'Unsupported normalized status throws' {
    $b = New-TestBundle
    $b.Evaluation.Status = 'MADE_UP'
    Assert-Throws { Invoke-Bundle $b }
}
Test-Case 'UNKNOWN evaluation stays non-scored' {
    $r = Invoke-Bundle (New-TestBundle -Status UNKNOWN)
    Assert-Equal $r.Status 'UNKNOWN'
    Assert-Equal $r.ScoreValue $null
}

# ============================================================
# GROUP 4 - AGGREGATION AND COVERAGE
# ============================================================

Test-Case 'Disabled policy never produces a security score' {
    $r = Invoke-Device @((New-TestBundle))
    Assert-Equal $r.Status 'NOT_SCORED'
    Assert-Equal $r.Score $null
    Assert-Equal $r.Coverage 100
}
Test-Case 'Disabled policy preserves verified control counts' {
    $r = Invoke-Device @((New-TestBundle))
    Assert-Equal $r.VerifiedChecks 1
    Assert-Equal $r.PassedCount 1
    Assert-Equal $r.ScoringEligible $false
}
Test-Case 'No expected controls means no security score' {
    $r = Invoke-Device @((New-TestBundle)) (New-TestPolicy -Active $true) @()
    Assert-Equal $r.Score $null
    Assert-Equal $r.Status 'NOT_SCORED'
}
Test-Case 'Active synthetic all PASS means 100 percent' {
    $r = Invoke-Device @((New-TestBundle)) (New-TestPolicy -Active $true)
    Assert-Equal $r.Score 100
    Assert-Equal $r.Coverage 100
    Assert-Equal $r.AssessmentStatus 'COMPLETE'
}
Test-Case 'Active synthetic all FAIL means zero percent' {
    $r = Invoke-Device @((New-TestBundle -Status FAIL)) (New-TestPolicy -Active $true)
    Assert-Equal $r.Score 0
    Assert-Equal $r.FailedCount 1
}
Test-Case 'One PASS and one FAIL results in 50 percent' {
    $bundles = @(
        (New-TestBundle -CheckId 'WSA-SYS-001' -CriterionId 'TEST-CRIT-001'),
        (New-TestBundle -CheckId 'WSA-SYS-002' -CriterionId 'TEST-CRIT-002' -Status FAIL -Section NetworkSecurity)
    )
    $r = Invoke-Device $bundles (New-TestPolicy -Active $true) @('WSA-SYS-001','WSA-SYS-002')
    Assert-Equal $r.Score 50
    Assert-Equal $r.PassedRules 1
    Assert-Equal $r.ScoredRules 2
}
Test-Case 'Missing expected control produces NOT_SCORED' {
    $r = Invoke-Device @((New-TestBundle)) (New-TestPolicy -Active $true) @('WSA-SYS-001','WSA-SYS-002')
    Assert-Equal $r.Score $null
    Assert-Equal $r.Coverage 50
    Assert-Equal $r.AssessmentStatus 'INCOMPLETE'
    Assert-Equal $r.NotCheckedCount 1
}
Test-Case 'UNKNOWN control lowers coverage not security points' {
    $bundles = @(
        (New-TestBundle -CheckId 'WSA-SYS-001' -CriterionId 'TEST-CRIT-001'),
        (New-TestBundle -CheckId 'WSA-SYS-002' -CriterionId 'TEST-CRIT-002' -Status UNKNOWN)
    )
    $r = Invoke-Device $bundles (New-TestPolicy -Active $true) @('WSA-SYS-001','WSA-SYS-002')
    Assert-Equal $r.Score $null
    Assert-Equal $r.Coverage 50
    Assert-Equal $r.ScoredRules 1
}
Test-Case 'NOT_EVALUATED cannot lower a fabricated security score' {
    $r = Invoke-Device @((New-TestBundle -Status NOT_EVALUATED)) (New-TestPolicy -Active $true)
    Assert-Equal $r.Score $null
    Assert-Equal $r.NotEvaluatedCount 1
}
Test-Case 'Unauthorized PASS has zero verified coverage' {
    $b = New-TestBundle
    $b.Selection.Status = 'DRAFT_BLOCKED'
    $r = Invoke-Device @($b) (New-TestPolicy -Active $true)
    Assert-Equal $r.Score $null
    Assert-Equal $r.Coverage 0
    Assert-Equal $r.UnknownCount 1
}
Test-Case 'Section totals remain divided into five sections' {
    $r = Invoke-Device @((New-TestBundle))
    Assert-Equal @($r.SectionResults).Count 5
    Assert-Equal @($r.SectionResults | Where-Object { $_.Key -eq 'SystemSecurity' }).Count 1
}
Test-Case 'Disabled policy suppresses section scores' {
    $r = Invoke-Device @((New-TestBundle))
    foreach ($section in $r.SectionResults) { Assert-Equal $section.Score $null }
}
Test-Case 'Incomplete assessment suppresses every section score' {
    $r = Invoke-Device @((New-TestBundle)) (New-TestPolicy -Active $true) @('WSA-SYS-001','WSA-SYS-002')
    foreach ($section in $r.SectionResults) { Assert-Equal $section.Score $null }
}
Test-Case 'Duplicate CheckId is rejected' {
    $bundles = @((New-TestBundle), (New-TestBundle))
    Assert-Throws { Invoke-Device $bundles (New-TestPolicy -Active $true) }
}
Test-Case 'Duplicate expected CheckId is rejected' {
    Assert-Throws { Invoke-Device @((New-TestBundle)) (New-TestPolicy -Active $true) @('WSA-SYS-001','WSA-SYS-001') }
}
Test-Case 'Unexpected CheckId is rejected' {
    Assert-Throws { Invoke-Device @((New-TestBundle)) (New-TestPolicy -Active $true) @('WSA-SYS-002') }
}
Test-Case 'Foreign device results cannot affect selected device score' {
    $local = New-TestBundle
    $foreign = New-TestBundle -Device 'local:FOREIGN' -Status FAIL
    $r = Invoke-Device @($local,$foreign) (New-TestPolicy -Active $true)
    Assert-Equal $r.Score 100
    Assert-Equal $r.TotalChecks 1
}
Test-Case 'Foreign scan results cannot affect selected scan score' {
    $local = New-TestBundle
    $foreign = New-TestBundle -Scan 'OTHER-SCAN' -Status FAIL
    $r = Invoke-Device @($local,$foreign) (New-TestPolicy -Active $true)
    Assert-Equal $r.Score 100
    Assert-Equal $r.ScanId 'TEST-SCAN-001'
}
Test-Case 'Score result disclaims XCCDF certification' {
    $r = Invoke-Device @((New-TestBundle))
    Assert-Equal $r.IsXCCDFCertified $false
    Assert-Equal $r.ScoringModel 'urn:xccdf:scoring:flat-unweighted'
}
Test-Case 'No evaluations produces a missing-check entry' {
    $r = Invoke-Device @() (New-TestPolicy -Active $true)
    Assert-Equal $r.Score $null
    Assert-Equal $r.NotCheckedCount 1
    Assert-Equal $r.Coverage 0
}

# ============================================================
# GROUP 5 - READ-ONLY SOURCE VALIDATION
# ============================================================

Test-Case 'Score Engine parses without PowerShell syntax errors' {
    $tokens = $null; $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:EnginePath, [ref]$tokens, [ref]$errors)
    Assert-Equal @($errors).Count 0
}
Test-Case 'Score Engine does not invoke modifying Windows commands' {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:EnginePath, [ref]$tokens, [ref]$errors)
    Assert-Equal @($errors).Count 0
    $forbidden = '^(Set-Mp|Add-Mp|Remove-Mp|Start-MpScan$|Update-MpSignature$|Set-Item|New-Item|Remove-Item|Set-Content|Add-Content|Out-File$|Set-Service|Start-Service|Stop-Service|Invoke-CimMethod$|Set-CimInstance$|Invoke-Expression$|Start-Process$|Invoke-Command$)'
    $commands = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true)
    foreach ($command in $commands) {
        $name = $command.GetCommandName()
        Assert-True (-not ($name -match $forbidden)) "Modifying command found: $name"
    }
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed
Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'SCORE ENGINE UNIT TEST SUMMARY' -ForegroundColor Cyan
Write-Host "TOTAL : $total"
Write-Host "PASS  : $script:Passed"
Write-Host "FAIL  : $script:Failed"
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''
if ($script:Failed -gt 0) { throw "$($script:Failed) Score Engine unit test(s) failed." }
Write-Host 'All Score Engine unit tests passed.' -ForegroundColor Green
