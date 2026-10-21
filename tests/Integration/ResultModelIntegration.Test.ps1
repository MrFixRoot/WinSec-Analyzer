
# ============================================================
# WinSec Analyzer
# Test Suite : Result Model Integration
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Verifies ResultModel integration with the existing
# security evaluation and findings pipeline.
#
# Includes:
# - CriteriaService -> EvaluationEngine
# - EvaluationEngine -> FindingsEngine
# - EvaluationEngine -> ScoreEngine
# - Authorized and unauthorized scoring
# - Device and scan identity protection
# - Real Defender draft catalog protection
# - Safe public results
# - Configuration integrity
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# Synthetic criteria are TEST FIXTURES only.
# No Windows settings are modified.
# Production scoring remains disabled.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

$script:Paths = [ordered]@{
    Model = Join-Path $script:ProjectRoot `
        'src/Core/ResultModel.ps1'

    Evaluation = Join-Path $script:ProjectRoot `
        'src/Core/EvaluationEngine.ps1'

    Findings = Join-Path $script:ProjectRoot `
        'src/Core/FindingsEngine.ps1'

    Score = Join-Path $script:ProjectRoot `
        'src/Core/ScoreEngine.ps1'

    Criteria = Join-Path $script:ProjectRoot `
        'src/Services/CriteriaService.ps1'

    ScoringConfig = Join-Path $script:ProjectRoot `
        'config/scoring.json'

    DefenderCatalog = Join-Path $script:ProjectRoot `
        'config/criteria/defender.json'
}

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
            throw "$Message Expected null; got [$Actual]."
        }
        return
    }

    if ($null -eq $Actual -or $Actual -cne $Expected) {
        throw "$Message Expected [$Expected]; got [$Actual]."
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

function Assert-Throws {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    $threw = $false

    try {
        $null = & $Action
    }
    catch {
        $threw = $true
    }

    if (-not $threw) {
        throw 'Expected an exception.'
    }
}

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
            "[FAIL] {0} - {1}" -f $Name, $_.Exception.Message
        ) -ForegroundColor Red

        if ($_.ScriptStackTrace) {
            Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
        }
    }
}

function Copy-Fixture {
    param([Parameter(Mandatory)][object]$Value)

    return (
        $Value |
        ConvertTo-Json -Depth 40 |
        ConvertFrom-Json
    )
}

# ============================================================
# SYNTHETIC CRITERIA / COLLECTOR
# ============================================================

function New-IntegrationBundle {
    param(
        [int]$PUA = 1,
        [string]$DeviceId = 'local:INTEGRATION-PC',
        [string]$ScanId = 'RESULT-INTEGRATION-001'
    )

    $criterion = [pscustomobject]@{
        CriterionId = 'TEST-LOCAL-001'
        CheckId = 'WSA-SYS-001'

        Area = 'ThreatProtection'
        Name = 'Synthetic PUA criterion'

        EvidencePath = 'DefenderPreferences.PUAProtection'
        Operator = 'Equals'
        ExpectedValue = 1

        Approved = $true

        Recommendation = (
            'Synthetic test recommendation only.'
        )

        Source = [pscustomobject]@{
            Framework = 'LOCAL_POLICY'
            Version = 'TEST-ONLY'
            ControlId = 'TEST-LOCAL-001'
            Title = 'Synthetic criterion'
            Url = 'https://example.invalid/test'
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

        ActivationDependencies = @(
            'active-antivirus-mode'
        )

        FrameworkMappings = [pscustomobject]@{
            CISBenchmarks = @()
            CISControls = @()
            NISTCSF = @()
            MITREATTACK = @()
        }
    }

    $catalog = [pscustomobject]@{
        CatalogId = 'RESULT-INTEGRATION-TEST'
        CatalogVersion = '0.9.0'
        CheckId = 'WSA-SYS-001'

        Status = 'APPROVED'
        ScoringEnabled = $true
        DeviceChangesAllowed = $false

        Criteria = @($criterion)
        ReviewOnly = @()
    }

    $collector = [pscustomobject]@{
        DeviceId = $DeviceId
        ScanId = $ScanId
        CheckId = 'WSA-SYS-001'

        SectionKey = 'SystemSecurity'
        Status = 'INFORMATIONAL'

        Evidence = [pscustomobject]@{
            DeviceId = $DeviceId
            ScanId = $ScanId
            CheckId = 'WSA-SYS-001'

            CollectionSuccessful = $true

            DefenderPreferences = [pscustomobject]@{
                PUAProtection = $PUA
            }

            SecretTestValue = (
                'INTEGRATION_SECRET_DO_NOT_EXPORT'
            )
        }
    }

    $context = [pscustomobject]@{
        DeviceId = $DeviceId
        ScanId = $ScanId

        OSFamily = 'Windows'
        OSRelease = '11-24H2'
        Edition = 'Pro'
        Profile = 'Level1'
    }

    $selection = Get-WinSecApplicableCriteria `
        -Catalog $catalog `
        -TargetContext $context `
        -ControlResult $collector `
        -ProjectRoot $script:ProjectRoot `
        -DependencyEvidence @{
            'active-antivirus-mode' = $true
        }

    $evaluation = Invoke-WinSecControlEvaluation `
        -ControlResult $collector `
        -Criteria $selection.EligibleCriteria `
        -TargetContext $context

    return [pscustomobject]@{
        Catalog = $catalog
        Collector = $collector
        Context = $context
        Selection = $selection
        Evaluation = $evaluation
    }
}

# ============================================================
# RESULT PIPELINE
# ============================================================

function New-IntegratedSession {
    param(
        [Parameter(Mandatory)]
        [object]$Bundle,

        [Parameter(Mandatory)]
        [object]$Policy,

        [string[]]$ExpectedCheckIds = @('WSA-SYS-001'),

        [AllowNull()]
        [object]$ScoreResult = $null,

        [hashtable]$Scope = @{}
    )

    $findingResult = ConvertTo-WinSecFindings `
        -EvaluationResult $Bundle.Evaluation `
        -ControlResult $Bundle.Collector `
        -SelectionResult $Bundle.Selection `
        -IncludeReviewOnly

    return New-WinSecResultSession `
        -DeviceId $Bundle.Collector.DeviceId `
        -ScanId $Bundle.Collector.ScanId `
        -CollectionMode 'LOCAL' `
        -StartedAtUTC '2026-01-01T00:00:00Z' `
        -CompletedAtUTC '2026-01-01T00:01:00Z' `
        -ExecutionStatus 'COMPLETED' `
        -ExpectedCheckIds $ExpectedCheckIds `
        -ControlResults @($Bundle.Collector) `
        -EvaluationResults @($Bundle.Evaluation) `
        -CriteriaSelections @($Bundle.Selection) `
        -Findings @($findingResult.Findings) `
        -ReviewItems @($findingResult.ReviewItems) `
        -ScoringPolicy $Policy `
        -ScoreResult $ScoreResult @Scope
}

# ============================================================
# INITIALIZATION
# ============================================================

Write-Host ''
Write-Host 'WinSec Analyzer - Result Model Integration Tests' `
    -ForegroundColor Cyan
Write-Host ''

foreach ($path in $script:Paths.Values) {
    if (-not (
        Test-Path -LiteralPath $path -PathType Leaf
    )) {
        throw "Missing integration dependency: $path"
    }
}

$script:ScoringHashBefore = (
    Get-FileHash `
        -LiteralPath $script:Paths.ScoringConfig `
        -Algorithm SHA256
).Hash

$script:CatalogHashBefore = (
    Get-FileHash `
        -LiteralPath $script:Paths.DefenderCatalog `
        -Algorithm SHA256
).Hash

. $script:Paths.Evaluation
. $script:Paths.Criteria
. $script:Paths.Findings
. $script:Paths.Score
. $script:Paths.Model

$script:RealPolicy = Get-WinSecScoringPolicy

$script:TestPolicy = Copy-Fixture $script:RealPolicy
$script:TestPolicy.enabled = $true
$script:TestPolicy.activationStatus = 'ACTIVE'

$script:DraftCatalog = Import-WinSecCriteriaCatalog `
    -ProjectRoot $script:ProjectRoot

# ============================================================
# GROUP 1: CONTRACTS
# ============================================================

Test-Case 'All integration functions are available' {
    foreach ($name in @(
        'Get-WinSecApplicableCriteria'
        'Invoke-WinSecControlEvaluation'
        'ConvertTo-WinSecFindings'
        'Get-WinSecSecurityScore'
        'New-WinSecResultSession'
        'Test-WinSecResultSession'
        'ConvertTo-WinSecPublicScanResult'
    )) {
        Assert-True (
            $null -ne (
                Get-Command $name -ErrorAction SilentlyContinue
            )
        ) "Missing function: $name"
    }
}

Test-Case 'Production scoring policy remains disabled' {
    Assert-Equal $script:RealPolicy.enabled $false

    Assert-Equal (
        $script:RealPolicy.activationStatus
    ) 'PENDING_APPROVED_CRITERIA'
}

Test-Case 'Synthetic policy is activated in memory only' {
    Assert-Equal (
        Test-WinSecScoringPolicy -Policy $script:TestPolicy
    ) $true

    Assert-Equal $script:RealPolicy.enabled $false
}

# ============================================================
# GROUP 2: FULL SYNTHETIC PIPELINE
# ============================================================

Test-Case 'Approved synthetic criteria are selected' {
    $bundle = New-IntegrationBundle

    Assert-Equal $bundle.Selection.Status 'READY'
    Assert-Equal $bundle.Selection.ScoringEligible $true
}

Test-Case 'Synthetic PASS reaches ResultModel' {
    $bundle = New-IntegrationBundle -PUA 1

    Assert-Equal $bundle.Evaluation.Status 'PASS'

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:TestPolicy

    Assert-Equal (
        Test-WinSecResultSession -Session $session
    ) $true

    Assert-Equal $session.OverallScore 100
    Assert-Equal $session.OverallStatus 'COMPLETE'
    Assert-Equal $session.ScoringEligible $true
}

Test-Case 'Synthetic FAIL reaches ResultModel' {
    $bundle = New-IntegrationBundle -PUA 0

    Assert-Equal $bundle.Evaluation.Status 'FAIL'

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:TestPolicy

    Assert-Equal $session.OverallScore 0
    Assert-Equal $session.OverallCoverage 100
}

Test-Case 'Failed criterion remains a finding' {
    $bundle = New-IntegrationBundle -PUA 0

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:TestPolicy

    $deviations = @(
        $session.Findings | Where-Object {
            $_.Kind -ceq 'CONFIGURATION_DEVIATION'
        }
    )

    Assert-Equal $deviations.Count 1
    Assert-Equal $deviations[0].CheckId 'WSA-SYS-001'
}

Test-Case 'Completed scan retains execution identity' {
    $bundle = New-IntegrationBundle

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:TestPolicy

    Assert-Equal $session.DeviceId $bundle.Collector.DeviceId
    Assert-Equal $session.ScanId $bundle.Collector.ScanId
    Assert-Equal $session.ExecutionStatus 'COMPLETED'
    Assert-Equal $session.DurationSeconds 60
}

# ============================================================
# GROUP 3: SCORING SAFEGUARDS
# ============================================================

Test-Case 'Disabled policy returns NOT_SCORED' {
    $bundle = New-IntegrationBundle

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:RealPolicy

    Assert-Equal $session.OverallScore $null
    Assert-Equal $session.OverallStatus 'NOT_SCORED'
    Assert-Equal $session.ScoringEligible $false
}

Test-Case 'Incomplete expected scope cannot be scored' {
    $bundle = New-IntegrationBundle

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:TestPolicy `
        -ExpectedCheckIds @(
            'WSA-SYS-001',
            'WSA-SYS-002'
        )

    Assert-Equal $session.OverallScore $null
    Assert-Equal $session.OverallStatus 'NOT_SCORED'
    Assert-Equal $session.OverallCoverage 50
}

Test-Case 'Altered criterion source cannot be scored' {
    $bundle = New-IntegrationBundle

    $bundle.Evaluation.Evaluations[0].
        Source.ControlId = 'FORGED-ID'

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:TestPolicy

    Assert-Equal $session.OverallScore $null
    Assert-Equal $session.ScoringEligible $false
}

Test-Case 'Forged ScoreResult cannot replace calculation' {
    $bundle = New-IntegrationBundle

    $forged = [pscustomobject]@{
        DeviceId = $bundle.Collector.DeviceId
        ScanId = $bundle.Collector.ScanId

        Score = 75
        Status = 'COMPLETE'
        AssessmentStatus = 'COMPLETE'
        ScoringEligible = $true
    }

    Assert-Throws {
        New-IntegratedSession `
            -Bundle $bundle `
            -Policy $script:TestPolicy `
            -ScoreResult $forged
    }
}

Test-Case 'Score mutation invalidates existing session' {
    $bundle = New-IntegrationBundle

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:TestPolicy

    $session.OverallScore = 73

    Assert-Equal (
        Test-WinSecResultSession -Session $session
    ) $false
}

# ============================================================
# GROUP 4: DEVICE AND SCAN ISOLATION
# ============================================================

Test-Case 'Collector from another scan is rejected' {
    $bundle = New-IntegrationBundle

    $bundle.Collector.ScanId = 'FOREIGN-SCAN'

    Assert-Throws {
        New-WinSecResultSession `
            -DeviceId $bundle.Evaluation.DeviceId `
            -ScanId $bundle.Evaluation.ScanId `
            -ControlResults @($bundle.Collector) `
            -EvaluationResults @($bundle.Evaluation)
    }
}

Test-Case 'Different devices produce independent sessions' {
    $a = New-IntegrationBundle `
        -DeviceId 'local:PC-A' `
        -ScanId 'SCAN-A'

    $b = New-IntegrationBundle `
        -DeviceId 'local:PC-B' `
        -ScanId 'SCAN-B'

    $sessionA = New-IntegratedSession `
        -Bundle $a `
        -Policy $script:TestPolicy

    $sessionB = New-IntegratedSession `
        -Bundle $b `
        -Policy $script:TestPolicy

    Assert-Equal $sessionA.DeviceId 'local:PC-A'
    Assert-Equal $sessionB.DeviceId 'local:PC-B'

    Assert-True (
        $sessionA.ScanId -cne $sessionB.ScanId
    )
}

# ============================================================
# GROUP 5: PUBLIC EXPORT SAFETY
# ============================================================

Test-Case 'Public output excludes collector secrets' {
    $bundle = New-IntegrationBundle

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:RealPolicy

    $public = ConvertTo-WinSecPublicScanResult `
        -Session $session

    $json = $public | ConvertTo-Json -Depth 40

    Assert-True (
        -not $json.Contains(
            'INTEGRATION_SECRET_DO_NOT_EXPORT'
        )
    ) 'Sensitive evidence leaked into public output.'

    Assert-Equal $public.ContainsRawEvidence $false
}

Test-Case 'Public PASS score requires authorization' {
    $bundle = New-IntegrationBundle -PUA 1

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:TestPolicy

    $public = ConvertTo-WinSecPublicScanResult `
        -Session $session

    Assert-Equal $public.OverallScore 100
    Assert-Equal $public.ScoringEligible $true
}

Test-Case 'Sections without evaluated controls never inherit overall COMPLETE' {
    $bundle = New-IntegrationBundle
    $session = New-IntegratedSession -Bundle $bundle -Policy $script:TestPolicy
    $public = ConvertTo-WinSecPublicScanResult $session
    Assert-Equal $public.OverallStatus 'COMPLETE'
    Assert-Equal @($public.SectionResults | Where-Object { $_.Key -ceq 'SystemSecurity' })[0].Status 'COMPLETE'
    foreach ($section in @($public.SectionResults | Where-Object { $_.Key -cne 'SystemSecurity' })) {
        Assert-Equal $section.Status 'NOT_SCORED'
        Assert-Equal $section.Score $null
    }
}

foreach ($mutation in @('SCORE','COVERAGE','STATUS','DEVICE','SCAN','DUPLICATE','MISSING')) {
    Test-Case ('Section summary mutation rejects before public export: '+$mutation) {
        $bundle = New-IntegrationBundle
        $session = New-IntegratedSession -Bundle $bundle -Policy $script:TestPolicy
        switch ($mutation) {
            'SCORE' { $session.SectionResults[0].Score=73 }
            'COVERAGE' { $session.SectionResults[0].Coverage=[pscustomobject]@{Evidence='PRIVATE-SECTION-MARKER'} }
            'STATUS' { $session.SectionResults[0].Status='NOT_SCORED' }
            'DEVICE' { $session.SectionResults[0].DeviceId='local:FOREIGN' }
            'SCAN' { $session.SectionResults[0].ScanId='foreign-scan' }
            'DUPLICATE' { $session.SectionResults+= $session.SectionResults[0] }
            'MISSING' { $session.SectionResults=@($session.SectionResults | Select-Object -Skip 1) }
        }
        Assert-Equal (Test-WinSecResultSession $session) $false
        Assert-Throws { ConvertTo-WinSecPublicScanResult $session }
    }
}

Test-Case 'Public FAIL finding has no invented severity' {
    $bundle = New-IntegrationBundle -PUA 0

    $session = New-IntegratedSession `
        -Bundle $bundle `
        -Policy $script:TestPolicy

    $public = ConvertTo-WinSecPublicScanResult `
        -Session $session

    Assert-True (
        @($public.Findings).Count -gt 0
    )

    Assert-Equal $public.Findings[0].Severity 'UNASSIGNED'
    Assert-Equal $public.Findings[0].Priority 'UNASSIGNED'
}

# ============================================================
# GROUP 6: REAL DEFENDER DRAFT CATALOG
# ============================================================

Test-Case 'Real Defender catalog is still unapproved' {
    $validation = Test-WinSecCriteriaCatalog `
        -Catalog $script:DraftCatalog

    Assert-Equal $validation.Status 'DRAFT_UNAPPROVED'
    Assert-Equal $validation.ReadyForScoring $false
}

Test-Case 'Real draft catalog blocks synthetic evidence' {
    $bundle = New-IntegrationBundle

    $selection = Get-WinSecApplicableCriteria `
        -Catalog $script:DraftCatalog `
        -TargetContext $bundle.Context `
        -ControlResult $bundle.Collector `
        -ProjectRoot $script:ProjectRoot

    Assert-Equal $selection.Status 'DRAFT_BLOCKED'
    Assert-Equal $selection.ScoringEligible $false
    Assert-Equal @($selection.EligibleCriteria).Count 0
}

# ============================================================
# GROUP 7: EXPLICIT RESULT SCOPES
# ============================================================

foreach ($scope in @(
    @{ScopeType='DEVICE';ScopeKey='ALL'},
    @{ScopeType='SECTION';ScopeKey='SystemSecurity'},
    @{ScopeType='CONTROL';ScopeKey='WSA-SYS-001'}
)) {
    Test-Case ('Evaluation and findings retain public scope without production scoring: '+$scope.ScopeType) {
        $bundle = New-IntegrationBundle -PUA 0
        $session = New-IntegratedSession -Bundle $bundle -Policy $script:RealPolicy -Scope $scope
        $public = ConvertTo-WinSecPublicScanResult -Session $session
        Assert-True (Test-WinSecResultSession $session)
        Assert-Equal $public.ScopeType $scope.ScopeType
        Assert-Equal $public.ScopeKey $scope.ScopeKey
        Assert-Equal $public.OverallStatus 'NOT_SCORED'
        Assert-Equal $public.OverallScore $null
        Assert-Equal $public.Findings.Count 1
        Assert-Equal $public.Findings[0].CheckId 'WSA-SYS-001'
        Assert-True ((ConvertTo-Json -InputObject $public -Depth 30) -notmatch 'INTEGRATION_SECRET_DO_NOT_EXPORT|"Evidence"')
    }
}

Test-Case 'Evaluation pipeline cannot relabel a result as another section or control' {
    $bundle = New-IntegrationBundle
    foreach ($scope in @(
        @{ScopeType='SECTION';ScopeKey='NetworkSecurity'},
        @{ScopeType='CONTROL';ScopeKey='WSA-SYS-002'}
    )) {
        Assert-Throws { New-IntegratedSession -Bundle $bundle -Policy $script:RealPolicy -Scope $scope }
    }
}

# ============================================================
# GROUP 8: CONFIGURATION INTEGRITY
# ============================================================

Test-Case 'Scoring config remains unchanged' {
    $after = (
        Get-FileHash `
            -LiteralPath $script:Paths.ScoringConfig `
            -Algorithm SHA256
    ).Hash

    Assert-Equal $after $script:ScoringHashBefore
}

Test-Case 'Defender catalog remains unchanged' {
    $after = (
        Get-FileHash `
            -LiteralPath $script:Paths.DefenderCatalog `
            -Algorithm SHA256
    ).Hash

    Assert-Equal $after $script:CatalogHashBefore
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray

Write-Host 'RESULT MODEL INTEGRATION TEST SUMMARY' `
    -ForegroundColor Cyan

Write-Host "TOTAL : $total"
Write-Host "PASS  : $($script:Passed)" -ForegroundColor Green

Write-Host "FAIL  : $($script:Failed)" -ForegroundColor $(
    if ($script:Failed -gt 0) { 'Red' } else { 'Green' }
)

Write-Host ('=' * 60) -ForegroundColor DarkGray

if ($script:Failed -gt 0) {
    throw "$($script:Failed) ResultModel integration test(s) failed."
}

Write-Host 'All ResultModel integration tests passed.' `
    -ForegroundColor Green
