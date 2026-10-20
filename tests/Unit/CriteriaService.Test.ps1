
# ============================================================
# WinSec Analyzer
# Test Suite : Criteria Service
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit and contract tests for criteria catalog handling.
#
# Includes:
# - JSON loading and path containment
# - Corrupt and unexpected JSON input
# - Catalog structure and duplicate identifiers
# - Scoring and verification safeguards
# - Device and scan identity isolation
# - Windows edition and benchmark profile scope
# - Activation dependencies and partial selections
# - Evaluation Engine integration contract
# - Read-only source inspection
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# Synthetic approval metadata is only a test fixture.
# No live device is scanned and no security setting is changed.
# Temporary JSON test files are deleted in finally blocks.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)
$script:ServicePath = Join-Path $script:ProjectRoot 'src/Services/CriteriaService.ps1'
$script:EnginePath = Join-Path $script:ProjectRoot 'src/Core/EvaluationEngine.ps1'
$script:CatalogPath = Join-Path $script:ProjectRoot 'config/criteria/defender.json'

# ============================================================
# TEST UTILITIES
# ============================================================

function Assert-WinSecEqual {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [string]$Message = 'Values differ.'
    )

    if ($null -eq $Expected) {
        if ($null -ne $Actual) { throw "$Message Expected null; got [$Actual]." }
        return
    }

    if ($null -eq $Actual -or $Actual -cne $Expected) {
        throw "$Message Expected [$Expected]; got [$Actual]."
    }
}

function Assert-WinSecTrue {
    param([bool]$Condition, [string]$Message = 'Assertion failed.')
    if (-not $Condition) { throw $Message }
}

function Assert-WinSecThrows {
    param([scriptblock]$Action, [string]$Message = 'Expected an exception.')
    $raised = $false
    try { $null = & $Action }
    catch { $raised = $true }
    if (-not $raised) { throw $Message }
}

function Test-WinSecCase {
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

function Copy-WinSecFixture {
    param([Parameter(Mandatory)][object]$InputObject)
    return ($InputObject | ConvertTo-Json -Depth 40 | ConvertFrom-Json)
}

function New-WinSecFixtureContext {
    return [pscustomobject]@{
        DeviceId = 'local:FIXTURE-PC'
        ScanId = 'CRITERIA-TEST-001'
        OSFamily = 'Windows'
        OSRelease = '11-24H2'
        Edition = 'Pro'
        Profile = 'Level1'
    }
}

function New-WinSecFixtureControl {
    return [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:FIXTURE-PC'
        ScanId = 'CRITERIA-TEST-001'
        Status = 'INFORMATIONAL'
        Evidence = [pscustomobject]@{
            CheckId = 'WSA-SYS-001'
            DeviceId = 'local:FIXTURE-PC'
            ScanId = 'CRITERIA-TEST-001'
            CollectionSuccessful = $true
            DefenderPreferences = [pscustomobject]@{
                PUAProtection = 1
                DisableRealtimeMonitoring = $false
            }
        }
    }
}

function New-WinSecFixtureCriterion {
    param([string]$Id = 'TEST-LOCAL-001')
    return [pscustomobject]@{
        CriterionId = $Id
        CheckId = 'WSA-SYS-001'
        Area = 'ThreatProtection'
        Name = 'Synthetic PUA rule'
        EvidencePath = 'DefenderPreferences.PUAProtection'
        Operator = 'Equals'
        ExpectedValue = 1
        Approved = $true
        Recommendation = 'Test fixture only; do not apply to real devices.'
        Source = [pscustomobject]@{
            Framework = 'LOCAL_POLICY'
            Version = 'TEST-ONLY'
            ControlId = $Id
            Title = 'Synthetic test criterion'
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
        ActivationDependencies = @('active-antivirus-mode')
        FrameworkMappings = [pscustomobject]@{
            CISBenchmarks = @()
            CISControls = @()
            NISTCSF = @()
            MITREATTACK = @()
        }
    }
}

function New-WinSecFixtureCatalog {
    return [pscustomobject]@{
        CatalogId = 'WSA-TEST-CATALOG'
        CatalogVersion = '0.9.0'
        CheckId = 'WSA-SYS-001'
        Status = 'APPROVED'
        ScoringEnabled = $true
        DeviceChangesAllowed = $false
        Criteria = @((New-WinSecFixtureCriterion))
        ReviewOnly = @(
            [pscustomobject]@{
                Name = 'Synthetic information only'
                Assessment = 'REVIEW_ONLY'
                Area = 'ThreatProtection'
            }
        )
    }
}

function Invoke-WinSecFixtureSelection {
    param(
        [AllowNull()][object]$Catalog = $null,
        [AllowNull()][object]$Context = $null,
        [AllowNull()][object]$Control = $null,
        [AllowNull()][System.Collections.IDictionary]$Dependencies = $null,
        [bool]$UseDefaultDependencies = $true
    )
    if ($null -eq $Catalog) { $Catalog = New-WinSecFixtureCatalog }
    if ($null -eq $Context) { $Context = New-WinSecFixtureContext }
    if ($null -eq $Control) { $Control = New-WinSecFixtureControl }
    if ($UseDefaultDependencies -and $null -eq $Dependencies) {
        $Dependencies = @{ 'active-antivirus-mode' = $true }
    }
    return Get-WinSecApplicableCriteria `
        -Catalog $Catalog `
        -TargetContext $Context `
        -ControlResult $Control `
        -ProjectRoot $script:ProjectRoot `
        -DependencyEvidence $Dependencies
}

# ============================================================
# REQUIRED FILES
# ============================================================

Write-Host ''
Write-Host 'WinSec Analyzer - Criteria Service Unit Tests' -ForegroundColor Cyan
Write-Host ''

foreach ($path in @($script:ServicePath, $script:EnginePath, $script:CatalogPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required project file not found: $path"
    }
}

. $script:ServicePath

$script:ActualCatalog = Import-WinSecCriteriaCatalog `
    -ProjectRoot $script:ProjectRoot

# ============================================================
# GROUP 1 - LOADING AND PARSING
# ============================================================

Test-WinSecCase 'Imports the real Defender catalog' {
    Assert-WinSecEqual $script:ActualCatalog.CatalogId 'WSA-DEFENDER'
}

Test-WinSecCase 'Default relative path resolves inside project' {
    $c = Import-WinSecCriteriaCatalog -ProjectRoot $script:ProjectRoot
    Assert-WinSecEqual $c.CheckId 'WSA-SYS-001'
}

Test-WinSecCase 'Normalized in-project path is accepted' {
    $c = Import-WinSecCriteriaCatalog `
        -ProjectRoot $script:ProjectRoot `
        -RelativePath 'config/criteria/../criteria/defender.json'
    Assert-WinSecEqual $c.CatalogId 'WSA-DEFENDER'
}

Test-WinSecCase 'Absolute catalog path is rejected' {
    Assert-WinSecThrows {
        Import-WinSecCriteriaCatalog `
            -ProjectRoot $script:ProjectRoot `
            -RelativePath $script:CatalogPath
    }
}

Test-WinSecCase 'Parent-directory traversal is rejected' {
    Assert-WinSecThrows {
        Import-WinSecCriteriaCatalog `
            -ProjectRoot $script:ProjectRoot `
            -RelativePath '../outside.json'
    }
}

Test-WinSecCase 'Non-JSON extension is rejected' {
    Assert-WinSecThrows {
        Import-WinSecCriteriaCatalog `
            -ProjectRoot $script:ProjectRoot `
            -RelativePath 'config/criteria/defender.ps1'
    }
}

Test-WinSecCase 'Missing JSON file is rejected' {
    Assert-WinSecThrows {
        Import-WinSecCriteriaCatalog `
            -ProjectRoot $script:ProjectRoot `
            -RelativePath 'config/criteria/does-not-exist.json'
    }
}

Test-WinSecCase 'Corrupt JSON is rejected without script execution' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
        ('WSA-CriteriaTest-' + [guid]::NewGuid().ToString('N'))
    try {
        $null = New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop
        [System.IO.File]::WriteAllText(
            (Join-Path $tempRoot 'broken.json'),
            '{ "Criteria": [ }',
            [System.Text.Encoding]::UTF8
        )
        Assert-WinSecThrows {
            Import-WinSecCriteriaCatalog -ProjectRoot $tempRoot `
                -RelativePath 'broken.json'
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
}

Test-WinSecCase 'JSON array is rejected as catalog root' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
        ('WSA-CriteriaTest-' + [guid]::NewGuid().ToString('N'))
    try {
        $null = New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop
        [System.IO.File]::WriteAllText(
            (Join-Path $tempRoot 'array.json'),
            '[{"CatalogId":"ARRAY"}]',
            [System.Text.Encoding]::UTF8
        )
        Assert-WinSecThrows {
            Import-WinSecCriteriaCatalog -ProjectRoot $tempRoot `
                -RelativePath 'array.json'
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
}

# ============================================================
# GROUP 2 - REAL DRAFT CATALOG
# ============================================================

Test-WinSecCase 'Real catalog is structurally valid' {
    $v = Test-WinSecCriteriaCatalog -Catalog $script:ActualCatalog
    Assert-WinSecEqual $v.Valid $true
    Assert-WinSecEqual @($v.Errors).Count 0
}

Test-WinSecCase 'Real catalog has twenty candidate criteria' {
    $v = Test-WinSecCriteriaCatalog -Catalog $script:ActualCatalog
    Assert-WinSecEqual $v.CriteriaCount 20
}

Test-WinSecCase 'Real catalog preserves fourteen review-only entries' {
    $v = Test-WinSecCriteriaCatalog -Catalog $script:ActualCatalog
    Assert-WinSecEqual $v.ReviewOnlyCount 14
}

Test-WinSecCase 'Real draft does not qualify for scoring' {
    $v = Test-WinSecCriteriaCatalog -Catalog $script:ActualCatalog
    Assert-WinSecEqual $v.Status 'DRAFT_UNAPPROVED'
    Assert-WinSecEqual $v.ReadyForScoring $false
}

Test-WinSecCase 'Real draft selection is blocked' {
    $r = Invoke-WinSecFixtureSelection -Catalog $script:ActualCatalog
    Assert-WinSecEqual $r.Status 'DRAFT_BLOCKED'
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

Test-WinSecCase 'Draft selection retains review-only observations' {
    $r = Invoke-WinSecFixtureSelection -Catalog $script:ActualCatalog
    Assert-WinSecEqual @($r.ReviewOnly).Count 14
}

# ============================================================
# GROUP 3 - STRUCTURAL VALIDATION
# ============================================================

Test-WinSecCase 'Synthetic approved catalog is structurally valid' {
    $v = Test-WinSecCriteriaCatalog -Catalog (New-WinSecFixtureCatalog)
    Assert-WinSecEqual $v.Valid $true
    Assert-WinSecEqual $v.ReadyForScoring $true
}

Test-WinSecCase 'Missing CatalogId is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.CatalogId = ''
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Missing CheckId is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.CheckId = ''
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Missing catalog version is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.CatalogVersion = ''
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Unsupported catalog status is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.Status = 'TRUST_ME'
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Non-Boolean scoring flag is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.ScoringEnabled = 'true'
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Device modification permission is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.DeviceChangesAllowed = $true
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Draft catalog cannot enable scoring' {
    $c = New-WinSecFixtureCatalog
    $c.Status = 'DRAFT_UNAPPROVED'
    $c.ScoringEnabled = $true
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Criteria must be a nonempty array' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria = @()
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Duplicate criterion identifiers are rejected' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria = @(
        (New-WinSecFixtureCriterion -Id 'REPEAT'),
        (New-WinSecFixtureCriterion -Id 'REPEAT')
    )
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Case-insensitive duplicate identifiers are rejected' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria = @(
        (New-WinSecFixtureCriterion -Id 'Repeat'),
        (New-WinSecFixtureCriterion -Id 'repeat')
    )
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Cross-check criterion identity is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria[0].CheckId = 'WSA-SYS-999'
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'PowerShell expression in evidence path is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria[0].EvidencePath = 'DefenderPreferences.$(Get-Process)'
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Unsupported operator is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria[0].Operator = 'Invoke'
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Missing recommendation is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria[0].Recommendation = ''
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Missing source version is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria[0].Source.Version = ''
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Missing OS edition scope is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria[0].Applicability.Edition = ''
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Missing framework mapping array is rejected' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria[0].FrameworkMappings.MITREATTACK = $null
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Review-only entry cannot use PASS status' {
    $c = New-WinSecFixtureCatalog
    $c.ReviewOnly[0].Assessment = 'PASS'
    Assert-WinSecEqual (Test-WinSecCriteriaCatalog $c).Valid $false
}

Test-WinSecCase 'Invalid catalog never releases criteria' {
    $c = New-WinSecFixtureCatalog
    $c.Criteria[0].Operator = 'Execute'
    $r = Invoke-WinSecFixtureSelection -Catalog $c
    Assert-WinSecEqual $r.Status 'BLOCKED'
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

# ============================================================
# GROUP 4 - SELECTION, IDENTITY AND PREREQUISITES
# ============================================================

Test-WinSecCase 'Complete synthetic fixture can be selected' {
    $r = Invoke-WinSecFixtureSelection
    Assert-WinSecEqual $r.Status 'READY'
    Assert-WinSecEqual $r.ScoringEligible $true
    Assert-WinSecEqual @($r.EligibleCriteria).Count 1
    Assert-WinSecEqual $r.DeviceId 'local:FIXTURE-PC'
    Assert-WinSecEqual $r.ScanId 'CRITERIA-TEST-001'
}

Test-WinSecCase 'Review-only observations stay outside selected criteria' {
    $r = Invoke-WinSecFixtureSelection
    Assert-WinSecEqual @($r.ReviewOnly).Count 1
    Assert-WinSecEqual @($r.EligibleCriteria).Count 1
}

Test-WinSecCase 'Control CheckId mismatch is blocked' {
    $control = New-WinSecFixtureControl
    $control.CheckId = 'WSA-SYS-999'
    $r = Invoke-WinSecFixtureSelection -Control $control
    Assert-WinSecEqual $r.Status 'BLOCKED'
}

Test-WinSecCase 'Collector ERROR is blocked' {
    $control = New-WinSecFixtureControl
    $control.Status = 'ERROR'
    $r = Invoke-WinSecFixtureSelection -Control $control
    Assert-WinSecEqual $r.Status 'BLOCKED'
}

Test-WinSecCase 'Unsuccessful collection is blocked' {
    $control = New-WinSecFixtureControl
    $control.Evidence.CollectionSuccessful = $false
    $r = Invoke-WinSecFixtureSelection -Control $control
    Assert-WinSecEqual $r.Status 'BLOCKED'
}

Test-WinSecCase 'Evidence from another device is blocked' {
    $control = New-WinSecFixtureControl
    $control.Evidence.DeviceId = 'local:FOREIGN-PC'
    $r = Invoke-WinSecFixtureSelection -Control $control
    Assert-WinSecEqual $r.Status 'BLOCKED'
}

Test-WinSecCase 'Evidence from another scan is blocked' {
    $control = New-WinSecFixtureControl
    $control.Evidence.ScanId = 'OTHER-SCAN'
    $r = Invoke-WinSecFixtureSelection -Control $control
    Assert-WinSecEqual $r.Status 'BLOCKED'
}

Test-WinSecCase 'Evidence with another CheckId is blocked' {
    $control = New-WinSecFixtureControl
    $control.Evidence.CheckId = 'WSA-SYS-999'
    $r = Invoke-WinSecFixtureSelection -Control $control
    Assert-WinSecEqual $r.Status 'BLOCKED'
}

Test-WinSecCase 'Target context from another device is blocked' {
    $context = New-WinSecFixtureContext
    $context.DeviceId = 'local:FOREIGN-PC'
    $r = Invoke-WinSecFixtureSelection -Context $context
    Assert-WinSecEqual $r.Status 'BLOCKED'
}

Test-WinSecCase 'Target context from another scan is blocked' {
    $context = New-WinSecFixtureContext
    $context.ScanId = 'OTHER-SCAN'
    $r = Invoke-WinSecFixtureSelection -Context $context
    Assert-WinSecEqual $r.Status 'BLOCKED'
}

Test-WinSecCase 'Pending OS release blocks selection' {
    $context = New-WinSecFixtureContext
    $context.OSRelease = 'PENDING_SELECTION'
    $r = Invoke-WinSecFixtureSelection -Context $context
    Assert-WinSecEqual $r.Status 'BLOCKED'
}

Test-WinSecCase 'Wildcard profile blocks selection' {
    $context = New-WinSecFixtureContext
    $context.Profile = '*'
    $r = Invoke-WinSecFixtureSelection -Context $context
    Assert-WinSecEqual $r.Status 'BLOCKED'
}

Test-WinSecCase 'Different Windows release is not eligible' {
    $context = New-WinSecFixtureContext
    $context.OSRelease = '10-22H2'
    $r = Invoke-WinSecFixtureSelection -Context $context
    Assert-WinSecEqual $r.Status 'NO_ELIGIBLE_CRITERIA'
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual $r.ExcludedCriteria[0].Reason 'WINDOWS_SCOPE_MISMATCH'
}

Test-WinSecCase 'Different benchmark profile is not eligible' {
    $context = New-WinSecFixtureContext
    $context.Profile = 'Level2'
    $r = Invoke-WinSecFixtureSelection -Context $context
    Assert-WinSecEqual $r.Status 'NO_ELIGIBLE_CRITERIA'
}

Test-WinSecCase 'Different Windows edition is not eligible' {
    $context = New-WinSecFixtureContext
    $context.Edition = 'Enterprise'
    $r = Invoke-WinSecFixtureSelection -Context $context
    Assert-WinSecEqual $r.Status 'NO_ELIGIBLE_CRITERIA'
}

Test-WinSecCase 'Missing dependency evidence prevents selection' {
    $r = Invoke-WinSecFixtureSelection -UseDefaultDependencies $false
    Assert-WinSecEqual $r.Status 'NO_ELIGIBLE_CRITERIA'
    Assert-WinSecEqual $r.ScoringEligible $false
}

Test-WinSecCase 'False dependency prevents selection' {
    $r = Invoke-WinSecFixtureSelection `
        -Dependencies @{ 'active-antivirus-mode' = $false }
    Assert-WinSecEqual $r.Status 'NO_ELIGIBLE_CRITERIA'
}

Test-WinSecCase 'Textual true is not accepted as Boolean proof' {
    $r = Invoke-WinSecFixtureSelection `
        -Dependencies @{ 'active-antivirus-mode' = 'true' }
    Assert-WinSecEqual $r.Status 'NO_ELIGIBLE_CRITERIA'
}

Test-WinSecCase 'Unrecognized dependency name prevents selection' {
    $r = Invoke-WinSecFixtureSelection `
        -Dependencies @{ 'other-prerequisite' = $true }
    Assert-WinSecEqual $r.Status 'NO_ELIGIBLE_CRITERIA'
}

Test-WinSecCase 'Missing declared dependencies prevents selection' {
    $catalog = New-WinSecFixtureCatalog
    $catalog.Criteria[0].ActivationDependencies = @()
    $r = Invoke-WinSecFixtureSelection -Catalog $catalog
    Assert-WinSecEqual $r.Status 'NO_ELIGIBLE_CRITERIA'
}

Test-WinSecCase 'Unapproved criterion cannot be selected' {
    $catalog = New-WinSecFixtureCatalog
    $catalog.Criteria[0].Approved = $false
    $r = Invoke-WinSecFixtureSelection -Catalog $catalog
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

Test-WinSecCase 'Unverified criterion cannot be selected' {
    $catalog = New-WinSecFixtureCatalog
    $catalog.Criteria[0].Verification.Status = 'PENDING'
    $r = Invoke-WinSecFixtureSelection -Catalog $catalog
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

Test-WinSecCase 'Context mismatch plus applicable rule blocks partial score' {
    $catalog = New-WinSecFixtureCatalog
    $second = New-WinSecFixtureCriterion -Id 'TEST-LOCAL-002'
    $second.Applicability.Edition = 'Enterprise'
    $catalog.Criteria = @($catalog.Criteria[0], $second)
    $r = Invoke-WinSecFixtureSelection -Catalog $catalog
    Assert-WinSecEqual $r.Status 'PARTIAL_SELECTION_BLOCKED'
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
    Assert-WinSecEqual $r.MatchedCriteriaCount 1
}

Test-WinSecCase 'Unverified rule blocks otherwise valid selection' {
    $catalog = New-WinSecFixtureCatalog
    $second = New-WinSecFixtureCriterion -Id 'TEST-LOCAL-002'
    $second.Approved = $false
    $catalog.Criteria = @($catalog.Criteria[0], $second)
    $r = Invoke-WinSecFixtureSelection -Catalog $catalog
    Assert-WinSecEqual $r.Status 'PARTIAL_SELECTION_BLOCKED'
    Assert-WinSecEqual $r.ScoringEligible $false
    Assert-WinSecEqual @($r.EligibleCriteria).Count 0
}

# ============================================================
# GROUP 5 - REGRESSION: CATALOG APPROVAL GATE
# ============================================================

Test-WinSecCase 'APPROVED label cannot override an unapproved criterion' {
    $catalog = New-WinSecFixtureCatalog
    $catalog.Criteria[0].Approved = $false
    $v = Test-WinSecCriteriaCatalog -Catalog $catalog
    Assert-WinSecEqual $v.ReadyForScoring $false `
        'ReadyForScoring must require approved individual criteria.'
}

# ============================================================
# GROUP 6 - STATIC READ-ONLY VALIDATION
# ============================================================

Test-WinSecCase 'Criteria Service parses without errors' {
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:ServicePath, [ref]$tokens, [ref]$errors
    )
    Assert-WinSecEqual @($errors).Count 0
}

Test-WinSecCase 'Criteria Service does not call modifying commands' {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:ServicePath, [ref]$tokens, [ref]$errors
    )
    Assert-WinSecEqual @($errors).Count 0
    $forbidden = '^(Set-Mp|Add-Mp|Remove-Mp|Start-MpScan$|Update-MpSignature$|Set-Item|New-Item|Remove-Item|Set-Content|Add-Content|Out-File$|Set-Service|Start-Service|Stop-Service|Invoke-CimMethod$|Set-CimInstance$|Invoke-Expression$|Start-Process$|Invoke-Command$)'
    $commands = $ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        },
        $true
    )
    foreach ($command in $commands) {
        $name = $command.GetCommandName()
        Assert-WinSecTrue (-not ($name -match $forbidden)) `
            "Potentially modifying command in Criteria Service: $name"
    }
}

# ============================================================
# TEST SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed
Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'CRITERIA SERVICE UNIT TEST SUMMARY' -ForegroundColor Cyan
Write-Host "TOTAL : $total"
Write-Host "PASS  : $script:Passed"
Write-Host "FAIL  : $script:Failed"
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''

if ($script:Failed -gt 0) {
    throw "$($script:Failed) Criteria Service unit test(s) failed."
}

Write-Host 'All Criteria Service unit tests passed.' -ForegroundColor Green
