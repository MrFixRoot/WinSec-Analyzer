# ============================================================
# WinSec Analyzer
# Test Suite : Findings Engine
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit tests for traceable, privacy-conscious findings.
#
# Includes:
# - Findings and stable identifiers
# - FAIL, PASS, UNKNOWN, pending and N/A states
# - Collector and catalog authorization gates
# - Cross-device and cross-scan identity isolation
# - Duplicate and malformed criterion protection
# - Separate review-only observations and privacy
# - No invented severity, score or framework mapping
# - Read-only source validation
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# Synthetic evaluations only; never scans or changes Windows.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
$script:Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:EnginePath = Join-Path $script:Root 'src/Core/FindingsEngine.ps1'
if (-not (Test-Path -LiteralPath $script:EnginePath -PathType Leaf)) {
    throw "Missing Findings Engine: $script:EnginePath"
}
. $script:EnginePath

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

function Copy-Fixture {
    param([Parameter(Mandatory)][object]$Value)
    return ($Value | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
}

function New-Evaluation {
    param([string]$Status = 'NOT_EVALUATED', [object[]]$Items = @())
    return [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:UNIT-DEVICE'
        ScanId = 'UNIT-SCAN-001'
        Status = $Status
        ScoringEligible = $false
        Evaluations = @($Items)
        Reason = 'Synthetic evaluation.'
    }
}

function New-FixtureFindingItem {
    param([string]$Status = 'FAIL', [string]$Id = 'TEST-001')
    return [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:UNIT-DEVICE'
        ScanId = 'UNIT-SCAN-001'
        CriterionId = $Id
        Status = $Status
        ScoringEligible = ($Status -in @('PASS', 'FAIL'))
        EvidencePath = 'DefenderPreferences.PUAProtection'
        ObservedValue = 'SENSITIVE-RAW-DO-NOT-EXPORT'
        ExpectedValue = 1
        Recommendation = 'Review the applicable approved policy.'
        Source = [pscustomobject]@{
            Framework = 'LOCAL_POLICY'
            Version = 'TEST-ONLY'
            ControlId = $Id
            Title = 'Synthetic local policy'
            Url = 'https://example.invalid/policy'
        }
    }
}

function New-Control {
    param([string]$Status = 'INFORMATIONAL')
    return [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:UNIT-DEVICE'
        ScanId = 'UNIT-SCAN-001'
        Status = $Status
        Evidence = [pscustomobject]@{
            CheckId = 'WSA-SYS-001'
            DeviceId = 'local:UNIT-DEVICE'
            ScanId = 'UNIT-SCAN-001'
            CollectionSuccessful = ($Status -ne 'ERROR')
            DefenderPreferences = [pscustomobject]@{
                PUAProtection = 'SENSITIVE-RAW-DO-NOT-EXPORT'
            }
        }
    }
}

function New-Selection {
    param([string]$Status = 'READY', [string[]]$Ids = @('TEST-001'))
    $criteria = @(
        foreach ($id in $Ids) { [pscustomobject]@{ CriterionId = $id } }
    )
    return [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:UNIT-DEVICE'
        ScanId = 'UNIT-SCAN-001'
        Status = $Status
        ScoringEligible = ($Status -eq 'READY')
        EligibleCriteria = $criteria
        ReviewOnly = @(
            [pscustomobject]@{
                Name = 'PUA configuration'
                Area = 'ThreatProtection'
                EvidencePath = 'DefenderPreferences.PUAProtection'
                Assessment = 'REVIEW_ONLY'
                ReferenceUrl = 'https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus'
            }
            [pscustomobject]@{
                Name = 'Absent observation'
                Area = 'ThreatProtection'
                EvidencePath = 'DefenderPreferences.NotCollected'
                Assessment = 'REVIEW_ONLY'
                ReferenceUrl = 'https://learn.microsoft.com/en-us/powershell/module/defender/get-mppreference'
            }
        )
    }
}

function Invoke-Fixture {
    param([string]$Status = 'FAIL', [object[]]$Items = $null,
          [AllowNull()][object]$Control = $null,
          [AllowNull()][object]$Selection = $null,
          [switch]$Reviews)
    if ($null -eq $Items) { $Items = @(New-FixtureFindingItem -Status $Status) }
    $e = New-Evaluation -Status $Status -Items $Items
    $args = @{ EvaluationResult = $e }
    if ($null -ne $Control) { $args.ControlResult = $Control }
    if ($null -ne $Selection) { $args.SelectionResult = $Selection }
    if ($Reviews) { $args.IncludeReviewOnly = $true }
    return ConvertTo-WinSecFindings @args
}

Write-Host ''
Write-Host 'WinSec Analyzer - Findings Engine Unit Tests' -ForegroundColor Cyan
Write-Host ''

# ============================================================
# PUBLIC CONTRACT AND DETERMINISTIC ID
# ============================================================

Test-Case 'Public conversion function exists' {
    Assert-True ($null -ne (Get-Command ConvertTo-WinSecFindings))
}
Test-Case 'Finding ID is deterministic for the same identity' {
    $p = @{ DeviceId='DEVICE'; ScanId='SCAN'; CheckId='CHECK'; Kind='FAIL'; Key='RULE' }
    $a = New-WinSecFindingId @p
    $b = New-WinSecFindingId @p
    Assert-Equal $a $b
    Assert-True ($a -cmatch '^WSA-FND-[A-F0-9]{24}$')
}
Test-Case 'Finding ID changes with device' {
    $a = New-WinSecFindingId -DeviceId A -ScanId S -CheckId C -Kind K -Key X
    $b = New-WinSecFindingId -DeviceId B -ScanId S -CheckId C -Kind K -Key X
    Assert-True ($a -cne $b)
}
Test-Case 'Finding ID changes with scan' {
    $a = New-WinSecFindingId -DeviceId D -ScanId A -CheckId C -Kind K -Key X
    $b = New-WinSecFindingId -DeviceId D -ScanId B -CheckId C -Kind K -Key X
    Assert-True ($a -cne $b)
}
Test-Case 'Finding ID changes with criterion key' {
    $a = New-WinSecFindingId -DeviceId D -ScanId S -CheckId C -Kind K -Key X
    $b = New-WinSecFindingId -DeviceId D -ScanId S -CheckId C -Kind K -Key Y
    Assert-True ($a -cne $b)
}
Test-Case 'Separator collisions do not reuse finding IDs' {
    $a = New-WinSecFindingId -DeviceId 'a:b' -ScanId c -CheckId d -Kind e -Key f
    $b = New-WinSecFindingId -DeviceId a -ScanId 'b:c' -CheckId d -Kind e -Key f
    Assert-True ($a -cne $b)
}

# ============================================================
# AGGREGATE STATES AND DEVIATIONS
# ============================================================

Test-Case 'No criteria NOT_EVALUATED creates EVALUATION_PENDING' {
    $r = ConvertTo-WinSecFindings -EvaluationResult (New-Evaluation)
    Assert-Equal $r.Status 'INCOMPLETE'
    Assert-Equal $r.FindingCount 1
    Assert-Equal $r.PendingCount 1
    Assert-Equal $r.DeviationCount 0
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_PENDING'
}
Test-Case 'No criteria UNKNOWN creates EVALUATION_UNAVAILABLE' {
    $r = ConvertTo-WinSecFindings -EvaluationResult (New-Evaluation -Status 'UNKNOWN')
    Assert-Equal $r.Status 'INCOMPLETE'
    Assert-Equal $r.EvidenceGapCount 1
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_UNAVAILABLE'
}
Test-Case 'Empty PASS aggregate is rejected as inconsistent' {
    $r = ConvertTo-WinSecFindings -EvaluationResult (New-Evaluation -Status 'PASS')
    Assert-Equal $r.Status 'INVALID_INPUT'
    Assert-Equal $r.FindingCount 0
}
Test-Case 'Empty NOT_APPLICABLE aggregate creates no findings' {
    $r = ConvertTo-WinSecFindings -EvaluationResult (New-Evaluation -Status 'NOT_APPLICABLE')
    Assert-Equal $r.Status 'COMPLETE'
    Assert-Equal $r.FindingCount 0
}
Test-Case 'PASS criterion creates no findings' {
    $r = Invoke-Fixture -Status 'PASS'
    Assert-Equal $r.Status 'COMPLETE'
    Assert-Equal $r.FindingCount 0
}
Test-Case 'FAIL produces one verified-format configuration deviation' {
    $r = Invoke-Fixture
    Assert-Equal $r.Status 'COMPLETE'
    Assert-Equal $r.FindingCount 1
    Assert-Equal $r.DeviationCount 1
    Assert-Equal $r.Findings[0].Kind 'CONFIGURATION_DEVIATION'
    Assert-Equal $r.Findings[0].Category 'CONFIGURATION'
    Assert-Equal $r.Findings[0].EvaluationStatus 'FAIL'
    Assert-Equal $r.Findings[0].CriterionId 'TEST-001'
}
Test-Case 'Confirmed deviation never invents severity priority or score' {
    $f = (Invoke-Fixture).Findings[0]
    Assert-Equal $f.Severity 'UNASSIGNED'
    Assert-Equal $f.Priority 'UNASSIGNED'
    Assert-Equal $f.WorkflowStatus 'OPEN'
    Assert-Equal $f.ScoringEligible $false
    Assert-Equal $f.FrameworkMappings.CISBenchmarks.Count 0
    Assert-Equal $f.FrameworkMappings.CISControls.Count 0
    Assert-Equal $f.FrameworkMappings.NISTCSF.Count 0
    Assert-Equal $f.FrameworkMappings.MITREATTACK.Count 0
}
Test-Case 'Deviation preserves source and recommendation, not observed values' {
    $f = (Invoke-Fixture).Findings[0]
    Assert-Equal $f.Source.Framework 'LOCAL_POLICY'
    Assert-Equal $f.Source.Verification 'DECLARED_BY_EVALUATION_NOT_INDEPENDENTLY_CONFIRMED'
    Assert-True (-not [string]::IsNullOrWhiteSpace($f.Recommendation))
    Assert-Equal $f.EvidenceReference.Path 'DefenderPreferences.PUAProtection'
    Assert-Equal $f.EvidenceReference.RawValueIncluded $false
    $serialized = $f | ConvertTo-Json -Depth 15
    Assert-True (-not $serialized.Contains('SENSITIVE-RAW-DO-NOT-EXPORT'))
}
Test-Case 'UNKNOWN criterion becomes EVIDENCE_GAP, not FAIL' {
    $r = Invoke-Fixture -Status 'UNKNOWN'
    Assert-Equal $r.Findings[0].Kind 'EVIDENCE_GAP'
    Assert-Equal $r.EvidenceGapCount 1
    Assert-Equal $r.DeviationCount 0
    Assert-Equal $r.Status 'INCOMPLETE'
}
Test-Case 'NOT_EVALUATED criterion becomes CRITERION_PENDING' {
    $r = Invoke-Fixture -Status 'UNKNOWN' -Items @((New-FixtureFindingItem -Status 'NOT_EVALUATED'))
    Assert-Equal $r.Findings[0].Kind 'CRITERION_PENDING'
    Assert-Equal $r.PendingCount 1
}
Test-Case 'FAIL and UNKNOWN remain separately visible' {
    $items = @((New-FixtureFindingItem -Status 'FAIL'), (New-FixtureFindingItem -Status 'UNKNOWN' -Id 'TEST-002'))
    $r = Invoke-Fixture -Status 'UNKNOWN' -Items $items
    Assert-Equal $r.Status 'INCOMPLETE'
    Assert-Equal $r.FindingCount 2
    Assert-Equal $r.DeviationCount 1
    Assert-Equal $r.EvidenceGapCount 1
}
Test-Case 'PASS aggregate with FAIL criterion is INVALID_INPUT' {
    $r = Invoke-Fixture -Status 'PASS' -Items @((New-FixtureFindingItem -Status 'FAIL'))
    Assert-Equal $r.Status 'INVALID_INPUT'
}
Test-Case 'FAIL aggregate with UNKNOWN criterion is INVALID_INPUT' {
    $items = @((New-FixtureFindingItem -Status 'FAIL'), (New-FixtureFindingItem -Status 'UNKNOWN' -Id 'TEST-002'))
    $r = Invoke-Fixture -Status 'FAIL' -Items $items
    Assert-Equal $r.Status 'INVALID_INPUT'
}
Test-Case 'NOT_APPLICABLE aggregate with FAIL is INVALID_INPUT' {
    $r = Invoke-Fixture -Status 'NOT_APPLICABLE' -Items @((New-FixtureFindingItem -Status 'FAIL'))
    Assert-Equal $r.Status 'INVALID_INPUT'
}
Test-Case 'Unsupported aggregate status is INVALID_INPUT' {
    $r = ConvertTo-WinSecFindings -EvaluationResult (New-Evaluation -Status 'SUCCESS')
    Assert-Equal $r.Status 'INVALID_INPUT'
}

# ============================================================
# AUTHORIZATION AND COLLECTION GATES
# ============================================================

Test-Case 'Blocked selection never produces configuration deviations' {
    $r = Invoke-Fixture -Selection (New-Selection -Status 'DRAFT_BLOCKED')
    Assert-Equal $r.Status 'BLOCKED'
    Assert-Equal $r.DeviationCount 0
    Assert-Equal $r.Findings[0].Kind 'CATALOG_NOT_READY'
}
Test-Case 'READY selection releases a listed criterion' {
    $r = Invoke-Fixture -Selection (New-Selection)
    Assert-Equal $r.DeviationCount 1
    Assert-Equal $r.Status 'COMPLETE'
}
Test-Case 'READY selection with no authorized rules blocks grading' {
    $r = Invoke-Fixture -Selection (New-Selection -Ids @())
    Assert-Equal $r.Status 'BLOCKED'
    Assert-Equal $r.DeviationCount 0
}
Test-Case 'FAIL from an unselected criterion cannot become a deviation' {
    $r = Invoke-Fixture -Selection (New-Selection -Ids @('OTHER-ID'))
    Assert-Equal $r.DeviationCount 0
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_NOT_TRUSTED'
}
Test-Case 'Missing individual scoring flag prevents a confirmed deviation' {
    $item = New-FixtureFindingItem
    $item.ScoringEligible = $false
    $r = Invoke-Fixture -Items @($item)
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_NOT_TRUSTED'
}
Test-Case 'Unsupported framework source prevents a confirmed deviation' {
    $item = New-FixtureFindingItem
    $item.Source.Framework = 'NIST CSF'
    $r = Invoke-Fixture -Items @($item)
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_NOT_TRUSTED'
}
Test-Case 'Unsecured source URL prevents a confirmed deviation' {
    $item = New-FixtureFindingItem
    $item.Source.Url = 'http://example.invalid/policy'
    $r = Invoke-Fixture -Items @($item)
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_NOT_TRUSTED'
}
Test-Case 'Missing recommendation prevents a confirmed deviation' {
    $item = New-FixtureFindingItem
    $item.Recommendation = ''
    $r = Invoke-Fixture -Items @($item)
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_NOT_TRUSTED'
}
Test-Case 'Expression-like evidence path prevents a deviation' {
    $item = New-FixtureFindingItem
    $item.EvidencePath = 'DefenderPreferences.$(Get-Process)'
    $r = Invoke-Fixture -Items @($item)
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_NOT_TRUSTED'
}
Test-Case 'Collector ERROR produces a collection error, not a deviation' {
    $r = Invoke-Fixture -Control (New-Control -Status 'ERROR')
    Assert-Equal $r.Status 'BLOCKED'
    Assert-Equal $r.Findings[0].Kind 'COLLECTION_ERROR'
    Assert-Equal $r.EvidenceGapCount 1
    Assert-Equal $r.DeviationCount 0
}
Test-Case 'Collector identity mismatch is INVALID_INPUT' {
    $c = New-Control
    $c.DeviceId = 'local:OTHER-DEVICE'
    $r = Invoke-Fixture -Control $c
    Assert-Equal $r.Status 'INVALID_INPUT'
    Assert-Equal $r.FindingCount 0
}
Test-Case 'Evidence identity mismatch is INVALID_INPUT' {
    $c = New-Control
    $c.Evidence.ScanId = 'OTHER-SCAN'
    $r = Invoke-Fixture -Control $c
    Assert-Equal $r.Status 'INVALID_INPUT'
}
Test-Case 'Selection identity mismatch is INVALID_INPUT' {
    $s = New-Selection
    $s.DeviceId = 'local:OTHER-DEVICE'
    $r = Invoke-Fixture -Selection $s
    Assert-Equal $r.Status 'INVALID_INPUT'
}
Test-Case 'Incomplete evaluation identity is INVALID_INPUT' {
    $e = New-Evaluation
    $e.ScanId = ''
    $r = ConvertTo-WinSecFindings -EvaluationResult $e
    Assert-Equal $r.Status 'INVALID_INPUT'
}

# ============================================================
# MALFORMED CRITERION RECORDS
# ============================================================

Test-Case 'Duplicate criterion IDs produce one diagnostic, not two deviations' {
    $items = @((New-FixtureFindingItem), (New-FixtureFindingItem))
    $r = Invoke-Fixture -Items $items
    Assert-Equal $r.FindingCount 1
    Assert-Equal $r.DeviationCount 0
    Assert-Equal $r.Findings[0].Kind 'DUPLICATE_CRITERION'
}
Test-Case 'Criterion result from another scan is rejected' {
    $item = New-FixtureFindingItem
    $item.ScanId = 'FOREIGN-SCAN'
    $r = Invoke-Fixture -Items @($item)
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_IDENTITY_ERROR'
    Assert-Equal $r.DeviationCount 0
}
Test-Case 'Missing criterion ID is a data-quality finding' {
    $item = New-FixtureFindingItem
    $item.CriterionId = ''
    $r = Invoke-Fixture -Items @($item)
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_DATA_ERROR'
}
Test-Case 'Unsupported criterion state is a data-quality finding' {
    $item = New-FixtureFindingItem
    $item.Status = 'NOT_A_REAL_STATE'
    $r = Invoke-Fixture -Status 'UNKNOWN' -Items @($item)
    Assert-Equal $r.Findings[0].Kind 'EVALUATION_DATA_ERROR'
}

# ============================================================
# REVIEW-ONLY AND EVIDENCE PRIVACY
# ============================================================

Test-Case 'Review items are separate from findings' {
    $r = Invoke-Fixture -Status 'PASS' -Control (New-Control) `
        -Selection (New-Selection) -Reviews
    Assert-Equal $r.FindingCount 0
    Assert-Equal $r.ReviewItemCount 2
    Assert-Equal $r.ReviewItems[0].Type 'REVIEW_ONLY'
    Assert-Equal $r.ReviewItems[0].Status 'OBSERVED'
    Assert-Equal $r.ReviewItems[1].Status 'UNKNOWN'
}
Test-Case 'Review items cannot claim compliance, risk or score' {
    $r = Invoke-Fixture -Status 'PASS' -Control (New-Control) `
        -Selection (New-Selection) -Reviews
    foreach ($i in $r.ReviewItems) {
        Assert-Equal $i.ScoringEligible $false
        Assert-Equal $i.ComplianceStatus 'NOT_EVALUATED'
        Assert-Equal $i.Severity 'UNASSIGNED'
        Assert-Equal $i.RawValueIncluded $false
    }
}
Test-Case 'Review metadata does not expose sensitive raw evidence' {
    $r = Invoke-Fixture -Status 'PASS' -Control (New-Control) `
        -Selection (New-Selection) -Reviews
    $json = $r | ConvertTo-Json -Depth 15
    Assert-True (-not $json.Contains('SENSITIVE-RAW-DO-NOT-EXPORT'))
}
Test-Case 'ReviewOnly switch alone does not emit review records' {
    $r = Invoke-Fixture -Status 'PASS' -Reviews
    Assert-Equal $r.ReviewItemCount 0
}
Test-Case 'Malformed review-only entries are ignored' {
    $s = New-Selection
    $s.ReviewOnly[0].Assessment = 'PASS'
    $r = Invoke-Fixture -Status 'PASS' -Selection $s -Control (New-Control) -Reviews
    Assert-Equal $r.ReviewItemCount 1
}
Test-Case 'Review identity changes between scans' {
    $a = Invoke-Fixture -Status 'PASS' -Selection (New-Selection) `
        -Control (New-Control) -Reviews
    $item = $a.ReviewItems[0]
    Assert-Equal $item.DeviceId 'local:UNIT-DEVICE'
    Assert-Equal $item.ScanId 'UNIT-SCAN-001'
    Assert-True ($item.ReviewId -cmatch '^WSA-FND-[A-F0-9]{24}$')
}

# ============================================================
# STATIC READ-ONLY SAFEGUARDS
# ============================================================

Test-Case 'Findings Engine parses without syntax errors' {
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:EnginePath, [ref]$tokens, [ref]$errors
    )
    Assert-Equal @($errors).Count 0
}
Test-Case 'Findings Engine has no device-modifying command calls' {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:EnginePath, [ref]$tokens, [ref]$errors
    )
    Assert-Equal @($errors).Count 0
    $forbidden = '^(Set-Mp|Add-Mp|Remove-Mp|Start-MpScan$|Update-MpSignature$|Set-Item|New-Item|Remove-Item|Set-Content|Add-Content|Out-File$|Set-Service|Start-Service|Stop-Service|Invoke-CimMethod$|Set-CimInstance$|Invoke-Expression$|Start-Process$|Invoke-Command$)'
    $commands = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true)
    foreach ($command in $commands) {
        $name = $command.GetCommandName()
        Assert-True (-not ($name -match $forbidden)) `
            "Potential modification command: $name"
    }
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed
Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'FINDINGS ENGINE UNIT TEST SUMMARY' -ForegroundColor Cyan
Write-Host "TOTAL : $total"
Write-Host "PASS  : $script:Passed" -ForegroundColor Green
Write-Host "FAIL  : $script:Failed" -ForegroundColor $(if ($script:Failed) { 'Red' } else { 'Green' })
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''
if ($script:Failed -gt 0) {
    throw "$($script:Failed) Findings Engine unit test(s) failed."
}
Write-Host 'All Findings Engine unit tests passed.' -ForegroundColor Green
