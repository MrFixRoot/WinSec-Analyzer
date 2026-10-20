
# ============================================================
# WinSec Analyzer
# Test Suite : Result Model Unit Tests
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit tests for the in-memory scan result contract.
#
# Includes:
# - Public API verification
# - Identity and timestamp validation
# - Device and scan isolation
# - Duplicate detection
# - Internal/public result separation
# - Raw evidence privacy
# - Unauthorized score rejection
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# Synthetic test data only.
# No Windows configuration changes.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

$script:ModelPath = Join-Path `
    $script:ProjectRoot 'src/Core/ResultModel.ps1'

# ============================================================
# ASSERTIONS
# ============================================================

function Assert-WinSecEqual {
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

function Assert-WinSecTrue {
    param(
        [bool]$Condition,
        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-WinSecThrows {
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
        throw 'Expected an exception, but none occurred.'
    }
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

        Write-Host (
            "[FAIL] {0} - {1}" -f $Name, $_.Exception.Message
        ) -ForegroundColor Red

        if ($_.ScriptStackTrace) {
            Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
        }
    }
}

# ============================================================
# SYNTHETIC FIXTURES
# ============================================================

function New-WinSecFixtureControl {
    param(
        [string]$DeviceId = 'local:TEST-PC',
        [string]$ScanId = 'UNIT-SCAN-001',
        [string]$CheckId = 'WSA-SYS-001',
        [string]$Status = 'INFORMATIONAL'
    )

    return [pscustomobject]@{
        DeviceId = $DeviceId
        ScanId = $ScanId
        CheckId = $CheckId
        SectionKey = 'SystemSecurity'
        Status = $Status
        Evidence = [pscustomobject]@{
            CheckId = $CheckId
            DeviceId = $DeviceId
            ScanId = $ScanId
            CollectionSuccessful = $true
            SecretTestValue = 'WINSEC_SECRET_DO_NOT_EXPORT_9267'
        }
    }
}

function New-WinSecFixtureSession {
    return New-WinSecResultSession `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'UNIT-SCAN-001' `
        -ExpectedCheckIds @('WSA-SYS-001')
}

function Copy-WinSecFixture {
    param([Parameter(Mandatory)][object]$Value)

    return (
        $Value |
        ConvertTo-Json -Depth 40 |
        ConvertFrom-Json
    )
}

# ============================================================
# INITIALIZATION
# ============================================================

Write-Host ''
Write-Host 'WinSec Analyzer - Result Model Unit Tests' `
    -ForegroundColor Cyan
Write-Host ''

if (-not (
    Test-Path -LiteralPath $script:ModelPath -PathType Leaf
)) {
    throw "ResultModel not found: $script:ModelPath"
}

. $script:ModelPath

# ============================================================
# GROUP 1: PUBLIC CONTRACT
# ============================================================

Test-WinSecCase 'ResultModel parses without syntax errors' {
    $tokens = $null
    $errors = $null

    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:ModelPath,
        [ref]$tokens,
        [ref]$errors
    )

    Assert-WinSecEqual @($errors).Count 0
}

Test-WinSecCase 'Required public functions exist' {
    foreach ($name in @(
        'Get-WinSecResultField'
        'Test-WinSecResultText'
        'ConvertTo-WinSecResultUtc'
        'Assert-WinSecResultItems'
        'New-WinSecResultSession'
        'Test-WinSecResultSession'
        'ConvertTo-WinSecPublicScanResult'
    )) {
        Assert-WinSecTrue (
            $null -ne (
                Get-Command $name `
                    -CommandType Function `
                    -ErrorAction SilentlyContinue
            )
        ) "Missing function: $name"
    }
}

Test-WinSecCase 'Object and dictionary properties are readable' {
    $object = [pscustomobject]@{
        DeviceId = 'local:TEST-PC'
    }

    $dictionary = @{
        DeviceId = 'local:TEST-PC'
    }

    Assert-WinSecEqual (
        Get-WinSecResultField $object 'DeviceId'
    ) 'local:TEST-PC'

    Assert-WinSecEqual (
        Get-WinSecResultField $dictionary 'deviceid'
    ) 'local:TEST-PC'
}

# ============================================================
# GROUP 2: SESSION DEFAULTS
# ============================================================

Test-WinSecCase 'Empty session is valid' {
    $session = New-WinSecFixtureSession

    Assert-WinSecEqual (
        Test-WinSecResultSession -Session $session
    ) $true
}

Test-WinSecCase 'Session preserves device and scan identity' {
    $session = New-WinSecFixtureSession

    Assert-WinSecEqual $session.DeviceId 'local:TEST-PC'
    Assert-WinSecEqual $session.ScanId 'UNIT-SCAN-001'
    Assert-WinSecEqual $session.AuditId 'UNIT-SCAN-001'
}

Test-WinSecCase 'Session defaults to pending execution' {
    $session = New-WinSecFixtureSession

    Assert-WinSecEqual $session.ExecutionStatus 'PENDING'
    Assert-WinSecEqual $session.CompletedAtUTC $null
}

Test-WinSecCase 'Session defaults to NOT_SCORED' {
    $session = New-WinSecFixtureSession

    Assert-WinSecEqual $session.OverallScore $null
    Assert-WinSecEqual $session.OverallStatus 'NOT_SCORED'
    Assert-WinSecEqual $session.ScoringEligible $false
}

Test-WinSecCase 'Expected checks are preserved' {
    $session = New-WinSecFixtureSession

    Assert-WinSecEqual $session.SelectedChecks 1
    Assert-WinSecEqual $session.ExpectedCheckIds[0] 'WSA-SYS-001'
}

# ============================================================
# GROUP 3: IDENTITY VALIDATION
# ============================================================

Test-WinSecCase 'Empty DeviceId is rejected' {
    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId ' ' `
            -ScanId 'UNIT-SCAN-001'
    }
}

Test-WinSecCase 'Invalid ScanId is rejected' {
    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId "UNIT`nSCAN"
    }
}

Test-WinSecCase 'Duplicate expected CheckId is rejected' {
    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -ExpectedCheckIds @(
                'WSA-SYS-001',
                'WSA-SYS-001'
            )
    }
}

Test-WinSecCase 'Foreign device collector is rejected' {
    $control = New-WinSecFixtureControl `
        -DeviceId 'local:OTHER-PC'

    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -ControlResults @($control)
    }
}

Test-WinSecCase 'Foreign scan collector is rejected' {
    $control = New-WinSecFixtureControl `
        -ScanId 'OTHER-SCAN'

    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -ControlResults @($control)
    }
}

Test-WinSecCase 'Duplicate collector CheckId is rejected' {
    $a = New-WinSecFixtureControl
    $b = New-WinSecFixtureControl

    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -ControlResults @($a, $b)
    }
}

Test-WinSecCase 'Evaluation without collector is rejected' {
    $evaluation = [pscustomobject]@{
        DeviceId = 'local:TEST-PC'
        ScanId = 'UNIT-SCAN-001'
        CheckId = 'WSA-SYS-001'
        Status = 'PASS'
    }

    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -EvaluationResults @($evaluation)
    }
}

Test-WinSecCase 'Selection without collector is rejected' {
    $selection = [pscustomobject]@{
        DeviceId = 'local:TEST-PC'
        ScanId = 'UNIT-SCAN-001'
        CheckId = 'WSA-SYS-001'
        Status = 'READY'
    }

    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -CriteriaSelections @($selection)
    }
}

Test-WinSecCase 'Finding with unknown CheckId is rejected' {
    $control = New-WinSecFixtureControl

    $finding = [pscustomobject]@{
        FindingId = 'TEST-FINDING-001'
        DeviceId = 'local:TEST-PC'
        ScanId = 'UNIT-SCAN-001'
        CheckId = 'WSA-UNKNOWN-999'
        Kind = 'EVIDENCE_GAP'
    }

    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -ControlResults @($control) `
            -Findings @($finding)
    }
}

Test-WinSecCase 'Duplicate FindingId is rejected' {
    $control = New-WinSecFixtureControl

    $finding = [pscustomobject]@{
        FindingId = 'TEST-FINDING-001'
        DeviceId = 'local:TEST-PC'
        ScanId = 'UNIT-SCAN-001'
        CheckId = 'WSA-SYS-001'
        Kind = 'EVIDENCE_GAP'
    }

    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -ControlResults @($control) `
            -Findings @($finding, $finding)
    }
}

# ============================================================
# GROUP 4: UTC TIMESTAMPS
# ============================================================

Test-WinSecCase 'UTC timestamp is accepted' {
    $date = ConvertTo-WinSecResultUtc `
        -Value '2026-01-01T00:00:00Z' `
        -FieldName 'TestDate'

    Assert-WinSecEqual $date.Offset.TotalMinutes 0
}

Test-WinSecCase 'Non-UTC timestamp is rejected' {
    Assert-WinSecThrows {
        ConvertTo-WinSecResultUtc `
            -Value '2026-01-01T00:00:00-06:00' `
            -FieldName 'TestDate'
    }
}

Test-WinSecCase 'Completion before start is rejected' {
    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -StartedAtUTC '2026-01-02T00:00:00Z' `
            -CompletedAtUTC '2026-01-01T00:00:00Z' `
            -ExecutionStatus 'COMPLETED'
    }
}

Test-WinSecCase 'Completed execution requires a timestamp' {
    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -ExecutionStatus 'COMPLETED'
    }
}

Test-WinSecCase 'Pending execution rejects completion timestamp' {
    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -StartedAtUTC '2026-01-01T00:00:00Z' `
            -CompletedAtUTC '2026-01-01T01:00:00Z' `
            -ExecutionStatus 'PENDING'
    }
}

Test-WinSecCase 'Completed session includes duration' {
    $session = New-WinSecResultSession `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'UNIT-SCAN-001' `
        -StartedAtUTC '2026-01-01T00:00:00Z' `
        -CompletedAtUTC '2026-01-01T00:01:00Z' `
        -ExecutionStatus 'COMPLETED'

    Assert-WinSecEqual $session.DurationSeconds 60
    Assert-WinSecEqual (
        Test-WinSecResultSession -Session $session
    ) $true
}

# ============================================================
# GROUP 5: SCORE PROTECTION
# ============================================================

Test-WinSecCase 'Foreign ScoreResult is rejected' {
    $score = [pscustomobject]@{
        DeviceId = 'local:OTHER-PC'
        ScanId = 'UNIT-SCAN-001'
        Score = 100
        Status = 'COMPLETE'
        ScoringEligible = $true
    }

    Assert-WinSecThrows {
        New-WinSecResultSession `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'UNIT-SCAN-001' `
            -ScoreResult $score
    }
}

Test-WinSecCase 'Forged score is not published' {
    $score = [pscustomobject]@{
        DeviceId = 'local:TEST-PC'
        ScanId = 'UNIT-SCAN-001'
        Score = 100
        Status = 'COMPLETE'
        ScoringEligible = $true
    }

    $session = New-WinSecResultSession `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'UNIT-SCAN-001' `
        -ScoreResult $score

    Assert-WinSecEqual $session.OverallScore $null
    Assert-WinSecEqual $session.OverallStatus 'NOT_SCORED'
    Assert-WinSecEqual $session.ScoringEligible $false
}

Test-WinSecCase 'Changing scoring flags invalidates session' {
    $session = New-WinSecFixtureSession
    $session.OverallScore = 100
    $session.OverallStatus = 'COMPLETE'
    $session.ScoringEligible = $true

    Assert-WinSecEqual (
        Test-WinSecResultSession -Session $session
    ) $false
}

# ============================================================
# GROUP 6: PUBLIC PROJECTION
# ============================================================

Test-WinSecCase 'Public projection is explicitly marked safe' {
    $session = New-WinSecFixtureSession

    $public = ConvertTo-WinSecPublicScanResult `
        -Session $session

    Assert-WinSecEqual $public.PublicProjection $true
    Assert-WinSecEqual $public.ContainsRawEvidence $false
}

Test-WinSecCase 'Public projection preserves safe identifiers' {
    $public = ConvertTo-WinSecPublicScanResult `
        -Session (New-WinSecFixtureSession)

    Assert-WinSecEqual $public.DeviceId 'local:TEST-PC'
    Assert-WinSecEqual $public.ScanId 'UNIT-SCAN-001'
    Assert-WinSecEqual $public.OverallStatus 'NOT_SCORED'
}

Test-WinSecCase 'Raw evidence is not exported' {
    $control = New-WinSecFixtureControl

    $session = New-WinSecResultSession `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'UNIT-SCAN-001' `
        -ControlResults @($control) `
        -ExpectedCheckIds @('WSA-SYS-001')

    $public = ConvertTo-WinSecPublicScanResult `
        -Session $session

    $json = $public | ConvertTo-Json -Depth 30

    Assert-WinSecTrue (
        -not $json.Contains(
            'WINSEC_SECRET_DO_NOT_EXPORT_9267'
        )
    ) 'Raw evidence leaked into public output.'

    Assert-WinSecTrue (
        $null -eq $public.ControlResults[0].
            PSObject.Properties['Evidence']
    ) 'Public control exposes Evidence.'
}

Test-WinSecCase 'Internal model preserves collector reference' {
    $control = New-WinSecFixtureControl

    $session = New-WinSecResultSession `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'UNIT-SCAN-001' `
        -ControlResults @($control)

    Assert-WinSecEqual (
        $session.ControlResults[0].Evidence.SecretTestValue
    ) 'WINSEC_SECRET_DO_NOT_EXPORT_9267'
}

Test-WinSecCase 'Unknown public status becomes UNKNOWN' {
    $control = New-WinSecFixtureControl `
        -Status 'UNEXPECTED_STATUS'

    $session = New-WinSecResultSession `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'UNIT-SCAN-001' `
        -ControlResults @($control)

    $public = ConvertTo-WinSecPublicScanResult `
        -Session $session

    Assert-WinSecEqual (
        $public.ControlResults[0].Status
    ) 'UNKNOWN'
}

Test-WinSecCase 'Public findings do not inherit severity' {
    $control = New-WinSecFixtureControl

    $finding = [pscustomobject]@{
        FindingId = 'TEST-FINDING-001'
        DeviceId = 'local:TEST-PC'
        ScanId = 'UNIT-SCAN-001'
        CheckId = 'WSA-SYS-001'
        Kind = 'EVIDENCE_GAP'
        EvaluationStatus = 'UNKNOWN'
        Severity = 'CRITICAL'
        Priority = 'HIGH'
        Secret = 'WINSEC_SECRET_DO_NOT_EXPORT_9267'
    }

    $session = New-WinSecResultSession `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'UNIT-SCAN-001' `
        -ControlResults @($control) `
        -Findings @($finding)

    $public = ConvertTo-WinSecPublicScanResult `
        -Session $session

    Assert-WinSecEqual (
        $public.Findings[0].Severity
    ) 'UNASSIGNED'

    Assert-WinSecEqual (
        $public.Findings[0].Priority
    ) 'UNASSIGNED'
}

Test-WinSecCase 'Review-only records remain separate' {
    $control = New-WinSecFixtureControl

    $review = [pscustomobject]@{
        ReviewId = 'REVIEW-001'
        DeviceId = 'local:TEST-PC'
        ScanId = 'UNIT-SCAN-001'
        CheckId = 'WSA-SYS-001'
        Status = 'OBSERVED'
        Secret = 'WINSEC_SECRET_DO_NOT_EXPORT_9267'
    }

    $session = New-WinSecResultSession `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'UNIT-SCAN-001' `
        -ControlResults @($control) `
        -ReviewItems @($review)

    $public = ConvertTo-WinSecPublicScanResult `
        -Session $session

    Assert-WinSecEqual @($public.Findings).Count 0
    Assert-WinSecEqual @($public.ReviewItems).Count 1
    Assert-WinSecEqual $public.ReviewItems[0].Type 'REVIEW_ONLY'
}

Test-WinSecCase 'Invalid internal session cannot be exported' {
    $session = New-WinSecFixtureSession
    $session.ScanId = 'ALTERED-SCAN'

    Assert-WinSecThrows {
        ConvertTo-WinSecPublicScanResult -Session $session
    }
}

# ============================================================
# GROUP 7: INTEGRITY
# ============================================================

Test-WinSecCase 'Unexpected schema version is rejected' {
    $session = Copy-WinSecFixture (
        New-WinSecFixtureSession
    )

    $session.SchemaVersion = '999.0.0'

    Assert-WinSecEqual (
        Test-WinSecResultSession -Session $session
    ) $false
}

Test-WinSecCase 'ResultModel contains no remediation commands' {
    $tokens = $null
    $errors = $null

    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:ModelPath,
        [ref]$tokens,
        [ref]$errors
    )

    $commands = $ast.FindAll({
        param($node)

        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true)

    $forbidden = @(
        'Set-MpPreference'
        'Add-MpPreference'
        'Remove-MpPreference'
        'Set-NetFirewallProfile'
        'Set-ItemProperty'
        'Remove-Item'
        'Restart-Computer'
    )

    foreach ($command in $commands) {
        Assert-WinSecTrue (
            $command.GetCommandName() -notin $forbidden
        ) "Forbidden command: $($command.GetCommandName())"
    }
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'RESULT MODEL UNIT TEST SUMMARY' -ForegroundColor Cyan

Write-Host "TOTAL : $total"
Write-Host "PASS  : $($script:Passed)" -ForegroundColor Green
Write-Host "FAIL  : $($script:Failed)" -ForegroundColor $(
    if ($script:Failed -gt 0) { 'Red' } else { 'Green' }
)

Write-Host ('=' * 60) -ForegroundColor DarkGray

if ($script:Failed -gt 0) {
    throw "$($script:Failed) ResultModel unit test(s) failed."
}

Write-Host 'All ResultModel unit tests passed.' `
    -ForegroundColor Green
