
# ============================================================
# WinSec Analyzer
# Test Suite : Scan Coordinator Unit Tests
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit tests for ScanCoordinator.ps1.
#
# Includes:
# - Coordinator initialization
# - DeviceId / ScanId validation
# - Local, remote and imported target protection
# - AuditEngine result contract validation
# - Synthetic scan execution
# - Mandatory SkipScoring enforcement
# - Duplicate scan prevention
# - Public/internal session separation
# - In-memory history isolation
# - No automatic evidence persistence
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# - Uses synthetic audit results.
# - Invoke-WinSecAudit is mocked before scan tests.
# - No real security checks are executed.
# - No files are written.
# - No Windows security settings are changed.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

# ============================================================
# PATHS
# ============================================================

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

$script:CoordinatorPath = Join-Path `
    $script:ProjectRoot 'src/Core/ScanCoordinator.ps1'

$script:AuditPath = Join-Path `
    $script:ProjectRoot 'src/Core/AuditEngine.ps1'

$script:ModelPath = Join-Path `
    $script:ProjectRoot 'src/Core/ResultModel.ps1'

$script:TargetPath = Join-Path `
    $script:ProjectRoot 'src/Core/TargetRegistry.ps1'

$script:EvidencePath = Join-Path `
    $script:ProjectRoot 'src/Services/EvidenceService.ps1'

$script:SecretMarker = 'WINSEC_PRIVATE_SCAN_TEST_9274'

# ============================================================
# ASSERTIONS
# ============================================================

function Assert-Equal {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Expected,

        [string]$Message = 'Values differ.'
    )

    if ($null -eq $Expected) {
        if ($null -ne $Actual) {
            throw "$Message Expected null; got [$Actual]."
        }

        return
    }

    if (
        $null -eq $Actual -or
        $Actual -cne $Expected
    ) {
        throw (
            '{0} Expected [{1}]; got [{2}].' -f
            $Message, $Expected, $Actual
        )
    }
}

function Assert-True {
    [CmdletBinding()]
    param(
        [bool]$Condition,

        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Throws {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    $caught = $null

    try {
        $null = & $Action
    }
    catch {
        $caught = $_
    }

    if ($null -eq $caught) {
        throw 'Expected an exception, but none occurred.'
    }
}

# ============================================================
# TEST RUNNER
# ============================================================

function Test-Case {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    try {
        $null = & $Action

        $script:Passed++

        Write-Host (
            '[PASS] {0}' -f $Name
        ) -ForegroundColor Green
    }
    catch {
        $script:Failed++

        Write-Host (
            '[FAIL] {0} - {1}' -f
            $Name, $_.Exception.Message
        ) -ForegroundColor Red

        if ($_.ScriptStackTrace) {
            Write-Host $_.ScriptStackTrace `
                -ForegroundColor DarkGray
        }
    }
}

# ============================================================
# SYNTHETIC COORDINATOR
# ============================================================

function New-TestCoordinator {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Targets = @()
    )

    return [pscustomobject]@{
        Component = 'ScanCoordinator'
        SchemaVersion = '1.0.0'
        ProjectRoot = $script:ProjectRoot

        Registry = [pscustomobject]@{
            schemaVersion = '1.0.0'
            targets = @($Targets)
        }

        CreatedAtUTC = [DateTime]::UtcNow.ToString('o')

        Sessions = @{}

        ParallelExecution = $false
        RemoteExecution = $false

        AutomaticEvidencePersistence = $false
        ScoringEnabled = $false
    }
}

function New-TestTarget {
    [CmdletBinding()]
    param(
        [string]$DeviceId,
        [string]$Hostname,
        [string]$Mode = 'LOCAL',
        [bool]$Enabled = $true
    )

    return [pscustomobject]@{
        DeviceId = $DeviceId
        Hostname = $Hostname
        Mode = $Mode
        Enabled = $Enabled
    }
}

# ============================================================
# SYNTHETIC AUDIT RECORD
# ============================================================

function New-TestAuditRecord {
    [CmdletBinding()]
    param(
        [string]$DeviceId,
        [string]$ScanId,
        [string]$CheckId = 'WSA-SYS-001',
        [string]$Status = 'INFORMATIONAL'
    )

    return [pscustomobject]@{
        DeviceId = $DeviceId
        ScanId = $ScanId
        CheckId = $CheckId

        SectionKey = 'SystemSecurity'

        Status = $Status
        ObservedStatus = $Status

        Evidence = if ($Status -ceq 'NOT_SELECTED') {
            $null
        }
        else {
            [pscustomobject]@{
                Synthetic = $true
                TestValue = 123
                Secret = $script:SecretMarker
            }
        }
    }
}

# ============================================================
# SYNTHETIC AUDIT RESULT
# ============================================================

function New-TestAuditResult {
    [CmdletBinding()]
    param(
        [string]$DeviceId,
        [string]$ScanId,
        [string]$Mode = 'NO_CHECKS'
    )

    $status = 'NO_EXECUTABLE_CHECKS'

    $records = @(
        New-TestAuditRecord `
            -DeviceId $DeviceId `
            -ScanId $ScanId `
            -Status 'NOT_SELECTED'
    )

    if ($Mode -ceq 'COMPLETED') {
        $status = 'COMPLETED'

        $records = @(
            New-TestAuditRecord `
                -DeviceId $DeviceId `
                -ScanId $ScanId
        )
    }

    if ($Mode -ceq 'WITH_ERRORS') {
        $status = 'COMPLETED_WITH_ERRORS'

        $records = @(
            New-TestAuditRecord `
                -DeviceId $DeviceId `
                -ScanId $ScanId `
                -Status 'ERROR'
        )
    }

    if ($Mode -ceq 'MIXED') {
        $status = 'COMPLETED'

        $records = @(
            (New-TestAuditRecord `
                -DeviceId $DeviceId `
                -ScanId $ScanId `
                -CheckId 'WSA-SYS-001')

            (New-TestAuditRecord `
                -DeviceId $DeviceId `
                -ScanId $ScanId `
                -CheckId 'WSA-SYS-002' `
                -Status 'NOT_SELECTED')
        )
    }

    return [pscustomobject]@{
        AuditId = $ScanId
        ScanId = $ScanId
        DeviceId = $DeviceId

        ComputerName = [Environment]::MachineName
        CollectionMode = 'LOCAL'

        StartedAtUTC = '2026-01-01T00:00:00Z'
        CompletedAtUTC = '2026-01-01T00:01:00Z'

        ExecutionStatus = $status

        TotalRegisteredChecks = $records.Count
        SelectedChecks = @(
            $records | Where-Object {
                $_.Status -cne 'NOT_SELECTED'
            }
        ).Count

        OverallScore = $null
        OverallCoverage = $null
        OverallStatus = 'PENDING'

        SectionResults = @()

        ControlResults = @($records)
        CheckResults = @($records)

        ScoreResult = $null
        ScoringEnabled = $false

        Findings = @()
        CatalogVersion = 'UNIT-TEST-ONLY'
    }
}

# ============================================================
# DEPENDENCY VALIDATION
# ============================================================

Write-Host ''
Write-Host 'WinSec Analyzer - Scan Coordinator Unit Tests' `
    -ForegroundColor Cyan
Write-Host ''

foreach ($path in @(
    $script:CoordinatorPath,
    $script:AuditPath,
    $script:ModelPath,
    $script:TargetPath,
    $script:EvidencePath
)) {
    if (-not (
        Test-Path -LiteralPath $path -PathType Leaf
    )) {
        throw "Missing dependency: $path"
    }
}

# Load coordinator and real dependencies.
# This does not execute an audit.

. $script:CoordinatorPath

# ============================================================
# GROUP 1: COMPONENT CONTRACTS
# ============================================================

Test-Case 'ScanCoordinator parses correctly' {
    $tokens = $null
    $errors = $null

    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:CoordinatorPath,
        [ref]$tokens,
        [ref]$errors
    )

    Assert-Equal @($errors).Count 0
}

Test-Case 'Required functions are available' {
    foreach ($name in @(
        'Assert-WinSecScanIdentifier'
        'Get-WinSecScanSessionKey'
        'Assert-WinSecScanCoordinator'
        'New-WinSecScanCoordinator'
        'Resolve-WinSecScanTarget'
        'Assert-WinSecCoordinatedAuditResult'
        'ConvertTo-WinSecCoordinatedSession'
        'Save-WinSecCoordinatedEvidence'
        'Invoke-WinSecCoordinatedScan'
        'Get-WinSecCoordinatorSession'
        'Get-WinSecCoordinatorPublicResult'
        'Get-WinSecCoordinatorHistory'
    )) {
        Assert-True (
            $null -ne (
                Get-Command `
                    -Name $name `
                    -CommandType Function `
                    -ErrorAction SilentlyContinue
            )
        ) "Missing function: $name"
    }
}

Test-Case 'Coordinator initializes with project configuration' {
    $coordinator = New-WinSecScanCoordinator

    Assert-Equal $coordinator.Component 'ScanCoordinator'
    Assert-Equal $coordinator.SchemaVersion '1.0.0'

    Assert-True (
        $null -ne $coordinator.Registry
    )
}

Test-Case 'Coordinator defaults are restrictive' {
    $coordinator = New-WinSecScanCoordinator

    Assert-Equal $coordinator.RemoteExecution $false
    Assert-Equal $coordinator.ParallelExecution $false

    Assert-Equal (
        $coordinator.AutomaticEvidencePersistence
    ) $false

    Assert-Equal $coordinator.ScoringEnabled $false
}

Test-Case 'Coordinator starts with empty session history' {
    $coordinator = New-TestCoordinator

    Assert-Equal $coordinator.Sessions.Count 0
}

Test-Case 'Invalid coordinator is rejected' {
    Assert-Throws {
        Assert-WinSecScanCoordinator `
            -Coordinator ([pscustomobject]@{
                Component = 'INVALID'
                SchemaVersion = '1.0.0'
                Registry = $null
                Sessions = @{}
            })
    }
}

Test-Case 'Invalid target registry is rejected' {
    $coordinator = New-TestCoordinator

    $coordinator.Registry.schemaVersion = '999.0.0'

    Assert-Throws {
        Assert-WinSecScanCoordinator `
            -Coordinator $coordinator
    }
}

Test-Case 'Different project root is rejected' {
    $otherRoot = Join-Path `
        $script:ProjectRoot 'UNRELATED-PROJECT'

    Assert-Throws {
        New-WinSecScanCoordinator -ProjectRoot $otherRoot
    }
}

# ============================================================
# GROUP 2: IDENTITIES AND SESSION KEYS
# ============================================================

Test-Case 'Valid DeviceId is accepted' {
    Assert-WinSecScanIdentifier `
        -Value 'local:TEST-PC' `
        -FieldName 'DeviceId'
}

Test-Case 'Unsafe DeviceId is rejected' {
    Assert-Throws {
        Assert-WinSecScanIdentifier `
            -Value 'local:TEST PC' `
            -FieldName 'DeviceId'
    }
}

Test-Case 'Unsafe ScanId is rejected' {
    Assert-Throws {
        Assert-WinSecScanIdentifier `
            -Value '../OTHER-SCAN' `
            -FieldName 'ScanId'
    }
}

Test-Case 'Session key correlates device and scan' {
    $key = Get-WinSecScanSessionKey `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    Assert-Equal $key 'local:TEST-PC|SCAN-001'
}

Test-Case 'Different ScanId produces a different key' {
    $a = Get-WinSecScanSessionKey `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    $b = Get-WinSecScanSessionKey `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-002'

    Assert-True ($a -cne $b)
}

Test-Case 'Different DeviceId produces a different key' {
    $a = Get-WinSecScanSessionKey `
        -DeviceId 'local:PC-A' `
        -ScanId 'SCAN-001'

    $b = Get-WinSecScanSessionKey `
        -DeviceId 'local:PC-B' `
        -ScanId 'SCAN-001'

    Assert-True ($a -cne $b)
}

# ============================================================
# GROUP 3: TARGET RESOLUTION
# ============================================================

Test-Case 'Empty registry resolves current local device' {
    $coordinator = New-TestCoordinator

    $target = Resolve-WinSecScanTarget `
        -Coordinator $coordinator

    Assert-Equal $target.Mode 'LOCAL'
    Assert-Equal $target.Enabled $true

    Assert-Equal `
        $target.DeviceId `
        (New-WinSecLocalTarget).DeviceId
}

Test-Case 'Remote target cannot be audited' {
    $target = New-TestTarget `
        -DeviceId 'remote:SERVER-01' `
        -Hostname 'SERVER-01' `
        -Mode 'REMOTE'

    $coordinator = New-TestCoordinator `
        -Targets @($target)

    Assert-Throws {
        Resolve-WinSecScanTarget `
            -Coordinator $coordinator `
            -DeviceId 'remote:SERVER-01'
    }
}

Test-Case 'Imported target cannot be audited' {
    $target = New-TestTarget `
        -DeviceId 'imported:PC-002' `
        -Hostname 'PC-002' `
        -Mode 'IMPORTED'

    $coordinator = New-TestCoordinator `
        -Targets @($target)

    Assert-Throws {
        Resolve-WinSecScanTarget `
            -Coordinator $coordinator `
            -DeviceId 'imported:PC-002'
    }
}

Test-Case 'Disabled local target is rejected' {
    $local = New-WinSecLocalTarget

    $target = New-TestTarget `
        -DeviceId $local.DeviceId `
        -Hostname $local.Hostname `
        -Mode 'LOCAL' `
        -Enabled $false

    $coordinator = New-TestCoordinator `
        -Targets @($target)

    Assert-Throws {
        Resolve-WinSecScanTarget `
            -Coordinator $coordinator `
            -DeviceId $local.DeviceId
    }
}

Test-Case 'Another local device cannot be impersonated' {
    $target = New-TestTarget `
        -DeviceId 'local:OTHER-PC' `
        -Hostname 'OTHER-PC' `
        -Mode 'LOCAL'

    $coordinator = New-TestCoordinator `
        -Targets @($target)

    Assert-Throws {
        Resolve-WinSecScanTarget `
            -Coordinator $coordinator `
            -DeviceId 'local:OTHER-PC'
    }
}

Test-Case 'Unregistered target is rejected' {
    $coordinator = New-TestCoordinator

    Assert-Throws {
        Resolve-WinSecScanTarget `
            -Coordinator $coordinator `
            -DeviceId 'remote:NOT-REGISTERED'
    }
}

# ============================================================
# GROUP 4: AUDIT RESULT CONTRACT
# ============================================================

Test-Case 'Valid no-checks audit result is accepted' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    Assert-WinSecCoordinatedAuditResult `
        -AuditResult $result `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'
}

Test-Case 'Valid completed audit result is accepted' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001' `
        -Mode 'COMPLETED'

    Assert-WinSecCoordinatedAuditResult `
        -AuditResult $result `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'
}

Test-Case 'Foreign audit device is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:OTHER-PC' `
        -ScanId 'SCAN-001'

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

Test-Case 'Foreign audit scan is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'OTHER-SCAN'

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

Test-Case 'AuditId mismatch is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    $result.AuditId = 'FORGED-AUDIT'

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

Test-Case 'Remote collection mode is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    $result.CollectionMode = 'REMOTE'

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

Test-Case 'Unexpected execution status is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    $result.ExecutionStatus = 'UNAUTHORIZED'

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

Test-Case 'Unauthorized numeric score is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    $result.OverallScore = 100

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

Test-Case 'Unauthorized ScoreResult is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    $result.ScoreResult = [pscustomobject]@{
        Score = 100
        ScoringEligible = $true
    }

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

Test-Case 'Unexpected scoring enablement is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    $result.ScoringEnabled = $true

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

Test-Case 'Foreign control record is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001' `
        -Mode 'COMPLETED'

    $result.ControlResults[0].DeviceId = 'local:OTHER-PC'

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

Test-Case 'Duplicate control CheckId is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001' `
        -Mode 'COMPLETED'

    $duplicate = New-TestAuditRecord `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    $result.ControlResults = @(
        $result.ControlResults[0],
        $duplicate
    )

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

Test-Case 'Invalid control identifier is rejected' {
    $result = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001' `
        -Mode 'COMPLETED'

    $result.ControlResults[0].CheckId = '../UNSAFE'

    Assert-Throws {
        Assert-WinSecCoordinatedAuditResult `
            -AuditResult $result `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'SCAN-001'
    }
}

# ============================================================
# GROUP 5: RESULT MODEL CONVERSION
# ============================================================

Test-Case 'No-checks result remains NOT_SCORED' {
    $audit = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    $session = ConvertTo-WinSecCoordinatedSession `
        -AuditResult $audit

    Assert-Equal $session.OverallScore $null
    Assert-Equal $session.OverallStatus 'NOT_SCORED'
    Assert-Equal $session.ScoringEligible $false

    Assert-Equal (
        Test-WinSecResultSession -Session $session
    ) $true
}

Test-Case 'Raw observations do not authorize scoring' {
    $audit = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001' `
        -Mode 'COMPLETED'

    $session = ConvertTo-WinSecCoordinatedSession `
        -AuditResult $audit

    Assert-Equal $session.OverallScore $null
    Assert-Equal $session.OverallStatus 'NOT_SCORED'
    Assert-Equal $session.ScoringEligible $false
}

Test-Case 'NOT_SELECTED checks are excluded from scope' {
    $audit = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001' `
        -Mode 'MIXED'

    $session = ConvertTo-WinSecCoordinatedSession `
        -AuditResult $audit

    Assert-Equal $session.ExpectedCheckIds.Count 1
    Assert-Equal $session.ExpectedCheckIds[0] 'WSA-SYS-001'

    Assert-Equal $session.ControlResults.Count 2
}

Test-Case 'Raw collector statuses do not invent findings' {
    $audit = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001' `
        -Mode 'WITH_ERRORS'

    $session = ConvertTo-WinSecCoordinatedSession `
        -AuditResult $audit

    Assert-Equal @($session.Findings).Count 0
    Assert-Equal @($session.EvaluationResults).Count 0
    Assert-Equal $session.OverallScore $null
}

Test-Case 'Invalid collector identity is rejected by model' {
    $audit = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001' `
        -Mode 'COMPLETED'

    $audit.ControlResults[0].ScanId = 'OTHER-SCAN'

    Assert-Throws {
        ConvertTo-WinSecCoordinatedSession `
            -AuditResult $audit
    }
}

# ============================================================
# GROUP 6: MOCKED AUDIT EXECUTION
# ============================================================

# All Invoke-WinSecAudit calls below are intercepted.
# The real AuditEngine is never invoked by this group.

$script:OriginalAuditFunction = (
    Get-Command Invoke-WinSecAudit `
        -CommandType Function `
        -ErrorAction Stop
).ScriptBlock

$script:MockAuditCalls = 0
$script:MockSkipScoring = $false
$script:MockCheckIds = @()
$script:MockMode = 'NO_CHECKS'

function Invoke-WinSecAudit {
    [CmdletBinding()]
    param(
        [string]$DeviceId,
        [string]$ScanId,
        [string[]]$CheckIds,
        [AllowNull()][object]$Registry = $null,
        [switch]$SkipScoring
    )

    $script:MockAuditCalls++

    $script:MockSkipScoring = [bool]$SkipScoring
    $script:MockCheckIds = @($CheckIds)

    if ($script:MockMode -ceq 'THROW') {
        throw 'Synthetic AuditEngine failure.'
    }

    $result = New-TestAuditResult `
        -DeviceId $DeviceId `
        -ScanId $ScanId `
        -Mode $script:MockMode

    if ($script:MockMode -ceq 'FOREIGN_RESULT') {
        $result.DeviceId = 'local:FOREIGN-PC'
    }

    if ($script:MockMode -ceq 'FORGED_SCORE') {
        $result.OverallScore = 100
    }

    return $result
}

try {

    Test-Case 'Coordinated scan calls AuditEngine with SkipScoring' {
        $script:MockMode = 'NO_CHECKS'
        $script:MockAuditCalls = 0
        $script:MockSkipScoring = $false

        $coordinator = New-TestCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-001'

        Assert-Equal $script:MockAuditCalls 1
        Assert-Equal $script:MockSkipScoring $true

        Assert-Equal $result.OverallScore $null
        Assert-Equal $result.OverallStatus 'NOT_SCORED'
    }

    Test-Case 'Coordinated scan returns a public projection' {
        $script:MockMode = 'COMPLETED'

        $coordinator = New-TestCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-002'

        Assert-Equal $result.PublicProjection $true
        Assert-Equal $result.ContainsRawEvidence $false
        Assert-Equal $result.ExecutionStatus 'COMPLETED'
    }

    Test-Case 'Public scan result excludes private evidence' {
        $script:MockMode = 'COMPLETED'

        $coordinator = New-TestCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-003'

        $json = ConvertTo-Json `
            -InputObject $result `
            -Depth 30

        Assert-True (
            -not $json.Contains($script:SecretMarker)
        ) 'Private evidence leaked into public result.'
    }

    Test-Case 'Evidence persistence is disabled by default' {
        $script:MockMode = 'COMPLETED'

        $coordinator = New-TestCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-004'

        Assert-Equal (
            $result.EvidenceStorageStatus
        ) 'NOT_REQUESTED'

        Assert-Equal $result.StoredEvidenceCount 0
        Assert-Equal $result.FailedEvidenceCount 0
    }

    Test-Case 'Coordinator registers completed scan in memory' {
        $script:MockMode = 'COMPLETED'

        $coordinator = New-TestCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-005'

        Assert-Equal $coordinator.Sessions.Count 1

        $session = Get-WinSecCoordinatorSession `
            -Coordinator $coordinator `
            -DeviceId $result.DeviceId `
            -ScanId $result.ScanId

        Assert-Equal $session.ScanId 'UNIT-SCAN-005'
        Assert-Equal $session.InternalOnly $true
    }

    Test-Case 'Duplicate ScanId is rejected before another audit' {
        $script:MockMode = 'COMPLETED'

        $coordinator = New-TestCoordinator

        $null = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-006'

        $before = $script:MockAuditCalls

        Assert-Throws {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'UNIT-SCAN-006'
        }

        Assert-Equal $script:MockAuditCalls $before
        Assert-Equal $coordinator.Sessions.Count 1
    }

    Test-Case 'Explicit check selection is passed to AuditEngine' {
        $script:MockMode = 'COMPLETED'
        $script:MockCheckIds = @()

        $coordinator = New-TestCoordinator

        $null = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-007' `
            -CheckIds @('WSA-SYS-001')

        Assert-Equal $script:MockCheckIds.Count 1
        Assert-Equal $script:MockCheckIds[0] 'WSA-SYS-001'
        Assert-Equal $script:MockSkipScoring $true
    }

    Test-Case 'Duplicate selected checks are rejected' {
        $script:MockMode = 'COMPLETED'
        $script:MockAuditCalls = 0

        $coordinator = New-TestCoordinator

        Assert-Throws {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'UNIT-SCAN-008' `
                -CheckIds @(
                    'WSA-SYS-001',
                    'WSA-SYS-001'
                )
        }

        Assert-Equal $script:MockAuditCalls 0
        Assert-Equal $coordinator.Sessions.Count 0
    }

    Test-Case 'Invalid selected check is rejected' {
        $script:MockMode = 'COMPLETED'
        $script:MockAuditCalls = 0

        $coordinator = New-TestCoordinator

        Assert-Throws {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'UNIT-SCAN-009' `
                -CheckIds @('../UNSAFE')
        }

        Assert-Equal $script:MockAuditCalls 0
    }

    Test-Case 'Invalid requested ScanId is rejected' {
        $script:MockMode = 'COMPLETED'
        $script:MockAuditCalls = 0

        $coordinator = New-TestCoordinator

        Assert-Throws {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'SCAN/UNSAFE'
        }

        Assert-Equal $script:MockAuditCalls 0
    }

    Test-Case 'Remote target is rejected before audit execution' {
        $script:MockMode = 'COMPLETED'
        $script:MockAuditCalls = 0

        $target = New-TestTarget `
            -DeviceId 'remote:SERVER-01' `
            -Hostname 'SERVER-01' `
            -Mode 'REMOTE'

        $coordinator = New-TestCoordinator `
            -Targets @($target)

        Assert-Throws {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -DeviceId 'remote:SERVER-01' `
                -ScanId 'UNIT-SCAN-010'
        }

        Assert-Equal $script:MockAuditCalls 0
    }

    Test-Case 'Foreign AuditEngine result is not registered' {
        $script:MockMode = 'FOREIGN_RESULT'

        $coordinator = New-TestCoordinator

        Assert-Throws {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'UNIT-SCAN-011'
        }

        Assert-Equal $coordinator.Sessions.Count 0
    }

    Test-Case 'Unauthorized numeric score is not registered' {
        $script:MockMode = 'FORGED_SCORE'

        $coordinator = New-TestCoordinator

        Assert-Throws {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'UNIT-SCAN-012'
        }

        Assert-Equal $coordinator.Sessions.Count 0
    }

    Test-Case 'AuditEngine failure does not create a session' {
        $script:MockMode = 'THROW'

        $coordinator = New-TestCoordinator

        Assert-Throws {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'UNIT-SCAN-013'
        }

        Assert-Equal $coordinator.Sessions.Count 0
    }

    Test-Case 'Missing scan returns null' {
        $coordinator = New-TestCoordinator

        $target = New-WinSecLocalTarget

        $result = Get-WinSecCoordinatorSession `
            -Coordinator $coordinator `
            -DeviceId $target.DeviceId `
            -ScanId 'UNKNOWN-SCAN'

        Assert-Equal $result $null
    }

    Test-Case 'Internal session preserves original evidence' {
        $script:MockMode = 'COMPLETED'

        $coordinator = New-TestCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-014'

        $session = Get-WinSecCoordinatorSession `
            -Coordinator $coordinator `
            -DeviceId $result.DeviceId `
            -ScanId $result.ScanId

        Assert-Equal (
            $session.ControlResults[0].Evidence.Secret
        ) $script:SecretMarker
    }

    Test-Case 'Public retrieval does not disclose original evidence' {
        $script:MockMode = 'COMPLETED'

        $coordinator = New-TestCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-015'

        $public = Get-WinSecCoordinatorPublicResult `
            -Coordinator $coordinator `
            -DeviceId $result.DeviceId `
            -ScanId $result.ScanId

        $json = ConvertTo-Json `
            -InputObject $public `
            -Depth 30

        Assert-Equal $public.ContainsRawEvidence $false

        Assert-True (
            -not $json.Contains($script:SecretMarker)
        )
    }

    Test-Case 'Scan history exposes only safe metadata' {
        $script:MockMode = 'COMPLETED'

        $coordinator = New-TestCoordinator

        $null = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-016'

        $history = @(
            Get-WinSecCoordinatorHistory `
                -Coordinator $coordinator
        )

        Assert-Equal $history.Count 1
        Assert-Equal $history[0].ScanId 'UNIT-SCAN-016'
        Assert-Equal $history[0].OverallScore $null

        $json = ConvertTo-Json `
            -InputObject $history `
            -Depth 20

        Assert-True (
            -not $json.Contains($script:SecretMarker)
        )

        Assert-True (
            $null -eq $history[0].PSObject.Properties['Evidence']
        )
    }

    Test-Case 'Multiple scans preserve independent history' {
        $script:MockMode = 'COMPLETED'

        $coordinator = New-TestCoordinator

        $null = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-017'

        $null = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-018'

        $history = @(
            Get-WinSecCoordinatorHistory `
                -Coordinator $coordinator
        )

        Assert-Equal $history.Count 2
        Assert-Equal $coordinator.Sessions.Count 2

        $ids = @($history | ForEach-Object { $_.ScanId })

        Assert-True ('UNIT-SCAN-017' -in $ids)
        Assert-True ('UNIT-SCAN-018' -in $ids)
    }

    Test-Case 'History filtering excludes other devices' {
        $script:MockMode = 'COMPLETED'

        $coordinator = New-TestCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'UNIT-SCAN-019'

        $matching = @(
            Get-WinSecCoordinatorHistory `
                -Coordinator $coordinator `
                -DeviceId $result.DeviceId
        )

        $foreign = @(
            Get-WinSecCoordinatorHistory `
                -Coordinator $coordinator `
                -DeviceId 'local:FOREIGN-PC'
        )

        Assert-Equal $matching.Count 1
        Assert-Equal $foreign.Count 0
    }

    Test-Case 'Automatically generated ScanId is valid' {
        $script:MockMode = 'NO_CHECKS'

        $coordinator = New-TestCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator

        Assert-True (
            Test-WinSecEvidenceIdentifier $result.ScanId
        )

        Assert-Equal $coordinator.Sessions.Count 1
        Assert-Equal $result.OverallStatus 'NOT_SCORED'
    }

}
finally {

    # Restore the real AuditEngine function.
    # Unit-test mocks must not remain installed.

    Set-Item `
        -Path Function:\Invoke-WinSecAudit `
        -Value $script:OriginalAuditFunction `
        -Force
}

# ============================================================
# GROUP 7: EVIDENCE PERSISTENCE SAFETY
# ============================================================

Test-Case 'Unselected controls do not create evidence files' {
    $audit = New-TestAuditResult `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'SCAN-001'

    $session = ConvertTo-WinSecCoordinatedSession `
        -AuditResult $audit

    # All controls are NOT_SELECTED.
    # This operation must not invoke Save-WinSecEvidence
    # or create a filesystem location.

    $result = Save-WinSecCoordinatedEvidence `
        -ProjectRoot $script:ProjectRoot `
        -Session $session

    Assert-Equal $result.Status 'NO_EVIDENCE'
    Assert-Equal $result.StoredCount 0
    Assert-Equal $result.FailedCount 0
    Assert-Equal $result.SkippedCount 1
}

Test-Case 'Coordinator has no automatic persistence' {
    $coordinator = New-TestCoordinator

    Assert-Equal (
        $coordinator.AutomaticEvidencePersistence
    ) $false

    Assert-Equal $coordinator.Sessions.Count 0
}

# ============================================================
# GROUP 8: CODE SECURITY
# ============================================================

Test-Case 'ScanCoordinator contains no remediation commands' {
    $tokens = $null
    $errors = $null

    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:CoordinatorPath,
        [ref]$tokens,
        [ref]$errors
    )

    Assert-Equal @($errors).Count 0

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
        'Restart-Computer'
        'Invoke-Command'
        'New-PSSession'
        'Enter-PSSession'
    )

    foreach ($command in $commands) {

        $name = $command.GetCommandName()

        Assert-True (
            $name -notin $forbidden
        ) "Forbidden command: $name"
    }
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray

Write-Host 'SCAN COORDINATOR UNIT TEST SUMMARY' `
    -ForegroundColor Cyan

Write-Host "TOTAL : $total"

Write-Host "PASS  : $($script:Passed)" `
    -ForegroundColor Green

Write-Host "FAIL  : $($script:Failed)" `
    -ForegroundColor $(
        if ($script:Failed -gt 0) {
            'Red'
        }
        else {
            'Green'
        }
    )

Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''

if ($script:Failed -gt 0) {
    throw (
        '{0} ScanCoordinator unit test(s) failed.' -f
        $script:Failed
    )
}

Write-Host 'All ScanCoordinator unit tests passed.' `
    -ForegroundColor Green
