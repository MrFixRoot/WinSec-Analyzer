
# ============================================================
# WinSec Analyzer
# Test Suite : Scan Coordinator Integration
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Integration tests for coordinated security assessments.
#
# Components:
# - ScanCoordinator
# - AuditEngine
# - CheckRegistry
# - TargetRegistry
# - ResultModel
# - EvidenceService
#
# Coverage:
# - Real AuditEngine with a synthetic empty catalog
# - Local target resolution
# - DeviceId and ScanId correlation
# - Mandatory SkipScoring
# - Duplicate scan prevention
# - Error and foreign-result rejection
# - Public/internal evidence isolation
# - Scan history
# - Explicit encrypted evidence persistence
# - Production configuration integrity
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# SECURITY:
# Real Windows checks are never executed by this suite.
# AuditEngine receives an empty synthetic check catalog.
# Other audit scenarios use a mocked execution boundary.
# Evidence is written only inside temporary test folders.
# No remote execution or Windows configuration changes.
# ============================================================

[CmdletBinding()]
param(
    # Skip the direct AuditEngine call and all disk-writing evidence tests.
    [switch]$InMemoryOnly
)

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

$script:TargetPath = Join-Path `
    $script:ProjectRoot 'src/Core/TargetRegistry.ps1'

$script:ModelPath = Join-Path `
    $script:ProjectRoot 'src/Core/ResultModel.ps1'

$script:EvidencePath = Join-Path `
    $script:ProjectRoot 'src/Services/EvidenceService.ps1'

$script:TargetsConfigPath = Join-Path `
    $script:ProjectRoot 'config/targets.json'

$script:ScoringConfigPath = Join-Path `
    $script:ProjectRoot 'config/scoring.json'

$script:SecretMarker = 'WINSEC_SCAN_INTEGRATION_PRIVATE_8392'

# ============================================================
# ASSERTIONS
# ============================================================

function Assert-WinSecIntEqual {
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
        throw (
            '{0} Expected [{1}], got [{2}].' -f
            $Message, $Expected, $Actual
        )
    }
}

function Assert-WinSecIntTrue {
    param(
        [bool]$Condition,
        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-WinSecIntThrows {
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

function Test-WinSecIntCase {
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
# SAFE COORDINATOR FIXTURE
# ============================================================

function New-WinSecIntCoordinator {
    # Initialize through the actual TargetRegistry service.
    $coordinator = New-WinSecScanCoordinator

    # Use an isolated, in-memory target registry.
    # This does not overwrite config/targets.json.
    #
    # The empty registry enables the legitimate local
    # fallback supplied by TargetRegistry.

    $coordinator.Registry = [pscustomobject]@{
        schemaVersion = '1.0.0'
        targets = @()
    }

    return $coordinator
}

function New-WinSecIntTarget {
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

function New-WinSecIntRecord {
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [string]$CheckId = 'WSA-SYS-001',

        [string]$Status = 'INFORMATIONAL'
    )

    $evidence = $null

    if ($Status -cne 'NOT_SELECTED') {
        $evidence = [pscustomobject]@{
            Synthetic = $true
            Value = 123
            Secret = $script:SecretMarker
        }
    }

    return [pscustomobject]@{
        DeviceId = $DeviceId
        ScanId = $ScanId
        CheckId = $CheckId

        SectionKey = 'SystemSecurity'
        CollectionMode = 'LOCAL'

        Status = $Status
        ObservedStatus = $Status

        Evidence = $evidence
    }
}

# ============================================================
# SYNTHETIC AUDIT RESULT
# ============================================================

function New-WinSecIntAuditResult {
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [ValidateSet(
            'EMPTY',
            'COMPLETED',
            'ERROR',
            'MIXED',
            'FOREIGN',
            'FORGED_SCORE'
        )]
        [string]$Mode = 'EMPTY'
    )

    $records = @()
    $executionStatus = 'NO_EXECUTABLE_CHECKS'

    switch ($Mode) {

        'COMPLETED' {
            $executionStatus = 'COMPLETED'

            $records = @(
                New-WinSecIntRecord `
                    -DeviceId $DeviceId `
                    -ScanId $ScanId
            )
        }

        'ERROR' {
            $executionStatus = 'COMPLETED_WITH_ERRORS'

            $records = @(
                New-WinSecIntRecord `
                    -DeviceId $DeviceId `
                    -ScanId $ScanId `
                    -Status 'ERROR'
            )
        }

        'MIXED' {
            $executionStatus = 'COMPLETED'

            $records = @(
                (New-WinSecIntRecord `
                    -DeviceId $DeviceId `
                    -ScanId $ScanId `
                    -CheckId 'WSA-SYS-001')

                (New-WinSecIntRecord `
                    -DeviceId $DeviceId `
                    -ScanId $ScanId `
                    -CheckId 'WSA-SYS-002' `
                    -Status 'NOT_SELECTED')
            )
        }

        'FOREIGN' {
            $executionStatus = 'COMPLETED'

            $records = @(
                New-WinSecIntRecord `
                    -DeviceId $DeviceId `
                    -ScanId $ScanId
            )
        }

        'FORGED_SCORE' {
            $executionStatus = 'COMPLETED'

            $records = @(
                New-WinSecIntRecord `
                    -DeviceId $DeviceId `
                    -ScanId $ScanId
            )
        }
    }

    $now = [DateTime]::UtcNow
    $start = $now.AddSeconds(-2)

    $result = [pscustomobject]@{
        AuditId = $ScanId
        ScanId = $ScanId
        DeviceId = $DeviceId

        ComputerName = [Environment]::MachineName
        CollectionMode = 'LOCAL'

        StartedAtUTC = $start.ToString('o')
        CompletedAtUTC = $now.ToString('o')

        ExecutionStatus = $executionStatus

        TotalRegisteredChecks = @($records).Count
        SelectedChecks = @(
            $records | Where-Object {
                $_.Status -cne 'NOT_SELECTED'
            }
        ).Count

        ControlResults = @($records)
        CheckResults = @($records)

        OverallScore = $null
        OverallCoverage = $null
        OverallStatus = 'PENDING'

        ScoreResult = $null
        ScoringEnabled = $false

        Findings = @()
        CatalogVersion = 'SYNTHETIC-TEST-ONLY'
    }

    if ($Mode -ceq 'FOREIGN') {
        $result.DeviceId = 'local:FOREIGN-PC'
    }

    if ($Mode -ceq 'FORGED_SCORE') {
        $result.OverallScore = 100
    }

    return $result
}

# ============================================================
# TEMPORARY EVIDENCE SANDBOX
# ============================================================

function New-WinSecIntConfirmationRegistry {
    param([string]$ProjectRoot)
    return [pscustomobject]@{
        CatalogVersion = 'SYNTHETIC-TEST-ONLY'
        Sections = @([pscustomobject]@{ key = 'SystemSecurity' })
        Checks = @([pscustomobject]@{
            CheckId = 'WSA-SYS-001'; Name = 'Synthetic integration control'; SectionKey = 'SystemSecurity'
            ExecutionEnabled = $true; ExecutionReady = $true
            ImplementationStatus = 'VALIDATED'; RegistryStatus = 'READY'
            ScriptPath = Join-Path $ProjectRoot 'src/Checks/Defender/Test-Defender.ps1'
        })
    }
}

function Invoke-WinSecIntSandbox {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    $root = Join-Path `
        ([System.IO.Path]::GetTempPath()) `
        (
            'WinSec-ScanIntegration-' +
            [guid]::NewGuid().ToString('N')
        )

    $reports = Join-Path $root 'reports'

    try {
        $null = [System.IO.Directory]::CreateDirectory(
            $reports
        )

        $null = & $Action $root
    }
    finally {
        if ([System.IO.Directory]::Exists($root)) {
            [System.IO.Directory]::Delete(
                $root,
                $true
            )
        }
    }
}

# ============================================================
# INITIALIZATION
# ============================================================

Write-Host ''
Write-Host 'WinSec Analyzer - Scan Coordinator Integration Tests' `
    -ForegroundColor Cyan
Write-Host ''

$requiredPaths = @(
    $script:CoordinatorPath
    $script:AuditPath
    $script:TargetPath
    $script:ModelPath
    $script:EvidencePath
    $script:TargetsConfigPath
    $script:ScoringConfigPath
)

foreach ($path in $requiredPaths) {
    if (-not (
        Test-Path -LiteralPath $path -PathType Leaf
    )) {
        throw "Required dependency not found: $path"
    }
}

$script:TargetsHashBefore = (
    Get-FileHash `
        -LiteralPath $script:TargetsConfigPath `
        -Algorithm SHA256
).Hash

$script:ScoringHashBefore = (
    Get-FileHash `
        -LiteralPath $script:ScoringConfigPath `
        -Algorithm SHA256
).Hash

# Loading the coordinator also loads its real dependencies.
# Dot-sourcing does not initiate an audit.

. $script:CoordinatorPath

# ============================================================
# GROUP 1: REAL COMPONENT CONTRACTS
# ============================================================

Test-WinSecIntCase 'All integration functions are available' {
    foreach ($name in @(
        'New-WinSecScanCoordinator'
        'Invoke-WinSecCoordinatedScan'
        'Get-WinSecCoordinatorSession'
        'Get-WinSecCoordinatorPublicResult'
        'Get-WinSecCoordinatorHistory'
        'Invoke-WinSecAudit'
        'Get-WinSecCheckRegistry'
        'Import-WinSecTargetRegistry'
        'New-WinSecResultSession'
        'Test-WinSecResultSession'
        'Save-WinSecEvidence'
        'Read-WinSecEvidence'
        'Get-WinSecEvidenceIndex'
    )) {
        Assert-WinSecIntTrue (
            $null -ne (
                Get-Command $name `
                    -CommandType Function `
                    -ErrorAction SilentlyContinue
            )
        ) "Missing function: $name"
    }
}

Test-WinSecIntCase 'Production target registry is valid' {
    $registry = Import-WinSecTargetRegistry `
        -ProjectRoot $script:ProjectRoot

    $validation = Test-WinSecTargetRegistry `
        -Registry $registry

    Assert-WinSecIntEqual $validation.Valid $true
}

Test-WinSecIntCase 'Coordinator defaults are secure' {
    $coordinator = New-WinSecScanCoordinator

    Assert-WinSecIntEqual $coordinator.RemoteExecution $false
    Assert-WinSecIntEqual $coordinator.ParallelExecution $false
    Assert-WinSecIntEqual $coordinator.ScoringEnabled $false

    Assert-WinSecIntEqual (
        $coordinator.AutomaticEvidencePersistence
    ) $false

    Assert-WinSecIntEqual $coordinator.Sessions.Count 0
}

Test-WinSecIntCase 'Production scoring remains disabled' {
    $policy = Get-Content `
        -LiteralPath $script:ScoringConfigPath `
        -Raw `
        -Encoding UTF8 |
        ConvertFrom-Json

    Assert-WinSecIntEqual $policy.enabled $false
}

# ============================================================
# GROUP 2: EMPTY CATALOG AND CONFIRMED SYNTHETIC SESSIONS
# ============================================================

# Preserve the real registry function and AuditEngine.
# The optional direct AuditEngine test uses an empty catalog. Subsequent
# session tests replace both the registry and collector in memory.
#
# The synthetic catalog contains zero checks, ensuring
# AuditEngine cannot execute any collector implementation.

$script:OriginalRegistryFunction = (
    Get-Command Get-WinSecCheckRegistry `
        -CommandType Function `
        -ErrorAction Stop
).ScriptBlock

$script:OriginalAuditFunction = (
    Get-Command Invoke-WinSecAudit `
        -CommandType Function `
        -ErrorAction Stop
).ScriptBlock

$script:SafeRegistryCalls = 0

try {
    Set-Item `
        -Path Function:\Get-WinSecCheckRegistry `
        -Value {
            [CmdletBinding()]
            param($ProjectRoot)

            $script:SafeRegistryCalls++

            return [pscustomobject]@{
                CatalogVersion = 'INTEGRATION-EMPTY-CATALOG'
                Checks = @()
                Sections = @()
            }
        } `
        -Force

    if (-not $InMemoryOnly) {
    Test-WinSecIntCase 'Real AuditEngine executes zero checks' {
        $local = New-WinSecLocalTarget

        $audit = Invoke-WinSecAudit `
            -DeviceId $local.DeviceId `
            -ScanId 'INT-REAL-001' `
            -SkipScoring

        Assert-WinSecIntEqual (
            $audit.ExecutionStatus
        ) 'NO_EXECUTABLE_CHECKS'

        Assert-WinSecIntEqual (
            @($audit.ControlResults).Count
        ) 0

        Assert-WinSecIntEqual $audit.ScoringEnabled $false
        Assert-WinSecIntEqual $audit.OverallScore $null

        Assert-WinSecIntTrue (
            $script:SafeRegistryCalls -gt 0
        ) 'AuditEngine did not use the safe catalog.'
    }

    }
    else {
        Write-Host '[SKIP] Direct AuditEngine invocation (-InMemoryOnly).'
    }

    # An empty catalog no longer creates a session. Keep the existing history,
    # duplicate and public-result checks using an explicitly confirmed synthetic
    # execution; the real collector is never invoked here.
    Set-Item -Path Function:\Get-WinSecCheckRegistry -Value {
        param($ProjectRoot)
        New-WinSecIntConfirmationRegistry -ProjectRoot $ProjectRoot
    }
    Set-Item -Path Function:\Invoke-WinSecAudit -Value {
        param($DeviceId, $ScanId, $CheckIds, $Registry, [switch]$SkipScoring)
        if (-not $SkipScoring) { throw 'Scoring must remain disabled.' }
        New-WinSecIntAuditResult -DeviceId $DeviceId -ScanId $ScanId -Mode 'COMPLETED'
    }

    Test-WinSecIntCase 'Confirmed synthetic pipeline creates NOT_SCORED result' {
        $coordinator = New-WinSecIntCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-REAL-002' -ConfirmAction { param($request) $true }

        Assert-WinSecIntEqual (
            $result.ExecutionStatus
        ) 'COMPLETED'

        Assert-WinSecIntEqual (
            $result.OverallStatus
        ) 'NOT_SCORED'

        Assert-WinSecIntEqual $result.OverallScore $null
        Assert-WinSecIntEqual $result.ScoringEligible $false

        Assert-WinSecIntEqual $result.PublicProjection $true
        Assert-WinSecIntEqual $coordinator.Sessions.Count 1
    }

    Test-WinSecIntCase 'Confirmed synthetic pipeline stores valid internal session' {
        $coordinator = New-WinSecIntCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-REAL-003' -ConfirmAction { param($request) $true }

        $session = Get-WinSecCoordinatorSession `
            -Coordinator $coordinator `
            -DeviceId $result.DeviceId `
            -ScanId $result.ScanId

        Assert-WinSecIntEqual (
            Test-WinSecResultSession -Session $session
        ) $true

        Assert-WinSecIntEqual $session.InternalOnly $true
        Assert-WinSecIntEqual $session.ScanId 'INT-REAL-003'
    }

    Test-WinSecIntCase 'Confirmed synthetic pipeline does not persist evidence' {
        $coordinator = New-WinSecIntCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-REAL-004' -ConfirmAction { param($request) $true }

        Assert-WinSecIntEqual (
            $result.EvidenceStorageStatus
        ) 'NOT_REQUESTED'

        Assert-WinSecIntEqual $result.StoredEvidenceCount 0
        Assert-WinSecIntEqual $result.FailedEvidenceCount 0
    }

    Test-WinSecIntCase 'Confirmed synthetic pipeline rejects duplicate ScanId' {
        $coordinator = New-WinSecIntCoordinator

        $null = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-REAL-005' -ConfirmAction { param($request) $true }

        Assert-WinSecIntThrows {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'INT-REAL-005' -ConfirmAction { param($request) $true }
        }

        Assert-WinSecIntEqual $coordinator.Sessions.Count 1
    }

    Test-WinSecIntCase 'Confirmed synthetic pipeline maintains independent history' {
        $coordinator = New-WinSecIntCoordinator

        $null = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-REAL-006' -ConfirmAction { param($request) $true }

        $null = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-REAL-007' -ConfirmAction { param($request) $true }

        $history = @(
            Get-WinSecCoordinatorHistory `
                -Coordinator $coordinator
        )

        Assert-WinSecIntEqual $history.Count 2
        Assert-WinSecIntEqual $coordinator.Sessions.Count 2

        foreach ($item in $history) {
            Assert-WinSecIntEqual (
                $item.OverallStatus
            ) 'NOT_SCORED'

            Assert-WinSecIntEqual $item.OverallScore $null
        }
    }
}
finally {
    # Always restore both actual boundaries.
    Set-Item -Path Function:\Invoke-WinSecAudit -Value $script:OriginalAuditFunction
    Set-Item `
        -Path Function:\Get-WinSecCheckRegistry `
        -Value $script:OriginalRegistryFunction `
        -Force
}

# ============================================================
# GROUP 3: CONTROLLED AUDITENGINE SIMULATION
# ============================================================

# These scenarios must not execute registered checks.
# Registry eligibility and the AuditEngine execution boundary are mocked.
#
# Real coordinator, target and result-model functions remain
# loaded and are executed normally.

$script:MockAuditCalls = 0
$script:MockSkipScoring = $false
$script:MockCheckIds = @()
$script:MockAuditMode = 'EMPTY'

try {
    Set-Item -Path Function:\Get-WinSecCheckRegistry -Value {
        param($ProjectRoot)
        New-WinSecIntConfirmationRegistry -ProjectRoot $ProjectRoot
    }
    Set-Item `
        -Path Function:\Invoke-WinSecAudit `
        -Value {
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

            if ($script:MockAuditMode -ceq 'THROW') {
                throw 'Synthetic AuditEngine execution failure.'
            }

            return New-WinSecIntAuditResult `
                -DeviceId $DeviceId `
                -ScanId $ScanId `
                -Mode $script:MockAuditMode
        } `
        -Force

    Test-WinSecIntCase 'Coordinator always requests SkipScoring' {
        $script:MockAuditMode = 'COMPLETED'
        $script:MockAuditCalls = 0
        $script:MockSkipScoring = $false

        $coordinator = New-WinSecIntCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-MOCK-001' -ConfirmAction { param($request) $true }

        Assert-WinSecIntEqual $script:MockAuditCalls 1
        Assert-WinSecIntEqual $script:MockSkipScoring $true

        Assert-WinSecIntEqual $result.OverallScore $null
        Assert-WinSecIntEqual $result.OverallStatus 'NOT_SCORED'
    }

    Test-WinSecIntCase 'Selected CheckIds reach AuditEngine' {
        $script:MockAuditMode = 'COMPLETED'
        $script:MockCheckIds = @()

        $coordinator = New-WinSecIntCoordinator

        $null = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-MOCK-002' `
            -CheckIds @('WSA-SYS-001') -ConfirmAction { param($request) $true }

        Assert-WinSecIntEqual $script:MockCheckIds.Count 1

        Assert-WinSecIntEqual (
            $script:MockCheckIds[0]
        ) 'WSA-SYS-001'

        Assert-WinSecIntEqual $script:MockSkipScoring $true
    }

    Test-WinSecIntCase 'Completed observations create no findings' {
        $script:MockAuditMode = 'COMPLETED'

        $coordinator = New-WinSecIntCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-MOCK-003' -ConfirmAction { param($request) $true }

        Assert-WinSecIntEqual (
            $result.ExecutionStatus
        ) 'COMPLETED'

        Assert-WinSecIntEqual @($result.Findings).Count 0
        Assert-WinSecIntEqual $result.OverallScore $null
    }

    Test-WinSecIntCase 'Collection errors do not create fake findings' {
        $script:MockAuditMode = 'ERROR'

        $coordinator = New-WinSecIntCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-MOCK-004' -ConfirmAction { param($request) $true }

        Assert-WinSecIntEqual (
            $result.ExecutionStatus
        ) 'COMPLETED_WITH_ERRORS'

        Assert-WinSecIntEqual @($result.Findings).Count 0
        Assert-WinSecIntEqual $result.OverallScore $null
        Assert-WinSecIntEqual $result.ScoringEligible $false
    }

    Test-WinSecIntCase 'Public result excludes collector secrets' {
        $script:MockAuditMode = 'COMPLETED'

        $coordinator = New-WinSecIntCoordinator

        $public = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-MOCK-005' -ConfirmAction { param($request) $true }

        $json = ConvertTo-Json `
            -InputObject $public `
            -Depth 30

        Assert-WinSecIntEqual (
            $public.ContainsRawEvidence
        ) $false

        Assert-WinSecIntTrue (
            -not $json.Contains($script:SecretMarker)
        ) 'Sensitive evidence leaked into public output.'
    }

    Test-WinSecIntCase 'Internal session retains collector evidence' {
        $script:MockAuditMode = 'COMPLETED'

        $coordinator = New-WinSecIntCoordinator

        $public = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-MOCK-006' -ConfirmAction { param($request) $true }

        $session = Get-WinSecCoordinatorSession `
            -Coordinator $coordinator `
            -DeviceId $public.DeviceId `
            -ScanId $public.ScanId

        Assert-WinSecIntEqual (
            $session.ControlResults[0].Evidence.Secret
        ) $script:SecretMarker
    }

    Test-WinSecIntCase 'Changing a retrieved session cannot rewrite a completed coordinated scan' {
        $script:MockAuditMode = 'COMPLETED'
        $coordinator = New-WinSecIntCoordinator
        $public = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScanId 'INT-SNAPSHOT-001' -ConfirmAction { $true }
        $before = ConvertTo-Json -InputObject $coordinator.Sessions -Depth 40 -Compress
        $session = Get-WinSecCoordinatorSession $coordinator $public.DeviceId $public.ScanId
        $session.ControlResults[0].Evidence.Secret = 'CHANGED-OUTSIDE-STORE'
        $session.ControlResults[0].Status = 'ERROR'
        $session.ExecutionStatus = 'FAILED'
        $session.ScanId = 'different-returned-copy'
        Assert-WinSecIntEqual (ConvertTo-Json -InputObject $coordinator.Sessions -Depth 40 -Compress) $before
        $again = Get-WinSecCoordinatorSession $coordinator $public.DeviceId $public.ScanId
        Assert-WinSecIntEqual $again.ExecutionStatus 'COMPLETED'
        Assert-WinSecIntEqual $again.ControlResults[0].Evidence.Secret $script:SecretMarker
        Assert-WinSecIntTrue (-not [object]::ReferenceEquals($again,$session))
    }

    Test-WinSecIntCase 'Public results and history remain stable after internal and public response mutations' {
        $script:MockAuditMode = 'COMPLETED'
        $coordinator = New-WinSecIntCoordinator
        $public = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScanId 'INT-SNAPSHOT-002' -ConfirmAction { $true }
        $before = ConvertTo-Json -InputObject @(Get-WinSecCoordinatorHistory $coordinator) -Depth 20 -Compress
        $session = Get-WinSecCoordinatorSession $coordinator $public.DeviceId $public.ScanId
        $session.CompletedAtUTC = '2026-02-01T00:00:00Z'
        $public.ControlResults[0].Status = 'UNKNOWN'
        $rows = @(Get-WinSecCoordinatorHistory $coordinator)
        $rows[0].ExecutionStatus = 'CANCELLED'
        Assert-WinSecIntEqual (ConvertTo-Json -InputObject @(Get-WinSecCoordinatorHistory $coordinator) -Depth 20 -Compress) $before
        $fresh = Get-WinSecCoordinatorPublicResult $coordinator $public.DeviceId $public.ScanId
        Assert-WinSecIntEqual $fresh.ControlResults[0].Status 'INFORMATIONAL'
        Assert-WinSecIntTrue ((ConvertTo-Json $fresh -Depth 30) -notmatch $script:SecretMarker)
        Assert-WinSecIntEqual $fresh.OverallStatus 'NOT_SCORED'
    }

    Test-WinSecIntCase 'A foreign valid model substituted under a real scan key cannot be retrieved or published' {
        $script:MockAuditMode = 'COMPLETED'
        $coordinator = New-WinSecIntCoordinator
        $public = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScanId 'INT-SNAPSHOT-003' -ConfirmAction { $true }
        $key = Get-WinSecScanSessionKey $public.DeviceId $public.ScanId
        $coordinator.Sessions[$key].Session = New-WinSecResultSession -DeviceId 'local:FOREIGN-FIXTURE' -ScanId 'foreign-scan'
        $before = ConvertTo-Json -InputObject $coordinator.Sessions -Depth 30 -Compress
        Assert-WinSecIntThrows { Get-WinSecCoordinatorSession $coordinator $public.DeviceId $public.ScanId }
        Assert-WinSecIntThrows { Get-WinSecCoordinatorPublicResult $coordinator $public.DeviceId $public.ScanId }
        Assert-WinSecIntEqual (ConvertTo-Json -InputObject $coordinator.Sessions -Depth 30 -Compress) $before
    }

    Test-WinSecIntCase 'Public retrieval remains evidence-free' {
        $script:MockAuditMode = 'COMPLETED'

        $coordinator = New-WinSecIntCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-MOCK-007' -ConfirmAction { param($request) $true }

        $public = Get-WinSecCoordinatorPublicResult `
            -Coordinator $coordinator `
            -DeviceId $result.DeviceId `
            -ScanId $result.ScanId

        $json = ConvertTo-Json `
            -InputObject $public `
            -Depth 30

        Assert-WinSecIntEqual $public.PublicProjection $true

        Assert-WinSecIntTrue (
            -not $json.Contains($script:SecretMarker)
        )
    }

    Test-WinSecIntCase 'History excludes raw evidence' {
        $script:MockAuditMode = 'COMPLETED'

        $coordinator = New-WinSecIntCoordinator

        $null = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-MOCK-008' -ConfirmAction { param($request) $true }

        $history = @(
            Get-WinSecCoordinatorHistory `
                -Coordinator $coordinator
        )

        $json = ConvertTo-Json `
            -InputObject $history `
            -Depth 20

        Assert-WinSecIntEqual $history.Count 1

        Assert-WinSecIntTrue (
            -not $json.Contains($script:SecretMarker)
        )

        Assert-WinSecIntTrue (
            $null -eq $history[0].PSObject.Properties['Evidence']
        )
    }

    Test-WinSecIntCase 'History rejects structured private storage metadata from a completed scan' {
        $script:MockAuditMode = 'COMPLETED'
        $coordinator = New-WinSecIntCoordinator
        $public = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScanId 'INT-HISTORY-001' -ConfirmAction { $true }
        $key = Get-WinSecScanSessionKey $public.DeviceId $public.ScanId
        $coordinator.Sessions[$key].EvidenceStorage.Status = [pscustomobject]@{Evidence=$script:SecretMarker}
        $received = New-Object 'System.Collections.Generic.List[object]'
        $caught = $false
        try { Get-WinSecCoordinatorHistory $coordinator | ForEach-Object { $received.Add($_) } }
        catch { $caught=$true; Assert-WinSecIntTrue ($_.Exception.Message -notmatch $script:SecretMarker) }
        Assert-WinSecIntTrue ($caught -and $received.Count -eq 0)
    }

    Test-WinSecIntCase 'History binds a completed scan to its actual index key' {
        $script:MockAuditMode = 'COMPLETED'
        $coordinator = New-WinSecIntCoordinator
        $public = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScanId 'INT-HISTORY-002' -ConfirmAction { $true }
        $key = Get-WinSecScanSessionKey $public.DeviceId $public.ScanId
        $entry = $coordinator.Sessions[$key]
        $coordinator.Sessions.Remove($key)
        $coordinator.Sessions[(Get-WinSecScanSessionKey $public.DeviceId 'wrong-index-scan')] = $entry
        Assert-WinSecIntThrows { Get-WinSecCoordinatorHistory $coordinator $public.DeviceId }
        Assert-WinSecIntEqual $coordinator.Sessions.Count 1
    }

    Test-WinSecIntCase 'History projects only validated storage metadata and preserves legacy unknown scope' {
        $script:MockAuditMode = 'COMPLETED'
        $coordinator = New-WinSecIntCoordinator
        $public = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScanId 'INT-HISTORY-003' -ConfirmAction { $true }
        $key = Get-WinSecScanSessionKey $public.DeviceId $public.ScanId
        $storage = $coordinator.Sessions[$key].EvidenceStorage
        $storage.Status='FAILED';$storage.FailedCount=1
        $storage.Failures=@([pscustomobject]@{CheckId='WSA-SYS-001';ErrorType=$script:SecretMarker;Status='STORAGE_FAILED'})
        $rows = @(Get-WinSecCoordinatorHistory $coordinator $public.DeviceId)
        Assert-WinSecIntEqual $rows.Count 1
        Assert-WinSecIntEqual $rows[0].EvidenceStorageStatus 'FAILED'
        Assert-WinSecIntEqual $rows[0].FailedEvidenceCount 1
        Assert-WinSecIntEqual $rows[0].OverallStatus 'NOT_SCORED'
        Assert-WinSecIntTrue ($null -eq $rows[0].PSObject.Properties['ScopeType'])
        Assert-WinSecIntTrue ((ConvertTo-Json -InputObject $rows -Depth 20) -notmatch $script:SecretMarker)
    }

    Test-WinSecIntCase 'NOT_SELECTED controls remain unscored' {
        $script:MockAuditMode = 'MIXED'

        $coordinator = New-WinSecIntCoordinator

        $result = Invoke-WinSecCoordinatedScan `
            -Coordinator $coordinator `
            -ScanId 'INT-MOCK-009' -ConfirmAction { param($request) $true }

        Assert-WinSecIntEqual (
            $result.ExpectedCheckCount
        ) 1

        Assert-WinSecIntEqual (
            @($result.ControlResults).Count
        ) 2

        Assert-WinSecIntEqual $result.OverallScore $null
    }

    Test-WinSecIntCase 'Foreign audit result is rejected' {
        $script:MockAuditMode = 'FOREIGN'

        $coordinator = New-WinSecIntCoordinator

        Assert-WinSecIntThrows {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'INT-MOCK-010' -ConfirmAction { param($request) $true }
        }

        Assert-WinSecIntEqual $coordinator.Sessions.Count 0
    }

    Test-WinSecIntCase 'Forged numeric score is rejected' {
        $script:MockAuditMode = 'FORGED_SCORE'

        $coordinator = New-WinSecIntCoordinator

        Assert-WinSecIntThrows {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'INT-MOCK-011' -ConfirmAction { param($request) $true }
        }

        Assert-WinSecIntEqual $coordinator.Sessions.Count 0
    }

    Test-WinSecIntCase 'Audit failure does not register a session' {
        $script:MockAuditMode = 'THROW'

        $coordinator = New-WinSecIntCoordinator

        Assert-WinSecIntThrows {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'INT-MOCK-012' -ConfirmAction { param($request) $true }
        }

        Assert-WinSecIntEqual $coordinator.Sessions.Count 0
    }

    Test-WinSecIntCase 'Remote target rejected before execution' {
        $script:MockAuditMode = 'COMPLETED'
        $script:MockAuditCalls = 0

        $coordinator = New-WinSecIntCoordinator

        $remote = New-WinSecIntTarget `
            -DeviceId 'remote:SERVER-01' `
            -Hostname 'SERVER-01' `
            -Mode 'REMOTE'

        $coordinator.Registry.targets = @($remote)

        Assert-WinSecIntThrows {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -DeviceId 'remote:SERVER-01' `
                -ScanId 'INT-MOCK-013' -ConfirmAction { param($request) $true }
        }

        Assert-WinSecIntEqual $script:MockAuditCalls 0
    }

    Test-WinSecIntCase 'Imported target rejected before execution' {
        $script:MockAuditMode = 'COMPLETED'
        $script:MockAuditCalls = 0

        $coordinator = New-WinSecIntCoordinator

        $imported = New-WinSecIntTarget `
            -DeviceId 'imported:PC-02' `
            -Hostname 'PC-02' `
            -Mode 'IMPORTED'

        $coordinator.Registry.targets = @($imported)

        Assert-WinSecIntThrows {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -DeviceId 'imported:PC-02' `
                -ScanId 'INT-MOCK-014' -ConfirmAction { param($request) $true }
        }

        Assert-WinSecIntEqual $script:MockAuditCalls 0
    }

    Test-WinSecIntCase 'Disabled local target rejected' {
        $script:MockAuditMode = 'COMPLETED'
        $script:MockAuditCalls = 0

        $coordinator = New-WinSecIntCoordinator

        $local = New-WinSecLocalTarget

        $disabled = New-WinSecIntTarget `
            -DeviceId $local.DeviceId `
            -Hostname $local.Hostname `
            -Mode 'LOCAL' `
            -Enabled $false

        $coordinator.Registry.targets = @($disabled)

        Assert-WinSecIntThrows {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -DeviceId $local.DeviceId `
                -ScanId 'INT-MOCK-015' -ConfirmAction { param($request) $true }
        }

        Assert-WinSecIntEqual $script:MockAuditCalls 0
    }

    Test-WinSecIntCase 'Invalid explicit selection prevents audit' {
        $script:MockAuditMode = 'COMPLETED'
        $script:MockAuditCalls = 0

        $coordinator = New-WinSecIntCoordinator

        Assert-WinSecIntThrows {
            Invoke-WinSecCoordinatedScan `
                -Coordinator $coordinator `
                -ScanId 'INT-MOCK-016' `
                -CheckIds @(
                    'WSA-SYS-001',
                    'WSA-SYS-001'
                ) -ConfirmAction { param($request) $true }
        }

        Assert-WinSecIntEqual $script:MockAuditCalls 0
    }

    Test-WinSecIntCase 'Missing session returns null' {
        $coordinator = New-WinSecIntCoordinator
        $local = New-WinSecLocalTarget

        $result = Get-WinSecCoordinatorSession `
            -Coordinator $coordinator `
            -DeviceId $local.DeviceId `
            -ScanId 'DOES-NOT-EXIST'

        Assert-WinSecIntEqual $result $null
    }
}
finally {
    # Restore the real AuditEngine after all simulated tests.
    Set-Item -Path Function:\Get-WinSecCheckRegistry -Value $script:OriginalRegistryFunction
    Set-Item `
        -Path Function:\Invoke-WinSecAudit `
        -Value $script:OriginalAuditFunction `
        -Force
}

# ============================================================
# GROUP 4: REAL EVIDENCESERVICE - TEMPORARY STORAGE
# ============================================================

# These tests use the real EvidenceService.
# The input is synthetic and produced in memory.
# Persistence is explicitly requested inside a temp sandbox.

if (-not $InMemoryOnly) {
Test-WinSecIntCase 'DPAPI protection is available' {
    Assert-WinSecIntEqual (
        Assert-WinSecEvidenceProtection
    ) $true
}

Test-WinSecIntCase 'Coordinated evidence is encrypted and stored' {
    Invoke-WinSecIntSandbox {
        param($root)

        $audit = New-WinSecIntAuditResult `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'INT-EVIDENCE-001' `
            -Mode 'COMPLETED'

        $session = ConvertTo-WinSecCoordinatedSession `
            -AuditResult $audit

        $storage = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $session

        Assert-WinSecIntEqual $storage.Status 'STORED'
        Assert-WinSecIntEqual $storage.StoredCount 1
        Assert-WinSecIntEqual $storage.FailedCount 0

        $path = Get-WinSecEvidencePath `
            -ProjectRoot $root `
            -DeviceId $session.DeviceId `
            -ScanId $session.ScanId `
            -CheckId 'WSA-SYS-001'

        Assert-WinSecIntTrue (
            Test-Path -LiteralPath $path -PathType Leaf
        ) 'Encrypted evidence was not created.'
    }
}

Test-WinSecIntCase 'Stored evidence can be decrypted' {
    Invoke-WinSecIntSandbox {
        param($root)

        $audit = New-WinSecIntAuditResult `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'INT-EVIDENCE-002' `
            -Mode 'COMPLETED'

        $session = ConvertTo-WinSecCoordinatedSession `
            -AuditResult $audit

        $null = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $session

        $record = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId $session.DeviceId `
            -ScanId $session.ScanId `
            -CheckId 'WSA-SYS-001'

        Assert-WinSecIntEqual (
            $record.Evidence.Payload.Secret
        ) $script:SecretMarker

        Assert-WinSecIntEqual (
            $record.Evidence.CollectionSuccessful
        ) $true
    }
}

Test-WinSecIntCase 'Encrypted file excludes plaintext marker' {
    Invoke-WinSecIntSandbox {
        param($root)

        $audit = New-WinSecIntAuditResult `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'INT-EVIDENCE-003' `
            -Mode 'COMPLETED'

        $session = ConvertTo-WinSecCoordinatedSession `
            -AuditResult $audit

        $null = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $session

        $path = Get-WinSecEvidencePath `
            -ProjectRoot $root `
            -DeviceId $session.DeviceId `
            -ScanId $session.ScanId `
            -CheckId 'WSA-SYS-001'

        $bytes = [System.IO.File]::ReadAllBytes($path)

        $text = [System.Text.Encoding]::UTF8.GetString(
            $bytes
        )

        Assert-WinSecIntTrue (
            -not $text.Contains($script:SecretMarker)
        ) 'Unencrypted evidence was detected.'
    }
}

Test-WinSecIntCase 'Duplicate persistence cannot overwrite' {
    Invoke-WinSecIntSandbox {
        param($root)

        $audit = New-WinSecIntAuditResult `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'INT-EVIDENCE-004' `
            -Mode 'COMPLETED'

        $session = ConvertTo-WinSecCoordinatedSession `
            -AuditResult $audit

        $first = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $session

        $second = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $session

        Assert-WinSecIntEqual $first.StoredCount 1
        Assert-WinSecIntEqual $second.StoredCount 0

        Assert-WinSecIntEqual $second.FailedCount 1
        Assert-WinSecIntEqual $second.Status 'FAILED'

        $record = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId $session.DeviceId `
            -ScanId $session.ScanId `
            -CheckId 'WSA-SYS-001'

        Assert-WinSecIntEqual (
            $record.Evidence.Payload.Secret
        ) $script:SecretMarker
    }
}

Test-WinSecIntCase 'NOT_SELECTED evidence is not persisted' {
    Invoke-WinSecIntSandbox {
        param($root)

        $audit = New-WinSecIntAuditResult `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'INT-EVIDENCE-005' `
            -Mode 'MIXED'

        $session = ConvertTo-WinSecCoordinatedSession `
            -AuditResult $audit

        $storage = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $session

        Assert-WinSecIntEqual $storage.StoredCount 1
        Assert-WinSecIntEqual $storage.SkippedCount 1

        $index = @(
            Get-WinSecEvidenceIndex `
                -ProjectRoot $root `
                -DeviceId $session.DeviceId `
                -ScanId $session.ScanId
        )

        Assert-WinSecIntEqual $index.Count 1
        Assert-WinSecIntEqual $index[0].CheckId 'WSA-SYS-001'
    }
}

Test-WinSecIntCase 'Evidence index contains no raw observations' {
    Invoke-WinSecIntSandbox {
        param($root)

        $audit = New-WinSecIntAuditResult `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'INT-EVIDENCE-006' `
            -Mode 'COMPLETED'

        $session = ConvertTo-WinSecCoordinatedSession `
            -AuditResult $audit

        $null = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $session

        $index = @(
            Get-WinSecEvidenceIndex `
                -ProjectRoot $root `
                -DeviceId $session.DeviceId `
                -ScanId $session.ScanId
        )

        $json = ConvertTo-Json `
            -InputObject $index `
            -Depth 20

        Assert-WinSecIntEqual $index.Count 1

        Assert-WinSecIntTrue (
            -not $json.Contains($script:SecretMarker)
        ) 'Evidence index exposed private information.'

        Assert-WinSecIntTrue (
            $null -eq $index[0].PSObject.Properties['Evidence']
        )
    }
}

Test-WinSecIntCase 'Different scans use isolated storage paths' {
    Invoke-WinSecIntSandbox {
        param($root)

        $auditA = New-WinSecIntAuditResult `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'INT-EVIDENCE-007A' `
            -Mode 'COMPLETED'

        $auditB = New-WinSecIntAuditResult `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'INT-EVIDENCE-007B' `
            -Mode 'COMPLETED'

        $sessionA = ConvertTo-WinSecCoordinatedSession `
            -AuditResult $auditA

        $sessionB = ConvertTo-WinSecCoordinatedSession `
            -AuditResult $auditB

        $null = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $sessionA

        $null = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $sessionB

        $pathA = Get-WinSecEvidencePath `
            -ProjectRoot $root `
            -DeviceId $sessionA.DeviceId `
            -ScanId $sessionA.ScanId `
            -CheckId 'WSA-SYS-001'

        $pathB = Get-WinSecEvidencePath `
            -ProjectRoot $root `
            -DeviceId $sessionB.DeviceId `
            -ScanId $sessionB.ScanId `
            -CheckId 'WSA-SYS-001'

        Assert-WinSecIntTrue (
            $pathA -cne $pathB
        ) 'Different scans share an evidence file.'

        Assert-WinSecIntTrue (
            (Test-Path -LiteralPath $pathA) -and
            (Test-Path -LiteralPath $pathB)
        )
    }
}

Test-WinSecIntCase 'Different devices use isolated storage paths' {
    Invoke-WinSecIntSandbox {
        param($root)

        $auditA = New-WinSecIntAuditResult `
            -DeviceId 'local:PC-A' `
            -ScanId 'INT-EVIDENCE-008' `
            -Mode 'COMPLETED'

        $auditB = New-WinSecIntAuditResult `
            -DeviceId 'local:PC-B' `
            -ScanId 'INT-EVIDENCE-008' `
            -Mode 'COMPLETED'

        $sessionA = ConvertTo-WinSecCoordinatedSession `
            -AuditResult $auditA

        $sessionB = ConvertTo-WinSecCoordinatedSession `
            -AuditResult $auditB

        $null = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $sessionA

        $null = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $root `
            -Session $sessionB

        $pathA = Get-WinSecEvidencePath `
            -ProjectRoot $root `
            -DeviceId $sessionA.DeviceId `
            -ScanId $sessionA.ScanId `
            -CheckId 'WSA-SYS-001'

        $pathB = Get-WinSecEvidencePath `
            -ProjectRoot $root `
            -DeviceId $sessionB.DeviceId `
            -ScanId $sessionB.ScanId `
            -CheckId 'WSA-SYS-001'

        Assert-WinSecIntTrue (
            $pathA -cne $pathB
        ) 'Different devices share an evidence file.'
    }
}

# ============================================================
}
else {
    Write-Host '[SKIP] Evidence persistence and DPAPI tests (-InMemoryOnly).'
}

# GROUP 5: PRODUCTION CONFIGURATION INTEGRITY
# ============================================================

Test-WinSecIntCase 'Production targets.json remains unchanged' {
    $after = (
        Get-FileHash `
            -LiteralPath $script:TargetsConfigPath `
            -Algorithm SHA256
    ).Hash

    Assert-WinSecIntEqual `
        -Actual $after `
        -Expected $script:TargetsHashBefore
}

Test-WinSecIntCase 'Production scoring.json remains unchanged' {
    $after = (
        Get-FileHash `
            -LiteralPath $script:ScoringConfigPath `
            -Algorithm SHA256
    ).Hash

    Assert-WinSecIntEqual `
        -Actual $after `
        -Expected $script:ScoringHashBefore
}

Test-WinSecIntCase 'Actual AuditEngine function was restored' {
    $current = (
        Get-Command Invoke-WinSecAudit `
            -CommandType Function `
            -ErrorAction Stop
    ).ScriptBlock

    Assert-WinSecIntTrue (
        $current.ToString() -ceq
        $script:OriginalAuditFunction.ToString()
    ) 'The simulated AuditEngine is still installed.'
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray

Write-Host 'SCAN COORDINATOR INTEGRATION TEST SUMMARY' `
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
        '{0} ScanCoordinator integration test(s) failed.' -f
        $script:Failed
    )
}

Write-Host 'All ScanCoordinator integration tests passed.' `
    -ForegroundColor Green
