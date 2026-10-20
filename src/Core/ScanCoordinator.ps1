
# ============================================================
# WinSec Analyzer
# Component  : Scan Coordinator
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Coordinates local Windows security assessments using
# the existing AuditEngine, TargetRegistry, ResultModel
# and EvidenceService components.
#
# Features:
# - Registered target selection
# - Local execution only
# - Unique DeviceId / ScanId correlation
# - In-memory scan history
# - Duplicate scan prevention
# - Validated result model
# - Safe public result projection
# - Optional encrypted evidence persistence
# - Independent evidence storage status
#
# PowerShell 5.1 / 7.x on Windows
#
# IMPORTANT:
# - No automatic remediation.
# - No privilege elevation.
# - No remote command execution.
# - No automatic evidence persistence.
# - Only AuditEngine executes registered checks.
# - AuditEngine is always called with -SkipScoring.
# - No scores or framework mappings are fabricated.
# - Internal sessions may contain sensitive evidence.
# - Parallel coordination is not implemented.
# ============================================================

# ============================================================
# PROJECT ROOT AND DEPENDENCIES
# ============================================================

$script:WinSecCoordinatorProjectRoot = (
    [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '../..')
    )
)

$script:WinSecCoordinatorDependencies = @(
    'src/Core/CheckRegistry.ps1'
    'src/Core/TargetRegistry.ps1'
    'src/Core/ResultModel.ps1'
    'src/Services/EvidenceService.ps1'
    'src/Core/AuditEngine.ps1'
)

# Load functions in the current scope so they remain available
# after coordinator initialization.

foreach ($relativePath in $script:WinSecCoordinatorDependencies) {

    $dependencyPath = Join-Path `
        $script:WinSecCoordinatorProjectRoot `
        $relativePath

    if (-not (
        Test-Path -LiteralPath $dependencyPath -PathType Leaf
    )) {
        throw "ScanCoordinator dependency not found: $relativePath"
    }

    . $dependencyPath
}

# ============================================================
# IDENTIFIER VALIDATION
# ============================================================

function Assert-WinSecScanIdentifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [string]$FieldName = 'Identifier'
    )

    if (
        -not (
            Test-WinSecTargetIdentifier -Value $Value
        ) -or
        -not (
            Test-WinSecEvidenceIdentifier -Value $Value
        )
    ) {
        throw "Invalid $FieldName."
    }
}

# ============================================================
# BUILD SESSION KEY
# ============================================================

function Get-WinSecScanSessionKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId
    )

    Assert-WinSecScanIdentifier `
        -Value $DeviceId `
        -FieldName 'DeviceId'

    Assert-WinSecScanIdentifier `
        -Value $ScanId `
        -FieldName 'ScanId'

    # Pipes are prohibited in identifiers.
    # The separator is therefore unambiguous.

    return ('{0}|{1}' -f $DeviceId, $ScanId)
}

# ============================================================
# VALIDATE COORDINATOR INSTANCE
# ============================================================

function Assert-WinSecScanCoordinator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Coordinator
    )

    if (
        $null -eq $Coordinator -or
        $Coordinator.SchemaVersion -cne '1.0.0' -or
        $Coordinator.Component -cne 'ScanCoordinator' -or
        $null -eq $Coordinator.Registry -or
        $Coordinator.Sessions -isnot [hashtable]
    ) {
        throw 'Invalid ScanCoordinator instance.'
    }

    $validation = Test-WinSecTargetRegistry `
        -Registry $Coordinator.Registry

    if (-not $validation.Valid) {
        throw 'Coordinator contains an invalid target registry.'
    }
}

# ============================================================
# CREATE COORDINATOR
# ============================================================

function New-WinSecScanCoordinator {
    [CmdletBinding()]
    param(
        [string]$ProjectRoot = (
            $script:WinSecCoordinatorProjectRoot
        )
    )

    $resolvedRoot = [System.IO.Path]::GetFullPath(
        $ProjectRoot
    )

    # The component dependencies are loaded from the
    # installed project. Avoid mixing two installations.

    if (-not (
        [string]::Equals(
            $resolvedRoot.TrimEnd('\', '/'),
            $script:WinSecCoordinatorProjectRoot.TrimEnd('\', '/'),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    )) {
        throw (
            'ScanCoordinator must use its installed project root.'
        )
    }

    $registry = Import-WinSecTargetRegistry `
        -ProjectRoot $resolvedRoot

    $validation = Test-WinSecTargetRegistry `
        -Registry $registry

    if (-not $validation.Valid) {
        throw 'Cannot initialize an invalid target registry.'
    }

    return [pscustomobject]@{
        Component = 'ScanCoordinator'
        SchemaVersion = '1.0.0'

        ProjectRoot = $resolvedRoot

        Registry = $registry

        CreatedAtUTC = [DateTime]::UtcNow.ToString('o')

        # This is an internal, in-memory session store.
        # Never serialize it directly into public reports.

        Sessions = @{}

        ParallelExecution = $false
        RemoteExecution = $false

        AutomaticEvidencePersistence = $false

        ScoringEnabled = $false
    }
}

# ============================================================
# SELECT REGISTERED TARGET
# ============================================================

function Resolve-WinSecScanTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Coordinator,

        [string]$DeviceId = ''
    )

    Assert-WinSecScanCoordinator `
        -Coordinator $Coordinator

    $localDevice = New-WinSecLocalTarget

    if ([string]::IsNullOrWhiteSpace($DeviceId)) {
        $DeviceId = $localDevice.DeviceId
    }

    Assert-WinSecScanIdentifier `
        -Value $DeviceId `
        -FieldName 'DeviceId'

    $target = Get-WinSecRegisteredTarget `
        -Registry $Coordinator.Registry `
        -DeviceId $DeviceId `
        -IncludeLocalFallback

    if ($null -eq $target) {
        throw "Device is not registered: $DeviceId"
    }

    if (-not $target.Enabled) {
        throw "Target is disabled: $DeviceId"
    }

    # Registered remote/imported devices are valid inventory
    # entries, but this component cannot audit them yet.

    if ($target.Mode -cne 'LOCAL') {
        throw (
            'Remote/imported execution is not implemented. ' +
            'No connection or scan was attempted.'
        )
    }

    # AuditEngine itself only supports the current
    # Windows computer. Verify identity before calling it.

    if (-not (
        [string]::Equals(
            $target.DeviceId,
            $localDevice.DeviceId,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    )) {
        throw (
            'Target is not the current local Windows device.'
        )
    }

    return $target
}

# ============================================================
# VALIDATE AUDITENGINE RESULT
# ============================================================

function Assert-WinSecCoordinatedAuditResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AuditResult,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId
    )

    if (
        $null -eq $AuditResult -or
        $AuditResult.DeviceId -cne $DeviceId -or
        $AuditResult.ScanId -cne $ScanId -or
        $AuditResult.AuditId -cne $ScanId -or
        $AuditResult.CollectionMode -cne 'LOCAL'
    ) {
        throw 'AuditEngine returned inconsistent scan identity.'
    }

    if (
        $AuditResult.ExecutionStatus -cnotin @(
            'COMPLETED'
            'COMPLETED_WITH_ERRORS'
            'NO_EXECUTABLE_CHECKS'
        )
    ) {
        throw 'AuditEngine returned an invalid execution status.'
    }

    if (
        $AuditResult.ControlResults -isnot [array]
    ) {
        throw 'AuditEngine did not return a ControlResults array.'
    }

    # AuditEngine must not calculate or accept a score
    # while coordinated execution uses -SkipScoring.

    if (
        $null -ne $AuditResult.OverallScore -or
        $null -ne $AuditResult.ScoreResult -or
        $AuditResult.ScoringEnabled -cne $false
    ) {
        throw (
            'AuditEngine returned scoring data despite -SkipScoring.'
        )
    }

    $seen = New-Object `
        'System.Collections.Generic.HashSet[string]' `
        ([System.StringComparer]::Ordinal)

    foreach ($record in $AuditResult.ControlResults) {

        if (
            $null -eq $record -or
            $record.DeviceId -cne $DeviceId -or
            $record.ScanId -cne $ScanId
        ) {
            throw 'Audit result contains a foreign control.'
        }

        Assert-WinSecScanIdentifier `
            -Value ([string]$record.CheckId) `
            -FieldName 'CheckId'

        if (-not $seen.Add([string]$record.CheckId)) {
            throw "Duplicate CheckId: $($record.CheckId)"
        }
    }
}

# ============================================================
# BUILD VALIDATED RESULT SESSION
# ============================================================

function ConvertTo-WinSecCoordinatedSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AuditResult
    )

    $expectedIds = @(
        foreach ($record in $AuditResult.ControlResults) {
            if ($record.Status -cne 'NOT_SELECTED') {
                [string]$record.CheckId
            }
        }
    )

    # IMPORTANT:
    # AuditEngine currently collects observations.
    # The EvaluationEngine / FindingsEngine integration
    # is not yet part of its production pipeline.
    #
    # No findings are created from raw check statuses.
    # No ScoreResult or ScoringPolicy is supplied.

    $session = New-WinSecResultSession `
        -DeviceId $AuditResult.DeviceId `
        -ScanId $AuditResult.ScanId `
        -ComputerName $AuditResult.ComputerName `
        -CollectionMode 'LOCAL' `
        -StartedAtUTC $AuditResult.StartedAtUTC `
        -CompletedAtUTC $AuditResult.CompletedAtUTC `
        -ExecutionStatus $AuditResult.ExecutionStatus `
        -ExpectedCheckIds $expectedIds `
        -ControlResults @($AuditResult.ControlResults) `
        -CatalogVersion ([string]$AuditResult.CatalogVersion)

    if (-not (
        Test-WinSecResultSession -Session $session
    )) {
        throw 'ResultModel rejected the coordinated scan session.'
    }

    if (
        $null -ne $session.OverallScore -or
        $session.OverallStatus -cne 'NOT_SCORED' -or
        $session.ScoringEligible -cne $false
    ) {
        throw 'Unapproved scoring was detected.'
    }

    return $session
}

# ============================================================
# PROTECT AND STORE COLLECTOR EVIDENCE
# ============================================================

function Save-WinSecCoordinatedEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [object]$Session
    )

    if (-not (
        Test-WinSecResultSession -Session $Session
    )) {
        throw 'Cannot persist evidence from an invalid session.'
    }

    $stored = 0
    $failed = 0
    $skipped = 0

    $failures = New-Object `
        'System.Collections.Generic.List[object]'

    foreach ($control in $Session.ControlResults) {

        # NOT_SELECTED records are not evidence.
        # Null observations are not written either.

        if (
            $control.Status -ceq 'NOT_SELECTED' -or
            $null -eq $control.Evidence
        ) {
            $skipped++
            continue
        }

        # AuditEngine accepts heterogeneous raw evidence.
        # EvidenceService requires an identity-bound wrapper.
        #
        # This wrapper does not change the original collector.

        $successful = (
            $control.ObservedStatus -cne 'ERROR' -and
            $control.Status -cne 'ERROR'
        )

        $wrapped = [pscustomobject]@{
            DeviceId = $Session.DeviceId
            ScanId = $Session.ScanId
            CheckId = $control.CheckId

            Evidence = [pscustomobject]@{
                DeviceId = $Session.DeviceId
                ScanId = $Session.ScanId
                CheckId = $control.CheckId

                CollectionSuccessful = [bool]$successful

                Payload = $control.Evidence
            }
        }

        try {
            $null = Save-WinSecEvidence `
                -ProjectRoot $ProjectRoot `
                -ControlResult $wrapped

            $stored++
        }
        catch {
            $failed++

            # Do not expose raw collector values or paths
            # through storage diagnostic messages.

            $failures.Add(
                [pscustomobject]@{
                    CheckId = [string]$control.CheckId

                    ErrorType = (
                        $_.Exception.GetType().Name
                    )

                    Status = 'STORAGE_FAILED'
                }
            )
        }
    }

    $status = 'STORED'

    if ($failed -gt 0 -and $stored -gt 0) {
        $status = 'PARTIAL'
    }
    elseif ($failed -gt 0) {
        $status = 'FAILED'
    }
    elseif ($stored -eq 0) {
        $status = 'NO_EVIDENCE'
    }

    return [pscustomobject]@{
        DeviceId = $Session.DeviceId
        ScanId = $Session.ScanId

        Status = $status

        StoredCount = $stored
        FailedCount = $failed
        SkippedCount = $skipped

        Failures = @($failures.ToArray())
    }
}

# ============================================================
# EXECUTE ONE COORDINATED SCAN
# ============================================================

function Get-WinSecScanConfirmationPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Coordinator,
        [string]$DeviceId = '',
        [string[]]$CheckIds
    )

    $target = Resolve-WinSecScanTarget -Coordinator $Coordinator -DeviceId $DeviceId
    if ($Coordinator.ScoringEnabled -cne $false -or
        $Coordinator.RemoteExecution -cne $false -or
        $Coordinator.AutomaticEvidencePersistence -cne $false) {
        throw 'Unsafe scan coordinator configuration.'
    }

    $catalogPath = Join-Path $Coordinator.ProjectRoot 'config/checks.json'
    $catalogHash = (Get-FileHash -LiteralPath $catalogPath -Algorithm SHA256 -ErrorAction Stop).Hash
    $registry = Get-WinSecCheckRegistry -ProjectRoot $Coordinator.ProjectRoot
    if ((Get-FileHash -LiteralPath $catalogPath -Algorithm SHA256 -ErrorAction Stop).Hash -cne $catalogHash) {
        throw 'Check catalog changed during scan preparation.'
    }

    $explicit = $PSBoundParameters.ContainsKey('CheckIds')
    $selected = @()
    if ($explicit) {
        if (@($CheckIds).Count -eq 0) { throw 'CheckIds cannot be an empty explicit selection.' }
        $seen = @{}
        foreach ($id in $CheckIds) {
            Assert-WinSecScanIdentifier -Value $id -FieldName 'CheckId'
            if ($seen.ContainsKey($id)) { throw 'Duplicate selected CheckId.' }
            $seen[$id] = $true
            $check = Get-WinSecRegisteredCheck -Registry $registry -CheckId $id
            if ($null -eq $check -or $check.CheckId -cne $id) {
                throw 'Selected check is not registered.'
            }
            $selected += $check
        }
    }
    else {
        $selected = @(Get-WinSecExecutableChecks -Registry $registry)
    }

    $checks = @()
    $sources = @()
    foreach ($check in @($selected | Sort-Object CheckId)) {
        if ($check.ExecutionEnabled -cne $true -or $check.ExecutionReady -cne $true -or
            $check.ImplementationStatus -cne 'VALIDATED' -or $check.RegistryStatus -cne 'READY') {
            throw 'Selected check is not executable.'
        }
        Assert-WinSecScanIdentifier -Value $check.CheckId -FieldName 'CheckId'
        if (-not (Test-WinSecResultText $check.Name) -or
            $check.SectionKey -cnotin @('SystemSecurity', 'NetworkSecurity',
                'IdentityAccess', 'LoggingAuditing', 'ServicesHardening')) {
            throw 'Invalid check confirmation metadata.'
        }
        $checks += [pscustomobject]@{
            CheckId = $check.CheckId
            Name = $check.Name
            SectionKey = $check.SectionKey
        }
        $sources += (Get-FileHash -LiteralPath $check.ScriptPath -Algorithm SHA256 -ErrorAction Stop).Hash
    }

    $request = [pscustomobject]@{
        Operation = 'SCAN'
        DeviceId = $target.DeviceId
        Hostname = $target.Hostname
        SelectionMode = if ($explicit) { 'EXPLICIT_CHECKS' } else { 'ALL_EXECUTABLE' }
        ReadOnly = $true
        CatalogVersion = $registry.CatalogVersion
        Checks = @($checks)
    }
    $requestJson = ConvertTo-Json -InputObject $request -Depth 8 -Compress
    return [pscustomobject]@{
        Target = $target
        Registry = $registry
        CheckIds = @($checks | ForEach-Object { $_.CheckId })
        RequestJson = $requestJson
        Fingerprint = [System.IO.Path]::GetFullPath($Coordinator.ProjectRoot) +
            '|' + $catalogHash + '|' + ($sources -join '|') + '|' + $requestJson
    }
}

function Invoke-WinSecCoordinatedScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Coordinator,

        [string]$DeviceId = '',

        [string]$ScanId = '',

        [string[]]$CheckIds,

        [switch]$PersistEvidence,

        [scriptblock]$ConfirmAction,

        [scriptblock]$ConfirmEvidenceAction
    )

    Assert-WinSecScanCoordinator `
        -Coordinator $Coordinator

    if ($null -eq $ConfirmAction) {
        throw 'Explicit confirmation is required for every scan operation.'
    }
    if ($PersistEvidence -and $null -eq $ConfirmEvidenceAction) {
        throw 'Raw evidence storage requires separate explicit confirmation.'
    }

    $target = Resolve-WinSecScanTarget `
        -Coordinator $Coordinator `
        -DeviceId $DeviceId

    if ([string]::IsNullOrWhiteSpace($ScanId)) {
        $ScanId = New-WinSecAuditScanId
    }

    Assert-WinSecScanIdentifier `
        -Value $ScanId `
        -FieldName 'ScanId'

    $key = Get-WinSecScanSessionKey `
        -DeviceId $target.DeviceId `
        -ScanId $ScanId

    if ($Coordinator.Sessions.ContainsKey($key)) {
        throw (
            'The requested DeviceId / ScanId already exists.'
        )
    }

    # Check explicit selection before any execution.
    # AuditEngine will perform final registry validation.

    $explicitSelection = $PSBoundParameters.ContainsKey(
        'CheckIds'
    )

    if ($explicitSelection) {

        if (@($CheckIds).Count -eq 0) {
            throw 'CheckIds cannot be an empty explicit selection.'
        }

        $seenChecks = New-Object `
            'System.Collections.Generic.HashSet[string]' `
            ([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($checkId in $CheckIds) {

            Assert-WinSecScanIdentifier `
                -Value $checkId `
                -FieldName 'CheckId'

            if (-not $seenChecks.Add($checkId)) {
                throw "Duplicate selected CheckId: $checkId"
            }
        }
    }

    # Confirmation is per invocation; no approval flag is cached or reused.
    $planArguments = @{ Coordinator = $Coordinator; DeviceId = $target.DeviceId }
    if ($explicitSelection) { $planArguments.CheckIds = $CheckIds }
    $plan = Get-WinSecScanConfirmationPlan @planArguments
    $preview = ConvertFrom-Json -InputObject $plan.RequestJson -ErrorAction Stop
    try { $decision = @(& $ConfirmAction $preview) }
    catch { throw 'Unable to obtain scan confirmation.' }
    if ($decision.Count -ne 1 -or $decision[0] -isnot [bool]) {
        throw 'Scan confirmation must return exactly one Boolean decision.'
    }
    if ($decision[0] -eq $false) { return $null }
    if ((ConvertTo-Json -InputObject $preview -Depth 8 -Compress) -cne $plan.RequestJson) {
        throw 'The displayed scan request was modified.'
    }
    if ($plan.CheckIds.Count -eq 0) {
        throw 'NO_EXECUTABLE_CHECKS: no scan was started.'
    }

    if ($PersistEvidence) {
        $evidencePreview = ConvertFrom-Json -InputObject $plan.RequestJson -ErrorAction Stop
        $evidencePreview.Operation = 'STORE_RAW_EVIDENCE'
        $evidenceRequestJson = ConvertTo-Json -InputObject $evidencePreview -Depth 8 -Compress
        try { $evidenceDecision = @(& $ConfirmEvidenceAction $evidencePreview) }
        catch { throw 'Unable to obtain separate evidence confirmation.' }
        if ($evidenceDecision.Count -ne 1 -or $evidenceDecision[0] -isnot [bool]) {
            throw 'Evidence confirmation must return exactly one Boolean decision.'
        }
        if ($evidenceDecision[0] -eq $false) { return $null }
        if ((ConvertTo-Json -InputObject $evidencePreview -Depth 8 -Compress) -cne $evidenceRequestJson) {
            throw 'The displayed evidence request was modified.'
        }
    }

    # Revalidate after user interaction, then execute exactly that selection.
    $approvedPlan = Get-WinSecScanConfirmationPlan @planArguments
    if ($approvedPlan.Fingerprint -cne $plan.Fingerprint -or
        $Coordinator.Sessions.ContainsKey($key)) {
        throw 'Scan authorization changed after confirmation; confirm a new request.'
    }

    # Preflight evidence storage before running checks.
    # Actual writes only occur when PersistEvidence is set.

    if ($PersistEvidence) {

        $null = Assert-WinSecEvidenceProtection

        $null = Get-WinSecEvidenceStorageRoot `
            -ProjectRoot $Coordinator.ProjectRoot
    }

    # --------------------------------------------------------
    # EXECUTION
    # --------------------------------------------------------

    # Always disable AuditEngine's legacy score calculation.
    # Production scoring requires a separate, authorized
    # CriteriaService -> EvaluationEngine -> ScoreEngine path.

    $audit = Invoke-WinSecAudit `
        -DeviceId $target.DeviceId `
        -ScanId $ScanId `
        -CheckIds $approvedPlan.CheckIds `
        -Registry $approvedPlan.Registry `
        -SkipScoring

    # --------------------------------------------------------
    # VALIDATE AUDIT RESULT
    # --------------------------------------------------------

    Assert-WinSecCoordinatedAuditResult `
        -AuditResult $audit `
        -DeviceId $target.DeviceId `
        -ScanId $ScanId

    $executedIds = @($audit.ControlResults | Where-Object {
        $_.Status -cne 'NOT_SELECTED'
    } | ForEach-Object { $_.CheckId } | Sort-Object)
    if (($executedIds -join '|') -cne (@($approvedPlan.CheckIds | Sort-Object) -join '|') -or
        $audit.CatalogVersion -cne $approvedPlan.Registry.CatalogVersion) {
        throw 'Audit result does not match the confirmed check selection.'
    }

    $session = ConvertTo-WinSecCoordinatedSession `
        -AuditResult $audit

    # The public representation contains no raw Evidence.

    $public = ConvertTo-WinSecPublicScanResult `
        -Session $session

    # --------------------------------------------------------
    # REGISTER SESSION IN MEMORY
    # --------------------------------------------------------

    $storage = [pscustomobject]@{
        DeviceId = $target.DeviceId
        ScanId = $ScanId

        Status = 'NOT_REQUESTED'

        StoredCount = 0
        FailedCount = 0
        SkippedCount = 0

        Failures = @()
    }

    $entry = [pscustomobject]@{
        DeviceId = $target.DeviceId
        ScanId = $ScanId

        Session = $session

        EvidenceStorage = $storage

        RegisteredAtUTC = [DateTime]::UtcNow.ToString('o')
    }

    $Coordinator.Sessions[$key] = $entry

    # --------------------------------------------------------
    # OPTIONAL EVIDENCE PERSISTENCE
    # --------------------------------------------------------

    if ($PersistEvidence) {

        $storage = Save-WinSecCoordinatedEvidence `
            -ProjectRoot $Coordinator.ProjectRoot `
            -Session $session

        $entry.EvidenceStorage = $storage
    }

    # --------------------------------------------------------
    # RETURN PUBLIC PROJECTION
    # --------------------------------------------------------

    # Do not return the raw session by default.

    $public | Add-Member `
        -NotePropertyName EvidenceStorageStatus `
        -NotePropertyValue $storage.Status

    $public | Add-Member `
        -NotePropertyName StoredEvidenceCount `
        -NotePropertyValue $storage.StoredCount

    $public | Add-Member `
        -NotePropertyName FailedEvidenceCount `
        -NotePropertyValue $storage.FailedCount

    return $public
}

# ============================================================
# GET INTERNAL SESSION
# ============================================================

function Get-WinSecCoordinatorSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Coordinator,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId
    )

    Assert-WinSecScanCoordinator `
        -Coordinator $Coordinator

    $key = Get-WinSecScanSessionKey `
        -DeviceId $DeviceId `
        -ScanId $ScanId

    if (-not $Coordinator.Sessions.ContainsKey($key)) {
        return $null
    }

    $entry = $Coordinator.Sessions[$key]

    if (-not (
        Test-WinSecResultSession -Session $entry.Session
    )) {
        throw 'Stored internal scan session failed validation.'
    }

    # INTERNAL ONLY: includes original collector evidence.
    # Never export this object directly to public reports.

    return $entry.Session
}

# ============================================================
# GET PUBLIC SESSION
# ============================================================

function Get-WinSecCoordinatorPublicResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Coordinator,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId
    )

    $session = Get-WinSecCoordinatorSession `
        -Coordinator $Coordinator `
        -DeviceId $DeviceId `
        -ScanId $ScanId

    if ($null -eq $session) {
        return $null
    }

    return ConvertTo-WinSecPublicScanResult `
        -Session $session
}

# ============================================================
# GET SCAN HISTORY
# ============================================================

function Get-WinSecCoordinatorHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Coordinator,

        [string]$DeviceId = ''
    )

    Assert-WinSecScanCoordinator `
        -Coordinator $Coordinator

    if (-not [string]::IsNullOrWhiteSpace($DeviceId)) {
        Assert-WinSecScanIdentifier `
            -Value $DeviceId `
            -FieldName 'DeviceId'
    }

    $history = New-Object `
        'System.Collections.Generic.List[object]'

    foreach ($entry in $Coordinator.Sessions.Values) {

        if (
            $DeviceId -and
            -not [string]::Equals(
                $entry.DeviceId,
                $DeviceId,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            continue
        }

        $public = ConvertTo-WinSecPublicScanResult `
            -Session $entry.Session

        # Only metadata is included in history.
        # No raw evidence, file paths or collector secrets.

        $history.Add(
            [pscustomobject]@{
                DeviceId = $public.DeviceId
                ScanId = $public.ScanId

                StartedAtUTC = $public.StartedAtUTC
                CompletedAtUTC = $public.CompletedAtUTC

                ExecutionStatus = $public.ExecutionStatus

                OverallScore = $public.OverallScore
                OverallStatus = $public.OverallStatus

                EvidenceStorageStatus = (
                    $entry.EvidenceStorage.Status
                )

                StoredEvidenceCount = (
                    $entry.EvidenceStorage.StoredCount
                )

                FailedEvidenceCount = (
                    $entry.EvidenceStorage.FailedCount
                )
            }
        )
    }

    return @(
        $history.ToArray() |
            Sort-Object StartedAtUTC, ScanId
    )
}
