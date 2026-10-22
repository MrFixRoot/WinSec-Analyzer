
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
    'src/Core/DeviceInventory.ps1'
    'src/Core/ResultModel.ps1'
    'src/Services/EvidenceService.ps1'
    'src/Core/AuditEngine.ps1'
    'src/Services/DeviceManagementService.ps1'
    'src/Services/PublicHistoryService.ps1'
    'src/Services/CriteriaService.ps1'
    'src/Services/SystemInfoService.ps1'
    'src/Core/EvaluationEngine.ps1'
    'src/Core/FindingsEngine.ps1'
    'src/Services/AssessmentService.ps1'
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
    $inventoryRequirement = Get-WinSecTargetField -InputObject $Coordinator -Name 'RequireDeviceInventory'
    if ($null -ne $inventoryRequirement -and $inventoryRequirement -isnot [bool]) {
        throw 'Invalid inventory authorization requirement.'
    }
    foreach($field in @('PublicHistoryEnabled','HistoryLoadFailed','AssessmentEnabled')){
        $value=Get-WinSecTargetField $Coordinator $field
        if($null -ne $value -and $value -isnot [bool]){throw 'Invalid public history coordination flag.'}
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
        RequireDeviceInventory = $false
        PublicHistoryEnabled = $false
        AssessmentEnabled = $false
        HistoryLoadFailed = $false

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

    # A confirmed removal also revokes direct calls made outside the CLI.
    $inventory = Import-WinSecDeviceInventory -ProjectRoot $Coordinator.ProjectRoot
    if (Test-WinSecDeviceInventoryRemoval -Inventory $inventory -DeviceId $target.DeviceId) {
        throw 'Target was removed from the managed inventory.'
    }
    # Persistence can restrict permission; it never adds targets to the catalog.
    if ((Get-WinSecTargetField -InputObject $Coordinator -Name 'RequireDeviceInventory') -ceq $true) {
        $saved = @($inventory.targets | Where-Object {
            [string]::Equals($_.DeviceId, $localDevice.DeviceId, [System.StringComparison]::OrdinalIgnoreCase)
        })
        if ($saved.Count -ne 1 -or $saved[0].Mode -cne 'LOCAL' -or $saved[0].Enabled -cne $true -or
            -not [string]::Equals($saved[0].Hostname, $localDevice.Hostname, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Local inventory does not permit this operation.'
        }
    }
    # Hostname is display metadata, never the authorization identity.
    $target.Hostname = $localDevice.Hostname
    $target.Name = $localDevice.Hostname

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
        [object]$AuditResult,

        [AllowNull()][object]$ScopeType = $null,
        [AllowNull()][object]$ScopeKey = $null,
        [AllowNull()][object]$Assessment = $null
    )

    $expectedIds = @(
        foreach ($record in $AuditResult.ControlResults) {
            if ($record.Status -cne 'NOT_SELECTED') {
                [string]$record.CheckId
            }
        }
    )

    # Findings come from the criteria/evaluation pipeline, never raw statuses.
    # No ScoreResult or ScoringPolicy is supplied: numeric scoring stays disabled.

    $scopeArguments = @{}
    if ($null -ne $Assessment) {
        $scopeArguments.EvaluationResults = @($Assessment.EvaluationResults)
        $scopeArguments.CriteriaSelections = @($Assessment.CriteriaSelections)
        $scopeArguments.Findings = @($Assessment.Findings)
        if ($null -ne (Get-WinSecResultField $Assessment 'ConfigurationAssessment')) {
            $scopeArguments.ConfigurationAssessment=$Assessment.ConfigurationAssessment
        }
    }
    if ($PSBoundParameters.ContainsKey('ScopeType') -or $PSBoundParameters.ContainsKey('ScopeKey')) {
        $scopeArguments.ScopeType = $ScopeType
        $scopeArguments.ScopeKey = $ScopeKey
    }

    $session = New-WinSecResultSession @scopeArguments `
        -DeviceId $AuditResult.DeviceId `
        -ScanId $AuditResult.ScanId `
        -ComputerName $AuditResult.ComputerName `
        -CollectionMode 'LOCAL' `
        -StartedAtUTC $AuditResult.StartedAtUTC `
        -CompletedAtUTC $AuditResult.CompletedAtUTC `
        -ExecutionStatus $AuditResult.ExecutionStatus `
        -ExpectedCheckIds $expectedIds `
        -ControlResults @($AuditResult.ControlResults) `
        -ReviewItems @(foreach ($control in $AuditResult.ControlResults) {
            New-WinSecDefenderReviewItems -ControlResult $control
            New-WinSecBitLockerReviewItems -ControlResult $control
        }) `
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
        [string[]]$CheckIds,
        [AllowNull()][object]$ScopeType = $null,
        [AllowNull()][object]$ScopeKey = $null,
        [AllowNull()][object]$AssessmentProfile = $null
    )

    $explicit = $PSBoundParameters.ContainsKey('CheckIds')
    $hasScope = $PSBoundParameters.ContainsKey('ScopeType') -or $PSBoundParameters.ContainsKey('ScopeKey')
    if ($hasScope -and $explicit) {
        throw 'Scope and legacy CheckIds cannot be combined.'
    }
    # The existing default selects the whole device. An arbitrary legacy
    # CheckIds subset cannot establish a DEVICE, SECTION or CONTROL scope.
    if (-not $hasScope -and -not $explicit) {
        $hasScope = $true
        $ScopeType = 'DEVICE'
        $ScopeKey = 'ALL'
    }
    if ($hasScope) {
        Assert-WinSecResultScope -ScopeType $ScopeType -ScopeKey $ScopeKey
        if ($ScopeType -ceq 'CONTROL') {
            Assert-WinSecScanIdentifier -Value $ScopeKey -FieldName 'CheckId'
        }
    }

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

    $selected = @()
    if ($hasScope -and $ScopeType -ceq 'SECTION') {
        $selected = @(Get-WinSecExecutableChecks -Registry $registry -SectionKey $ScopeKey)
    }
    elseif ($hasScope -and $ScopeType -ceq 'CONTROL') {
        $check = Get-WinSecRegisteredCheck -Registry $registry -CheckId $ScopeKey
        if ($null -eq $check -or $check.CheckId -cne $ScopeKey) {
            throw 'Selected scope control is not registered.'
        }
        $selected = @($check)
    }
    elseif ($explicit) {
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
    $selectedIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($check in @($selected | Sort-Object CheckId)) {
        if ($check.ExecutionEnabled -cne $true -or $check.ExecutionReady -cne $true -or
            $check.ImplementationStatus -cne 'VALIDATED' -or $check.RegistryStatus -cne 'READY') {
            throw 'Selected check is not executable.'
        }
        Assert-WinSecScanIdentifier -Value $check.CheckId -FieldName 'CheckId'
        if (-not $selectedIds.Add($check.CheckId)) { throw 'Duplicate executable CheckId.' }
        if (-not (Test-WinSecResultText $check.Name) -or
            $check.SectionKey -cnotin @('SystemSecurity', 'NetworkSecurity',
                'IdentityAccess', 'LoggingAuditing', 'ServicesHardening')) {
            throw 'Invalid check confirmation metadata.'
        }
        if ($hasScope -and
            (($ScopeType -ceq 'SECTION' -and $check.SectionKey -cne $ScopeKey) -or
             ($ScopeType -ceq 'CONTROL' -and $check.CheckId -cne $ScopeKey))) {
            throw 'Check selection does not match the requested scope.'
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
        SelectionMode = if ($explicit -or ($hasScope -and $ScopeType -cne 'DEVICE')) {
            'EXPLICIT_CHECKS'
        } else { 'ALL_EXECUTABLE' }
        ReadOnly = $true
        CatalogVersion = $registry.CatalogVersion
        Checks = @($checks)
    }
    if ($hasScope) {
        $request | Add-Member -NotePropertyName ScopeType -NotePropertyValue $ScopeType
        $request | Add-Member -NotePropertyName ScopeKey -NotePropertyValue $ScopeKey
    }
    $scanAction = 'Scan'
    if ($hasScope) {
        $scanAction = Get-WinSecScanAction -Coordinator $Coordinator -DeviceId $target.DeviceId `
            -ScopeType $ScopeType -ScopeKey $ScopeKey
    }
    $request | Add-Member -NotePropertyName ScanAction -NotePropertyValue $scanAction
    $profilePlan = $null
    if ($PSBoundParameters.ContainsKey('AssessmentProfile')) {
        if ((Get-WinSecTargetField $Coordinator 'AssessmentEnabled') -cne $true) {
            throw 'Profile selection requires the assessment pipeline.'
        }
        $profilePlan = Get-WinSecAssessmentProfilePlan -ProjectRoot $Coordinator.ProjectRoot `
            -CheckIds @($checks|ForEach-Object {$_.CheckId}) -Profile $AssessmentProfile
        $request | Add-Member -NotePropertyName EvaluationProfile -NotePropertyValue $profilePlan.Preview
    }
    $configurationPolicy=$null
    if ($null -ne $profilePlan -and @($profilePlan.Catalogs.Values|Where-Object {$null -ne $_ -and $_.Catalog.ScoringEnabled -ceq $true}).Count) {
        $configurationPolicy=Get-WinSecConfigurationScoringPolicy $Coordinator.ProjectRoot
        if ($null -ne $configurationPolicy -and $configurationPolicy.Policy.enabled) {
            $request|Add-Member -NotePropertyName ConfigurationScoring -NotePropertyValue ([pscustomobject]@{
                MethodologyId=$configurationPolicy.Policy.methodologyId;MethodologyVersion=$configurationPolicy.Policy.methodologyVersion;PolicySha256=$configurationPolicy.Sha256})
        }
    }
    $requestJson = ConvertTo-Json -InputObject $request -Depth 8 -Compress
    return [pscustomobject]@{
        Target = $target
        Registry = $registry
        CheckIds = @($checks | ForEach-Object { $_.CheckId })
        ScopeType = if ($hasScope) { $ScopeType } else { $null }
        ScopeKey = if ($hasScope) { $ScopeKey } else { $null }
        AssessmentCatalogs = if ($null -ne $profilePlan) { $profilePlan.Catalogs } else { $null }
        ConfigurationPolicy = $configurationPolicy
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

        [scriptblock]$ConfirmEvidenceAction,

        [AllowNull()][object]$ScopeType = $null,
        [AllowNull()][object]$ScopeKey = $null,

        [scriptblock]$ProgressCallback,
        [scriptblock]$CancellationAction,
        [AllowNull()][object]$TargetContext = $null,
        [AllowNull()][System.Collections.IDictionary]$DependencyEvidence = $null,
        [AllowNull()][object]$AssessmentProfile = $null
    )

    Assert-WinSecScanCoordinator `
        -Coordinator $Coordinator

    if ($null -eq $ConfirmAction) {
        throw 'Explicit confirmation is required for every scan operation.'
    }
    if ((Get-WinSecTargetField $Coordinator 'HistoryLoadFailed') -ceq $true) { throw 'Public history must be recovered before scanning.' }
    $publicHistoryEnabled=(Get-WinSecTargetField $Coordinator 'PublicHistoryEnabled') -ceq $true
    $assessmentEnabled=(Get-WinSecTargetField $Coordinator 'AssessmentEnabled') -ceq $true
    $assessmentInputs = Copy-WinSecResultData ([pscustomobject]@{TargetContext=$TargetContext;DependencyEvidence=$DependencyEvidence})
    $hasProfile = $PSBoundParameters.ContainsKey('AssessmentProfile')
    if ($hasProfile) {
        if (-not $assessmentEnabled -or -not (Test-WinSecTargetIdentifier $AssessmentProfile) -or
            $AssessmentProfile -in @('UNRESOLVED','PENDING_SELECTION')) {
            throw 'A concrete profile requires the assessment pipeline.'
        }
        $contextProfile = Get-WinSecResultField $assessmentInputs.TargetContext 'Profile'
        if ($null -ne $contextProfile -and ($contextProfile -isnot [string] -or
            ($contextProfile -cne 'UNRESOLVED' -and $contextProfile -cne $AssessmentProfile))) {
            throw 'Explicit profile conflicts with the assessment context.'
        }
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

    if ($null -ne $assessmentInputs.TargetContext -and
        ($assessmentInputs.TargetContext.DeviceId -isnot [string] -or $assessmentInputs.TargetContext.ScanId -isnot [string] -or
         $assessmentInputs.TargetContext.DeviceId -cne $target.DeviceId -or $assessmentInputs.TargetContext.ScanId -cne $ScanId)) {
        throw 'Assessment context belongs to another device or scan.'
    }

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
    if ($hasProfile) { $planArguments.AssessmentProfile = $AssessmentProfile }
    if ($explicitSelection) { $planArguments.CheckIds = $CheckIds }
    foreach ($name in @('ScopeType','ScopeKey')) {
        if ($PSBoundParameters.ContainsKey($name)) { $planArguments[$name] = $PSBoundParameters[$name] }
    }
    if ($publicHistoryEnabled -and
        -not $planArguments.ContainsKey('ScopeType') -and -not $planArguments.ContainsKey('ScopeKey')) {
        if($explicitSelection){throw 'Persistent explicit selections require a declared scope.'}
        $planArguments.ScopeType='DEVICE';$planArguments.ScopeKey='ALL'
    }
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
    # Freeze approved-catalog data before collecting. Evaluation never silently
    # switches to a policy edited while a collector is running.
    $assessmentCatalogs = @{}
    if ($hasProfile) {
        $assessmentCatalogs = Copy-WinSecResultData $approvedPlan.AssessmentCatalogs
    }
    elseif ($assessmentEnabled) {
        foreach ($checkId in $approvedPlan.CheckIds) {
            $assessmentCatalogs[$checkId] = Copy-WinSecResultData `
                (Get-WinSecAssessmentCatalog -ProjectRoot $Coordinator.ProjectRoot -CheckId $checkId)
        }
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

    if ((Get-WinSecTargetField $Coordinator 'HistoryLoadFailed') -ceq $true) { throw 'Public history became unavailable before collection.' }
    Assert-WinSecScanCoordinator -Coordinator $Coordinator
    if(((Get-WinSecTargetField $Coordinator 'PublicHistoryEnabled') -ceq $true) -cne $publicHistoryEnabled){throw 'Public history mode changed during confirmation.'}
    if(((Get-WinSecTargetField $Coordinator 'AssessmentEnabled') -ceq $true) -cne $assessmentEnabled){throw 'Assessment mode changed during confirmation.'}
    $executionCallbacks = @{}
    if ($null -ne $ProgressCallback) { $executionCallbacks.ProgressCallback = $ProgressCallback }
    if ($null -ne $CancellationAction) { $executionCallbacks.CancellationAction = $CancellationAction }
    try {
        $audit = Invoke-WinSecAudit @executionCallbacks `
            -DeviceId $target.DeviceId `
            -ScanId $ScanId `
            -CheckIds $approvedPlan.CheckIds `
            -Registry $approvedPlan.Registry `
            -SkipScoring
    }
    catch [OperationCanceledException] {
        # Discard partial records; no public session or persistence on cancellation.
        return $null
    }
    if (Test-WinSecScanCancellation -CancellationAction $CancellationAction) {
        Send-WinSecScanProgress -ProgressCallback $ProgressCallback -DeviceId $target.DeviceId -ScanId $ScanId `
            -Phase CANCELLED -CompletedChecks $approvedPlan.CheckIds.Count -TotalChecks $approvedPlan.CheckIds.Count
        return $null
    }
    # Cancellation closes before validation/persistence starts. No claims of
    # completion are emitted until the public session has actually been published.
    Send-WinSecScanProgress -ProgressCallback $ProgressCallback -DeviceId $target.DeviceId -ScanId $ScanId `
        -Phase FINALIZING -CompletedChecks $approvedPlan.CheckIds.Count -TotalChecks $approvedPlan.CheckIds.Count

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
    # Validate catalog section identity as well as the selected CheckIds.
    # A collector cannot relabel its result while retaining an approved ID.
    foreach ($record in $audit.ControlResults) {
        if ($record.Status -ceq 'NOT_SELECTED') { continue }
        $check = Get-WinSecRegisteredCheck -Registry $approvedPlan.Registry -CheckId $record.CheckId
        if ($null -eq $check -or $record.SectionKey -cne $check.SectionKey) {
            throw 'Audit result does not match the confirmed control section.'
        }
    }

    $scopeArguments = @{}
    if ($null -ne $approvedPlan.ScopeType) {
        $scopeArguments.ScopeType = $approvedPlan.ScopeType
        $scopeArguments.ScopeKey = $approvedPlan.ScopeKey
    }
    Assert-WinSecScanCoordinator -Coordinator $Coordinator
    if (((Get-WinSecTargetField $Coordinator 'AssessmentEnabled') -ceq $true) -cne $assessmentEnabled) {
        throw 'Assessment mode changed during collection.'
    }
    if ($assessmentEnabled) {
        if ($null -eq $assessmentInputs.TargetContext) {
            # Collect applicability metadata only for this completed, confirmed
            # local scan. Policy profile remains unresolved until selected.
            $assessmentInputs.TargetContext = Get-WinSecLocalAssessmentContext `
                -DeviceId $target.DeviceId -ScanId $ScanId
        }
        if ($hasProfile) {
            if ($assessmentInputs.TargetContext -is [System.Collections.IDictionary]) {
                $assessmentInputs.TargetContext['Profile'] = $AssessmentProfile
            }
            elseif ($assessmentInputs.TargetContext -is [pscustomobject]) {
                $assessmentInputs.TargetContext | Add-Member -NotePropertyName Profile -NotePropertyValue $AssessmentProfile -Force
            }
            else { throw 'Invalid assessment target context.' }
        }
        $scopeArguments.Assessment = Invoke-WinSecScanAssessment -AuditResult $audit -ProjectRoot $Coordinator.ProjectRoot `
            -TargetContext $assessmentInputs.TargetContext -DependencyEvidence $assessmentInputs.DependencyEvidence `
            -CatalogSnapshots $assessmentCatalogs
        if ($null -ne $approvedPlan.ConfigurationPolicy) {
            $summary=New-WinSecConfigurationAssessment -Audit $audit -Assessment $scopeArguments.Assessment `
                -Context $assessmentInputs.TargetContext -Registry $approvedPlan.Registry -Catalogs $assessmentCatalogs `
                -PolicySnapshot $approvedPlan.ConfigurationPolicy -ScopeType $approvedPlan.ScopeType -ScopeKey $approvedPlan.ScopeKey -ProjectRoot $Coordinator.ProjectRoot
            if ($null -ne $summary) {$scopeArguments.Assessment|Add-Member -NotePropertyName ConfigurationAssessment -NotePropertyValue $summary}
        }
    }
    $session = ConvertTo-WinSecCoordinatedSession @scopeArguments `
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

    Assert-WinSecScanCoordinator -Coordinator $Coordinator
    if ((Get-WinSecTargetField $Coordinator 'HistoryLoadFailed') -ceq $true) { throw 'Public history is unavailable.' }
    if(((Get-WinSecTargetField $Coordinator 'PublicHistoryEnabled') -ceq $true) -cne $publicHistoryEnabled){throw 'Public history mode changed during collection.'}
    if(((Get-WinSecTargetField $Coordinator 'AssessmentEnabled') -ceq $true) -cne $assessmentEnabled){throw 'Assessment mode changed during validation.'}
    if ($publicHistoryEnabled -and
        $session.ExecutionStatus -cin @('COMPLETED','COMPLETED_WITH_ERRORS')) {
        $null=Save-WinSecPublicHistory -ProjectRoot $Coordinator.ProjectRoot -Session $session
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

    Send-WinSecScanProgress -ProgressCallback $ProgressCallback -DeviceId $target.DeviceId -ScanId $ScanId `
        -Phase $session.ExecutionStatus -CompletedChecks $approvedPlan.CheckIds.Count -TotalChecks $approvedPlan.CheckIds.Count
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

    # Own the response before validation; never return a reference into the store.
    $snapshot = Copy-WinSecResultData -Value ([pscustomobject]@{
        DeviceId = $entry.DeviceId
        ScanId = $entry.ScanId
        Session = $entry.Session
    })
    if ($snapshot.DeviceId -isnot [string] -or $snapshot.ScanId -isnot [string] -or
        -not [string]::Equals($snapshot.DeviceId,$DeviceId,[StringComparison]::OrdinalIgnoreCase) -or
        $snapshot.ScanId -cne $ScanId -or $null -eq $snapshot.Session) {
        throw 'Stored internal scan session failed validation.'
    }

    if (-not (
        Test-WinSecResultSession -Session $snapshot.Session
    ) -or $snapshot.Session.DeviceId -cne $snapshot.DeviceId -or
        $snapshot.Session.ScanId -cne $snapshot.ScanId) {
        throw 'Stored internal scan session failed validation.'
    }

    # INTERNAL ONLY: the isolated copy includes collector evidence.
    # Never export this object directly to public reports.

    return $snapshot.Session
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

        [string]$DeviceId = '',

        [AllowNull()][object]$ScopeType = $null,
        [AllowNull()][object]$ScopeKey = $null
    )

    Assert-WinSecScanCoordinator `
        -Coordinator $Coordinator

    if ($DeviceId.Length -gt 0) {
        Assert-WinSecScanIdentifier `
            -Value $DeviceId `
            -FieldName 'DeviceId'
    }
    $hasScopeFilter = $PSBoundParameters.ContainsKey('ScopeType') -or $PSBoundParameters.ContainsKey('ScopeKey')
    if ($hasScopeFilter) {
        if ($DeviceId.Length -eq 0) { throw 'Scope history requires a device identifier.' }
        Assert-WinSecResultScope -ScopeType $ScopeType -ScopeKey $ScopeKey
        if ($ScopeType -ceq 'CONTROL') {
            Assert-WinSecScanIdentifier -Value $ScopeKey -FieldName 'CheckId'
        }
    }

    $history = New-Object `
        'System.Collections.Generic.List[object]'

    $integerTypes = @([byte],[sbyte],[int16],[uint16],[int32],[uint32],[int64],[uint64])
    foreach ($item in $Coordinator.Sessions.GetEnumerator()) {

        if ($item.Key -isnot [string]) { throw 'Stored scan history failed validation.' }
        $identity = $item.Key.Split([char]'|')
        if ($identity.Count -ne 2) { throw 'Stored scan history failed validation.' }
        try { $null = Get-WinSecScanSessionKey -DeviceId $identity[0] -ScanId $identity[1] }
        catch { throw 'Stored scan history failed validation.' }

        if (
            $DeviceId -and
            -not [string]::Equals(
                $identity[0],
                $DeviceId,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            continue
        }

        # Validate an owned entry; filter by the index before reading other devices.
        $entry = Copy-WinSecResultData -Value $item.Value
        if (($entry -isnot [pscustomobject] -and $entry -isnot [System.Collections.IDictionary]) -or
            $entry.DeviceId -isnot [string] -or $entry.ScanId -isnot [string] -or
            -not [string]::Equals($entry.DeviceId,$identity[0],[StringComparison]::OrdinalIgnoreCase) -or
            $entry.ScanId -cne $identity[1] -or $null -eq $entry.Session) {
            throw 'Stored scan history failed validation.'
        }
        $public = ConvertTo-WinSecPublicScanResult `
            -Session $entry.Session
        if ($public.DeviceId -cne $entry.DeviceId -or $public.ScanId -cne $entry.ScanId) {
            throw 'Stored scan history failed validation.'
        }

        $storage = $entry.EvidenceStorage
        if (($storage -isnot [pscustomobject] -and $storage -isnot [System.Collections.IDictionary]) -or
            $storage.DeviceId -isnot [string] -or $storage.ScanId -isnot [string] -or
            $storage.DeviceId -cne $public.DeviceId -or $storage.ScanId -cne $public.ScanId -or
            $storage.Status -isnot [string] -or
            $storage.Status -cnotin @('NOT_REQUESTED','NOT_RECORDED','STORED','PARTIAL','FAILED','NO_EVIDENCE')) {
            throw 'Stored evidence metadata failed validation.'
        }
        foreach ($name in @('StoredCount','FailedCount','SkippedCount')) {
            $count = Get-WinSecResultField -InputObject $storage -Name $name
            if ($null -eq $count -or $count.GetType() -notin $integerTypes -or
                $count -lt 0 -or $count -gt [int]::MaxValue) {
                throw 'Stored evidence metadata failed validation.'
            }
        }
        $stored = [int]$storage.StoredCount
        $failed = [int]$storage.FailedCount
        $total = [long]$stored + [long]$failed + [long]$storage.SkippedCount
        if ($storage.Status -ceq 'NOT_RECORDED' -and (Get-WinSecTargetField $entry 'HistoryOrigin') -cne 'PUBLIC_STORE') {
            throw 'Unrecorded evidence metadata is restricted to restored public history.'
        }
        if ($storage.Status -cin @('NOT_REQUESTED','NOT_RECORDED')) {
            if ($total -ne 0) { throw 'Stored evidence metadata failed validation.' }
        }
        else {
            if ($total -ne @($entry.Session.ControlResults).Count) {
                throw 'Stored evidence metadata failed validation.'
            }
            $consistent = switch -CaseSensitive ($storage.Status) {
                'STORED' { $stored -gt 0 -and $failed -eq 0 }
                'PARTIAL' { $stored -gt 0 -and $failed -gt 0 }
                'FAILED' { $stored -eq 0 -and $failed -gt 0 }
                'NO_EVIDENCE' { $stored -eq 0 -and $failed -eq 0 }
            }
            if ($consistent -cne $true) { throw 'Stored evidence metadata failed validation.' }
        }

        # Filter only after validating the selected device's stored entry.
        # Legacy sessions with unknown scope cannot match an explicit scope.
        if ($hasScopeFilter -and
            ((Get-WinSecResultField $public 'ScopeType') -cne $ScopeType -or
             (Get-WinSecResultField $public 'ScopeKey') -cne $ScopeKey)) { continue }

        # Only metadata is included in history.
        # No raw evidence, file paths or collector secrets.

        $row = [pscustomobject]@{
            DeviceId = $public.DeviceId
            ScanId = $public.ScanId

            StartedAtUTC = $public.StartedAtUTC
            CompletedAtUTC = $public.CompletedAtUTC

            ExecutionStatus = $public.ExecutionStatus

            OverallScore = $public.OverallScore
            OverallStatus = $public.OverallStatus

            EvidenceStorageStatus = $storage.Status

            StoredEvidenceCount = $stored

            FailedEvidenceCount = $failed
        }
        $scopeType = Get-WinSecResultField -InputObject $public -Name 'ScopeType'
        if ($null -ne $scopeType) {
            $row | Add-Member -NotePropertyName ScopeType -NotePropertyValue $scopeType
            $row | Add-Member -NotePropertyName ScopeKey -NotePropertyValue $public.ScopeKey
        }
        $history.Add($row)
    }

    return @(
        $history.ToArray() |
            Sort-Object StartedAtUTC, ScanId, DeviceId
    )
}

# Display context only. This read never authorizes or starts a scan.
function Get-WinSecScanAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Coordinator,
        [Parameter(Mandatory)][string]$DeviceId,
        [Parameter(Mandatory)][AllowNull()][object]$ScopeType,
        [Parameter(Mandatory)][AllowNull()][object]$ScopeKey
    )
    $history = @(Get-WinSecCoordinatorHistory -Coordinator $Coordinator -DeviceId $DeviceId `
        -ScopeType $ScopeType -ScopeKey $ScopeKey)
    if (@($history | Where-Object {
        $_.ExecutionStatus -cin @('COMPLETED','COMPLETED_WITH_ERRORS')
    }).Count -gt 0) { return 'Rescan' }
    return 'Scan'
}
