
# ============================================================
# WinSec Analyzer
# Component : AuditEngine
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Coordinates registered Windows security checks,
# validates their results and calculates assessment scores.
#
# Features:
# - Explicit execution of validated controls
# - Local Windows assessments
# - DeviceId / ScanId isolation
# - Evidence collection
# - Error handling
# - Scoring integration
# - PowerShell 5.1+ compatibility
#
# Security:
# - No automatic remediation
# - No automatic privilege elevation
# - No remote execution
# - No execution of unregistered checks
#
# IMPORTANT:
# Check implementations must be reviewed for read-only
# behavior before being enabled. AST validation does not
# provide a security sandbox.
# ============================================================


# ------------------------------------------------------------
# Resolve project locations
# ------------------------------------------------------------

$script:WinSecAuditProjectRoot = (
    [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..')
    )
)

$script:WinSecAuditRegistryPath = Join-Path `
    -Path $PSScriptRoot `
    -ChildPath 'CheckRegistry.ps1'

$script:WinSecAuditScorePath = Join-Path `
    -Path $PSScriptRoot `
    -ChildPath 'ScoreEngine.ps1'


# ------------------------------------------------------------
# Load required components
# ------------------------------------------------------------

# Definitions only; no compilation or policy query while importing the engine.
# Keep check scripts function-only for Get-WinSecAuditImplementation validation.
. (Join-Path $PSScriptRoot '../Checks/System/WindowsUpdatePolicyReader.ps1')
. (Join-Path $PSScriptRoot 'WindowsUpdatePolicyApplicability.ps1')
. (Join-Path $PSScriptRoot 'FirewallTelemetry.ps1')
. (Join-Path $PSScriptRoot 'SmbTelemetry.ps1')
. (Join-Path $PSScriptRoot 'RdpTelemetry.ps1')
. (Join-Path $PSScriptRoot 'OpenPortsTelemetry.ps1')
. (Join-Path $PSScriptRoot 'NetworkConfigurationTelemetry.ps1')

function Import-WinSecAuditDependencies {
    [CmdletBinding()]
    param(
        [switch]$SkipScoring
    )

    if (-not (Get-Command New-WinSecLocalTarget -CommandType Function -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'TargetRegistry.ps1')
    }

    if (-not (
        Get-Command `
            -Name 'Get-WinSecCheckRegistry' `
            -CommandType Function `
            -ErrorAction SilentlyContinue
    )) {

        if (-not (
            Test-Path `
                -LiteralPath $script:WinSecAuditRegistryPath `
                -PathType Leaf
        )) {
            throw 'CheckRegistry.ps1 was not found.'
        }

        . $script:WinSecAuditRegistryPath
    }

    if (-not $SkipScoring) {

        if (-not (
            Get-Command `
                -Name 'Get-WinSecSecurityScore' `
                -CommandType Function `
                -ErrorAction SilentlyContinue
        )) {

            if (-not (
                Test-Path `
                    -LiteralPath $script:WinSecAuditScorePath `
                    -PathType Leaf
            )) {
                throw 'ScoreEngine.ps1 was not found.'
            }

            . $script:WinSecAuditScorePath
        }
    }
}


# ------------------------------------------------------------
# Read check result properties
# ------------------------------------------------------------

function Get-WinSecAuditField {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {

        foreach ($key in $InputObject.Keys) {

            if (
                [string]::Equals(
                    [string]$key,
                    $Name,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            ) {
                return $InputObject[$key]
            }
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}


# ------------------------------------------------------------
# Verify evidence presence
# ------------------------------------------------------------

function Test-WinSecAuditEvidence {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Evidence
    )

    if ($null -eq $Evidence) {
        return $false
    }

    if ($Evidence -is [string]) {

        return (
            -not [string]::IsNullOrWhiteSpace(
                $Evidence
            )
        )
    }

    if ($Evidence -is [System.Collections.IDictionary]) {
        return ($Evidence.Count -gt 0)
    }

    if ($Evidence -is [array]) {
        return ($Evidence.Count -gt 0)
    }

    if (
        $Evidence -is [PSCustomObject] -and
        @($Evidence.PSObject.Properties).Count -eq 0
    ) {
        return $false
    }

    return $true
}


# ------------------------------------------------------------
# Generate unique scan identifier
# ------------------------------------------------------------

function New-WinSecAuditScanId {
    [CmdletBinding()]
    param()

    return (
        'WSA-{0}-{1}' -f `
            [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'),
            [guid]::NewGuid().ToString('N').Substring(0, 8)
    )
}


# ------------------------------------------------------------
# Create normalized audit record
# ------------------------------------------------------------

function New-WinSecAuditRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Check,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [Parameter(Mandatory)]
        [string]$Status,

        [string]$ObservedStatus = '',

        [AllowNull()]
        [object]$Evidence = $null,

        [string]$NotApplicableReason = '',

        [string]$ErrorMessage = '',

        [string]$ValidationIssue = ''
    )

    return [PSCustomObject]@{
        CheckId             = $Check.CheckId
        ControlKey          = $Check.ControlKey
        SectionKey          = $Check.SectionKey
        Name                = $Check.Name

        DeviceId            = $DeviceId
        ScanId              = $ScanId

        ComputerName        = $env:COMPUTERNAME
        CollectionMode      = 'LOCAL'

        Status              = $Status
        ObservedStatus      = $ObservedStatus

        Evidence            = $Evidence
        NotApplicableReason = $NotApplicableReason

        ErrorMessage        = $ErrorMessage
        ValidationIssue     = $ValidationIssue

        AssessmentMode      = $Check.AssessmentMode
        ScoringEligible     = $Check.ScoringEligible
        CriteriaSource      = $Check.CriteriaSource

        RegistryStatus      = $Check.RegistryStatus
        TimestampUTC        = [DateTime]::UtcNow.ToString('o')
    }
}


# ------------------------------------------------------------
# Parse an implementation without executing it
# ------------------------------------------------------------

function Get-WinSecAuditImplementation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Check
    )

    if (
        -not $Check.ExecutionEnabled -or
        -not $Check.ExecutionReady -or
        $Check.ImplementationStatus -ne 'VALIDATED' -or
        $Check.RegistryStatus -ne 'READY'
    ) {
        throw "Check is not eligible for execution: $($Check.CheckId)"
    }

    if (-not (
        Test-Path `
            -LiteralPath $Check.ScriptPath `
            -PathType Leaf
    )) {
        throw "Check script not found: $($Check.ScriptPath)"
    }

    # --------------------------------------------------------
    # Read script once to avoid parsing one version
    # and invoking a subsequently modified version.
    # --------------------------------------------------------

    $source = [System.IO.File]::ReadAllText(
        $Check.ScriptPath
    )

    if ([string]::IsNullOrWhiteSpace($source)) {
        throw "Check script is empty: $($Check.CheckId)"
    }

    # Reject #Requires directives in check implementations.
    if ($source -match '(?im)^\s*#requires\b') {
        throw "Check script contains a #Requires directive."
    }

    $tokens = $null
    $parseErrors = $null

    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $source,
        $Check.ScriptPath,
        [ref]$tokens,
        [ref]$parseErrors
    )

    if (
        $null -ne $parseErrors -and
        $parseErrors.Count -gt 0
    ) {
        throw (
            "Syntax error in check '{0}': {1}" -f `
                $Check.CheckId,
                $parseErrors[0].Message
        )
    }

    # --------------------------------------------------------
    # Only top-level function definitions are accepted.
    # This prevents immediate execution of arbitrary
    # statements while importing the implementation.
    # --------------------------------------------------------

    if (
        $null -ne $ast.ParamBlock -or
        $null -ne $ast.BeginBlock -or
        $null -ne $ast.ProcessBlock -or
        $null -ne $ast.DynamicParamBlock -or
        @($ast.UsingStatements).Count -gt 0
    ) {
        throw 'Check scripts may only contain function definitions.'
    }

    $found = $false

    foreach ($statement in $ast.EndBlock.Statements) {

        if (
            $statement -isnot
            [System.Management.Automation.Language.FunctionDefinitionAst]
        ) {
            throw (
                "Top-level executable statements are not allowed: " +
                $Check.CheckId
            )
        }

        if ($statement.Name.Contains(':')) {
            throw 'Explicitly scoped function declarations are not allowed.'
        }

        if (
            [string]::Equals(
                $statement.Name,
                $Check.FunctionName,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            $found = $true
        }
    }

    if (-not $found) {
        throw (
            "Expected function '{0}' was not declared." -f `
                $Check.FunctionName
        )
    }

    # Create from the same source that was inspected.
    return [scriptblock]::Create($source)
}


# ------------------------------------------------------------
# Validate one check result
# ------------------------------------------------------------

function ConvertTo-WinSecAuditRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$RawResult,

        [Parameter(Mandatory)]
        [object]$Check,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId
    )

    # --------------------------------------------------------
    # Confirm result identity
    # --------------------------------------------------------

    $resultCheckId = [string](
        Get-WinSecAuditField `
            -InputObject $RawResult `
            -Name 'CheckId'
    )

    $resultDeviceId = [string](
        Get-WinSecAuditField `
            -InputObject $RawResult `
            -Name 'DeviceId'
    )

    $resultScanId = [string](
        Get-WinSecAuditField `
            -InputObject $RawResult `
            -Name 'ScanId'
    )

    $resultSectionKey = [string](
        Get-WinSecAuditField `
            -InputObject $RawResult `
            -Name 'SectionKey'
    )

    if (
        $resultCheckId -cne $Check.CheckId -or
        $resultDeviceId -cne $DeviceId -or
        $resultScanId -cne $ScanId -or
        $resultSectionKey -cne $Check.SectionKey
    ) {
        throw (
            "Check result identity mismatch: {0}" -f `
                $Check.CheckId
        )
    }

    # --------------------------------------------------------
    # Normalize observed status
    # --------------------------------------------------------

    $status = [string](
        Get-WinSecAuditField `
            -InputObject $RawResult `
            -Name 'Status'
    )

    $status = $status.Trim().ToUpperInvariant()

    $allowedStatuses = @(
        'PASS'
        'FAIL'
        'ERROR'
        'UNKNOWN'
        'PENDING'
        'NOT_APPLICABLE'
        'INFORMATIONAL'
    )

    if ($status -notin $allowedStatuses) {
        throw (
            "Unsupported check result status '{0}' for {1}." -f `
                $status,
                $Check.CheckId
        )
    }

    $evidence = Get-WinSecAuditField `
        -InputObject $RawResult `
        -Name 'Evidence'

    $reason = [string](
        Get-WinSecAuditField `
            -InputObject $RawResult `
            -Name 'NotApplicableReason'
    )

    $errorMessage = [string](
        Get-WinSecAuditField `
            -InputObject $RawResult `
            -Name 'ErrorMessage'
    )

    $validationIssue = ''

    # --------------------------------------------------------
    # Enforce evidence for PASS
    # --------------------------------------------------------

    if (
        $status -eq 'PASS' -and
        -not (Test-WinSecAuditEvidence -Evidence $evidence)
    ) {
        $status = 'UNKNOWN'

        $validationIssue = (
            'PASS was returned without evidence. ' +
            'Result normalized to UNKNOWN.'
        )
    }

    # --------------------------------------------------------
    # Require a reason for NOT_APPLICABLE
    # --------------------------------------------------------

    if (
        $status -eq 'NOT_APPLICABLE' -and
        [string]::IsNullOrWhiteSpace($reason)
    ) {
        throw (
            "NOT_APPLICABLE requires a reason: {0}" -f `
                $Check.CheckId
        )
    }

    $observedStatus = $status
    $effectiveStatus = $status

    # --------------------------------------------------------
    # Prevent unapproved scoring
    # --------------------------------------------------------

    if (-not $Check.ScoringEligible) {

        $effectiveStatus = 'INFORMATIONAL'
    }

    return New-WinSecAuditRecord `
        -Check $Check `
        -DeviceId $DeviceId `
        -ScanId $ScanId `
        -Status $effectiveStatus `
        -ObservedStatus $observedStatus `
        -Evidence $evidence `
        -NotApplicableReason $reason `
        -ErrorMessage $errorMessage `
        -ValidationIssue $validationIssue
}


# ------------------------------------------------------------
# Execute a validated security check
# ------------------------------------------------------------

function Invoke-WinSecAuditCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Check,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId,
        [scriptblock]$CollectorProgress,
        [scriptblock]$CancellationAction
    )

    try {

        # ----------------------------------------------------
        # Parse and validate implementation structure
        # ----------------------------------------------------

        $implementation = Get-WinSecAuditImplementation `
            -Check $Check

        # ----------------------------------------------------
        # Execute inside a child scope
        # ----------------------------------------------------

        $rawResults = @(
            & {
                param(
                    [scriptblock]$Implementation,
                    [string]$FunctionName,
                    [string]$TargetDeviceId,
                    [string]$CurrentScanId,
                    [string]$CurrentCheckId,
                    [scriptblock]$CollectorProgress,
                    [scriptblock]$CancellationAction
                )

                # Import function declarations locally.
                . $Implementation

                $command = Get-Command `
                    -Name $FunctionName `
                    -CommandType Function `
                    -ErrorAction Stop

                # Standard function contract for all checks.
                $arguments=@{DeviceId=$TargetDeviceId;ScanId=$CurrentScanId;CheckId=$CurrentCheckId}
                if($CurrentCheckId -cin @('WSA-NET-001','WSA-NET-002','WSA-NET-003','WSA-NET-004','WSA-NET-005')) {
                    $arguments.ProgressCallback=$CollectorProgress;$arguments.CancellationAction=$CancellationAction
                }
                & $command @arguments

            } `
                $implementation `
                $Check.FunctionName `
                $DeviceId `
                $ScanId `
                $Check.CheckId `
                $CollectorProgress `
                $CancellationAction
        )

        # ----------------------------------------------------
        # Require exactly one result object per check
        # ----------------------------------------------------

        if ($rawResults.Count -ne 1) {
            throw (
                "Check '{0}' returned {1} result objects; " +
                "exactly one is required." -f `
                    $Check.CheckId,
                    $rawResults.Count
            )
        }

        if ($null -eq $rawResults[0]) {
            throw 'Check returned a null result.'
        }

        # ----------------------------------------------------
        # Normalize result into assessment contract
        # ----------------------------------------------------

        return ConvertTo-WinSecAuditRecord `
            -RawResult $rawResults[0] `
            -Check $Check `
            -DeviceId $DeviceId `
            -ScanId $ScanId

    }
    catch [OperationCanceledException] { throw }
    catch {

        # ----------------------------------------------------
        # Execution errors must never become PASS.
        # ----------------------------------------------------

        $status = 'ERROR'

        if (-not $Check.ScoringEligible) {
            $status = 'INFORMATIONAL'
        }

        return New-WinSecAuditRecord `
            -Check $Check `
            -DeviceId $DeviceId `
            -ScanId $ScanId `
            -Status $status `
            -ObservedStatus 'ERROR' `
            -ErrorMessage $_.Exception.Message `
            -ValidationIssue 'Check execution failed.'
    }
}


# ------------------------------------------------------------
# Main audit coordinator
# ------------------------------------------------------------

function Send-WinSecScanProgress {
    [CmdletBinding()]
    param(
        [scriptblock]$ProgressCallback,
        [string]$DeviceId,
        [string]$ScanId,
        [ValidateSet('READING','CHECK_COMPLETED','FINALIZING','COMPLETED','COMPLETED_WITH_ERRORS','CANCELLED')]
        [string]$Phase,
        [int]$CompletedChecks,
        [int]$TotalChecks,
        [string]$CheckId = ''
    )
    if ($null -eq $ProgressCallback -or $TotalChecks -le 0) { return }
    # New scalar-only object on every notification: never expose records,
    # evidence, registry references or collector exception messages.
    $event = [pscustomobject]@{
        SchemaVersion = '1.0.0'; DeviceId = $DeviceId; ScanId = $ScanId
        Phase = $Phase; CompletedChecks = $CompletedChecks; TotalChecks = $TotalChecks; CheckId = $CheckId
    }
    try { $null = & $ProgressCallback $event }
    catch { } # Display failure must not change execution/publication semantics.
}

function Test-WinSecScanCancellation {
    [CmdletBinding()]
    param([scriptblock]$CancellationAction)
    if ($null -eq $CancellationAction) { return $false }
    try { $decision = @(& $CancellationAction) }
    catch { throw 'Unable to obtain scan cancellation state.' }
    if ($decision.Count -ne 1 -or $decision[0] -isnot [bool]) {
        throw 'Scan cancellation must return exactly one Boolean decision.'
    }
    return $decision[0]
}

function Invoke-WinSecAudit {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$DeviceId = '',

        [string]$ScanId = '',

        [string[]]$CheckIds,

        [AllowNull()]
        [object]$Registry = $null,

        [switch]$SkipScoring,

        [scriptblock]$ProgressCallback,
        [scriptblock]$CancellationAction
    )

    # --------------------------------------------------------
    # Ensure required components are available
    # --------------------------------------------------------

    . Import-WinSecAuditDependencies `
        -SkipScoring:$SkipScoring

    # --------------------------------------------------------
    # Enforce local execution
    # --------------------------------------------------------

    $localTarget = New-WinSecLocalTarget
    if (-not $PSBoundParameters.ContainsKey('DeviceId')) { $DeviceId = $localTarget.DeviceId }
    if (-not [string]::Equals($DeviceId, $localTarget.DeviceId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw (
            "Remote device execution is not implemented. " +
            "Only the current Windows device can be audited."
        )
    }

    # --------------------------------------------------------
    # Resolve registry
    # --------------------------------------------------------

    if ($null -eq $Registry) {
        $Registry = Get-WinSecCheckRegistry
    }

    if (
        $null -eq $Registry.Checks -or
        $null -eq $Registry.Sections
    ) {
        throw 'Invalid security check registry.'
    }

    # --------------------------------------------------------
    # Establish scan identity
    # --------------------------------------------------------

    if ([string]::IsNullOrWhiteSpace($ScanId)) {
        $ScanId = New-WinSecAuditScanId
    }

    $startedAtUTC = [DateTime]::UtcNow

    # --------------------------------------------------------
    # Determine selected controls
    # --------------------------------------------------------

    $selectedIds = @{}
    $explicitSelection = $PSBoundParameters.ContainsKey(
        'CheckIds'
    )

    if ($explicitSelection) {

        if (@($CheckIds).Count -eq 0) {
            throw 'CheckIds cannot be an empty explicit selection.'
        }

        foreach ($checkId in $CheckIds) {

            if ([string]::IsNullOrWhiteSpace($checkId)) {
                throw 'CheckIds cannot contain empty identifiers.'
            }

            if ($selectedIds.ContainsKey($checkId)) {
                throw "Duplicate selected CheckId: $checkId"
            }

            $selectedIds[$checkId] = $true
        }

        # ----------------------------------------------------
        # Validate all selected identifiers before execution
        # ----------------------------------------------------

        foreach ($checkId in $CheckIds) {

            $check = Get-WinSecRegisteredCheck `
                -Registry $Registry `
                -CheckId $checkId

            if ($null -eq $check) {
                throw "Unregistered security check: $checkId"
            }

            if (
                -not $check.ExecutionEnabled -or
                -not $check.ExecutionReady -or
                $check.ImplementationStatus -ne 'VALIDATED'
            ) {
                throw (
                    "Selected security check is not ready: " +
                    $checkId
                )
            }
        }
    }
    else {

        # ----------------------------------------------------
        # Default: all enabled and validated controls
        # ----------------------------------------------------

        foreach ($check in $Registry.Checks) {

            if (
                $check.ExecutionEnabled -and
                $check.ExecutionReady -and
                $check.ImplementationStatus -eq 'VALIDATED'
            ) {
                $selectedIds[$check.CheckId] = $true
            }
        }
    }

    # --------------------------------------------------------
    # Initialize results
    # --------------------------------------------------------

    $results = New-Object `
        'System.Collections.Generic.List[object]'

    $executedCount = 0
    $executionErrorCount = 0

    # --------------------------------------------------------
    # Execute selected controls sequentially
    # --------------------------------------------------------

    foreach ($check in $Registry.Checks) {

        if (-not $selectedIds.ContainsKey($check.CheckId)) {

            # ------------------------------------------------
            # Preserve all catalog controls in the results
            # without pretending they were executed.
            # ------------------------------------------------

            $results.Add(
                (New-WinSecAuditRecord `
                    -Check $check `
                    -DeviceId $DeviceId `
                    -ScanId $ScanId `
                    -Status 'NOT_SELECTED')
            )

            continue
        }

        if (Test-WinSecScanCancellation -CancellationAction $CancellationAction) {
            Send-WinSecScanProgress -ProgressCallback $ProgressCallback -DeviceId $DeviceId -ScanId $ScanId `
                -Phase CANCELLED -CompletedChecks $executedCount -TotalChecks $selectedIds.Count
            throw [OperationCanceledException]::new('Scan cancelled before publication.')
        }
        Send-WinSecScanProgress -ProgressCallback $ProgressCallback -DeviceId $DeviceId -ScanId $ScanId `
            -Phase READING -CompletedChecks $executedCount -TotalChecks $selectedIds.Count -CheckId $check.CheckId

        $firewallProgressSink=$ProgressCallback
        $firewallProgressDevice=$DeviceId;$firewallProgressScan=$ScanId
        $firewallProgressCompleted=$executedCount;$firewallProgressTotal=$selectedIds.Count;$firewallProgressCheck=$check.CheckId
        $collectorProgress={
            param($detail)
            if($null -eq $firewallProgressSink){return}
            if($detail.Stage -isnot [string] -or $detail.Stage -cnotmatch '\A[A-Z]{1,40}\z' -or
                $detail.CompletedSteps -isnot [int] -or $detail.TotalSteps -isnot [int] -or $detail.TotalSteps -lt 1 -or
                $detail.CompletedSteps -lt 0 -or $detail.CompletedSteps -gt $detail.TotalSteps){throw 'Invalid collector progress.'}
            $event=[pscustomobject]@{SchemaVersion='2.0.0';DeviceId=$firewallProgressDevice;ScanId=$firewallProgressScan;Phase='READING';
                CompletedChecks=$firewallProgressCompleted;TotalChecks=$firewallProgressTotal;CheckId=$firewallProgressCheck;
                Stage=$detail.Stage;CompletedSteps=$detail.CompletedSteps;TotalSteps=$detail.TotalSteps}
            try {$null=& $firewallProgressSink $event} catch { } # Display failures cannot alter collection.
        }.GetNewClosure()
        $checkArguments=@{Check=$check;DeviceId=$DeviceId;ScanId=$ScanId}
        if($check.CheckId -cin @('WSA-NET-001','WSA-NET-002','WSA-NET-003','WSA-NET-004','WSA-NET-005')){$checkArguments.CollectorProgress=$collectorProgress;$checkArguments.CancellationAction=$CancellationAction}
        $record = Invoke-WinSecAuditCheck @checkArguments

        $results.Add($record)

        $executedCount++

        if ($record.ObservedStatus -eq 'ERROR' -or ($check.CheckId -cin @('WSA-NET-001','WSA-NET-002','WSA-NET-003','WSA-NET-004','WSA-NET-005') -and $record.ObservedStatus -ceq 'UNKNOWN')) {
            $executionErrorCount++
        }
        Send-WinSecScanProgress -ProgressCallback $ProgressCallback -DeviceId $DeviceId -ScanId $ScanId `
            -Phase CHECK_COMPLETED -CompletedChecks $executedCount -TotalChecks $selectedIds.Count -CheckId $check.CheckId
        if (Test-WinSecScanCancellation -CancellationAction $CancellationAction) {
            Send-WinSecScanProgress -ProgressCallback $ProgressCallback -DeviceId $DeviceId -ScanId $ScanId `
                -Phase CANCELLED -CompletedChecks $executedCount -TotalChecks $selectedIds.Count
            throw [OperationCanceledException]::new('Scan cancelled before publication.')
        }
    }

    $completedAtUTC = [DateTime]::UtcNow

    # --------------------------------------------------------
    # Calculate scores from normalized records
    # --------------------------------------------------------

    $scoreResult = $null

    $overallScore = $null
    $overallCoverage = $null
    $overallStatus = 'PENDING'

    $sectionResults = @()

    if (-not $SkipScoring) {

        $scoreResult = Get-WinSecSecurityScore `
            -DeviceId $DeviceId `
            -ScanId $ScanId `
            -CheckResults $results.ToArray()

        $overallScore = $scoreResult.OverallScore
        $overallCoverage = $scoreResult.Coverage
        $overallStatus = $scoreResult.OverallStatus

        $sectionResults = @(
            $scoreResult.SectionResults
        )
    }

    # --------------------------------------------------------
    # Determine execution outcome separately from score
    # --------------------------------------------------------

    $executionStatus = 'COMPLETED'

    if ($executedCount -eq 0) {
        $executionStatus = 'NO_EXECUTABLE_CHECKS'
    }
    elseif ($executionErrorCount -gt 0) {
        $executionStatus = 'COMPLETED_WITH_ERRORS'
    }

    $unselectedCount = (
        $results.Count - $executedCount
    )

    # --------------------------------------------------------
    # Return complete audit session
    # --------------------------------------------------------

    return [PSCustomObject]@{

        AuditId = $ScanId
        ScanId = $ScanId

        DeviceId = $DeviceId
        ComputerName = $env:COMPUTERNAME
        CollectionMode = 'LOCAL'

        StartedAtUTC = $startedAtUTC.ToString('o')
        CompletedAtUTC = $completedAtUTC.ToString('o')

        DurationSeconds = [Math]::Round(
            ($completedAtUTC - $startedAtUTC).TotalSeconds,
            3
        )

        ExecutionStatus = $executionStatus

        TotalRegisteredChecks = $results.Count
        SelectedChecks = $selectedIds.Count
        ExecutedChecks = $executedCount
        UnselectedChecks = $unselectedCount
        ExecutionErrors = $executionErrorCount

        OverallScore = $overallScore
        OverallCoverage = $overallCoverage
        OverallStatus = $overallStatus

        SectionResults = $sectionResults

        ControlResults = $results.ToArray()
        CheckResults = $results.ToArray()

        ScoreResult = $scoreResult

        # Findings must come from actual evaluated
        # conditions, never from invented results.
        Findings = @()

        CatalogVersion = $Registry.CatalogVersion

        ScoringEnabled = (-not $SkipScoring)
    }
}
