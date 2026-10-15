
# ============================================================
# WinSec Analyzer
# Component : ScoreEngine
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Evidence-based Windows security scoring engine.
#
# Methodology:
# - XCCDF 1.2 Flat Unweighted (adapted)
# - Equal weight per applicable security check
# - No severity-based scoring
# - No framework-based scoring
# - No partial credit
#
# Supports:
# - Control-level scoring
# - Section-level scoring
# - Device-level scoring
# - Audit coverage calculation
# - Multi-device / multi-scan isolation
#
# IMPORTANT:
# WinSec Analyzer is not an XCCDF-certified evaluator.
# ============================================================


# ------------------------------------------------------------
# Default scoring configuration
# ------------------------------------------------------------

$script:WinSecScoringConfigPath = (
    [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..\config\scoring.json')
    )
)


# ------------------------------------------------------------
# Read object or dictionary properties
# ------------------------------------------------------------

function Get-WinSecScoreField {
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
# Validate scoring configuration
# ------------------------------------------------------------

function Test-WinSecScoringPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Policy
    )

    $methodology = Get-WinSecScoreField `
        -InputObject $Policy `
        -Name 'methodology'

    $rules = Get-WinSecScoreField `
        -InputObject $Policy `
        -Name 'scoringRules'

    $definitions = Get-WinSecScoreField `
        -InputObject $Policy `
        -Name 'statusDefinitions'

    $coverage = Get-WinSecScoreField `
        -InputObject $Policy `
        -Name 'coverage'

    $aggregation = Get-WinSecScoreField `
        -InputObject $Policy `
        -Name 'aggregation'

    if (
        $null -eq $methodology -or
        $null -eq $rules -or
        $null -eq $definitions -or
        $null -eq $coverage -or
        $null -eq $aggregation
    ) {
        throw 'Incomplete scoring policy configuration.'
    }

    if ($Policy.enabled -ne $true) {
        throw 'Security scoring is disabled.'
    }

    # --------------------------------------------------------
    # Validate supported scoring methodology
    # --------------------------------------------------------

    if (
        $methodology.scoringModel -ne
        'urn:xccdf:scoring:flat-unweighted'
    ) {
        throw 'Unsupported scoring methodology.'
    }

    if ([int]$methodology.unitWeight -ne 1) {
        throw 'Only unit weights are supported.'
    }

    if (
        $methodology.allowCustomWeights -ne $false -or
        $methodology.allowSeverityWeights -ne $false -or
        $methodology.allowFrameworkWeights -ne $false -or
        $methodology.allowPartialCredit -ne $false
    ) {
        throw 'Weighted or partial-credit scoring is not enabled.'
    }

    if (
        $aggregation.method -ne 'FLAT_UNWEIGHTED' -or
        $aggregation.averageSectionScores -ne $false
    ) {
        throw 'Unsupported aggregation configuration.'
    }

    if (
        $aggregation.requireDeviceId -ne $true -or
        $aggregation.requireScanId -ne $true -or
        $aggregation.requireCheckId -ne $true
    ) {
        throw 'Device, scan and check identifiers must be required.'
    }

    if (
        $rules.evaluateEachCheckOnce -ne $true -or
        $rules.requireUniqueCheckId -ne $true
    ) {
        throw 'Each check must be scored exactly once.'
    }

    if (
        $rules.requireEvidenceForPass -ne $true -or
        [int]$rules.passScore -ne 1 -or
        [int]$rules.nonPassScore -ne 0
    ) {
        throw 'Invalid evidence or scoring rules.'
    }

    if (
        $rules.unsupportedStatusPolicy -ne 'REJECT' -or
        $rules.warningAsPartialCredit -ne $false
    ) {
        throw 'Unsupported status handling policy.'
    }

    # --------------------------------------------------------
    # Validate known statuses and configured values
    # --------------------------------------------------------

    $expectedValues = @{
        PASS          = 1
        FAIL          = 0
        ERROR         = 0
        UNKNOWN       = 0
    }

    foreach ($status in $expectedValues.Keys) {

        $definition = Get-WinSecScoreField `
            -InputObject $definitions `
            -Name $status

        if ($null -eq $definition) {
            throw "Missing status definition: $status"
        }

        if (
            $definition.includedInScore -ne $true -or
            [int]$definition.scoreValue -ne
                $expectedValues[$status]
        ) {
            throw "Invalid scoring definition: $status"
        }
    }

    $excluded = @(
        'PENDING',
        'NOT_CHECKED',
        'NOT_APPLICABLE',
        'NOT_SELECTED',
        'MANUAL',
        'INFORMATIONAL'
    )

    foreach ($status in $excluded) {

        $definition = Get-WinSecScoreField `
            -InputObject $definitions `
            -Name $status

        if ($null -eq $definition) {
            throw "Missing status definition: $status"
        }

        if (
            $definition.includedInScore -ne $false -or
            $null -ne $definition.scoreValue
        ) {
            throw "Invalid excluded status: $status"
        }
    }

    # --------------------------------------------------------
    # Validate coverage configuration
    # --------------------------------------------------------

    if ($coverage.enabled -ne $true) {
        throw 'Assessment coverage must be enabled.'
    }

    $expectedNumerator = @('PASS', 'FAIL')

    $expectedDenominator = @(
        'PASS',
        'FAIL',
        'ERROR',
        'UNKNOWN',
        'PENDING',
        'NOT_CHECKED'
    )

    $actualNumerator = @(
        $coverage.numeratorStatuses |
            Sort-Object
    )

    $actualDenominator = @(
        $coverage.denominatorStatuses |
            Sort-Object
    )

    if (
        ($actualNumerator -join ',') -ne
        (($expectedNumerator | Sort-Object) -join ',')
    ) {
        throw 'Unsupported coverage numerator.'
    }

    if (
        ($actualDenominator -join ',') -ne
        (($expectedDenominator | Sort-Object) -join ',')
    ) {
        throw 'Unsupported coverage denominator.'
    }

    return $true
}


# ------------------------------------------------------------
# Load scoring configuration
# ------------------------------------------------------------

function Get-WinSecScoringPolicy {
    [CmdletBinding()]
    param(
        [string]$Path = $script:WinSecScoringConfigPath
    )

    if (-not (
        Test-Path -LiteralPath $Path -PathType Leaf
    )) {
        throw "Scoring configuration not found: $Path"
    }

    try {

        $json = Get-Content `
            -LiteralPath $Path `
            -Encoding UTF8 `
            -Raw `
            -ErrorAction Stop

        $policy = ConvertFrom-Json `
            -InputObject $json `
            -ErrorAction Stop

        if ($null -eq $policy) {
            throw 'Scoring configuration is empty.'
        }

        $null = Test-WinSecScoringPolicy `
            -Policy $policy

        return $policy
    }
    catch {

        throw (
            'Unable to load scoring configuration: {0}' -f `
                $_.Exception.Message
        )
    }
}


# ------------------------------------------------------------
# Verify whether evidence is present
# ------------------------------------------------------------

function Test-WinSecScoreEvidence {
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
            -not [string]::IsNullOrWhiteSpace($Evidence)
        )
    }

    if (
        $Evidence -is [array] -or
        $Evidence -is [System.Collections.IDictionary]
    ) {
        return ($Evidence.Count -gt 0)
    }

    return $true
}


# ------------------------------------------------------------
# Normalize and evaluate one security check
# ------------------------------------------------------------

function Get-WinSecCheckScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$CheckResult,

        [Parameter(Mandatory)]
        [object]$Policy
    )

    $checkId = [string](
        Get-WinSecScoreField `
            -InputObject $CheckResult `
            -Name 'CheckId'
    )

    $deviceId = [string](
        Get-WinSecScoreField `
            -InputObject $CheckResult `
            -Name 'DeviceId'
    )

    $scanId = [string](
        Get-WinSecScoreField `
            -InputObject $CheckResult `
            -Name 'ScanId'
    )

    $sectionKey = [string](
        Get-WinSecScoreField `
            -InputObject $CheckResult `
            -Name 'SectionKey'
    )

    $rawStatus = [string](
        Get-WinSecScoreField `
            -InputObject $CheckResult `
            -Name 'Status'
    )

    # --------------------------------------------------------
    # Validate required assessment identifiers
    # --------------------------------------------------------

    if (
        [string]::IsNullOrWhiteSpace($checkId) -or
        [string]::IsNullOrWhiteSpace($deviceId) -or
        [string]::IsNullOrWhiteSpace($scanId)
    ) {
        throw 'CheckId, DeviceId and ScanId are required.'
    }

    $allowedSections = @(
        'SystemSecurity',
        'NetworkSecurity',
        'IdentityAccess',
        'LoggingAuditing',
        'ServicesHardening'
    )

    if ($sectionKey -notin $allowedSections) {

        throw (
            "Invalid section for check ${checkId}: $sectionKey"
        )
    }

    # --------------------------------------------------------
    # Normalize status
    # --------------------------------------------------------

    $status = $rawStatus.Trim().ToUpperInvariant()

    $definition = Get-WinSecScoreField `
        -InputObject $Policy.statusDefinitions `
        -Name $status

    if ($null -eq $definition) {

        throw (
            "Unsupported status for check ${checkId}: $status"
        )
    }

    # --------------------------------------------------------
    # Validate applicability exclusions
    # --------------------------------------------------------

    if ($status -eq 'NOT_APPLICABLE') {

        $reason = [string](
            Get-WinSecScoreField `
                -InputObject $CheckResult `
                -Name 'NotApplicableReason'
        )

        if (
            $Policy.applicability.requireNotApplicableReason -and
            [string]::IsNullOrWhiteSpace($reason)
        ) {

            throw (
                "NOT_APPLICABLE requires a reason: $checkId"
            )
        }
    }

    # --------------------------------------------------------
    # Validate available evidence
    # --------------------------------------------------------

    $evidence = Get-WinSecScoreField `
        -InputObject $CheckResult `
        -Name 'Evidence'

    $hasEvidence = Test-WinSecScoreEvidence `
        -Evidence $evidence

    $effectiveStatus = $status
    $validationIssue = ''

    # A PASS without evidence cannot receive points.
    if (
        $status -eq 'PASS' -and
        $Policy.scoringRules.requireEvidenceForPass -and
        -not $hasEvidence
    ) {

        $effectiveStatus = 'UNKNOWN'

        $validationIssue = (
            'PASS result has no supporting evidence. ' +
            'It is treated as UNKNOWN for scoring.'
        )
    }

    # A FAIL remains a failure, but missing evidence
    # is reported as a traceability issue.
    if (
        $status -eq 'FAIL' -and
        -not $hasEvidence
    ) {

        $validationIssue = (
            'FAIL result has no supporting evidence.'
        )
    }

    # --------------------------------------------------------
    # Resolve effective scoring status
    # --------------------------------------------------------

    $effectiveDefinition = Get-WinSecScoreField `
        -InputObject $Policy.statusDefinitions `
        -Name $effectiveStatus

    $included = [bool](
        $effectiveDefinition.includedInScore
    )

    $verified = [bool](
        $effectiveDefinition.verified
    )

    $scoreValue = $null

    if ($included) {
        $scoreValue = [int](
            $effectiveDefinition.scoreValue
        )
    }

    # --------------------------------------------------------
    # Return normalized evaluation
    # --------------------------------------------------------

    return [PSCustomObject]@{
        CheckId         = $checkId
        DeviceId        = $deviceId
        ScanId          = $scanId
        SectionKey      = $sectionKey

        OriginalStatus  = $status
        Status          = $effectiveStatus

        IncludedInScore = $included
        ScoreValue      = $scoreValue

        Verified        = $verified
        EvidencePresent = $hasEvidence

        ValidationIssue = $validationIssue

        OriginalResult  = $CheckResult
    }
}


# ------------------------------------------------------------
# Calculate score and coverage for a set of checks
# ------------------------------------------------------------

function Get-WinSecScoreSummary {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$CheckResults = @(),

        [Parameter(Mandatory)]
        [object]$Policy
    )

    # --------------------------------------------------------
    # Initialize counters
    # --------------------------------------------------------

    $counts = @{
        PASS           = 0
        FAIL           = 0
        ERROR          = 0
        UNKNOWN        = 0
        PENDING        = 0
        NOT_CHECKED    = 0
        NOT_APPLICABLE = 0
        NOT_SELECTED   = 0
        MANUAL         = 0
        INFORMATIONAL  = 0
    }

    $passedRules = 0
    $scoredRules = 0

    $verifiedChecks = 0
    $selectedApplicableChecks = 0

    # --------------------------------------------------------
    # Read configured coverage statuses
    # --------------------------------------------------------

    $coverageNumerator = @(
        $Policy.coverage.numeratorStatuses
    )

    $coverageDenominator = @(
        $Policy.coverage.denominatorStatuses
    )

    # --------------------------------------------------------
    # Aggregate normalized check results
    # --------------------------------------------------------

    foreach ($check in $CheckResults) {

        if ($null -eq $check) {
            continue
        }

        $status = [string]$check.Status

        if (-not $counts.ContainsKey($status)) {
            throw "Unknown normalized status: $status"
        }

        $counts[$status]++

        # ----------------------------------------------------
        # Score numerator and denominator
        # ----------------------------------------------------

        if ($check.IncludedInScore) {

            $scoredRules++

            if ($check.ScoreValue -eq 1) {
                $passedRules++
            }
        }

        # ----------------------------------------------------
        # Coverage numerator and denominator
        # ----------------------------------------------------

        if ($status -in $coverageNumerator) {
            $verifiedChecks++
        }

        if ($status -in $coverageDenominator) {
            $selectedApplicableChecks++
        }
    }

    # --------------------------------------------------------
    # Calculate flat-unweighted security score
    # --------------------------------------------------------

    $score = $null

    if ($scoredRules -gt 0) {

        $score = [Math]::Round(
            (
                $passedRules /
                [double]$scoredRules
            ) * 100,
            [int]$Policy.methodology.decimalPlaces,
            [System.MidpointRounding]::AwayFromZero
        )
    }

    # --------------------------------------------------------
    # Calculate assessment coverage
    # --------------------------------------------------------

    $coverage = $null

    if ($selectedApplicableChecks -gt 0) {

        $coverage = [Math]::Round(
            (
                $verifiedChecks /
                [double]$selectedApplicableChecks
            ) * 100,
            [int]$Policy.coverage.decimalPlaces,
            [System.MidpointRounding]::AwayFromZero
        )
    }

    # --------------------------------------------------------
    # Determine assessment completeness
    # --------------------------------------------------------

    $assessmentStatus = 'PENDING'

    if ($selectedApplicableChecks -gt 0) {

        if (
            $verifiedChecks -eq
            $selectedApplicableChecks
        ) {
            $assessmentStatus = 'COMPLETE'
        }
        else {
            $assessmentStatus = 'PROVISIONAL'
        }
    }

    # --------------------------------------------------------
    # Return scoring summary
    # --------------------------------------------------------

    return [PSCustomObject]@{

        Score        = $score
        Coverage     = $coverage
        Status       = $assessmentStatus

        PassedRules  = $passedRules
        ScoredRules  = $scoredRules

        VerifiedChecks = $verifiedChecks

        SelectedApplicableChecks = (
            $selectedApplicableChecks
        )

        TotalChecks = @($CheckResults).Count

        PassedCount        = $counts.PASS
        FailedCount        = $counts.FAIL
        ErrorCount         = $counts.ERROR
        UnknownCount       = $counts.UNKNOWN
        PendingCount       = $counts.PENDING
        NotCheckedCount    = $counts.NOT_CHECKED
        NotApplicableCount = $counts.NOT_APPLICABLE
        NotSelectedCount   = $counts.NOT_SELECTED
        ManualCount        = $counts.MANUAL
        InformationalCount = $counts.INFORMATIONAL

        IsComplete = (
            $assessmentStatus -eq 'COMPLETE'
        )
    }
}


# ------------------------------------------------------------
# Get security score for one device and one scan
# ------------------------------------------------------------

function Get-WinSecSecurityScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScanId,

        [AllowEmptyCollection()]
        [object[]]$CheckResults = @(),

        [AllowNull()]
        [object]$Policy = $null
    )

    # --------------------------------------------------------
    # Load policy if not supplied
    # --------------------------------------------------------

    if ($null -eq $Policy) {
        $Policy = Get-WinSecScoringPolicy
    }
    else {
        $null = Test-WinSecScoringPolicy `
            -Policy $Policy
    }

    # --------------------------------------------------------
    # Filter and evaluate checks from the selected scan
    # --------------------------------------------------------

    $evaluated = New-Object `
        'System.Collections.Generic.List[object]'

    $processedCheckIds = @{}

    foreach ($result in $CheckResults) {

        if ($null -eq $result) {
            continue
        }

        $recordDevice = [string](
            Get-WinSecScoreField `
                -InputObject $result `
                -Name 'DeviceId'
        )

        if (-not $recordDevice) {
            throw 'Assessment record without DeviceId.'
        }

        # Ignore records belonging to another device.
        if ($recordDevice -ne $DeviceId) {
            continue
        }

        $recordScan = [string](
            Get-WinSecScoreField `
                -InputObject $result `
                -Name 'ScanId'
        )

        if (-not $recordScan) {

            throw (
                "Assessment record without ScanId: $DeviceId"
            )
        }

        # Ignore records from different scan executions.
        if ($recordScan -ne $ScanId) {
            continue
        }

        # ----------------------------------------------------
        # Evaluate individual check
        # ----------------------------------------------------

        $check = Get-WinSecCheckScore `
            -CheckResult $result `
            -Policy $Policy

        # ----------------------------------------------------
        # Prevent duplicate scoring
        # ----------------------------------------------------

        if (
            $processedCheckIds.ContainsKey(
                $check.CheckId
            )
        ) {

            throw (
                "Duplicate CheckId in assessment: {0}" -f `
                    $check.CheckId
            )
        }

        $processedCheckIds[$check.CheckId] = $true

        $evaluated.Add($check)
    }

    $evaluatedChecks = $evaluated.ToArray()

    # --------------------------------------------------------
    # Calculate device-wide score
    # --------------------------------------------------------

    $overall = Get-WinSecScoreSummary `
        -CheckResults $evaluatedChecks `
        -Policy $Policy

    # --------------------------------------------------------
    # Calculate scores for the five security sections
    # --------------------------------------------------------

    $sections = @(
        @{
            Key  = 'SystemSecurity'
            Name = 'System Security'
        }
        @{
            Key  = 'NetworkSecurity'
            Name = 'Network Security'
        }
        @{
            Key  = 'IdentityAccess'
            Name = 'Identity & Access Security'
        }
        @{
            Key  = 'LoggingAuditing'
            Name = 'Logging & Auditing'
        }
        @{
            Key  = 'ServicesHardening'
            Name = 'Services & Hardening'
        }
    )

    $sectionResults = @(
        foreach ($section in $sections) {

            $sectionChecks = @(
                $evaluatedChecks | Where-Object {
                    $_.SectionKey -eq $section.Key
                }
            )

            $summary = Get-WinSecScoreSummary `
                -CheckResults $sectionChecks `
                -Policy $Policy

            [PSCustomObject]@{

                DeviceId   = $DeviceId
                ScanId     = $ScanId

                Key        = $section.Key
                Name       = $section.Name

                Score      = $summary.Score
                Coverage   = $summary.Coverage
                Status     = $summary.Status

                TotalChecks = $summary.TotalChecks

                PassedRules = $summary.PassedRules
                ScoredRules = $summary.ScoredRules

                PassedCount  = $summary.PassedCount
                FailedCount  = $summary.FailedCount
                ErrorCount   = $summary.ErrorCount
                UnknownCount = $summary.UnknownCount

                PendingCount = $summary.PendingCount

                IsComplete = $summary.IsComplete
            }
        }
    )

    # --------------------------------------------------------
    # Return complete device scoring result
    # --------------------------------------------------------

    return [PSCustomObject]@{

        DeviceId = $DeviceId
        ScanId   = $ScanId

        # Overall security score
        Score   = $overall.Score
        Coverage = $overall.Coverage
        Status  = $overall.Status

        # Explicit aliases for dashboard integration
        OverallScore  = $overall.Score
        OverallStatus = $overall.Status

        # Scoring methodology
        ScoringModel = (
            $Policy.methodology.scoringModel
        )

        ScoringMethod = (
            $Policy.methodology.name
        )

        IsXCCDFCertified = $false

        # Assessment totals
        TotalChecks = $overall.TotalChecks

        PassedRules = $overall.PassedRules
        ScoredRules = $overall.ScoredRules

        VerifiedChecks = $overall.VerifiedChecks

        SelectedApplicableChecks = (
            $overall.SelectedApplicableChecks
        )

        PassedCount  = $overall.PassedCount
        FailedCount  = $overall.FailedCount
        ErrorCount   = $overall.ErrorCount
        UnknownCount = $overall.UnknownCount

        PendingCount       = $overall.PendingCount
        NotCheckedCount    = $overall.NotCheckedCount
        NotApplicableCount = $overall.NotApplicableCount
        ManualCount        = $overall.ManualCount
        InformationalCount = $overall.InformationalCount

        IsComplete = $overall.IsComplete

        # Detailed assessment information
        SectionResults = $sectionResults
        CheckResults   = $evaluatedChecks
    }
}
