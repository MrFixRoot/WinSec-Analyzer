# ============================================================
# WinSec Analyzer
# Component  : ScoreEngine
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Conservative scoring of approved Windows security checks.
#
# Includes:
# - XCCDF 1.2 flat-unweighted methodology (adapted)
# - Control, section, and device-level scoring
# - Assessment coverage independent of the security score
# - Mandatory CriteriaService and EvaluationEngine contracts
# - Original collector evidence and identity validation
# - Explicit expected CheckId coverage
# - Device/scan isolation and duplicate detection
# - NOT_SCORED when inactive or incomplete
# - No weights, partial credit, or framework-based scores
#
# PowerShell 5.1 / 7.x
#
# IMPORTANT:
# In-memory, read-only calculations. Never modifies Windows.
# This is not an XCCDF-certified implementation.
# Approval metadata does not independently prove source review.
# ============================================================

$script:WinSecScoringConfigPath = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../../config/scoring.json')
)

# D-042: criterion percentages and equal-control section means use the
# versioned configuration assessment contract; legacy device scoring stays off.
. (Join-Path $PSScriptRoot 'ConfigurationScore.ps1')

# ============================================================
# OBJECT HELPERS
# ============================================================

function Get-WinSecScoreField {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]::Equals([string]$key, $Name,
                [System.StringComparison]::OrdinalIgnoreCase)) {
                return ,$InputObject[$key]
            }
        }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return ,$property.Value
}

function Test-WinSecScoreText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    return ($Value -is [string] -and
        -not [string]::IsNullOrWhiteSpace($Value))
}

function Test-WinSecScoreEvidence {
    [CmdletBinding()]
    param([AllowNull()][object]$Evidence)
    if ($null -eq $Evidence) { return $false }
    if ($Evidence -is [string]) {
        return (-not [string]::IsNullOrWhiteSpace($Evidence))
    }
    if ($Evidence -is [array] -or
        $Evidence -is [System.Collections.IDictionary]) {
        return ($Evidence.Count -gt 0)
    }
    return $true
}

function Assert-WinSecScoreIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Reference,
        [AllowNull()][object]$Candidate,
        [string[]]$Fields = @('CheckId', 'DeviceId', 'ScanId')
    )
    if ($null -eq $Candidate) { return $false }
    foreach ($field in $Fields) {
        $left = Get-WinSecScoreField $Reference $field
        $right = Get-WinSecScoreField $Candidate $field
        if (-not (Test-WinSecScoreText $left) -or
            -not (Test-WinSecScoreText $right) -or
            $left -cne $right) { return $false }
    }
    return $true
}

# ============================================================
# POLICY VALIDATION AND LOADING
# ============================================================

function Test-WinSecScoringPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Policy)

    if ((Get-WinSecScoreField $Policy 'schemaVersion') -cne '1.1.0') {
        throw 'Unsupported scoring policy schema; expected 1.1.0.'
    }
    if ((Get-WinSecScoreField $Policy 'enabled') -isnot [bool]) {
        throw 'Policy.enabled must be Boolean.'
    }
    if ((Get-WinSecScoreField $Policy 'enabled') -eq $true -and
        (Get-WinSecScoreField $Policy 'activationStatus') -cne 'ACTIVE') {
        throw 'An enabled policy requires explicit ACTIVE activation.'
    }

    $method = Get-WinSecScoreField $Policy 'methodology'
    $rules = Get-WinSecScoreField $Policy 'scoringRules'
    $coverage = Get-WinSecScoreField $Policy 'coverage'
    $aggregation = Get-WinSecScoreField $Policy 'aggregation'
    $definitions = Get-WinSecScoreField $Policy 'statusDefinitions'
    $applicability = Get-WinSecScoreField $Policy 'applicability'

    foreach ($entry in @($method, $rules, $coverage,
        $aggregation, $definitions, $applicability)) {
        if ($null -eq $entry) { throw 'Incomplete scoring policy.' }
    }

    if ($method.scoringModel -cne 'urn:xccdf:scoring:flat-unweighted' -or
        $method.scoringUnit -cne 'CheckId' -or
        ($method.unitWeight -isnot [int] -and $method.unitWeight -isnot [long]) -or
        $method.unitWeight -ne 1 -or
        $method.allowCustomWeights -cne $false -or
        $method.allowSeverityWeights -cne $false -or
        $method.allowFrameworkWeights -cne $false -or
        $method.allowPartialCredit -cne $false -or
        $method.xccdfConformant -cne $false -or
        $method.cisCertified -cne $false) {
        throw 'Unsupported or unsafe scoring methodology.'
    }

    if ($aggregation.method -cne 'FLAT_UNWEIGHTED' -or
        $aggregation.averageSectionScores -cne $false -or
        $aggregation.allowCrossDeviceAggregation -cne $false -or
        $aggregation.allowCrossScanAggregation -cne $false -or
        $aggregation.requireDeviceId -cne $true -or
        $aggregation.requireScanId -cne $true -or
        $aggregation.requireCheckId -cne $true) {
        throw 'Unsupported aggregation policy.'
    }

    foreach ($field in @('evaluateEachCheckOnce', 'requireUniqueCheckId',
        'requireEvidenceForPass', 'requireApprovedCriteria',
        'requireVerifiedCriteriaSelection', 'requireEvaluationEngineResult',
        'requireIdentityMatch', 'requireExpectedCheckIdSet',
        'requireCompleteAssessment')) {
        if ((Get-WinSecScoreField $rules $field) -cne $true) {
            throw "Required scoring safeguard missing: $field."
        }
    }
    if ($rules.allowProvisionalScore -cne $false -or
        $rules.warningAsPartialCredit -cne $false -or
        $rules.unsupportedStatusPolicy -cne 'REJECT' -or
        $rules.readOnlyAssessment -cne $true -or
        $rules.automaticRemediation -cne $false -or
        $rules.incompleteScoreStatus -cne 'NOT_SCORED' -or
        $null -ne $rules.incompleteScoreResult -or
        $rules.passScore -ne 1 -or $rules.nonPassScore -ne 0) {
        throw 'Unsafe scoring rules.'
    }

    $included = @('PASS', 'FAIL')
    $excluded = @('ERROR', 'UNKNOWN', 'NOT_EVALUATED', 'PENDING',
        'NOT_CHECKED', 'NOT_APPLICABLE', 'NOT_SELECTED',
        'MANUAL', 'INFORMATIONAL')
    if ((@($rules.includedStatuses | Sort-Object) -join '|') -cne
        (@($included | Sort-Object) -join '|') -or
        (@($rules.excludedStatuses | Sort-Object) -join '|') -cne
        (@($excluded | Sort-Object) -join '|')) {
        throw 'Unexpected included or excluded scoring statuses.'
    }

    foreach ($status in @($included + $excluded)) {
        $definition = Get-WinSecScoreField $definitions $status
        if ($null -eq $definition) { throw "Missing status definition: $status." }
        if ($status -ceq 'PASS' -or $status -ceq 'FAIL') {
            $value = if ($status -ceq 'PASS') { 1 } else { 0 }
            if ($definition.includedInScore -cne $true -or
                $definition.verified -cne $true -or
                ($definition.scoreValue -isnot [int] -and $definition.scoreValue -isnot [long]) -or
                $definition.scoreValue -ne $value) {
                throw "Unsafe score status: $status."
            }
        }
        elseif ($definition.includedInScore -cne $false -or
            $definition.verified -cne $false -or
            $null -ne $definition.scoreValue) {
            throw "Excluded status is incorrectly scored: $status."
        }
    }

    if ($coverage.enabled -cne $true -or
        (@($coverage.numeratorStatuses | Sort-Object) -join '|') -cne
        (@($included | Sort-Object) -join '|') -or
        (@($coverage.denominatorStatuses | Sort-Object) -join '|') -cne
        (@(@('PASS','FAIL','ERROR','UNKNOWN','NOT_EVALUATED',
            'PENDING','NOT_CHECKED') | Sort-Object) -join '|') -or
        $coverage.incompleteAssessmentStatus -cne 'INCOMPLETE' -or
        $coverage.completeAssessmentStatus -cne 'COMPLETE' -or
        $applicability.requireVerifiedTargetContext -cne $true -or
        $applicability.requireNotApplicableReason -cne $true) {
        throw 'Unsupported coverage or applicability policy.'
    }
    return $true
}

function Get-WinSecScoringPolicy {
    [CmdletBinding()]
    param([string]$Path = $script:WinSecScoringConfigPath)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Scoring configuration not found: $Path"
    }
    try {
        $file = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($file.Length -gt 1048576) {
            throw 'Scoring policy exceeds 1 MiB.'
        }
        $json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
        # Prevent a root JSON array from being silently unwrapped by the pipeline.
        if ($json.TrimStart([char]0xFEFF, [char]' ', [char]"`r",
            [char]"`n", [char]"`t").StartsWith('[')) {
            throw 'Policy JSON root must be an object.'
        }
        $policy = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        if ($null -eq $policy -or $policy -is [array]) {
            throw 'Policy JSON root must be an object.'
        }
        $null = Test-WinSecScoringPolicy -Policy $policy
        return $policy
    }
    catch {
        throw "Unable to load scoring configuration: $($_.Exception.Message)"
    }
}

# ============================================================
# CATALOG / EVALUATION TRACEABILITY
# ============================================================

function Test-WinSecScoreAuthorization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Evaluation,
        [AllowNull()][object]$CriteriaSelection,
        [AllowNull()][object]$CollectorResult
    )
    $fail = [pscustomobject]@{ Authorized = $false; Reason = '' }
    if ($null -eq $CriteriaSelection -or
        $CriteriaSelection.Status -cne 'READY' -or
        $CriteriaSelection.ScoringEligible -cne $true) {
        $fail.Reason = 'No READY, scoring-eligible criteria selection.'
        return $fail
    }
    if (-not (Assert-WinSecScoreIdentity $Evaluation $CriteriaSelection)) {
        $fail.Reason = 'Criteria selection identity mismatch.'
        return $fail
    }
    if (-not (Assert-WinSecScoreIdentity $Evaluation $CollectorResult)) {
        $fail.Reason = 'Collector evidence identity mismatch.'
        return $fail
    }
    if ($CollectorResult.Status -cne 'INFORMATIONAL' -or
        $null -eq $CollectorResult.Evidence -or
        $CollectorResult.Evidence.CollectionSuccessful -cne $true -or
        -not (Assert-WinSecScoreIdentity $Evaluation $CollectorResult.Evidence)) {
        $fail.Reason = 'Collector evidence is missing, unsuccessful or mismatched.'
        return $fail
    }
    if ($Evaluation.CollectorStatus -cne 'INFORMATIONAL') {
        $fail.Reason = 'Evaluation collector status is not INFORMATIONAL.'
        return $fail
    }
    if ($Evaluation.ScoringEligible -cne $true -or
        $Evaluation.Status -cnotin @('PASS', 'FAIL')) {
        $fail.Reason = 'Evaluation is not a complete PASS or FAIL.'
        return $fail
    }
    if (-not (Test-WinSecScoreText $CriteriaSelection.CatalogId)) {
        $fail.Reason = 'Criteria catalog identity is missing.'
        return $fail
    }

    $criteria = @($CriteriaSelection.EligibleCriteria)
    $results = @($Evaluation.Evaluations)
    if ($criteria.Count -eq 0 -or
        $results.Count -ne $criteria.Count -or
        $CriteriaSelection.CatalogCriteriaCount -ne $criteria.Count -or
        $CriteriaSelection.MatchedCriteriaCount -ne $criteria.Count -or
        @($CriteriaSelection.ExcludedCriteria).Count -ne 0) {
        $fail.Reason = 'Criterion selection is incomplete.'
        return $fail
    }

    $criterionIds = @{}
    $resultIds = @{}
    $passed = 0
    $failed = 0
    foreach ($criterion in $criteria) {
        $id = Get-WinSecScoreField $criterion 'CriterionId'
        if (-not (Test-WinSecScoreText $id) -or
            $criterionIds.ContainsKey($id) -or
            $criterion.CheckId -cne $Evaluation.CheckId -or
            $criterion.Approved -cne $true -or
            $criterion.Verification.Status -cne 'VERIFIED' -or
            -not (Test-WinSecScoreText $criterion.Verification.ReviewedBy) -or
            -not (Test-WinSecScoreText $criterion.Source.ControlId) -or
            $criterion.Source.Framework -cnotin @('LOCAL_POLICY','CIS Benchmarks')) {
            $fail.Reason = 'Criterion authorization metadata is invalid.'
            return $fail
        }
        $reviewDate = [DateTimeOffset]::MinValue
        $sourceUri = $null
        if (-not (Test-WinSecScoreText $criterion.Verification.ReviewedAtUTC) -or
            -not [DateTimeOffset]::TryParse(
                [string]$criterion.Verification.ReviewedAtUTC, [ref]$reviewDate) -or
            $reviewDate -gt [DateTimeOffset]::UtcNow -or
            -not (Test-WinSecScoreText $criterion.Source.Url) -or
            -not [System.Uri]::TryCreate(
                [string]$criterion.Source.Url,
                [System.UriKind]::Absolute, [ref]$sourceUri) -or
            $sourceUri.Scheme -cne 'https') {
            $fail.Reason = 'Criterion source or review record is invalid.'
            return $fail
        }
        $criterionIds[$id] = $criterion
    }
    foreach ($item in $results) {
        $id = Get-WinSecScoreField $item 'CriterionId'
        if (-not (Test-WinSecScoreText $id) -or
            $resultIds.ContainsKey($id) -or
            -not $criterionIds.ContainsKey($id) -or
            -not (Assert-WinSecScoreIdentity $Evaluation $item) -or
            $item.Status -cnotin @('PASS','FAIL') -or
            $item.ScoringEligible -cne $true) {
            $fail.Reason = 'Criterion evaluation result is incomplete or invalid.'
            return $fail
        }
        $source = $criterionIds[$id]
        # Compare the complete documented source identity. Evaluations
        # must retain a separate Source snapshot (EvaluationEngine) so
        # a modified result cannot silently modify the approved criterion.
        if ($item.EvidencePath -cne $source.EvidencePath -or
            $item.Operator -cne $source.Operator -or
            $item.Source.ControlId -cne $source.Source.ControlId -or
            $item.Source.Framework -cne $source.Source.Framework -or
            $item.Source.Version -cne $source.Source.Version -or
            $item.Source.Title -cne $source.Source.Title -or
            $item.Source.Url -cne $source.Source.Url) {
            $fail.Reason = 'Criterion evaluation does not match the selected source.'
            return $fail
        }
        $resultIds[$id] = $true
        if ($item.Status -ceq 'PASS') { $passed++ } else { $failed++ }
    }
    if ($Evaluation.PassedCriteria -ne $passed -or
        $Evaluation.FailedCriteria -ne $failed -or
        $Evaluation.EvaluatedCriteria -ne ($passed + $failed) -or
        $Evaluation.UnknownCriteria -ne 0 -or
        $Evaluation.NotEvaluatedCriteria -ne 0 -or
        $Evaluation.NotApplicableCriteria -ne 0 -or
        ($failed -gt 0 -and $Evaluation.Status -cne 'FAIL') -or
        ($failed -eq 0 -and $Evaluation.Status -cne 'PASS')) {
        $fail.Reason = 'Control-level result is inconsistent with its criteria.'
        return $fail
    }
    return [pscustomobject]@{ Authorized = $true; Reason = 'Complete, matching criterion evaluation.' }
}

# ============================================================
# NORMALIZE A SECURITY CHECK (PRESERVED PUBLIC API)
# ============================================================

function Get-WinSecCheckScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$CheckResult,
        [Parameter(Mandatory)][object]$Policy,
        [AllowNull()][object]$CriteriaSelection = $null,
        [AllowNull()][object]$CollectorResult = $null
    )
    $null = Test-WinSecScoringPolicy -Policy $Policy
    $checkId = Get-WinSecScoreField $CheckResult 'CheckId'
    $deviceId = Get-WinSecScoreField $CheckResult 'DeviceId'
    $scanId = Get-WinSecScoreField $CheckResult 'ScanId'
    if (-not (Test-WinSecScoreText $checkId) -or
        -not (Test-WinSecScoreText $deviceId) -or
        -not (Test-WinSecScoreText $scanId)) {
        throw 'CheckId, DeviceId and ScanId are required.'
    }
    $sectionKey = Get-WinSecScoreField $CollectorResult 'SectionKey'
    if (-not (Test-WinSecScoreText $sectionKey)) {
        $sectionKey = Get-WinSecScoreField $CheckResult 'SectionKey'
    }
    $allowedSections = @('SystemSecurity','NetworkSecurity',
        'IdentityAccess','LoggingAuditing','ServicesHardening')
    if ($null -ne $sectionKey -and $sectionKey -cnotin $allowedSections) {
        throw "Invalid section for check ${checkId}: $sectionKey"
    }

    $status = [string](Get-WinSecScoreField $CheckResult 'Status')
    $status = $status.Trim().ToUpperInvariant()
    if ($null -eq (Get-WinSecScoreField $Policy.statusDefinitions $status)) {
        throw "Unsupported status for check ${checkId}: $status"
    }

    $normalized = [pscustomobject]@{
        CheckId = $checkId
        DeviceId = $deviceId
        ScanId = $scanId
        SectionKey = $sectionKey
        OriginalStatus = $status
        Status = $status
        IncludedInScore = $false
        ScoreValue = $null
        Verified = $false
        EvidencePresent = $false
        ValidationIssue = ''
        ScoringEligible = $false
        # Legacy public API: intentionally retains the source object reference.
        # Do not serialize OriginalResult into a public report without redaction.
        OriginalResult = $CheckResult
    }

    $normalized.EvidencePresent = (
        $null -ne $CollectorResult -and
        $null -ne $CollectorResult.Evidence -and
        $CollectorResult.Evidence.CollectionSuccessful -ceq $true
    )
    if ($status -cnotin @('PASS', 'FAIL')) {
        $normalized.ValidationIssue = 'Control is not fully evaluated.'
        return $normalized
    }
    $auth = Test-WinSecScoreAuthorization -Evaluation $CheckResult `
        -CriteriaSelection $CriteriaSelection -CollectorResult $CollectorResult
    if (-not $auth.Authorized) {
        $normalized.Status = 'UNKNOWN'
        $normalized.ValidationIssue = $auth.Reason
        return $normalized
    }
    if (-not (Test-WinSecScoreText $sectionKey)) {
        $normalized.Status = 'UNKNOWN'
        $normalized.ValidationIssue = 'SectionKey from collector is unavailable.'
        return $normalized
    }
    $normalized.Verified = $true
    $normalized.IncludedInScore = $true
    $normalized.ScoreValue = if ($status -ceq 'PASS') { 1 } else { 0 }
    $normalized.ScoringEligible = $true
    return $normalized
}

# ============================================================
# REVALIDATE NORMALIZED CHECK PROVENANCE
# A public summary cannot trust caller-supplied scoring flags.
# ============================================================

function Test-WinSecScoreNormalizedProvenance {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Normalized,
        [AllowEmptyCollection()][object[]]$CriteriaSelections = @(),
        [AllowEmptyCollection()][object[]]$CollectorResults = @()
    )

    if ($null -eq $Normalized) { return $false }
    $original = Get-WinSecScoreField $Normalized 'OriginalResult'
    if ($null -eq $original) { return $false }
    if (-not (Assert-WinSecScoreIdentity -Reference $original -Candidate $Normalized)) {
        return $false
    }

    $status = Get-WinSecScoreField $Normalized 'Status'
    $originalStatus = Get-WinSecScoreField $original 'Status'
    if ($status -cnotin @('PASS','FAIL') -or
        $originalStatus -cne $status -or
        (Get-WinSecScoreField $Normalized 'OriginalStatus') -cne $status -or
        $Normalized.Verified -cne $true -or
        $Normalized.IncludedInScore -cne $true -or
        $Normalized.ScoringEligible -cne $true -or
        $Normalized.EvidencePresent -cne $true) {
        return $false
    }

    $expectedValue = if ($status -ceq 'PASS') { 1 } else { 0 }
    if ($Normalized.ScoreValue -isnot [int] -and
        $Normalized.ScoreValue -isnot [long]) { return $false }
    if ($Normalized.ScoreValue -ne $expectedValue) { return $false }

    $selection = $null
    $collector = $null
    $selectionCount = 0
    $collectorCount = 0

    foreach ($item in $CriteriaSelections) {
        if ($null -eq $item) { continue }
        if (Assert-WinSecScoreIdentity -Reference $original -Candidate $item) {
            $selection = $item
            $selectionCount++
        }
    }
    foreach ($item in $CollectorResults) {
        if ($null -eq $item) { continue }
        if (Assert-WinSecScoreIdentity -Reference $original -Candidate $item) {
            $collector = $item
            $collectorCount++
        }
    }
    if ($selectionCount -ne 1 -or $collectorCount -ne 1) { return $false }

    $section = Get-WinSecScoreField $collector 'SectionKey'
    if (-not (Test-WinSecScoreText $section) -or
        $Normalized.SectionKey -cne $section -or
        $section -cnotin @('SystemSecurity','NetworkSecurity',
            'IdentityAccess','LoggingAuditing','ServicesHardening')) {
        return $false
    }

    # This recomputes source, criterion, collector and aggregate checks using
    # the original evaluation, not flags copied into the normalized object.
    $authorization = Test-WinSecScoreAuthorization `
        -Evaluation $original `
        -CriteriaSelection $selection `
        -CollectorResult $collector
    return ($authorization.Authorized -ceq $true)
}

# ============================================================
# COVERAGE AND SCORE SUMMARY (PRESERVED PUBLIC API)
# ============================================================

function Get-WinSecScoreSummary {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$CheckResults = @(),
        [Parameter(Mandatory)][object]$Policy,
        [AllowEmptyCollection()][string[]]$ExpectedCheckIds = @(),
        [bool]$AllowScore = $false,
        [AllowEmptyCollection()][object[]]$CriteriaSelections = @(),
        [AllowEmptyCollection()][object[]]$CollectorResults = @()
    )
    $null = Test-WinSecScoringPolicy -Policy $Policy
    $counts = @{}
    foreach ($status in @('PASS','FAIL','ERROR','UNKNOWN','NOT_EVALUATED',
        'PENDING','NOT_CHECKED','NOT_APPLICABLE','NOT_SELECTED',
        'MANUAL','INFORMATIONAL')) { $counts[$status] = 0 }

    $passedRules = 0
    $scoredRules = 0
    $verifiedChecks = 0
    $selectedApplicableChecks = 0
    $incomplete = $false
    $seenIds = @{}
    $presentCount = 0
    foreach ($check in $CheckResults) {
        if ($null -eq $check) { continue }
        $presentCount++
        $checkId = Get-WinSecScoreField $check 'CheckId'
        if (-not (Test-WinSecScoreText $checkId) -or
            $ExpectedCheckIds -cnotcontains $checkId -or
            $seenIds.ContainsKey([string]$checkId)) {
            $incomplete = $true
        }
        else {
            $seenIds[[string]$checkId] = $true
        }
        $status = [string]$check.Status
        if (-not $counts.ContainsKey($status)) { throw "Unknown normalized status: $status" }
        $counts[$status]++
        if ($status -cin @($Policy.coverage.denominatorStatuses)) {
            $selectedApplicableChecks++
        }
        if ($status -cin @('PASS','FAIL') -and
            (Test-WinSecScoreNormalizedProvenance `
                -Normalized $check `
                -CriteriaSelections $CriteriaSelections `
                -CollectorResults $CollectorResults)) {
            $verifiedChecks++
            $scoredRules++
            if ($status -ceq 'PASS' -and $check.ScoreValue -eq 1) { $passedRules++ }
        }
        elseif ($status -cin @('PASS','FAIL')) {
            $incomplete = $true
        }
        # All expected controls must be conclusively evaluated.
        # A mere NOT_APPLICABLE/INFORMATIONAL label is not a verified exemption.
        if ($status -cnotin @('PASS','FAIL')) { $incomplete = $true }
    }

    if ($ExpectedCheckIds.Count -eq 0 -or
        $presentCount -ne $ExpectedCheckIds.Count -or
        $seenIds.Count -ne $ExpectedCheckIds.Count) {
        $incomplete = $true
    }
    $expectedSeen = @{}
    foreach ($id in $ExpectedCheckIds) {
        if (-not (Test-WinSecScoreText $id) -or
            $expectedSeen.ContainsKey($id) -or
            -not $seenIds.ContainsKey($id)) {
            $incomplete = $true
        }
        else {
            $expectedSeen[$id] = $true
        }
    }
    $coverageValue = $null
    if ($selectedApplicableChecks -gt 0 -and $ExpectedCheckIds.Count -gt 0) {
        $coverageValue = [Math]::Round(
            ($verifiedChecks / [double]$selectedApplicableChecks) * 100,
            [int]$Policy.coverage.decimalPlaces,
            [System.MidpointRounding]::AwayFromZero
        )
    }
    $assessment = 'PENDING'
    if ($ExpectedCheckIds.Count -gt 0) {
        $assessment = if ($incomplete) { 'INCOMPLETE' } else { 'COMPLETE' }
    }
    $canScore = ($Policy.enabled -ceq $true -and $AllowScore -and
        $assessment -ceq 'COMPLETE' -and $scoredRules -gt 0)
    $score = $null
    if ($canScore) {
        $score = [Math]::Round(
            ($passedRules / [double]$scoredRules) * 100,
            [int]$Policy.methodology.decimalPlaces,
            [System.MidpointRounding]::AwayFromZero
        )
    }
    return [pscustomobject]@{
        Score = $score
        Coverage = $coverageValue
        Status = if ($canScore) { 'COMPLETE' } else { 'NOT_SCORED' }
        AssessmentStatus = $assessment
        ScoringEligible = $canScore
        PassedRules = $passedRules
        ScoredRules = $scoredRules
        VerifiedChecks = $verifiedChecks
        SelectedApplicableChecks = $selectedApplicableChecks
        TotalChecks = @($CheckResults | Where-Object { $null -ne $_ }).Count
        PassedCount = $counts.PASS
        FailedCount = $counts.FAIL
        ErrorCount = $counts.ERROR
        UnknownCount = $counts.UNKNOWN
        NotEvaluatedCount = $counts.NOT_EVALUATED
        PendingCount = $counts.PENDING
        NotCheckedCount = $counts.NOT_CHECKED
        NotApplicableCount = $counts.NOT_APPLICABLE
        NotSelectedCount = $counts.NOT_SELECTED
        ManualCount = $counts.MANUAL
        InformationalCount = $counts.INFORMATIONAL
        IsComplete = ($assessment -ceq 'COMPLETE')
    }
}

# ============================================================
# DEVICE AND SECTION SCORING (PRESERVED PUBLIC API)
# ============================================================

function Get-WinSecSecurityScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DeviceId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ScanId,
        [AllowEmptyCollection()][object[]]$CheckResults = @(),
        [AllowNull()][object]$Policy = $null,
        [AllowEmptyCollection()][object[]]$CriteriaSelections = @(),
        [AllowEmptyCollection()][object[]]$CollectorResults = @(),
        [AllowEmptyCollection()][string[]]$ExpectedCheckIds = @()
    )
    if ($null -eq $Policy) { $Policy = Get-WinSecScoringPolicy }
    $null = Test-WinSecScoringPolicy -Policy $Policy

    $expected = @{}
    foreach ($id in $ExpectedCheckIds) {
        if (-not (Test-WinSecScoreText $id) -or $expected.ContainsKey($id)) {
            throw 'ExpectedCheckIds must contain unique nonempty values.'
        }
        $expected[$id] = $true
    }

    $selections = @{}
    foreach ($item in $CriteriaSelections) {
        if ($null -eq $item) { continue }
        if ($item.DeviceId -cne $DeviceId -or $item.ScanId -cne $ScanId) { continue }
        if (-not (Test-WinSecScoreText $item.CheckId) -or
            $selections.ContainsKey($item.CheckId)) {
            throw 'Duplicate or invalid criteria selection CheckId.'
        }
        $selections[$item.CheckId] = $item
    }
    $collectors = @{}
    foreach ($item in $CollectorResults) {
        if ($null -eq $item) { continue }
        if ($item.DeviceId -cne $DeviceId -or $item.ScanId -cne $ScanId) { continue }
        if (-not (Test-WinSecScoreText $item.CheckId) -or
            $collectors.ContainsKey($item.CheckId)) {
            throw 'Duplicate or invalid collector CheckId.'
        }
        $collectors[$item.CheckId] = $item
    }

    $evaluated = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    foreach ($item in $CheckResults) {
        if ($null -eq $item) { continue }
        if (-not (Test-WinSecScoreText $item.DeviceId) -or
            -not (Test-WinSecScoreText $item.ScanId)) {
            throw 'Assessment record without DeviceId or ScanId.'
        }
        if ($item.DeviceId -cne $DeviceId -or $item.ScanId -cne $ScanId) { continue }
        if (-not (Test-WinSecScoreText $item.CheckId) -or
            $seen.ContainsKey($item.CheckId)) {
            throw 'Duplicate or invalid assessment CheckId.'
        }
        if ($expected.Count -gt 0 -and -not $expected.ContainsKey($item.CheckId)) {
            throw "Unexpected CheckId in assessment: $($item.CheckId)"
        }
        $seen[$item.CheckId] = $true
        $selection = if ($selections.ContainsKey($item.CheckId)) {
            $selections[$item.CheckId]
        } else { $null }
        $collector = if ($collectors.ContainsKey($item.CheckId)) {
            $collectors[$item.CheckId]
        } else { $null }
        $normalized = Get-WinSecCheckScore -CheckResult $item -Policy $Policy `
            -CriteriaSelection $selection -CollectorResult $collector
        $evaluated.Add($normalized)
    }

    # Every expected check is represented, even when its evaluation is missing.
    foreach ($id in $ExpectedCheckIds) {
        if ($seen.ContainsKey($id)) { continue }
        $section = $null
        if ($collectors.ContainsKey($id)) {
            $section = $collectors[$id].SectionKey
        }
        $evaluated.Add([pscustomobject]@{
            CheckId = $id
            DeviceId = $DeviceId
            ScanId = $ScanId
            SectionKey = $section
            OriginalStatus = 'NOT_CHECKED'
            Status = 'NOT_CHECKED'
            IncludedInScore = $false
            ScoreValue = $null
            Verified = $false
            EvidencePresent = $false
            ValidationIssue = 'Expected check has no evaluation.'
            ScoringEligible = $false
            OriginalResult = $null
        })
    }

    $all = @($evaluated.ToArray())
    $overall = Get-WinSecScoreSummary -CheckResults $all -Policy $Policy `
        -ExpectedCheckIds $ExpectedCheckIds -AllowScore $true `
        -CriteriaSelections $CriteriaSelections -CollectorResults $CollectorResults

    $sections = @(
        @{ Key = 'SystemSecurity'; Name = 'System Security' },
        @{ Key = 'NetworkSecurity'; Name = 'Network Security' },
        @{ Key = 'IdentityAccess'; Name = 'Identity & Access Security' },
        @{ Key = 'LoggingAuditing'; Name = 'Logging & Auditing' },
        @{ Key = 'ServicesHardening'; Name = 'Services & Hardening' }
    )
    $sectionResults = @(
        foreach ($section in $sections) {
            $items = @($all | Where-Object { $_.SectionKey -ceq $section.Key })
            $ids = @($items | ForEach-Object { $_.CheckId })
            # Never expose section scores while the overall audit is incomplete.
            $summary = Get-WinSecScoreSummary -CheckResults $items -Policy $Policy `
                -ExpectedCheckIds $ids -AllowScore $overall.ScoringEligible `
                -CriteriaSelections $CriteriaSelections -CollectorResults $CollectorResults
            [pscustomobject]@{
                DeviceId = $DeviceId
                ScanId = $ScanId
                Key = $section.Key
                Name = $section.Name
                Score = $summary.Score
                Coverage = $summary.Coverage
                Status = $summary.Status
                TotalChecks = $summary.TotalChecks
                PassedRules = $summary.PassedRules
                ScoredRules = $summary.ScoredRules
                PassedCount = $summary.PassedCount
                FailedCount = $summary.FailedCount
                ErrorCount = $summary.ErrorCount
                UnknownCount = $summary.UnknownCount
                NotEvaluatedCount = $summary.NotEvaluatedCount
                PendingCount = $summary.PendingCount
                IsComplete = $summary.IsComplete
            }
        }
    )

    return [pscustomobject]@{
        DeviceId = $DeviceId
        ScanId = $ScanId
        Score = $overall.Score
        Coverage = $overall.Coverage
        Status = $overall.Status
        OverallScore = $overall.Score
        OverallStatus = $overall.Status
        AssessmentStatus = $overall.AssessmentStatus
        ScoringEligible = $overall.ScoringEligible
        ScoringModel = $Policy.methodology.scoringModel
        ScoringMethod = $Policy.methodology.name
        IsXCCDFCertified = $false
        TotalChecks = $overall.TotalChecks
        ExpectedCheckCount = $ExpectedCheckIds.Count
        PassedRules = $overall.PassedRules
        ScoredRules = $overall.ScoredRules
        VerifiedChecks = $overall.VerifiedChecks
        SelectedApplicableChecks = $overall.SelectedApplicableChecks
        PassedCount = $overall.PassedCount
        FailedCount = $overall.FailedCount
        ErrorCount = $overall.ErrorCount
        UnknownCount = $overall.UnknownCount
        NotEvaluatedCount = $overall.NotEvaluatedCount
        PendingCount = $overall.PendingCount
        NotCheckedCount = $overall.NotCheckedCount
        NotApplicableCount = $overall.NotApplicableCount
        NotSelectedCount = $overall.NotSelectedCount
        ManualCount = $overall.ManualCount
        InformationalCount = $overall.InformationalCount
        IsComplete = $overall.IsComplete
        SectionResults = $sectionResults
        CheckResults = $all
    }
}
