# ============================================================
# WinSec Analyzer
# Component  : Findings Engine
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Converts existing security evaluations into traceable,
# privacy-conscious findings and separate review items.
#
# Includes:
# - Device, scan and control identity validation
# - Confirmed criterion deviations (FAIL)
# - Evidence gaps and pending evaluations
# - Draft catalog and collector error safeguards
# - Review-only observations without compliance claims
# - Deterministic finding identifiers
# - No raw values from audit evidence in findings
# - No invented severity, score or framework mapping
#
# PowerShell 5.1 / 7.x
#
# IMPORTANT:
# In-memory, read-only processing. Never changes Windows.
# Source/approval metadata is not independent verification.
# Only EvaluationEngine may judge approved criteria.
# ============================================================

# ============================================================
# PROPERTY HELPERS
# ============================================================

function Get-WinSecFindingProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return ,$InputObject[$Name]
        }
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return ,$property.Value
}

function Test-WinSecFindingText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    return (
        $Value -is [string] -and
        -not [string]::IsNullOrWhiteSpace($Value)
    )
}

function Test-WinSecFindingIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Expected,
        [AllowNull()][object]$Actual,
        [Parameter(Mandatory)][string[]]$Fields
    )

    if ($null -eq $Actual) { return $false }

    foreach ($field in $Fields) {
        $a = Get-WinSecFindingProperty $Expected $field
        $b = Get-WinSecFindingProperty $Actual $field

        if (-not (Test-WinSecFindingText $a) -or
            -not (Test-WinSecFindingText $b) -or
            $a -cne $b) {
            return $false
        }
    }

    return $true
}

# ============================================================
# STABLE FINDING ID - NO USER DATA IN IDENTIFIER
# ============================================================

function New-WinSecFindingId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DeviceId,
        [Parameter(Mandatory)][string]$ScanId,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Key
    )

    # Length-prefix each element to avoid separator collisions.
    $parts = @($DeviceId, $ScanId, $CheckId, $Kind, $Key)
    $canonical = [string]::Join('', @(
        foreach ($part in $parts) {
            '{0}:{1}' -f $part.Length, $part
        }
    ))

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
        $digest = $sha.ComputeHash($bytes)
        $hex = [System.BitConverter]::ToString($digest).Replace('-', '')
        return 'WSA-FND-{0}' -f $hex.Substring(0, 24)
    }
    finally {
        $sha.Dispose()
    }
}

# ============================================================
# OUTPUT CONTRACT
# ============================================================

function New-WinSecFindingRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Identity,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][string]$EvaluationStatus,
        [AllowNull()][string]$CriterionId = $null,
        [AllowNull()][string]$EvidencePath = $null,
        [AllowNull()][string]$Recommendation = $null,
        [AllowNull()][object]$Source = $null
    )

    $checkId = Get-WinSecFindingProperty $Identity 'CheckId'
    $deviceId = Get-WinSecFindingProperty $Identity 'DeviceId'
    $scanId = Get-WinSecFindingProperty $Identity 'ScanId'

    $category = if ($Kind -eq 'CONFIGURATION_DEVIATION') {
        'CONFIGURATION'
    }
    else {
        'DATA_QUALITY'
    }

    return [pscustomobject]@{
        FindingId = New-WinSecFindingId `
            -DeviceId $deviceId -ScanId $scanId `
            -CheckId $checkId -Kind $Kind -Key $Key
        CheckId = $checkId
        DeviceId = $deviceId
        ScanId = $scanId
        Kind = $Kind
        Category = $category
        Title = $Title
        EvaluationStatus = $EvaluationStatus
        WorkflowStatus = 'OPEN'
        Severity = 'UNASSIGNED'
        SeverityBasis = 'No approved severity methodology was supplied.'
        Priority = 'UNASSIGNED'
        Reason = $Reason
        CriterionId = $CriterionId
        EvidenceReference = [pscustomobject]@{
            CheckId = $checkId
            DeviceId = $deviceId
            ScanId = $scanId
            CriterionId = $CriterionId
            Path = $EvidencePath
            RawValueIncluded = $false
        }
        Recommendation = $Recommendation
        Source = $Source
        FrameworkMappings = [pscustomobject]@{
            CISBenchmarks = @()
            CISControls = @()
            NISTCSF = @()
            MITREATTACK = @()
        }
        ScoringEligible = $false
        GeneratedAtUTC = [DateTime]::UtcNow.ToString('o')
    }
}

function Test-WinSecFindingSource {
    [CmdletBinding()]
    param([AllowNull()][object]$Source)

    if ($null -eq $Source) { return $false }

    $framework = Get-WinSecFindingProperty $Source 'Framework'
    $version = Get-WinSecFindingProperty $Source 'Version'
    $controlId = Get-WinSecFindingProperty $Source 'ControlId'
    $title = Get-WinSecFindingProperty $Source 'Title'
    $url = Get-WinSecFindingProperty $Source 'Url'

    if ($framework -cnotin @('LOCAL_POLICY', 'CIS Benchmarks')) {
        return $false
    }
    foreach ($value in @($version, $controlId, $title, $url)) {
        if (-not (Test-WinSecFindingText $value)) { return $false }
    }

    $uri = $null
    return (
        [System.Uri]::TryCreate(
            [string]$url,
            [System.UriKind]::Absolute,
            [ref]$uri
        ) -and $uri.Scheme -ceq 'https'
    )
}

# ============================================================
# OPTIONAL REVIEW-ONLY EVIDENCE LOOKUP
# ============================================================

function Test-WinSecFindingEvidencePath {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Evidence,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Path -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$') {
        return $false
    }

    $current = $Evidence
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $current) { return $false }
        if ($current -is [array]) { return $false }

        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($part)) { return $false }
            $current = $current[$part]
        }
        else {
            $property = $current.PSObject.Properties[$part]
            if ($null -eq $property) { return $false }
            $current = $property.Value
        }
    }

    return ($null -ne $current)
}

# ============================================================
# FINDINGS ENGINE
# ============================================================

function ConvertTo-WinSecFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$EvaluationResult,

        [AllowNull()]
        [object]$ControlResult = $null,

        [AllowNull()]
        [object]$SelectionResult = $null,

        [switch]$IncludeReviewOnly
    )

    $checkId = Get-WinSecFindingProperty $EvaluationResult 'CheckId'
    $deviceId = Get-WinSecFindingProperty $EvaluationResult 'DeviceId'
    $scanId = Get-WinSecFindingProperty $EvaluationResult 'ScanId'

    $output = [pscustomobject]@{
        CheckId = $checkId
        DeviceId = $deviceId
        ScanId = $scanId
        Status = 'INVALID_INPUT'
        Reason = ''
        Findings = @()
        ReviewItems = @()
        FindingCount = 0
        DeviationCount = 0
        EvidenceGapCount = 0
        PendingCount = 0
        ReviewItemCount = 0
        ScoringEligible = $false
        GeneratedAtUTC = [DateTime]::UtcNow.ToString('o')
    }

    # --------------------------------------------------------
    # Identity is mandatory; never merge devices or scans.
    # --------------------------------------------------------

    foreach ($value in @($checkId, $deviceId, $scanId)) {
        if (-not (Test-WinSecFindingText $value)) {
            $output.Reason = 'Evaluation identity is incomplete.'
            return $output
        }
    }

    if ($null -ne $ControlResult) {
        if (-not (Test-WinSecFindingIdentity `
            -Expected $EvaluationResult -Actual $ControlResult `
            -Fields @('CheckId', 'DeviceId', 'ScanId'))) {
            $output.Reason = 'Collector and evaluation identities differ.'
            return $output
        }

        $evidence = Get-WinSecFindingProperty $ControlResult 'Evidence'
        if ($null -ne $evidence) {
            foreach ($name in @('CheckId', 'DeviceId', 'ScanId')) {
                $id = Get-WinSecFindingProperty $evidence $name
                if ((Test-WinSecFindingText $id) -and
                    $id -cne (Get-WinSecFindingProperty $EvaluationResult $name)) {
                    $output.Reason = "Collector evidence identity mismatch: $name."
                    return $output
                }
            }
        }
    }

    if ($null -ne $SelectionResult) {
        if (-not (Test-WinSecFindingIdentity `
            -Expected $EvaluationResult -Actual $SelectionResult `
            -Fields @('CheckId', 'DeviceId', 'ScanId'))) {
            $output.Reason = 'Selection and evaluation identities differ.'
            return $output
        }
    }

    $findings = New-Object 'System.Collections.Generic.List[object]'
    $reviews = New-Object 'System.Collections.Generic.List[object]'

    # --------------------------------------------------------
    # Selection is an authorization gate, not just metadata.
    # --------------------------------------------------------

    $selectionReady = $true
    $allowedIds = @{}

    if ($null -ne $SelectionResult) {
        $selectionReady = (
            (Get-WinSecFindingProperty $SelectionResult 'Status') -ceq 'READY' -and
            (Get-WinSecFindingProperty $SelectionResult 'ScoringEligible') -is [bool] -and
            (Get-WinSecFindingProperty $SelectionResult 'ScoringEligible') -eq $true
        )

        if ($selectionReady) {
            $eligibleCriteria = Get-WinSecFindingProperty $SelectionResult 'EligibleCriteria'
            foreach ($criterion in @($eligibleCriteria)) {
                $id = Get-WinSecFindingProperty $criterion 'CriterionId'
                if (Test-WinSecFindingText $id) {
                    $allowedIds[[string]$id] = $true
                }
            }
            if ($allowedIds.Count -eq 0) { $selectionReady = $false }
        }

        if (-not $selectionReady) {
            $findings.Add((New-WinSecFindingRecord `
                -Identity $EvaluationResult `
                -Kind 'CATALOG_NOT_READY' `
                -Key 'catalog' `
                -Title 'Catalog selection is not authorized for findings evaluation' `
                -Reason 'No compliance deviation can be asserted from blocked or incomplete criteria selection.' `
                -EvaluationStatus 'NOT_EVALUATED'))
        }
    }

    # --------------------------------------------------------
    # Collector ERROR blocks claimed confirmed deviations.
    # --------------------------------------------------------

    $collectorError = (
        $null -ne $ControlResult -and
        (Get-WinSecFindingProperty $ControlResult 'Status') -ceq 'ERROR'
    )

    if ($collectorError) {
        $findings.Add((New-WinSecFindingRecord `
            -Identity $EvaluationResult `
            -Kind 'COLLECTION_ERROR' `
            -Key 'collection' `
            -Title 'Security evidence collection failed' `
            -Reason 'Collector reported ERROR. Review the original collection log; raw error details are not exported.' `
            -EvaluationStatus 'UNKNOWN'))
    }

    $rawEvaluations = Get-WinSecFindingProperty $EvaluationResult 'Evaluations'
    $items = @($rawEvaluations | Where-Object { $null -ne $_ })
    $aggregateStatus = Get-WinSecFindingProperty $EvaluationResult 'Status'

    if ($aggregateStatus -cnotin @(
        'PASS', 'FAIL', 'UNKNOWN', 'NOT_EVALUATED', 'NOT_APPLICABLE'
    )) {
        $output.Reason = 'Unsupported aggregate evaluation status.'
        return $output
    }

    if ($selectionReady -and -not $collectorError) {
        $hasFail = @($items | Where-Object { $_.Status -ceq 'FAIL' }).Count -gt 0
        $hasIncomplete = @($items | Where-Object {
            $_.Status -cin @('UNKNOWN', 'NOT_EVALUATED')
        }).Count -gt 0

        if (($aggregateStatus -eq 'PASS' -and
             ($items.Count -eq 0 -or $hasFail -or $hasIncomplete)) -or
            ($aggregateStatus -eq 'FAIL' -and
             (-not $hasFail -or $hasIncomplete)) -or
            ($aggregateStatus -eq 'NOT_APPLICABLE' -and
             @($items | Where-Object { $_.Status -cne 'NOT_APPLICABLE' }).Count -gt 0)) {
            $output.Reason = 'Aggregate and criterion-level statuses disagree.'
            return $output
        }
    }

    $duplicateIds = @{}
    $idCounts = @{}

    foreach ($item in $items) {
        if ($null -eq $item) { continue }
        $id = Get-WinSecFindingProperty $item 'CriterionId'
        if (-not (Test-WinSecFindingText $id)) { continue }
        if (-not $idCounts.ContainsKey([string]$id)) { $idCounts[[string]$id] = 0 }
        $idCounts[[string]$id]++
    }

    $index = 0
    foreach ($item in $items) {
        if (-not $selectionReady -or $collectorError) { break }
        $index++
        if ($null -eq $item) { continue }
        $criterionId = Get-WinSecFindingProperty $item 'CriterionId'
        $state = Get-WinSecFindingProperty $item 'Status'
        $path = Get-WinSecFindingProperty $item 'EvidencePath'
        $validIdentity = Test-WinSecFindingIdentity `
            -Expected $EvaluationResult -Actual $item `
            -Fields @('CheckId', 'DeviceId', 'ScanId')

        if (-not $validIdentity) {
            $findings.Add((New-WinSecFindingRecord `
                -Identity $EvaluationResult -Kind 'EVALUATION_IDENTITY_ERROR' `
                -Key "identity-$index" `
                -Title 'A criterion evaluation has mismatched identity' `
                -Reason 'Criterion results from another device, scan or control cannot be combined.' `
                -EvaluationStatus 'UNKNOWN'))
            continue
        }

        if (-not (Test-WinSecFindingText $criterionId)) {
            $findings.Add((New-WinSecFindingRecord `
                -Identity $EvaluationResult -Kind 'EVALUATION_DATA_ERROR' `
                -Key "missing-id-$index" `
                -Title 'Criterion evaluation has no identifier' `
                -Reason 'The criterion result cannot be traced to an approved rule.' `
                -EvaluationStatus 'UNKNOWN'))
            continue
        }

        if ($idCounts[[string]$criterionId] -gt 1) {
            if (-not $duplicateIds.ContainsKey([string]$criterionId)) {
                $duplicateIds[[string]$criterionId] = $true
                $findings.Add((New-WinSecFindingRecord `
                    -Identity $EvaluationResult -Kind 'DUPLICATE_CRITERION' `
                    -Key $criterionId `
                    -Title 'Duplicate criterion evaluation identifier' `
                    -Reason 'Duplicate evaluations must be resolved before reporting a compliance deviation.' `
                    -EvaluationStatus 'UNKNOWN' -CriterionId $criterionId))
            }
            continue
        }

        if ($state -cnotin @('PASS', 'FAIL', 'UNKNOWN', 'NOT_EVALUATED', 'NOT_APPLICABLE')) {
            $findings.Add((New-WinSecFindingRecord `
                -Identity $EvaluationResult -Kind 'EVALUATION_DATA_ERROR' `
                -Key "invalid-state-$criterionId" `
                -Title 'Unsupported criterion evaluation state' `
                -Reason 'An unrecognized evaluation state cannot be interpreted as compliant or noncompliant.' `
                -EvaluationStatus 'UNKNOWN' -CriterionId $criterionId))
            continue
        }

        # PASS and justified NOT_APPLICABLE generate no finding.
        if ($state -in @('PASS', 'NOT_APPLICABLE')) { continue }

        if ($state -eq 'FAIL') {
            # Fail closed if a supplied catalog was not released,
            # the result was not scored, or the source is incomplete.
            $accepted = (
                $selectionReady -and
                ($null -eq $SelectionResult -or $allowedIds.ContainsKey([string]$criterionId)) -and
                -not $collectorError -and
                (Get-WinSecFindingProperty $item 'ScoringEligible') -is [bool] -and
                (Get-WinSecFindingProperty $item 'ScoringEligible') -eq $true -and
                (Test-WinSecFindingText $path) -and
                $path -cmatch '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$' -and
                (Test-WinSecFindingText (Get-WinSecFindingProperty $item 'Recommendation')) -and
                (Test-WinSecFindingSource (Get-WinSecFindingProperty $item 'Source'))
            )

            if ($accepted) {
                $source = Get-WinSecFindingProperty $item 'Source'
                $safeSource = [pscustomobject]@{
                    Framework = Get-WinSecFindingProperty $source 'Framework'
                    Version = Get-WinSecFindingProperty $source 'Version'
                    ControlId = Get-WinSecFindingProperty $source 'ControlId'
                    Title = Get-WinSecFindingProperty $source 'Title'
                    Url = Get-WinSecFindingProperty $source 'Url'
                    Verification = 'DECLARED_BY_EVALUATION_NOT_INDEPENDENTLY_CONFIRMED'
                }
                $findings.Add((New-WinSecFindingRecord `
                    -Identity $EvaluationResult -Kind 'CONFIGURATION_DEVIATION' `
                    -Key $criterionId `
                    -Title ('Criterion not satisfied: {0}' -f $criterionId) `
                    -Reason 'Observed evidence did not match the applicable criterion evaluated by EvaluationEngine.' `
                    -EvaluationStatus 'FAIL' -CriterionId $criterionId `
                    -EvidencePath $path `
                    -Recommendation (Get-WinSecFindingProperty $item 'Recommendation') `
                    -Source $safeSource))
            }
            elseif ($selectionReady -and -not $collectorError) {
                $findings.Add((New-WinSecFindingRecord `
                    -Identity $EvaluationResult -Kind 'EVALUATION_NOT_TRUSTED' `
                    -Key $criterionId `
                    -Title 'Failed evaluation lacks required evidence or authorization' `
                    -Reason 'Result cannot become a confirmed deviation until scoring eligibility, selection and documentation are consistent.' `
                    -EvaluationStatus 'NOT_EVALUATED' -CriterionId $criterionId))
            }
            continue
        }

        if ($state -eq 'UNKNOWN') {
            $findings.Add((New-WinSecFindingRecord `
                -Identity $EvaluationResult -Kind 'EVIDENCE_GAP' `
                -Key $criterionId `
                -Title ('Evidence unavailable: {0}' -f $criterionId) `
                -Reason 'The criterion could not be evaluated. This does not demonstrate a vulnerable configuration.' `
                -EvaluationStatus 'UNKNOWN' -CriterionId $criterionId `
                -EvidencePath $path))
        }
        elseif ($state -eq 'NOT_EVALUATED') {
            $findings.Add((New-WinSecFindingRecord `
                -Identity $EvaluationResult -Kind 'CRITERION_PENDING' `
                -Key $criterionId `
                -Title ('Criterion not evaluated: {0}' -f $criterionId) `
                -Reason 'Evaluation is pending or its approval/verification is incomplete.' `
                -EvaluationStatus 'NOT_EVALUATED' -CriterionId $criterionId `
                -EvidencePath $path))
        }
    }

    # --------------------------------------------------------
    # No criterion-level records: retain the aggregate state.
    # --------------------------------------------------------

    if ($items.Count -eq 0 -and -not $collectorError -and
        ($null -eq $SelectionResult -or $selectionReady)) {
        $aggregateStatus = Get-WinSecFindingProperty $EvaluationResult 'Status'
        if ($aggregateStatus -in @('UNKNOWN', 'NOT_EVALUATED')) {
            $kind = if ($aggregateStatus -eq 'UNKNOWN') {
                'EVALUATION_UNAVAILABLE'
            }
            else {
                'EVALUATION_PENDING'
            }
            $findings.Add((New-WinSecFindingRecord `
                -Identity $EvaluationResult -Kind $kind -Key 'aggregate' `
                -Title 'Control evaluation is incomplete' `
                -Reason 'No criterion-level evaluations are available for this control.' `
                -EvaluationStatus $aggregateStatus))
        }
    }

    # --------------------------------------------------------
    # ReviewOnly is separate from security findings.
    # We only reveal metadata and an evidence reference,
    # never raw registry, exclusion, path or process values.
    # --------------------------------------------------------

    if ($IncludeReviewOnly -and
        $null -ne $SelectionResult -and
        $null -ne $ControlResult) {

        $evidence = Get-WinSecFindingProperty $ControlResult 'Evidence'
        $rawReviewItems = Get-WinSecFindingProperty $SelectionResult 'ReviewOnly'
        $reviewItems = @($rawReviewItems | Where-Object { $null -ne $_ })
        $reviewIndex = 0

        foreach ($review in $reviewItems) {
            $reviewIndex++
            if ($null -eq $review) { continue }
            $name = Get-WinSecFindingProperty $review 'Name'
            $area = Get-WinSecFindingProperty $review 'Area'
            $path = Get-WinSecFindingProperty $review 'EvidencePath'
            $assessment = Get-WinSecFindingProperty $review 'Assessment'

            if (-not (Test-WinSecFindingText $name) -or
                -not (Test-WinSecFindingText $area) -or
                -not (Test-WinSecFindingText $path) -or
                $assessment -cne 'REVIEW_ONLY') {
                continue
            }

            $available = (
                -not $collectorError -and
                (Test-WinSecFindingEvidencePath -Evidence $evidence -Path $path)
            )

            $reviews.Add([pscustomobject]@{
                ReviewId = New-WinSecFindingId `
                    -DeviceId $deviceId -ScanId $scanId `
                    -CheckId $checkId -Kind 'REVIEW_ONLY' `
                    -Key ('{0}:{1}:{2}' -f $reviewIndex, $area, $path)
                CheckId = $checkId
                DeviceId = $deviceId
                ScanId = $scanId
                Area = $area
                Name = $name
                Type = 'REVIEW_ONLY'
                Status = if ($available) { 'OBSERVED' } else { 'UNKNOWN' }
                EvidencePath = $path
                ReferenceUrl = Get-WinSecFindingProperty $review 'ReferenceUrl'
                RawValueIncluded = $false
                ComplianceStatus = 'NOT_EVALUATED'
                ScoringEligible = $false
                Severity = 'UNASSIGNED'
            })
        }
    }

    # --------------------------------------------------------
    # Summary: these counts are NOT security scores.
    # --------------------------------------------------------

    $output.Findings = @($findings.ToArray())
    $output.ReviewItems = @($reviews.ToArray())
    $output.FindingCount = $output.Findings.Count
    $output.ReviewItemCount = $output.ReviewItems.Count
    $output.DeviationCount = @($output.Findings | Where-Object {
        $_.Kind -eq 'CONFIGURATION_DEVIATION'
    }).Count
    $output.EvidenceGapCount = @($output.Findings | Where-Object {
        $_.Kind -in @('EVIDENCE_GAP', 'EVALUATION_UNAVAILABLE', 'COLLECTION_ERROR')
    }).Count
    $output.PendingCount = @($output.Findings | Where-Object {
        $_.Kind -in @('CRITERION_PENDING', 'EVALUATION_PENDING',
                     'CATALOG_NOT_READY', 'EVALUATION_NOT_TRUSTED',
                     'EVALUATION_DATA_ERROR', 'EVALUATION_IDENTITY_ERROR',
                     'DUPLICATE_CRITERION')
    }).Count

    if ($collectorError -or -not $selectionReady) {
        $output.Status = 'BLOCKED'
        $output.Reason = 'Collection or criterion selection did not authorize a complete assessment.'
    }
    elseif ($output.FindingCount -eq 0) {
        $output.Status = 'COMPLETE'
        $output.Reason = 'No deviations or evaluation gaps were reported.'
    }
    elseif ($output.DeviationCount -eq $output.FindingCount) {
        $output.Status = 'COMPLETE'
        $output.Reason = 'Criterion deviations are listed without severity or score.'
    }
    else {
        $output.Status = 'INCOMPLETE'
        $output.Reason = 'The output includes evidence gaps, pending criteria or validation issues.'
    }

    return $output
}
