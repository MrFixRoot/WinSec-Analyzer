# ============================================================
# WinSec Analyzer
# Component  : Evaluation Engine
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Evidence-based, read-only evaluation of Windows security
# controls against explicitly approved criteria.
#
# Includes:
# - Evidence and identity validation
# - Approved criterion validation
# - Explicit Windows target applicability
# - Safe property-path resolution
# - Strict typed comparisons
# - PASS, FAIL, UNKNOWN and NOT_EVALUATED
# - Justified NOT_APPLICABLE results
# - Conservative control aggregation
# - Evidence, source and recommendations
# - No unsupported framework mappings or scoring
#
# PowerShell 5.1 / 7.x
# No Pester required for this component.
#
# IMPORTANT:
# This engine only processes existing objects in memory.
# It never modifies Windows or starts a security scan.
# Approval metadata is not independent source verification.
# Only externally reviewed criteria may be approved.
# ============================================================

# ============================================================
# PROPERTY HELPERS
# ============================================================

. (Join-Path $PSScriptRoot 'CriterionApplicability.ps1')

. (Join-Path $PSScriptRoot 'WindowsUpdateCriterionEvidence.ps1')

function Get-WinSecEvaluationProperty {
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

function Test-WinSecEvaluationProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject.Contains($Name)
    }
    return ($null -ne $InputObject.PSObject.Properties[$Name])
}

function Test-WinSecEvaluationText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    return (
        $Value -is [string] -and
        -not [string]::IsNullOrWhiteSpace($Value)
    )
}

function Resolve-WinSecEvaluationPath {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Evidence,
        [Parameter(Mandatory)][string]$Path
    )

    $result = [pscustomobject]@{ Found=$false; Value=$null }

    if ($Path -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$') {
        return $result
    }

    $current = $Evidence
    foreach ($segment in $Path.Split('.')) {
        if (-not (Test-WinSecEvaluationProperty -InputObject $current -Name $segment)) {
            return $result
        }
        $current = Get-WinSecEvaluationProperty -InputObject $current -Name $segment
    }

    $result.Found = $true
    $result.Value = $current
    return $result
}

# ============================================================
# TYPE-SAFE COMPARISONS
# ============================================================

function Test-WinSecEvaluationNumber {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or $Value -is [bool]) { return $false }

    return $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or
        $Value -is [decimal] -or $Value -is [double] -or
        $Value -is [single]
}

function Compare-WinSecEvaluationScalar {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [ValidateSet('Equals','NotEquals','GreaterThanOrEqual','LessThanOrEqual')]
        [string]$Operator = 'Equals'
    )

    $result = [pscustomobject]@{ Supported=$false; Matches=$false }
    if ($null -eq $Actual -or $null -eq $Expected) { return $result }
    if ($Actual -is [array] -or $Expected -is [array]) { return $result }
    if ($Actual -is [System.Collections.IDictionary] -or
        $Expected -is [System.Collections.IDictionary]) { return $result }

    $comparison = $null

    if ($Actual -is [string] -and $Expected -is [string]) {
        if ($Operator -notin @('Equals','NotEquals')) { return $result }
        $comparison = [string]::CompareOrdinal($Actual, $Expected)
    }
    elseif ($Actual -is [bool] -and $Expected -is [bool]) {
        if ($Operator -notin @('Equals','NotEquals')) { return $result }
        $comparison = ([int]$Actual).CompareTo([int]$Expected)
    }
    elseif ((Test-WinSecEvaluationNumber $Actual) -and
            (Test-WinSecEvaluationNumber $Expected)) {
        try {
            $left = [decimal]$Actual
            $right = [decimal]$Expected
            $comparison = $left.CompareTo($right)
        }
        catch { return $result }
    }
    else {
        # Do not coerce numeric strings, nulls or incompatible values.
        return $result
    }

    $result.Supported = $true
    switch ($Operator) {
        'Equals'             { $result.Matches = ($comparison -eq 0) }
        'NotEquals'          { $result.Matches = ($comparison -ne 0) }
        'GreaterThanOrEqual' { $result.Matches = ($comparison -ge 0) }
        'LessThanOrEqual'    { $result.Matches = ($comparison -le 0) }
    }
    return $result
}

function Compare-WinSecEvaluationValue {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [Parameter(Mandatory)][string]$Operator
    )

    if ($Operator -in @('In','NotIn')) {
        $result = [pscustomobject]@{ Supported=$false; Matches=$false }
        if ($Expected -isnot [array] -or $Expected.Count -eq 0) {
            return $result
        }

        $found = $false
        foreach ($candidate in $Expected) {
            $comparison = Compare-WinSecEvaluationScalar `
                -Actual $Actual -Expected $candidate -Operator Equals
            if (-not $comparison.Supported) {
                return $result
            }
            if ($comparison.Matches) { $found = $true }
        }
        $result.Supported = $true
        $result.Matches = if ($Operator -eq 'In') { $found } else { -not $found }
        return $result
    }

    return Compare-WinSecEvaluationScalar `
        -Actual $Actual -Expected $Expected -Operator $Operator
}

# ============================================================
# CRITERION CONTRACT AND SOURCE VALIDATION
# ============================================================

function Test-WinSecEvaluationCriterion {
    [CmdletBinding()]
    param([AllowNull()][object]$Criterion)

    $result = [pscustomobject]@{ Valid=$false; Reason='' }
    if ($null -eq $Criterion) {
        $result.Reason = 'Criterion is null.'
        return $result
    }

    foreach ($name in @('CriterionId','CheckId','EvidencePath','Operator','Recommendation')) {
        $value = Get-WinSecEvaluationProperty $Criterion $name
        if (-not (Test-WinSecEvaluationText $value)) {
            $result.Reason = "Missing or invalid criterion field: $name."
            return $result
        }
    }

    $path = Get-WinSecEvaluationProperty $Criterion 'EvidencePath'
    if ($path -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$') {
        $result.Reason = 'EvidencePath must be a literal dotted property path.'
        return $result
    }

    $operator = Get-WinSecEvaluationProperty $Criterion 'Operator'
    if ($operator -cnotin @('Equals','NotEquals','In','NotIn','GreaterThanOrEqual','LessThanOrEqual')) {
        $result.Reason = 'Criterion operator is not supported.'
        return $result
    }

    $expected = Get-WinSecEvaluationProperty $Criterion 'ExpectedValue'
    if ($null -eq $expected) {
        $result.Reason = 'ExpectedValue cannot be null.'
        return $result
    }
    if ($operator -in @('In','NotIn')) {
        if ($expected -isnot [array] -or $expected.Count -eq 0) {
            $result.Reason = 'In/NotIn requires a nonempty ExpectedValue array.'
            return $result
        }
    }
    elseif ($expected -is [array]) {
        $result.Reason = 'ExpectedValue must be scalar for this operator.'
        return $result
    }

    $approved = Get-WinSecEvaluationProperty $Criterion 'Approved'
    if ($approved -isnot [bool] -or -not $approved) {
        $result.Reason = 'Criterion was not explicitly approved.'
        return $result
    }

    $source = Get-WinSecEvaluationProperty $Criterion 'Source'
    foreach ($name in @('Framework','Version','ControlId','Title','Url')) {
        if (-not (Test-WinSecEvaluationText (Get-WinSecEvaluationProperty $source $name))) {
            $result.Reason = "Missing documented source field: $name."
            return $result
        }
    }

    $framework = Get-WinSecEvaluationProperty $source 'Framework'
    if ($framework -cnotin @('LOCAL_POLICY','CIS Benchmarks')) {
        $result.Reason = 'Only local policy and verified CIS Benchmark criteria can grade controls; NIST CSF, CIS Controls and MITRE ATT&CK are contextual mappings.'
        return $result
    }

    $uri = $null
    $url = Get-WinSecEvaluationProperty $source 'Url'
    if (-not [System.Uri]::TryCreate($url,[System.UriKind]::Absolute,[ref]$uri) -or
        $uri.Scheme -cne 'https') {
        $result.Reason = 'Source URL must be an absolute HTTPS URL.'
        return $result
    }

    $verification = Get-WinSecEvaluationProperty $Criterion 'Verification'
    if ((Get-WinSecEvaluationProperty $verification 'Status') -cne 'VERIFIED' -or
        -not (Test-WinSecEvaluationText (Get-WinSecEvaluationProperty $verification 'ReviewedBy'))) {
        $result.Reason = 'Criterion requires explicit external verification metadata.'
        return $result
    }

    $reviewDateText = Get-WinSecEvaluationProperty $verification 'ReviewedAtUTC'
    $reviewDate = [DateTimeOffset]::MinValue
    if (-not (Test-WinSecEvaluationText $reviewDateText) -or
        -not [DateTimeOffset]::TryParse($reviewDateText,[ref]$reviewDate)) {
        $result.Reason = 'Criterion verification timestamp is invalid.'
        return $result
    }
    if ($reviewDate -gt [DateTimeOffset]::UtcNow) {
        $result.Reason = 'Criterion verification timestamp is in the future.'
        return $result
    }

    $scope = Get-WinSecEvaluationProperty $Criterion 'Applicability'
    foreach ($name in @('OSFamily','OSRelease','Edition','Profile')) {
        if (-not (Test-WinSecEvaluationText (Get-WinSecEvaluationProperty $scope $name))) {
            $result.Reason = "Criterion has no explicit applicability field: $name."
            return $result
        }
    }

    try {$null=Get-WinSecCriterionPlatformExclusion $Criterion}
    catch {$result.Reason='Invalid verified platform applicability metadata.';return $result}
    $result.Valid = $true
    $result.Reason = 'Criterion metadata is structurally valid.'
    return $result
}

# ============================================================
# EVALUATE ONE CRITERION
# ============================================================

function Invoke-WinSecCriterionEvaluation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Criterion,
        [Parameter(Mandatory)][object]$Evidence,
        [Parameter(Mandatory)][object]$TargetContext,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$DeviceId,
        [Parameter(Mandatory)][string]$ScanId
    )

    $output = [pscustomobject]@{
        CriterionId = Get-WinSecEvaluationProperty $Criterion 'CriterionId'
        CheckId = $CheckId
        DeviceId = $DeviceId
        ScanId = $ScanId
        Status = 'NOT_EVALUATED'
        ScoringEligible = $false
        EvidencePath = $null
        ObservedValue = $null
        ExpectedValue = $null
        Operator = $null
        Source = $null
        Recommendation = $null
        Reason = ''
        EvaluatedAtUTC = [DateTime]::UtcNow.ToString('o')
    }

    $validation = Test-WinSecEvaluationCriterion -Criterion $Criterion
    if (-not $validation.Valid) {
        $output.Reason = $validation.Reason
        return $output
    }

    if ((Get-WinSecEvaluationProperty $Criterion 'CheckId') -cne $CheckId) {
        $output.Reason = 'Criterion CheckId does not match the control.'
        return $output
    }

    $output.EvidencePath = Get-WinSecEvaluationProperty $Criterion 'EvidencePath'

    # Keep the expected-value snapshot independent of the approved criterion.
    # In/NotIn criteria operate on arrays of immutable scalar values; clone
    # the array so subsequent changes to an evaluation cannot mutate its rule.
    $criterionExpected = Get-WinSecEvaluationProperty $Criterion 'ExpectedValue'
    if ($criterionExpected -is [array]) {
        $output.ExpectedValue = $criterionExpected.Clone()
    }
    else {
        $output.ExpectedValue = $criterionExpected
    }
    $output.Operator = Get-WinSecEvaluationProperty $Criterion 'Operator'

    # Source metadata must be a snapshot, not an alias to the approved
    # criterion's mutable Source object. Otherwise a caller could modify
    # the evaluation source AND the selected criterion source at once,
    # defeating the independent comparison in ScoreEngine.
    $criterionSource = Get-WinSecEvaluationProperty $Criterion 'Source'
    $output.Source = [pscustomobject]@{
        Framework = Get-WinSecEvaluationProperty $criterionSource 'Framework'
        Version   = Get-WinSecEvaluationProperty $criterionSource 'Version'
        ControlId = Get-WinSecEvaluationProperty $criterionSource 'ControlId'
        Title     = Get-WinSecEvaluationProperty $criterionSource 'Title'
        Url       = Get-WinSecEvaluationProperty $criterionSource 'Url'
    }
    $output.Recommendation = Get-WinSecEvaluationProperty $Criterion 'Recommendation'

    # A criterion must match the OS scope explicitly. Missing target fields
    # are NOT_EVALUATED, never NOT_APPLICABLE or PASS.
    $scope = Get-WinSecEvaluationProperty $Criterion 'Applicability'
    foreach ($name in @('OSFamily','OSRelease','Edition','Profile')) {
        $expectedScope = Get-WinSecEvaluationProperty $scope $name
        $observedScope = Get-WinSecEvaluationProperty $TargetContext $name

        if (-not (Test-WinSecEvaluationText $observedScope)) {
            $output.Reason = "Target applicability information is missing: $name."
            return $output
        }

        if (-not [string]::Equals($expectedScope,$observedScope,
            [System.StringComparison]::OrdinalIgnoreCase)) {
            $output.Status = 'NOT_APPLICABLE'
            $output.Reason = "Criterion scope does not match the target field: $name."
            return $output
        }
    }

    $exclusion=Get-WinSecCriterionPlatformExclusion $Criterion $TargetContext
    if($null -ne $exclusion) {
        $output.Status='NOT_APPLICABLE'
        $output.Reason=$exclusion.Reason
        return $output
    }

    if($CheckId -ceq 'WSA-SYS-003') {
        # Pure derivation shared by initial evaluation and provenance replay.
        # No I/O, provider calls, caller verdicts or mutation of original evidence.
        $Evidence=Get-WinSecWindowsUpdateCriterionEvidence -Criterion $Criterion -Evidence $Evidence `
            -TargetContext $TargetContext -DeviceId $DeviceId -ScanId $ScanId
    }
    $resolved = Resolve-WinSecEvaluationPath `
        -Evidence $Evidence -Path $output.EvidencePath

    if (-not $resolved.Found -or $null -eq $resolved.Value) {
        $output.Status = 'UNKNOWN'
        $output.Reason = 'Required evidence path is unavailable or null.'
        return $output
    }

    $output.ObservedValue = $resolved.Value
    $comparison = Compare-WinSecEvaluationValue `
        -Actual $resolved.Value -Expected $output.ExpectedValue `
        -Operator $output.Operator

    if (-not $comparison.Supported) {
        $output.Status = 'UNKNOWN'
        $output.Reason = 'Evidence and expected value have incompatible types or unsupported values.'
        return $output
    }

    if ($comparison.Matches) {
        $output.Status = 'PASS'
        $output.Reason = 'Evidence matches the approved, applicable criterion.'
    }
    else {
        $output.Status = 'FAIL'
        $output.Reason = 'Evidence does not match the approved, applicable criterion.'
    }
    $output.ScoringEligible = $true
    return $output
}

# ============================================================
# EVALUATE ONE SECURITY CONTROL
# ============================================================

function Invoke-WinSecControlEvaluation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$ControlResult,
        [AllowNull()][object[]]$Criteria = @(),
        [AllowNull()][object]$TargetContext = $null
    )

    $checkId = Get-WinSecEvaluationProperty $ControlResult 'CheckId'
    $deviceId = Get-WinSecEvaluationProperty $ControlResult 'DeviceId'
    $scanId = Get-WinSecEvaluationProperty $ControlResult 'ScanId'
    $collectorStatus = Get-WinSecEvaluationProperty $ControlResult 'Status'
    $evidence = Get-WinSecEvaluationProperty $ControlResult 'Evidence'

    $output = [pscustomobject]@{
        CheckId = $checkId
        DeviceId = $deviceId
        ScanId = $scanId
        CollectorStatus = $collectorStatus
        Status = 'NOT_EVALUATED'
        ScoringEligible = $false
        EvaluatedCriteria = 0
        PassedCriteria = 0
        FailedCriteria = 0
        UnknownCriteria = 0
        NotEvaluatedCriteria = 0
        NotApplicableCriteria = 0
        Evaluations = @()
        Reason = ''
        EvaluatedAtUTC = [DateTime]::UtcNow.ToString('o')
    }

    foreach ($value in @($checkId,$deviceId,$scanId)) {
        if (-not (Test-WinSecEvaluationText $value)) {
            $output.Reason = 'Control identity is incomplete.'
            return $output
        }
    }

    if ($collectorStatus -eq 'ERROR') {
        $output.Status = 'UNKNOWN'
        $output.Reason = 'The collector reported an error.'
        return $output
    }

    if ($collectorStatus -eq 'NOT_APPLICABLE') {
        # Collector NA alone is not sufficient for an auditable exception.
        $output.Reason = 'Collector N/A requires independently verified applicability evidence.'
        return $output
    }

    if ($collectorStatus -cne 'INFORMATIONAL') {
        $output.Reason = 'Unsupported collector status for evidence evaluation.'
        return $output
    }

    if ($null -eq $evidence -or
        (Get-WinSecEvaluationProperty $evidence 'CollectionSuccessful') -cne $true) {
        $output.Status = 'UNKNOWN'
        $output.Reason = 'Successful evidence collection was not confirmed.'
        return $output
    }

    foreach ($name in @('CheckId','DeviceId','ScanId')) {
        if (Test-WinSecEvaluationProperty $evidence $name) {
            $evidenceIdentity = Get-WinSecEvaluationProperty $evidence $name
            $controlIdentity = Get-WinSecEvaluationProperty $ControlResult $name
            if ($evidenceIdentity -cne $controlIdentity) {
                $output.Status = 'UNKNOWN'
                $output.Reason = "Evidence identity does not match: $name."
                return $output
            }
        }
    }

    if (@($Criteria).Count -eq 0) {
        $output.Reason = 'No approved evaluation criteria were supplied.'
        return $output
    }

    if ($null -eq $TargetContext) {
        $output.Reason = 'Target OS release, edition and benchmark profile were not supplied.'
        return $output
    }

    # Ensure target context cannot be reused for a different device or scan.
    foreach ($name in @('DeviceId','ScanId')) {
        if (Test-WinSecEvaluationProperty $TargetContext $name) {
            $targetIdentity = Get-WinSecEvaluationProperty $TargetContext $name
            $controlIdentity = Get-WinSecEvaluationProperty $ControlResult $name
            if ($targetIdentity -cne $controlIdentity) {
                $output.Status = 'UNKNOWN'
                $output.Reason = "Target context identity does not match: $name."
                return $output
            }
        }
    }

    $evaluations = New-Object 'System.Collections.Generic.List[object]'
    $criterionIds = @{}

    foreach ($criterion in $Criteria) {
        $criterionId = Get-WinSecEvaluationProperty $criterion 'CriterionId'
        $evaluation = Invoke-WinSecCriterionEvaluation `
            -Criterion $criterion -Evidence $evidence `
            -TargetContext $TargetContext -CheckId $checkId `
            -DeviceId $deviceId -ScanId $scanId

        # Duplicate IDs invalidate the entire aggregate: avoid inflated grading.
        if (Test-WinSecEvaluationText $criterionId) {
            if ($criterionIds.ContainsKey($criterionId)) {
                $evaluation.Status = 'NOT_EVALUATED'
                $evaluation.ScoringEligible = $false
                $evaluation.Reason = 'Duplicate CriterionId in this evaluation batch.'
            }
            $criterionIds[$criterionId] = $true
        }
        $evaluations.Add($evaluation)
    }

    # If an ID occurs twice, invalidate every occurrence, not only the second.
    $countsById = @{}
    foreach ($item in $evaluations) {
        if (Test-WinSecEvaluationText $item.CriterionId) {
            $key = [string]$item.CriterionId
            if (-not $countsById.ContainsKey($key)) { $countsById[$key] = 0 }
            $countsById[$key]++
        }
    }
    foreach ($item in $evaluations) {
        if ((Test-WinSecEvaluationText $item.CriterionId) -and
            $countsById[[string]$item.CriterionId] -gt 1) {
            $item.Status = 'NOT_EVALUATED'
            $item.ScoringEligible = $false
            $item.Reason = 'Duplicate CriterionId in this evaluation batch.'
        }
    }

    $output.Evaluations = @($evaluations.ToArray())
    foreach ($item in $output.Evaluations) {
        switch ($item.Status) {
            'PASS' {
                $output.PassedCriteria++
                $output.EvaluatedCriteria++
            }
            'FAIL' {
                $output.FailedCriteria++
                $output.EvaluatedCriteria++
            }
            'UNKNOWN'       { $output.UnknownCriteria++ }
            'NOT_EVALUATED' { $output.NotEvaluatedCriteria++ }
            'NOT_APPLICABLE' { $output.NotApplicableCriteria++ }
        }
    }

    # Any incomplete criterion prevents a grade, even if another failed.
    # Individual FAIL evidence remains visible in Evaluations.
    if ($output.UnknownCriteria -gt 0 -or $output.NotEvaluatedCriteria -gt 0) {
        $output.Status = 'UNKNOWN'
        $output.Reason = 'One or more criteria could not be evaluated; review individual results.'
        return $output
    }

    if ($output.FailedCriteria -gt 0) {
        $output.Status = 'FAIL'
        $output.ScoringEligible = $true
        $output.Reason = 'At least one applicable criterion failed.'
        return $output
    }

    if ($output.PassedCriteria -gt 0) {
        $output.Status = 'PASS'
        $output.ScoringEligible = $true
        $output.Reason = 'All applicable criteria passed.'
        return $output
    }

    if ($output.NotApplicableCriteria -gt 0) {
        $output.Status = 'NOT_APPLICABLE'
        $output.Reason = 'All verified criteria have a scope different from the target.'
        return $output
    }

    $output.Reason = 'No evaluable criteria were found.'
    return $output
}
