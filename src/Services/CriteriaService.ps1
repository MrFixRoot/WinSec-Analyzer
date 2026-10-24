# ============================================================
# WinSec Analyzer
# Component  : Criteria Service
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Loads, validates and selects locally stored security criteria
# for an identified Windows device and audit scan.
#
# Includes:
# - Local JSON catalog loading
# - Catalog and criterion structure validation
# - Explicit approval and scoring gates
# - Device, scan, OS edition and profile checks
# - Prerequisite evidence checks
# - Evaluation Engine contract verification
# - Review-only observations kept separate
# - No grading of draft or partially selected catalogs
#
# PowerShell 5.1 / 7.x
#
# IMPORTANT:
# This service reads files and evaluates in-memory objects only.
# It never modifies Windows settings or approves criteria.
# Approval flags are declarations, NOT proof of external review.
# ============================================================

# ============================================================
# PROPERTY HELPERS
# ============================================================

. (Join-Path $PSScriptRoot '../Core/CriterionApplicability.ps1')
. (Join-Path $PSScriptRoot '../Core/CriterionWeight.ps1')

function Get-WinSecCriteriaField {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return ,$InputObject[$Name] }
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return ,$property.Value
}

function Test-WinSecCriteriaText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    return (
        $Value -is [string] -and
        -not [string]::IsNullOrWhiteSpace($Value)
    )
}

# ============================================================
# LOCAL CATALOG LOADER
# ============================================================

function Import-WinSecCriteriaCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProjectRoot,

        [ValidateNotNullOrEmpty()]
        [string]$RelativePath = 'config/criteria/defender.json'
    )

    $root = [System.IO.Path]::GetFullPath($ProjectRoot)
    $separators = [char[]]@(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $rootPrefix = $root.TrimEnd($separators) +
        [System.IO.Path]::DirectorySeparatorChar

    # Do not read absolute paths, UNC paths or parent directories.
    if ([System.IO.Path]::IsPathRooted($RelativePath)) {
        throw 'The catalog path must be relative to ProjectRoot.'
    }

    $candidate = [System.IO.Path]::GetFullPath(
        (Join-Path -Path $root -ChildPath $RelativePath)
    )

    if (-not $candidate.StartsWith(
        $rootPrefix, [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'The catalog path escapes the project directory.'
    }

    if ([System.IO.Path]::GetExtension($candidate) -cne '.json') {
        throw 'Only JSON criteria catalogs are supported.'
    }

    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Criteria catalog not found: $candidate"
    }

    $file = Get-Item -LiteralPath $candidate -ErrorAction Stop
    if ($file.Length -gt 5242880) {
        throw 'Criteria catalog exceeds the 5 MiB safety limit.'
    }

    try {
        $json = Get-Content -LiteralPath $candidate -Raw -Encoding UTF8 -ErrorAction Stop
        # ConvertFrom-Json can enumerate a single-element JSON root array
        # into a single object. Validate the JSON document shape BEFORE
        # conversion so arrays and primitives can never masquerade as a catalog.
        if ($json.TrimStart() -notmatch '^\{') {
            throw 'The catalog root must be a JSON object.'
        }

        $catalog = ConvertFrom-Json -InputObject $json -ErrorAction Stop
    }
    catch {
        throw ('Unable to parse the criteria catalog: {0}' -f $_.Exception.Message)
    }

    if ($null -eq $catalog -or $catalog -is [array]) {
        throw 'The catalog root must be a JSON object.'
    }
    # PowerShell 7 may parse ISO timestamps as DateTime; 5.1 keeps strings.
    # Preserve an explicitly UTC approval timestamp in the common data contract.
    foreach ($criterion in @($catalog.Criteria)) {
        $reviewed = Get-WinSecCriteriaField (Get-WinSecCriteriaField $criterion 'Verification') 'ReviewedAtUTC'
        if ($reviewed -is [datetime] -and $reviewed.Kind -eq [DateTimeKind]::Utc) {
            $criterion.Verification.ReviewedAtUTC = $reviewed.ToString('o')
        }
    }

    return $catalog
}

# ============================================================
# APPROVAL READINESS GATE
# ============================================================

function Test-WinSecCriteriaApprovalReady {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Criterion
    )

    if ($null -eq $Criterion) { return $false }

    # An approved catalog never overrides each criterion's approval.
    $approved = Get-WinSecCriteriaField $Criterion 'Approved'
    if ($approved -isnot [bool] -or -not $approved) {
        return $false
    }

    $source = Get-WinSecCriteriaField $Criterion 'Source'
    if ((Get-WinSecCriteriaField $source 'Framework') -cnotin @(
        'LOCAL_POLICY', 'CIS Benchmarks'
    )) {
        return $false
    }

    $sourceId = Get-WinSecCriteriaField $source 'ControlId'
    if (-not (Test-WinSecCriteriaText $sourceId) -or
        $sourceId -ceq 'NOT_ASSIGNED') {
        return $false
    }

    $uriText = Get-WinSecCriteriaField $source 'Url'
    $uri = $null
    if (-not (Test-WinSecCriteriaText $uriText) -or
        -not [System.Uri]::TryCreate(
            [string]$uriText,
            [System.UriKind]::Absolute,
            [ref]$uri
        ) -or $uri.Scheme -cne 'https') {
        return $false
    }

    $verification = Get-WinSecCriteriaField $Criterion 'Verification'
    if ((Get-WinSecCriteriaField $verification 'Status') -cne 'VERIFIED' -or
        -not (Test-WinSecCriteriaText (
            Get-WinSecCriteriaField $verification 'ReviewedBy'
        ))) {
        return $false
    }

    $reviewedAt = Get-WinSecCriteriaField $verification 'ReviewedAtUTC'
    $reviewDate = [DateTimeOffset]::MinValue
    if (-not (Test-WinSecCriteriaText $reviewedAt) -or
        -not [DateTimeOffset]::TryParse(
            [string]$reviewedAt, [ref]$reviewDate
        ) -or $reviewDate -gt [DateTimeOffset]::UtcNow) {
        return $false
    }

    $scope = Get-WinSecCriteriaField $Criterion 'Applicability'
    foreach ($name in @('OSFamily', 'OSRelease', 'Edition', 'Profile')) {
        $value = Get-WinSecCriteriaField $scope $name
        if (-not (Test-WinSecCriteriaText $value) -or
            $value -ceq 'PENDING_SELECTION' -or $value -ceq '*') {
            return $false
        }
    }

    try {$null=Get-WinSecCriterionPlatformExclusion $Criterion}
    catch {return $false}
    $dependencies = Get-WinSecCriteriaField $Criterion 'ActivationDependencies'
    if ($dependencies -isnot [array] -or $dependencies.Count -eq 0) {
        return $false
    }

    foreach ($dependency in $dependencies) {
        if (-not (Test-WinSecCriteriaText $dependency)) {
            return $false
        }
    }

    # Readiness is metadata gating only. Runtime dependencies must
    # still be validated by Get-WinSecApplicableCriteria, and source
    # authenticity must be reviewed outside of this service.
    return $true
}

# ============================================================
# STRUCTURAL CATALOG VALIDATION
# ============================================================

function Test-WinSecCriteriaCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Catalog
    )

    $errors = New-Object 'System.Collections.Generic.List[string]'
    $catalogId = Get-WinSecCriteriaField $Catalog 'CatalogId'
    $checkId = Get-WinSecCriteriaField $Catalog 'CheckId'
    $version = Get-WinSecCriteriaField $Catalog 'CatalogVersion'
    $status = Get-WinSecCriteriaField $Catalog 'Status'
    $enabled = Get-WinSecCriteriaField $Catalog 'ScoringEnabled'
    $evaluationEnabled = Get-WinSecCriteriaField $Catalog 'EvaluationEnabled'
    $allowChanges = Get-WinSecCriteriaField $Catalog 'DeviceChangesAllowed'
    $criteria = Get-WinSecCriteriaField $Catalog 'Criteria'
    $reviewOnly = Get-WinSecCriteriaField $Catalog 'ReviewOnly'

    if (-not (Test-WinSecCriteriaText $catalogId)) {
        $errors.Add('CatalogId is required.')
    }
    if (-not (Test-WinSecCriteriaText $checkId)) {
        $errors.Add('CheckId is required.')
    }
    if (-not (Test-WinSecCriteriaText $version)) {
        $errors.Add('CatalogVersion is required.')
    }
    if ($status -cnotin @('DRAFT_UNAPPROVED', 'APPROVED')) {
        $errors.Add('Catalog status is unsupported.')
    }
    if ($enabled -isnot [bool]) {
        $errors.Add('ScoringEnabled must be Boolean.')
    }
    if ($null -ne $evaluationEnabled -and $evaluationEnabled -isnot [bool]) {
        $errors.Add('EvaluationEnabled must be Boolean when declared.')
    }
    if ($status -ceq 'DRAFT_UNAPPROVED' -and $evaluationEnabled -ceq $true) {
        $errors.Add('A draft catalog cannot enable evaluation.')
    }
    if ($allowChanges -isnot [bool] -or $allowChanges) {
        $errors.Add('DeviceChangesAllowed must be Boolean false.')
    }
    if ($status -eq 'DRAFT_UNAPPROVED' -and $enabled -eq $true) {
        $errors.Add('A draft catalog cannot enable scoring.')
    }
    if ($criteria -isnot [array] -or @($criteria).Count -eq 0) {
        $errors.Add('Criteria must be a nonempty JSON array.')
    }
    if ($reviewOnly -isnot [array]) {
        $errors.Add('ReviewOnly must be a JSON array.')
    }

    $ids = @{}
    foreach ($criterion in @($criteria)) {
        if ($null -eq $criterion) { $errors.Add('Null criterion.'); continue }
        $id = Get-WinSecCriteriaField $criterion 'CriterionId'
        $cCheckId = Get-WinSecCriteriaField $criterion 'CheckId'
        $path = Get-WinSecCriteriaField $criterion 'EvidencePath'
        $operator = Get-WinSecCriteriaField $criterion 'Operator'
        $approved = Get-WinSecCriteriaField $criterion 'Approved'
        $source = Get-WinSecCriteriaField $criterion 'Source'
        $scope = Get-WinSecCriteriaField $criterion 'Applicability'
        $recommendation = Get-WinSecCriteriaField $criterion 'Recommendation'

        if (-not (Test-WinSecCriteriaText $id)) {
            $errors.Add('CriterionId is missing.'); continue
        }
        if ($ids.ContainsKey([string]$id)) {
            $errors.Add("Duplicate CriterionId: $id")
        }
        $ids[[string]$id] = $true

        try {$null=Get-WinSecCriterionWeight $criterion}
        catch {$errors.Add("$id has an invalid criterion weight.")}

        if ($cCheckId -cne $checkId) {
            $errors.Add("$id has a mismatched CheckId.")
        }
        if (-not (Test-WinSecCriteriaText $path) -or
            $path -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$') {
            $errors.Add("$id has an invalid EvidencePath.")
        }
        if ($operator -cnotin @('Equals','NotEquals','In','NotIn',
                                 'GreaterThanOrEqual','LessThanOrEqual')) {
            $errors.Add("$id has an unsupported Operator.")
        }
        if ($approved -isnot [bool]) {
            $errors.Add("$id Approved must be Boolean.")
        }
        if (-not (Test-WinSecCriteriaText $recommendation)) {
            $errors.Add("$id requires a recommendation.")
        }
        foreach ($name in @('Framework','Version','ControlId','Title','Url')) {
            if (-not (Test-WinSecCriteriaText (Get-WinSecCriteriaField $source $name))) {
                $errors.Add("$id has no Source.$name.")
            }
        }
        foreach ($name in @('OSFamily','OSRelease','Edition','Profile')) {
            if (-not (Test-WinSecCriteriaText (Get-WinSecCriteriaField $scope $name))) {
                $errors.Add("$id has no Applicability.$name.")
            }
        }
        $mapping = Get-WinSecCriteriaField $criterion 'FrameworkMappings'
        try {$null=Get-WinSecCriterionPlatformExclusion $criterion}
        catch {$errors.Add("$id has invalid platform exclusion metadata.")}
        foreach ($name in @('CISBenchmarks','CISControls','NISTCSF','MITREATTACK')) {
            if ((Get-WinSecCriteriaField $mapping $name) -isnot [array]) {
                $errors.Add("$id has no FrameworkMappings.$name array.")
            }
        }
    }

    foreach ($item in @($reviewOnly)) {
        if ($null -eq $item) { $errors.Add('Null review-only entry.'); continue }
        if ((Get-WinSecCriteriaField $item 'Assessment') -cne 'REVIEW_ONLY') {
            $errors.Add('ReviewOnly entries must have Assessment=REVIEW_ONLY.')
        }
    }

    $valid = ($errors.Count -eq 0)

    # Catalog-level approval is insufficient: every criterion must
    # have its own approval, verification and concrete scope.
    $allCriteriaReady = $valid
    if ($allCriteriaReady) {
        foreach ($criterion in @($criteria)) {
            if (-not (Test-WinSecCriteriaApprovalReady -Criterion $criterion)) {
                $allCriteriaReady = $false
                break
            }
        }
    }

    $ready = (
        $valid -and
        $status -ceq 'APPROVED' -and
        $enabled -eq $true -and
        $allCriteriaReady
    )

    return [pscustomobject]@{
        CatalogId = $catalogId
        CheckId = $checkId
        Valid = $valid
        ReadyForScoring = $ready
        ReadyForEvaluation = ($valid -and $status -ceq 'APPROVED' -and $allCriteriaReady -and
            ($enabled -ceq $true -or $evaluationEnabled -ceq $true))
        Status = $status
        CriteriaCount = @($criteria | Where-Object { $null -ne $_ }).Count
        ReviewOnlyCount = @($reviewOnly | Where-Object { $null -ne $_ }).Count
        Errors = @($errors.ToArray())
    }
}

# ============================================================
# TARGET AND APPROVAL SELECTION
# ============================================================

function Get-WinSecApplicableCriteria {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Catalog,

        [Parameter(Mandatory)]
        [object]$TargetContext,

        [Parameter(Mandatory)]
        [object]$ControlResult,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProjectRoot,

        [AllowNull()]
        [System.Collections.IDictionary]$DependencyEvidence = $null,

        [switch]$ForEvaluation
    )

    $catalogId = Get-WinSecCriteriaField $Catalog 'CatalogId'
    $checkId = Get-WinSecCriteriaField $ControlResult 'CheckId'
    $deviceId = Get-WinSecCriteriaField $ControlResult 'DeviceId'
    $scanId = Get-WinSecCriteriaField $ControlResult 'ScanId'
    $validation = Test-WinSecCriteriaCatalog -Catalog $Catalog

    # Do not wrap an array-returning helper directly in @(...):
    # it may preserve the entire collection as a single element.
    $reviewSource = Get-WinSecCriteriaField $Catalog 'ReviewOnly'
    $reviewEntries = @()
    if ($reviewSource -is [array]) {
        $reviewEntries = $reviewSource.Clone()
    }

    $output = [pscustomobject]@{
        CatalogId = $catalogId
        CheckId = $checkId
        DeviceId = $deviceId
        ScanId = $scanId
        Status = 'BLOCKED'
        Reason = ''
        ScoringEligible = $false
        CatalogCriteriaCount = $validation.CriteriaCount
        MatchedCriteriaCount = 0
        EligibleCriteria = @()
        ExcludedCriteria = @()
        ReviewOnly = $reviewEntries
        ValidationIssues = @($validation.Errors)
    }
    if ($ForEvaluation) { $output|Add-Member -NotePropertyName EvaluationEligible -NotePropertyValue $false }

    if (-not $validation.Valid) {
        $output.Reason = 'Catalog structure is invalid.'
        return $output
    }

    # Draft or disabled catalogs are blocked before selection.
    # For APPROVED-labeled catalogs with individually unapproved rules,
    # retain per-rule diagnostic selection but NEVER release a partial set.
    $catalogEnabled = (Get-WinSecCriteriaField $Catalog 'ScoringEnabled') -ceq $true
    if ($ForEvaluation) { $catalogEnabled = $catalogEnabled -or ((Get-WinSecCriteriaField $Catalog 'EvaluationEnabled') -ceq $true) }
    if ($validation.Status -cne 'APPROVED' -or -not $catalogEnabled) {
        $output.Status = 'DRAFT_BLOCKED'
        $output.Reason = if($ForEvaluation){'The catalog is not approved for evaluation.'}else{'The catalog is not approved for scoring.'}
        return $output
    }

    if ($checkId -cne $validation.CheckId) {
        $output.Reason = 'Catalog and collected CheckId differ.'
        return $output
    }

    if ((Get-WinSecCriteriaField $ControlResult 'Status') -cne 'INFORMATIONAL') {
        $output.Reason = 'Collector did not return an informational result.'
        return $output
    }

    $evidence = Get-WinSecCriteriaField $ControlResult 'Evidence'
    if ((Get-WinSecCriteriaField $evidence 'CollectionSuccessful') -cne $true) {
        $output.Reason = 'Evidence collection is not confirmed successful.'
        return $output
    }

    foreach ($idName in @('CheckId','DeviceId','ScanId')) {
        $expectedIdentity = Get-WinSecCriteriaField $ControlResult $idName
        $evidenceIdentity = Get-WinSecCriteriaField $evidence $idName
        if (-not (Test-WinSecCriteriaText $expectedIdentity) -or
            $evidenceIdentity -cne $expectedIdentity) {
            $output.Reason = "Evidence identity mismatch: $idName."
            return $output
        }
    }

    foreach ($idName in @('DeviceId','ScanId')) {
        if ((Get-WinSecCriteriaField $TargetContext $idName) -cne
            (Get-WinSecCriteriaField $ControlResult $idName)) {
            $output.Reason = "Target context identity mismatch: $idName."
            return $output
        }
    }

    foreach ($name in @('OSFamily','OSRelease','Edition','Profile')) {
        $value = Get-WinSecCriteriaField $TargetContext $name
        if (-not (Test-WinSecCriteriaText $value) -or
            $value -ceq 'PENDING_SELECTION' -or $value -ceq '*') {
            $output.Reason = "Target context is incomplete: $name."
            return $output
        }
    }

    # Load the same validator used by the evaluator. Dot-sourcing here
    # keeps the imported functions in this invocation's scope.
    $engine = Join-Path ([System.IO.Path]::GetFullPath($ProjectRoot)) `
        'src/Core/EvaluationEngine.ps1'
    if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) {
        $output.Reason = 'EvaluationEngine.ps1 is missing.'
        return $output
    }
    try {
        . $engine
    }
    catch {
        $output.Reason = 'Evaluation Engine could not be loaded.'
        return $output
    }

    $selected = New-Object 'System.Collections.Generic.List[object]'
    $excluded = New-Object 'System.Collections.Generic.List[object]'
    $blocked = $false

    foreach ($criterion in $Catalog.Criteria) {
        $id = Get-WinSecCriteriaField $criterion 'CriterionId'
        $scope = Get-WinSecCriteriaField $criterion 'Applicability'
        $matches = $true
        foreach ($field in @('OSFamily','OSRelease','Edition','Profile')) {
            $required = Get-WinSecCriteriaField $scope $field
            $actual = Get-WinSecCriteriaField $TargetContext $field
            if (-not [string]::Equals(
                [string]$required, [string]$actual,
                [System.StringComparison]::OrdinalIgnoreCase
            )) { $matches = $false; break }
        }
        if (-not $matches) {
            $excluded.Add([pscustomobject]@{
                CriterionId=$id; Reason='WINDOWS_SCOPE_MISMATCH'
            })
            continue
        }

        $criterionValidation = Test-WinSecEvaluationCriterion -Criterion $criterion
        if (-not $criterionValidation.Valid) {
            $blocked = $true
            $excluded.Add([pscustomobject]@{
                CriterionId=$id; Reason='CRITERION_NOT_VERIFIED'
            })
            continue
        }

        # An approved exact-platform exclusion is resolved without requiring
        # telemetry/prerequisites for a feature that does not apply there.
        if($null -ne (Get-WinSecCriterionPlatformExclusion $criterion $TargetContext)) {
            $selected.Add($criterion)
            continue
        }
        $dependencies = Get-WinSecCriteriaField $criterion 'ActivationDependencies'
        if ($dependencies -isnot [array] -or $dependencies.Count -eq 0) {
            $blocked = $true
            $excluded.Add([pscustomobject]@{
                CriterionId=$id; Reason='DEPENDENCIES_NOT_DECLARED'
            })
            continue
        }

        $dependenciesMet = $true
        foreach ($dependency in $dependencies) {
            if (-not (Test-WinSecCriteriaText $dependency) -or
                $null -eq $DependencyEvidence -or
                -not $DependencyEvidence.Contains([string]$dependency) -or
                $DependencyEvidence[[string]$dependency] -isnot [bool] -or
                $DependencyEvidence[[string]$dependency] -ne $true) {
                $dependenciesMet = $false
                break
            }
        }
        if (-not $dependenciesMet) {
            $blocked = $true
            $excluded.Add([pscustomobject]@{
                CriterionId=$id; Reason='PREREQUISITES_NOT_CONFIRMED'
            })
            continue
        }

        $selected.Add($criterion)
    }

    $output.MatchedCriteriaCount = $selected.Count
    $output.ExcludedCriteria = @($excluded.ToArray())

    # A subset must not be mistaken for compliance with the whole check.
    if ($selected.Count -eq 0) {
        $output.Status = 'NO_ELIGIBLE_CRITERIA'
        $output.Reason = 'No approved, applicable criteria with confirmed prerequisites.'
        return $output
    }
    $readyForPurpose = if($ForEvaluation){$validation.ReadyForEvaluation}else{$validation.ReadyForScoring}
    if ($blocked -or $excluded.Count -gt 0 -or -not $readyForPurpose) {
        $output.Status = 'PARTIAL_SELECTION_BLOCKED'
        $output.Reason = 'Full coverage is not confirmed; no criteria released for scoring.'
        return $output
    }

    $output.Status = 'READY'
    $output.Reason = 'All catalog criteria are approved, applicable and supported by prerequisite evidence.'
    $output.ScoringEligible = -not $ForEvaluation
    if ($ForEvaluation) { $output.EvaluationEligible = $true }
    $output.EligibleCriteria = @($selected.ToArray())
    return $output
}
