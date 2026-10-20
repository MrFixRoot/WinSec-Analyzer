# ============================================================
# WinSec Analyzer
# Component  : Result Model
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Defines and validates in-memory scan result contracts.
# Keeps devices, scans, collector results, criterion evaluations,
# findings, observations and score results correlated.
#
# Includes:
# - Strict DeviceId / ScanId / CheckId correlation
# - Duplicate record detection
# - UTC timestamps and explicit execution status
# - Safe NOT_SCORED defaults
# - Separate internal and public result representations
# - No fabricated risk, framework mapping or score
#
# PowerShell 5.1 / 7.x
#
# IMPORTANT:
# Read-only: no Windows changes and no file writes.
# Raw collector/evaluation objects may contain sensitive data.
# Never serialize the internal model for public reports; use
# ConvertTo-WinSecPublicScanResult or a reviewed exporter.
# A result model is NOT an authorization or scoring engine.
# ============================================================

function Get-WinSecResultField {
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

function Test-WinSecResultText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($Value -isnot [string]) { return $false }
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 256) {
        return $false
    }
    return (-not [regex]::IsMatch($Value, '[\x00-\x1F\x7F]'))
}

function ConvertTo-WinSecResultUtc {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$FieldName
    )

    # UTC-only timestamps prevent local-time ambiguity between machines.
    if ($Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$') {
        throw "$FieldName must be an ISO 8601 UTC timestamp ending in Z."
    }

    $parsed = [DateTimeOffset]::MinValue
    $style = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal

    $valid = [DateTimeOffset]::TryParse(
        $Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        $style,
        [ref]$parsed
    )
    if (-not $valid) { throw "$FieldName is not a valid UTC timestamp." }
    return $parsed
}

function Assert-WinSecResultItems {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Items = @(),
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$DeviceId,
        [Parameter(Mandatory)][string]$ScanId,
        [string]$IdentityField = 'CheckId',
        [switch]$RequireUnique,
        [AllowEmptyCollection()][string[]]$KnownCheckIds = @(),
        [switch]$RequireKnownCheck
    )

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $known = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($id in $KnownCheckIds) { $null = $known.Add($id) }

    foreach ($item in $Items) {
        if ($null -eq $item) { throw "$Kind contains a null record." }

        $recordDevice = Get-WinSecResultField $item 'DeviceId'
        $recordScan = Get-WinSecResultField $item 'ScanId'
        $recordCheck = Get-WinSecResultField $item 'CheckId'

        if (-not (Test-WinSecResultText $recordDevice) -or
            -not (Test-WinSecResultText $recordScan) -or
            -not (Test-WinSecResultText $recordCheck) -or
            $recordDevice -cne $DeviceId -or
            $recordScan -cne $ScanId) {
            throw "$Kind contains an incomplete or foreign device/scan/check identity."
        }

        if ($RequireKnownCheck -and -not $known.Contains([string]$recordCheck)) {
            throw "$Kind references an unknown CheckId: $recordCheck"
        }

        if ($RequireUnique) {
            $identity = Get-WinSecResultField $item $IdentityField
            if (-not (Test-WinSecResultText $identity)) {
                throw "$Kind is missing $IdentityField."
            }
            if (-not $seen.Add([string]$identity)) {
                throw "$Kind contains duplicate ${IdentityField}: $identity"
            }
        }
    }
}

function New-WinSecResultSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DeviceId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ScanId,
        [string]$ComputerName = '',
        [ValidateSet('LOCAL','REMOTE','IMPORTED')][string]$CollectionMode = 'LOCAL',
        [string]$StartedAtUTC = '',
        [string]$CompletedAtUTC = '',
        [ValidateSet('PENDING','COMPLETED','COMPLETED_WITH_ERRORS',
            'NO_EXECUTABLE_CHECKS','FAILED','CANCELLED')]
        [string]$ExecutionStatus = 'PENDING',
        [AllowEmptyCollection()][string[]]$ExpectedCheckIds = @(),
        [AllowEmptyCollection()][object[]]$ControlResults = @(),
        [AllowEmptyCollection()][object[]]$EvaluationResults = @(),
        [AllowEmptyCollection()][object[]]$CriteriaSelections = @(),
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [AllowEmptyCollection()][object[]]$ReviewItems = @(),
        [AllowNull()][object]$ScoreResult = $null,
        [AllowNull()][object]$ScoringPolicy = $null,
        [string]$CatalogVersion = ''
    )

    if (-not (Test-WinSecResultText $DeviceId) -or
        -not (Test-WinSecResultText $ScanId)) {
        throw 'DeviceId and ScanId must be nonempty, bounded identifiers.'
    }
    if ($ComputerName -and -not (Test-WinSecResultText $ComputerName)) {
        throw 'ComputerName contains invalid characters.'
    }

    if (-not $StartedAtUTC) { $StartedAtUTC = [DateTime]::UtcNow.ToString('o') }
    $start = ConvertTo-WinSecResultUtc -Value $StartedAtUTC -FieldName 'StartedAtUTC'
    $end = $null
    if ($CompletedAtUTC) {
        $end = ConvertTo-WinSecResultUtc -Value $CompletedAtUTC -FieldName 'CompletedAtUTC'
        if ($end -lt $start) { throw 'CompletedAtUTC cannot precede StartedAtUTC.' }
    }
    if ($ExecutionStatus -ceq 'PENDING' -and $null -ne $end) {
        throw 'A pending scan cannot have a completion timestamp.'
    }
    if ($ExecutionStatus -cne 'PENDING' -and $null -eq $end) {
        throw 'A completed, failed or cancelled scan requires CompletedAtUTC.'
    }

    $expectedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($id in $ExpectedCheckIds) {
        if (-not (Test-WinSecResultText $id) -or -not $expectedSet.Add($id)) {
            throw 'ExpectedCheckIds must contain unique, nonempty identifiers.'
        }
    }

    Assert-WinSecResultItems -Items $ControlResults -Kind 'ControlResults' `
        -DeviceId $DeviceId -ScanId $ScanId -RequireUnique
    Assert-WinSecResultItems -Items $EvaluationResults -Kind 'EvaluationResults' `
        -DeviceId $DeviceId -ScanId $ScanId -RequireUnique
    Assert-WinSecResultItems -Items $CriteriaSelections -Kind 'CriteriaSelections' `
        -DeviceId $DeviceId -ScanId $ScanId -RequireUnique
    Assert-WinSecResultItems -Items $Findings -Kind 'Findings' `
        -DeviceId $DeviceId -ScanId $ScanId -IdentityField 'FindingId' -RequireUnique
    Assert-WinSecResultItems -Items $ReviewItems -Kind 'ReviewItems' `
        -DeviceId $DeviceId -ScanId $ScanId -IdentityField 'ReviewId' -RequireUnique

    # Evaluations and criterion selections must have collector records.
    # This prevents joining evidence from a different execution.
    $controlIds = @($ControlResults | ForEach-Object { [string]$_.CheckId })
    if ($EvaluationResults.Count -gt 0) {
        Assert-WinSecResultItems -Items $EvaluationResults -Kind 'EvaluationResults' `
            -DeviceId $DeviceId -ScanId $ScanId `
            -KnownCheckIds $controlIds -RequireKnownCheck
    }
    if ($CriteriaSelections.Count -gt 0) {
        Assert-WinSecResultItems -Items $CriteriaSelections -Kind 'CriteriaSelections' `
            -DeviceId $DeviceId -ScanId $ScanId `
            -KnownCheckIds $controlIds -RequireKnownCheck
    }
    if ($Findings.Count -gt 0) {
        Assert-WinSecResultItems -Items $Findings -Kind 'Findings' `
            -DeviceId $DeviceId -ScanId $ScanId `
            -KnownCheckIds $controlIds -RequireKnownCheck
    }
    if ($ReviewItems.Count -gt 0) {
        Assert-WinSecResultItems -Items $ReviewItems -Kind 'ReviewItems' `
            -DeviceId $DeviceId -ScanId $ScanId `
            -KnownCheckIds $controlIds -RequireKnownCheck
    }

    # ScoreResult is a product of ScoreEngine, not a scoring instruction.
    # This layer never upgrades NOT_SCORED based solely on a number or flags.
    $scoreStatus = 'NOT_SCORED'
    $assessmentStatus = 'PENDING'
    $overallCoverage = $null
    $overallScore = $null
    $scoringEligible = $false
    $sectionResults = @()

    if ($null -ne $ScoreResult) {
        $scoreDevice = Get-WinSecResultField $ScoreResult 'DeviceId'
        $scoreScan = Get-WinSecResultField $ScoreResult 'ScanId'
        if ($scoreDevice -cne $DeviceId -or $scoreScan -cne $ScanId) {
            throw 'ScoreResult belongs to a different device or scan.'
        }
        # Keep an unverified ScoreResult internally for diagnostics only.
        # Its status, coverage and score must not reach presentation output.

    }

    # Optional independent calculation through the existing, hardened engine.
    # Caller-supplied scoring flags or numbers alone never authorize a score.
    if ($null -ne $ScoringPolicy) {
        if ($null -eq (Get-Command 'Get-WinSecSecurityScore' `
            -CommandType Function -ErrorAction SilentlyContinue)) {
            throw 'ScoreEngine must be loaded to verify scoring provenance.'
        }
        $verifiedScore = Get-WinSecSecurityScore `
            -DeviceId $DeviceId -ScanId $ScanId `
            -CheckResults $EvaluationResults `
            -Policy $ScoringPolicy `
            -CriteriaSelections $CriteriaSelections `
            -CollectorResults $ControlResults `
            -ExpectedCheckIds $ExpectedCheckIds

        if ($null -ne $ScoreResult) {
            if ($verifiedScore.Status -cne $ScoreResult.Status -or
                $verifiedScore.AssessmentStatus -cne $ScoreResult.AssessmentStatus -or
                $verifiedScore.ScoringEligible -cne $ScoreResult.ScoringEligible -or
                $verifiedScore.Score -ne $ScoreResult.Score) {
                throw 'ScoreResult does not match independent ScoreEngine evaluation.'
            }
        }

        $scoreStatus = [string]$verifiedScore.Status
        $assessmentStatus = [string]$verifiedScore.AssessmentStatus
        $scoringEligible = ($verifiedScore.ScoringEligible -ceq $true)
        $overallScore = $verifiedScore.Score
        $overallCoverage = $verifiedScore.Coverage
        $sectionResults = @($verifiedScore.SectionResults)
        $ScoreResult = $verifiedScore
    }

    $unselected = @($ControlResults | Where-Object {
        (Get-WinSecResultField $_ 'Status') -ceq 'NOT_SELECTED'
    }).Count
    $executionErrors = @($ControlResults | Where-Object {
        (Get-WinSecResultField $_ 'ObservedStatus') -ceq 'ERROR' -or
        (Get-WinSecResultField $_ 'Status') -ceq 'ERROR'
    }).Count
    $duration = $null
    if ($null -ne $end) {
        $duration = [Math]::Round(($end - $start).TotalSeconds, 3)
    }

    return [pscustomobject]@{
        SchemaVersion = '1.0.0'
        AuditId = $ScanId
        ScanId = $ScanId
        DeviceId = $DeviceId
        ComputerName = $ComputerName
        CollectionMode = $CollectionMode
        StartedAtUTC = $start.UtcDateTime.ToString('o')
        CompletedAtUTC = if ($null -ne $end) { $end.UtcDateTime.ToString('o') } else { $null }
        DurationSeconds = $duration
        ExecutionStatus = $ExecutionStatus
        TotalRegisteredChecks = $ControlResults.Count
        SelectedChecks = $ExpectedCheckIds.Count
        ExecutedChecks = @($ControlResults | Where-Object {
            (Get-WinSecResultField $_ 'Status') -cnotin @('NOT_SELECTED','PENDING','NOT_CHECKED')
        }).Count
        UnselectedChecks = $unselected
        ExecutionErrors = $executionErrors
        ExpectedCheckIds = @($ExpectedCheckIds)
        CatalogVersion = $CatalogVersion
        OverallScore = $overallScore
        OverallCoverage = $overallCoverage
        OverallStatus = $scoreStatus
        AssessmentStatus = $assessmentStatus
        ScoringEligible = $scoringEligible
        ScoringEnabled = $scoringEligible
        SectionResults = @($sectionResults)
        ControlResults = @($ControlResults)
        CheckResults = @($ControlResults)
        EvaluationResults = @($EvaluationResults)
        CriteriaSelections = @($CriteriaSelections)
        Findings = @($Findings)
        ReviewItems = @($ReviewItems)
        ScoreResult = $ScoreResult
        ScoringPolicy = $ScoringPolicy
        ContainsRawEvidence = ($ControlResults.Count -gt 0)
        InternalOnly = $true
    }
}

function Test-WinSecResultSession {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Session)

    try {
        if ((Get-WinSecResultField $Session 'InternalOnly') -cne $true -or
            (Get-WinSecResultField $Session 'SchemaVersion') -cne '1.0.0') {
            return $false
        }
        $deviceId = Get-WinSecResultField $Session 'DeviceId'
        $scanId = Get-WinSecResultField $Session 'ScanId'
        if (-not (Test-WinSecResultText $deviceId) -or
            -not (Test-WinSecResultText $scanId) -or
            (Get-WinSecResultField $Session 'AuditId') -cne $scanId) {
            return $false
        }
        $execution = Get-WinSecResultField $Session 'ExecutionStatus'
        if ($execution -cnotin @('PENDING','COMPLETED','COMPLETED_WITH_ERRORS',
            'NO_EXECUTABLE_CHECKS','FAILED','CANCELLED')) { return $false }
        if ($execution -ceq 'PENDING' -and
            $null -ne (Get-WinSecResultField $Session 'CompletedAtUTC')) { return $false }
        if ($execution -cne 'PENDING' -and
            $null -eq (Get-WinSecResultField $Session 'CompletedAtUTC')) { return $false }
        $score = Get-WinSecResultField $Session 'OverallScore'
        $scoreStatus = Get-WinSecResultField $Session 'OverallStatus'
        $eligible = Get-WinSecResultField $Session 'ScoringEligible'
        if ($eligible -ceq $true) {
            if ($scoreStatus -cne 'COMPLETE' -or $null -eq $score -or
                $score -isnot [ValueType] -or
                [double]$score -lt 0 -or [double]$score -gt 100 -or
                [double]::IsNaN([double]$score) -or
                [double]::IsInfinity([double]$score)) { return $false }
        }
        elseif ($null -ne $score -or $scoreStatus -cne 'NOT_SCORED') {
            return $false
        }
        $scorePolicy = Get-WinSecResultField $Session 'ScoringPolicy'
        if ($null -eq $scorePolicy -and $eligible -ceq $true) {
            return $false
        }
        $null = ConvertTo-WinSecResultUtc -Value $Session.StartedAtUTC -FieldName 'StartedAtUTC'
        if ($null -ne $Session.CompletedAtUTC) {
            $null = ConvertTo-WinSecResultUtc -Value $Session.CompletedAtUTC -FieldName 'CompletedAtUTC'
        }
        foreach ($spec in @(
            @{ Name='ControlResults'; Unique='CheckId' },
            @{ Name='EvaluationResults'; Unique='CheckId' },
            @{ Name='CriteriaSelections'; Unique='CheckId' },
            @{ Name='Findings'; Unique='FindingId' },
            @{ Name='ReviewItems'; Unique='ReviewId' }
        )) {
            $items = Get-WinSecResultField $Session $spec.Name
            if ($null -eq $items) { $items = @() }
            if ($items -isnot [array]) { return $false }
            Assert-WinSecResultItems -Items $items -Kind $spec.Name `
                -DeviceId $deviceId -ScanId $scanId `
                -IdentityField $spec.Unique -RequireUnique
        }
        $controls = Get-WinSecResultField $Session 'ControlResults'
        $knownIds = @($controls | ForEach-Object { [string]$_.CheckId })
        foreach ($name in @('EvaluationResults','CriteriaSelections','Findings','ReviewItems')) {
            $entries = Get-WinSecResultField $Session $name
            if ($null -eq $entries) { $entries = @() }
            Assert-WinSecResultItems -Items $entries -Kind $name `
                -DeviceId $deviceId -ScanId $scanId `
                -KnownCheckIds $knownIds -RequireKnownCheck
        }
        # Independently verify authorization; flags on the model alone
        # cannot establish a valid numeric security score.
        if ($null -ne $scorePolicy) {
            if ($null -eq (Get-Command 'Get-WinSecSecurityScore' `
                -CommandType Function -ErrorAction SilentlyContinue)) { return $false }
            $recomputed = Get-WinSecSecurityScore `
                -DeviceId $deviceId -ScanId $scanId `
                -CheckResults $Session.EvaluationResults `
                -Policy $scorePolicy `
                -CriteriaSelections $Session.CriteriaSelections `
                -CollectorResults $Session.ControlResults `
                -ExpectedCheckIds $Session.ExpectedCheckIds
            if ($recomputed.Score -ne $score -or
                $recomputed.Status -cne $scoreStatus -or
                $recomputed.ScoringEligible -cne $eligible -or
                $recomputed.AssessmentStatus -cne $Session.AssessmentStatus -or
                $recomputed.Coverage -ne $Session.OverallCoverage) { return $false }
        }
        $expected = Get-WinSecResultField $Session 'ExpectedCheckIds'
        if ($expected -isnot [array]) { return $false }
        $uniqueExpected = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($id in $expected) {
            if (-not (Test-WinSecResultText $id) -or
                -not $uniqueExpected.Add($id)) { return $false }
        }
        return $true
    }
    catch {
        return $false
    }
}

function ConvertTo-WinSecPublicScanResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Session)

    if (-not (Test-WinSecResultSession -Session $Session)) {
        throw 'Invalid or unsafe internal scan result.'
    }

    # Explicit allowlists; no Evidence, OriginalResult, Source, Reason,
    # ExpectedValue, raw values or freeform collector properties.
    $allowedStatuses = @('PASS','FAIL','ERROR','UNKNOWN','NOT_EVALUATED',
        'PENDING','NOT_CHECKED','NOT_APPLICABLE','NOT_SELECTED',
        'MANUAL','INFORMATIONAL')
    $allowedSections = @('SystemSecurity','NetworkSecurity',
        'IdentityAccess','LoggingAuditing','ServicesHardening')
    $allowedKinds = @('CONFIGURATION_DEVIATION','EVIDENCE_GAP',
        'EVALUATION_UNAVAILABLE','COLLECTION_ERROR','CRITERION_PENDING',
        'EVALUATION_PENDING','CATALOG_NOT_READY','EVALUATION_NOT_TRUSTED',
        'EVALUATION_DATA_ERROR','EVALUATION_IDENTITY_ERROR',
        'DUPLICATE_CRITERION')
    $controls = @(
        foreach ($item in $Session.ControlResults) {
            $section = Get-WinSecResultField $item 'SectionKey'
            $status = Get-WinSecResultField $item 'Status'
            $observed = Get-WinSecResultField $item 'ObservedStatus'
            [pscustomobject]@{
                CheckId = $item.CheckId
                DeviceId = $Session.DeviceId
                ScanId = $Session.ScanId
                SectionKey = if ($section -cin $allowedSections) { $section } else { $null }
                Status = if ($status -cin $allowedStatuses) { $status } else { 'UNKNOWN' }
                ObservedStatus = if ($observed -cin $allowedStatuses) { $observed } else { $null }
            }
        }
    )
    $findings = @(
        foreach ($item in $Session.Findings) {
            [pscustomobject]@{
                FindingId = $item.FindingId
                CheckId = $item.CheckId
                DeviceId = $Session.DeviceId
                ScanId = $Session.ScanId
                Kind = if ($item.Kind -cin $allowedKinds) { $item.Kind } else { 'UNCLASSIFIED' }
                EvaluationStatus = if ($item.EvaluationStatus -cin $allowedStatuses) {
                    $item.EvaluationStatus
                } else { 'UNKNOWN' }
                Severity = 'UNASSIGNED'
                Priority = 'UNASSIGNED'
            }
        }
    )
    $safeSections = @(
        foreach ($item in $Session.SectionResults) {
            $sectionKey = Get-WinSecResultField $item 'Key'
            if ($sectionKey -cnotin $allowedSections) { continue }
            $sectionName = switch ($sectionKey) {
                'SystemSecurity'    { 'System Security' }
                'NetworkSecurity'   { 'Network Security' }
                'IdentityAccess'    { 'Identity & Access Security' }
                'LoggingAuditing'   { 'Logging & Auditing' }
                'ServicesHardening' { 'Services & Hardening' }
            }
            [pscustomobject]@{
                DeviceId = $Session.DeviceId
                ScanId = $Session.ScanId
                Key = $sectionKey
                Name = $sectionName
                Score = if ($Session.ScoringEligible -ceq $true) {
                    Get-WinSecResultField $item 'Score'
                } else { $null }
                Coverage = Get-WinSecResultField $item 'Coverage'
                Status = if ($Session.ScoringEligible -ceq $true) {
                    'COMPLETE'
                } else { 'NOT_SCORED' }
            }
        }
    )
    $reviews = @(
        foreach ($item in $Session.ReviewItems) {
            [pscustomobject]@{
                ReviewId = $item.ReviewId
                CheckId = $item.CheckId
                DeviceId = $Session.DeviceId
                ScanId = $Session.ScanId
                Type = 'REVIEW_ONLY'
                Status = if ($item.Status -cin @('OBSERVED','UNKNOWN')) {
                    $item.Status
                } else { 'UNKNOWN' }
            }
        }
    )
    return [pscustomobject]@{
        SchemaVersion = $Session.SchemaVersion
        AuditId = $Session.AuditId
        ScanId = $Session.ScanId
        DeviceId = $Session.DeviceId
        CollectionMode = $Session.CollectionMode
        StartedAtUTC = $Session.StartedAtUTC
        CompletedAtUTC = $Session.CompletedAtUTC
        ExecutionStatus = $Session.ExecutionStatus
        # A public projection may expose a score only when the caller
        # independently supplied a policy and ScoreEngine recomputed it.
        OverallScore = $Session.OverallScore
        OverallCoverage = $Session.OverallCoverage
        OverallStatus = $Session.OverallStatus
        AssessmentStatus = $Session.AssessmentStatus
        ScoringEligible = $Session.ScoringEligible
        ExpectedCheckCount = @($Session.ExpectedCheckIds).Count
        SectionResults = $safeSections
        ControlResults = $controls
        CheckResults = @($controls)
        Findings = $findings
        ReviewItems = $reviews
        ContainsRawEvidence = $false
        PublicProjection = $true
    }
}
