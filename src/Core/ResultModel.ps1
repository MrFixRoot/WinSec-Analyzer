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

. (Join-Path $PSScriptRoot 'ConfigurationScore.ps1')
. (Join-Path $PSScriptRoot 'DefenderReviewModel.ps1')
. (Join-Path $PSScriptRoot 'BitLockerReviewModel.ps1')

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

function Test-WinSecResultPercentage {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $true }
    if ($Value.GetType() -notin @([byte],[sbyte],[int16],[uint16],[int32],
        [uint32],[int64],[uint64],[single],[double],[decimal])) { return $false }
    $number = [double]$Value
    return (-not [double]::IsNaN($number) -and -not [double]::IsInfinity($number) -and
        $number -ge 0 -and $number -le 100)
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
        if ($Kind -ceq 'Findings' -and $null -ne (Get-WinSecResultField $item 'Guidance')) {
            $null = ConvertTo-WinSecPublicFindingGuidance -Finding $item -Guidance (Get-WinSecResultField $item 'Guidance')
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

function Assert-WinSecResultScope {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$ScopeType,
        [AllowNull()][object]$ScopeKey,
        [AllowEmptyCollection()][string[]]$ExpectedCheckIds = @(),
        [AllowEmptyCollection()][object[]]$ControlResults = @(),
        [AllowEmptyCollection()][object[]]$DerivedResults = @(),
        [string]$ExecutionStatus = 'PENDING'
    )

    $sections = @('SystemSecurity','NetworkSecurity','IdentityAccess',
        'LoggingAuditing','ServicesHardening')
    if ($ScopeType -isnot [string] -or $ScopeKey -isnot [string] -or
        $ScopeType -cnotin @('DEVICE','SECTION','CONTROL')) {
        throw 'Invalid result scope identity.'
    }
    switch -CaseSensitive ($ScopeType) {
        'DEVICE' {
            if ($ScopeKey -cne 'ALL') { throw 'Invalid device scope key.' }
        }
        'SECTION' {
            if ($ScopeKey -cnotin $sections) { throw 'Invalid section scope key.' }
        }
        'CONTROL' {
            if ($ScopeKey -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' -or
                @($ExpectedCheckIds | Where-Object { $_ -cne $ScopeKey }).Count -gt 0) {
                throw 'Invalid control scope selection.'
            }
        }
    }

    $collected = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($record in $ControlResults) {
        $id = Get-WinSecResultField $record 'CheckId'
        $status = Get-WinSecResultField $record 'Status'
        if ($id -cnotin $ExpectedCheckIds) {
            if ($status -cne 'NOT_SELECTED') { throw 'Collector lies outside the declared scope selection.' }
            continue
        }
        $section = Get-WinSecResultField $record 'SectionKey'
        if ($section -cnotin $sections -or
            ($ScopeType -ceq 'SECTION' -and $section -cne $ScopeKey) -or
            $status -ceq 'NOT_SELECTED') {
            throw 'Collector does not match the declared result scope.'
        }
        $null = $collected.Add($id)
    }
    if ($ExecutionStatus -cin @('COMPLETED','COMPLETED_WITH_ERRORS') -and
        ($ExpectedCheckIds.Count -eq 0 -or $collected.Count -ne $ExpectedCheckIds.Count)) {
        throw 'Completed scope is missing its selected collector results.'
    }
    foreach ($record in $DerivedResults) {
        if ((Get-WinSecResultField $record 'CheckId') -cnotin $ExpectedCheckIds) {
            throw 'Derived result lies outside the declared scope selection.'
        }
    }
}

function Copy-WinSecResultData {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    # Copy data only. Do not serialize evidence or invoke calculated properties.
    $budget = @{ Nodes = 0 }
    $ancestors = New-Object 'System.Collections.Generic.List[object]'
    $copyNode = {
        param([AllowNull()][object]$Node, [int]$Depth)
        $budget.Nodes++
        if ($Depth -gt 64 -or $budget.Nodes -gt 10000) { throw 'Snapshot limit exceeded.' }
        if ($null -eq $Node) { return $null }
        if ($Node -is [string] -or $Node -is [ValueType]) {
            foreach ($property in $Node.PSObject.Properties) {
                if ($property.IsInstance -and
                    $property.MemberType -ne [System.Management.Automation.PSMemberTypes]::Property) {
                    throw 'Snapshot scalars cannot carry extended properties.'
                }
            }
            $type = $Node.GetType()
            if ($type.IsEnum -or $type -in @([string],[bool],[char],[byte],[sbyte],[int16],[uint16],
                [int32],[uint32],[int64],[uint64],[single],[double],[decimal],
                [datetime],[datetimeoffset],[timespan],[guid])) { return ,$Node }
            throw 'Unsupported snapshot scalar.'
        }
        foreach ($ancestor in $ancestors) {
            if ([object]::ReferenceEquals($ancestor,$Node)) { throw 'Cyclic snapshot data.' }
        }
        $ancestors.Add($Node)
        try {
            if ($Node -is [array]) {
                if ($Node.Rank -ne 1 -or $Node.GetLowerBound(0) -ne 0) { throw 'Unsupported snapshot array.' }
                $copy = $Node.Clone()
                for ($index=0; $index -lt $Node.Length; $index++) {
                    $item = & $copyNode -Node $Node.GetValue($index) -Depth ($Depth+1)
                    $copy.SetValue($item,$index)
                }
                return ,$copy
            }
            if ($Node -is [System.Collections.IDictionary]) {
                # Own the key comparer too; never retain a caller-supplied comparer.
                if ($Node.GetType() -eq [hashtable]) { $copy = @{} }
                elseif ($Node.GetType() -eq [System.Collections.Specialized.OrderedDictionary]) {
                    $copy = [ordered]@{}
                }
                elseif ($Node.GetType() -eq [System.Collections.Generic.Dictionary[string,object]]) {
                    $copy = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
                }
                else { throw 'Unsupported snapshot dictionary.' }
                $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                foreach ($entry in $Node.GetEnumerator()) {
                    if ($entry.Key -isnot [string]) { throw 'Snapshot dictionary keys must be strings.' }
                    if (-not $keys.Add($entry.Key)) { throw 'Ambiguous snapshot dictionary keys.' }
                    $item = & $copyNode -Node $entry.Value -Depth ($Depth+1)
                    $copy[$entry.Key] = $item
                }
                return ,$copy
            }
            if ($Node -is [System.Collections.IList]) {
                $type = $Node.GetType()
                if ($type -ne [System.Collections.ArrayList] -and
                    (-not $type.IsGenericType -or
                        $type.GetGenericTypeDefinition().FullName -cne 'System.Collections.Generic.List`1')) {
                    throw 'Unsupported snapshot list.'
                }
                $copy = [Activator]::CreateInstance($type)
                foreach ($item in $Node) {
                    $copiedItem = & $copyNode -Node $item -Depth ($Depth+1)
                    $null = $copy.Add($copiedItem)
                }
                return ,$copy
            }
            if ($Node -is [pscustomobject]) {
                $properties = [ordered]@{}
                foreach ($property in $Node.PSObject.Properties) {
                    if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty -or
                        $property.Name -in @('PSObject','psbase','psadapted','psextended','PSTypeNames','PSTypeName')) {
                        throw 'Snapshot objects must contain simple data properties.'
                    }
                    $properties.Add($property.Name,(& $copyNode -Node $property.Value -Depth ($Depth+1)))
                }
                return ,([pscustomobject]$properties)
            }
            throw 'Unsupported snapshot object.'
        }
        finally { $ancestors.RemoveAt($ancestors.Count-1) }
    }
    try { return ,(& $copyNode -Node $Value -Depth 0) }
    catch { throw 'Unable to create an isolated result snapshot.' }
}

function ConvertTo-WinSecPublicFindingGuidance {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Finding, [Parameter(Mandatory)][object]$Guidance)
    $copy = Copy-WinSecResultData $Guidance
    $fields = @('SchemaVersion','CheckId','CatalogId','CatalogVersion','CatalogSha256','CriterionId','CriterionTitle',
        'Recommendation','Framework','FrameworkVersion','ReferenceId','ReferenceTitle','ReferenceUrl',
        'VerifiedAtUTC','OSFamily','OSRelease','Edition','Profile')
    if ($copy -isnot [pscustomobject] -or @($copy.PSObject.Properties).Count -ne $fields.Count -or
        @($copy.PSObject.Properties|Where-Object {$_.Name -cnotin $fields}).Count -gt 0 -or
        $Finding.Kind -cne 'CONFIGURATION_DEVIATION' -or $Finding.EvaluationStatus -cne 'FAIL' -or
        $copy.SchemaVersion -cne '1.0.0' -or $copy.CheckId -cne $Finding.CheckId) {
        throw 'Invalid public finding guidance contract.'
    }
    if ($copy.VerifiedAtUTC -is [datetime] -and $copy.VerifiedAtUTC.Kind -eq [DateTimeKind]::Utc) {
        $copy.VerifiedAtUTC = $copy.VerifiedAtUTC.ToString('o')
    }
    foreach ($field in $fields) {
        $limit = if ($field -ceq 'Recommendation') {4096} elseif ($field -ceq 'ReferenceUrl') {1024} else {256}
        $value = $copy.$field
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or $value.Length -gt $limit -or
            $value -match '[\x00-\x1f\x7f]') { throw 'Invalid public guidance field.' }
    }
    if ($copy.Framework -cnotin @('LOCAL_POLICY','CIS Benchmarks') -or $copy.OSFamily -cne 'Windows' -or
        $copy.CatalogSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        $copy.CriterionId -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z' -or
        $copy.ReferenceId -ceq 'NOT_ASSIGNED' -or
        @('OSRelease','Edition','Profile'|Where-Object {$copy.$_ -cin @('*','PENDING_SELECTION','UNRESOLVED')}).Count -gt 0) {
        throw 'Unverified public guidance metadata.'
    }
    $date = ConvertTo-WinSecResultUtc $copy.VerifiedAtUTC 'VerifiedAtUTC'
    if ($date -gt [DateTimeOffset]::UtcNow) { throw 'Future guidance verification date.' }
    $copy.VerifiedAtUTC = $date.UtcDateTime.ToString('o')
    $uri = $null
    if (-not [Uri]::TryCreate($copy.ReferenceUrl,[UriKind]::Absolute,[ref]$uri) -or
        $uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
        throw 'Unsafe public guidance URL.'
    }
    return $copy
}

function Assert-WinSecFindingGuidanceProvenance {
    [CmdletBinding()]
    param([object]$Session,[object]$Finding,[object]$Guidance)
    # Restored public sessions have no raw evaluations: retain their validated
    # original snapshot, without claiming to re-evaluate or authenticate it.
    if ($Session.EvaluationResults.Count -eq 0 -and $Session.CriteriaSelections.Count -eq 0) { return }
    $selection=@($Session.CriteriaSelections|Where-Object {$_.CheckId -ceq $Finding.CheckId})
    $evaluation=@($Session.EvaluationResults|Where-Object {$_.CheckId -ceq $Finding.CheckId})
    $control=@($Session.ControlResults|Where-Object {$_.CheckId -ceq $Finding.CheckId})
    if ($selection.Count -ne 1 -or $evaluation.Count -ne 1 -or $control.Count -ne 1 -or
        $selection[0].Status -cne 'READY' -or
        (($selection[0].ScoringEligible -isnot [bool] -or $selection[0].ScoringEligible -cne $true) -and
         ($selection[0].EvaluationEligible -isnot [bool] -or $selection[0].EvaluationEligible -cne $true)) -or
        $selection[0].CatalogId -cne $Guidance.CatalogId -or $selection[0].CatalogVersion -cne $Guidance.CatalogVersion -or
        $selection[0].CatalogSha256 -cne $Guidance.CatalogSha256 -or $control[0].ObservedStatus -ceq 'ERROR') {
        throw 'Guidance does not match its original selection and collection.'
    }
    $rule=@($selection[0].EligibleCriteria|Where-Object {$_.CriterionId -ceq $Guidance.CriterionId})
    $item=@($evaluation[0].Evaluations|Where-Object {$_.CriterionId -ceq $Guidance.CriterionId})
    if ($rule.Count -ne 1 -or $item.Count -ne 1 -or $item[0].Status -cne 'FAIL' -or
        $Finding.CriterionId -cne $Guidance.CriterionId -or
        $rule[0].Name -cne $Guidance.CriterionTitle -or $rule[0].Recommendation -cne $Guidance.Recommendation -or
        $rule[0].Source.Framework -cne $Guidance.Framework -or $rule[0].Source.Version -cne $Guidance.FrameworkVersion -or
        $rule[0].Source.ControlId -cne $Guidance.ReferenceId -or $rule[0].Source.Title -cne $Guidance.ReferenceTitle -or
        $rule[0].Source.Url -cne $Guidance.ReferenceUrl) { throw 'Guidance source differs from the selected criterion.' }
    if (([DateTimeOffset]::Parse($rule[0].Verification.ReviewedAtUTC)).UtcDateTime.ToString('o') -cne $Guidance.VerifiedAtUTC) {
        throw 'Guidance verification date differs from the selected criterion.'
    }
    if($Finding.CheckId -ceq 'WSA-SYS-002' -and $Guidance.CriterionId -clike 'WSA-BLK-BASE-*') {
        Assert-WinSecBitLockerScoredCollection -ControlResult $control[0]
    }
    $context=[pscustomobject]@{DeviceId=$Session.DeviceId;ScanId=$Session.ScanId;OSFamily=$Guidance.OSFamily;
        OSRelease=$Guidance.OSRelease;Edition=$Guidance.Edition;Profile=$Guidance.Profile}
    $verified=Invoke-WinSecCriterionEvaluation -Criterion $rule[0] -Evidence $control[0].Evidence -TargetContext $context `
        -CheckId $Finding.CheckId -DeviceId $Session.DeviceId -ScanId $Session.ScanId
    if ($verified.Status -cne 'FAIL' -or $verified.ScoringEligible -cne $true) {
        throw 'Guidance deviation cannot be independently reproduced.'
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
        [AllowNull()][object]$ConfigurationAssessment = $null,
        [string]$CatalogVersion = '',
        [AllowNull()][object]$ScopeType = $null,
        [AllowNull()][object]$ScopeKey = $null
    )

    # Own the mutable inputs before reading identities or verifying provenance.
    $snapshot = Copy-WinSecResultData -Value ([pscustomobject]@{
        ExpectedCheckIds = $ExpectedCheckIds
        ControlResults = $ControlResults
        EvaluationResults = $EvaluationResults
        CriteriaSelections = $CriteriaSelections
        Findings = $Findings
        ReviewItems = $ReviewItems
        ScoreResult = $ScoreResult
        ScoringPolicy = $ScoringPolicy
    })
    $ExpectedCheckIds = $snapshot.ExpectedCheckIds
    $ControlResults = $snapshot.ControlResults
    $EvaluationResults = $snapshot.EvaluationResults
    $CriteriaSelections = $snapshot.CriteriaSelections
    $Findings = $snapshot.Findings
    $ReviewItems = $snapshot.ReviewItems
    $ScoreResult = $snapshot.ScoreResult
    $ScoringPolicy = $snapshot.ScoringPolicy

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

    $hasScope = $PSBoundParameters.ContainsKey('ScopeType') -or $PSBoundParameters.ContainsKey('ScopeKey')
    if ($hasScope) {
        Assert-WinSecResultScope -ScopeType $ScopeType -ScopeKey $ScopeKey `
            -ExpectedCheckIds $ExpectedCheckIds -ControlResults $ControlResults `
            -DerivedResults @($EvaluationResults + $CriteriaSelections + $Findings + $ReviewItems) `
            -ExecutionStatus $ExecutionStatus
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

    $session = [pscustomobject]@{
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
    if ($hasScope) {
        $session | Add-Member -NotePropertyName ScopeType -NotePropertyValue $ScopeType
        $session | Add-Member -NotePropertyName ScopeKey -NotePropertyValue $ScopeKey
    }
    if ($null -ne $ConfigurationAssessment) {
        $session|Add-Member -NotePropertyName ConfigurationAssessment -NotePropertyValue `
            (ConvertTo-WinSecPublicConfigurationAssessment $ConfigurationAssessment $session)
    }
    return $session
}

function Test-WinSecResultSession {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Session)

    try {
        # Public metadata must remain scalar data of its declared type.
        foreach ($name in @('SchemaVersion','AuditId','CollectionMode','ExecutionStatus',
            'StartedAtUTC','OverallStatus','AssessmentStatus')) {
            if ((Get-WinSecResultField $Session $name) -isnot [string]) { return $false }
        }
        if ((Get-WinSecResultField $Session 'InternalOnly') -isnot [bool] -or
            (Get-WinSecResultField $Session 'ScoringEligible') -isnot [bool] -or
            (Get-WinSecResultField $Session 'ScoringEnabled') -isnot [bool] -or
            $Session.ScoringEnabled -cne $Session.ScoringEligible -or
            $Session.CollectionMode -cnotin @('LOCAL','REMOTE','IMPORTED') -or
            $Session.AssessmentStatus -cnotin @('PENDING','INCOMPLETE','COMPLETE') -or
            -not (Test-WinSecResultPercentage (Get-WinSecResultField $Session 'OverallScore')) -or
            -not (Test-WinSecResultPercentage (Get-WinSecResultField $Session 'OverallCoverage'))) {
            return $false
        }
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
        $start = ConvertTo-WinSecResultUtc -Value $Session.StartedAtUTC -FieldName 'StartedAtUTC'
        if ($null -ne $Session.CompletedAtUTC) {
            if ($Session.CompletedAtUTC -isnot [string]) { return $false }
            $end = ConvertTo-WinSecResultUtc -Value $Session.CompletedAtUTC -FieldName 'CompletedAtUTC'
            if ($end -lt $start) { return $false }
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
        $sections = Get-WinSecResultField $Session 'SectionResults'
        if ($sections -isnot [array]) { return $false }
        if ($null -eq $scorePolicy -and
            ($sections.Count -ne 0 -or $null -ne $Session.OverallCoverage -or
                $Session.AssessmentStatus -cne 'PENDING')) { return $false }
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
            if ($sections.Count -ne @($recomputed.SectionResults).Count) { return $false }
            $seenSections = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
            foreach ($section in $sections) {
                $key = Get-WinSecResultField $section 'Key'
                if ($key -isnot [string] -or -not $seenSections.Add($key) -or
                    (Get-WinSecResultField $section 'DeviceId') -isnot [string] -or
                    (Get-WinSecResultField $section 'ScanId') -isnot [string] -or
                    $section.DeviceId -cne $deviceId -or $section.ScanId -cne $scanId -or
                    (Get-WinSecResultField $section 'Status') -isnot [string] -or
                    -not (Test-WinSecResultPercentage (Get-WinSecResultField $section 'Score')) -or
                    -not (Test-WinSecResultPercentage (Get-WinSecResultField $section 'Coverage'))) {
                    return $false
                }
                $verified = @($recomputed.SectionResults | Where-Object { $_.Key -ceq $key })
                if ($verified.Count -ne 1 -or $section.Status -cne $verified[0].Status -or
                    $section.Score -ne $verified[0].Score -or $section.Coverage -ne $verified[0].Coverage) {
                    return $false
                }
            }
        }
        $expected = Get-WinSecResultField $Session 'ExpectedCheckIds'
        if ($expected -isnot [array]) { return $false }
        $uniqueExpected = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($id in $expected) {
            if (-not (Test-WinSecResultText $id) -or
                -not $uniqueExpected.Add($id)) { return $false }
        }
        $fieldNames = if ($Session -is [System.Collections.IDictionary]) {
            @($Session.GetEnumerator() | ForEach-Object { $_.Key })
        } else { @($Session.PSObject.Properties.Name) }
        if ('ScopeType' -in $fieldNames -or 'ScopeKey' -in $fieldNames) {
            Assert-WinSecResultScope -ScopeType (Get-WinSecResultField $Session 'ScopeType') `
                -ScopeKey (Get-WinSecResultField $Session 'ScopeKey') `
                -ExpectedCheckIds $expected -ControlResults $controls `
                -DerivedResults @($Session.EvaluationResults + $Session.CriteriaSelections + $Session.Findings + $Session.ReviewItems) `
                -ExecutionStatus $execution
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
            $safeFinding = [pscustomobject]@{
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
            if ($null -ne (Get-WinSecResultField $item 'Guidance')) {
                $guidance=ConvertTo-WinSecPublicFindingGuidance -Finding $item -Guidance $item.Guidance
                Assert-WinSecFindingGuidanceProvenance -Session $Session -Finding $item -Guidance $guidance
                $safeFinding | Add-Member -NotePropertyName Guidance -NotePropertyValue `
                    $guidance
            }
            $safeFinding
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
                Status = if ($Session.ScoringEligible -ceq $true -and $item.Status -ceq 'COMPLETE') {
                    'COMPLETE'
                } else { 'NOT_SCORED' }
            }
        }
    )
    $reviews = @(
        foreach ($item in $Session.ReviewItems) {
            $safeReview = [pscustomobject]@{
                ReviewId = $item.ReviewId
                CheckId = $item.CheckId
                DeviceId = $Session.DeviceId
                ScanId = $Session.ScanId
                Type = 'REVIEW_ONLY'
                Status = if ($item.Status -cin @('OBSERVED','UNKNOWN')) {
                    $item.Status
                } else { 'UNKNOWN' }
            }
            if ($null -ne (Get-WinSecResultField $item 'DefenderSetting')) {
                $safeReview = ConvertTo-WinSecDefenderReviewItem -Item $item -Owner $Session
            }
            if ($null -ne (Get-WinSecResultField $item 'BitLockerSetting')) {
                $safeReview = ConvertTo-WinSecBitLockerReviewItem -Item $item -Owner $Session
                $source=@($Session.ControlResults|Where-Object CheckId -CEQ 'WSA-SYS-002')
                if($source.Count -ne 1){throw 'Missing BitLocker review source.'}
                if($null -ne (Get-WinSecResultField $source[0] 'Evidence')) {
                    $expected=@(New-WinSecBitLockerReviewItems $source[0]|Where-Object ReviewId -CEQ $safeReview.ReviewId)
                    if($expected.Count -ne 1 -or $expected[0].Status -cne $safeReview.Status -or
                        $expected[0].BitLockerSetting.Value -cne $safeReview.BitLockerSetting.Value){throw 'Untrusted BitLocker review observation.'}
                }
            }
            $safeReview
        }
    )
    $public = [pscustomobject]@{
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
    # Legacy sessions have no recorded scope; never infer one from their controls.
    $scopeType = Get-WinSecResultField $Session 'ScopeType'
    if ($null -ne $scopeType) {
        $public | Add-Member -NotePropertyName ScopeType -NotePropertyValue $scopeType
        $public | Add-Member -NotePropertyName ScopeKey -NotePropertyValue (Get-WinSecResultField $Session 'ScopeKey')
    }
    if ($null -ne (Get-WinSecResultField $Session 'ConfigurationAssessment')) {
        Assert-WinSecConfigurationProvenance $Session $Session.ConfigurationAssessment
        $public|Add-Member -NotePropertyName CatalogVersion -NotePropertyValue $Session.CatalogVersion
        $public|Add-Member -NotePropertyName ConfigurationAssessment -NotePropertyValue `
            (ConvertTo-WinSecPublicConfigurationAssessment $Session.ConfigurationAssessment $Session)
    }
    return $public
}
