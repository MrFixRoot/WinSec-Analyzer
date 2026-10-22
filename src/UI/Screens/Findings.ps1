
# ============================================================
# WinSec Analyzer
# Component : Findings
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Displays public findings and diagnostics with manual
# recommendations and framework context, without raw evidence.
#
# Features:
# - Multi-device and multi-scan isolation
# - Preserve Core's UNASSIGNED classifications
# - CIS, NIST and MITRE references
# - Adaptive terminal layout
# - Selected finding details
# - Persistent navigation selection
#
# This component does not execute security checks.
# ============================================================


# ------------------------------------------------------------
# Load required finding components
# ------------------------------------------------------------

$winSecProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\..')
)

$winSecFindingDependencies = @(
    @{
        Command = 'Invoke-WinSecFindingPrioritization'
        Path    = 'src/Core/FindingPriorityEngine.ps1'
    }
    @{
        Command = 'Get-WinSecFrameworkMappings'
        Path    = 'src/Core/FrameworkMappingEngine.ps1'
    }
    @{
        Command = 'Get-WinSecCheckFrameworkReferences'
        Path    = 'src/Services/FrameworkService.ps1'
    }
)

foreach ($dependency in $winSecFindingDependencies) {

    $command = Get-Command `
        -Name $dependency.Command `
        -CommandType Function `
        -ErrorAction SilentlyContinue

    if ($null -ne $command) {
        continue
    }

    $path = Join-Path `
        -Path $winSecProjectRoot `
        -ChildPath $dependency.Path

    if (Test-Path -LiteralPath $path -PathType Leaf) {
        . $path
    }
}


# ------------------------------------------------------------
# Read a property from a finding or mapping
# ------------------------------------------------------------

function Get-WinSecFindingProperty {
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

        foreach ($key in $InputObject.psbase.Keys) {

            if (
                [string]::Equals(
                    [string]$key,
                    $Name,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            ) {
                return ,$InputObject[$key]
            }
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -ne $property) {
        return ,$property.Value
    }

    return $null
}


# ------------------------------------------------------------
# Safely convert assessment data into display text
# ------------------------------------------------------------

function ConvertTo-WinSecFindingText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [string]) {
        return $Value.Trim()
    }

    if ($Value -is [array]) {

        $parts = @(
            foreach ($item in $Value) {
                ConvertTo-WinSecFindingText -Value $item
            }
        )

        return ($parts -join '; ')
    }

    if (
        $Value -is [PSCustomObject] -or
        $Value -is [System.Collections.IDictionary]
    ) {
        return ConvertTo-Json `
            -InputObject $Value `
            -Compress `
            -Depth 6
    }

    return [string]$Value
}


# ------------------------------------------------------------
# Read navigation context
# ------------------------------------------------------------

function Get-WinSecFindingsContext {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null
    )

    $sectionIndex = 0
    $controlIndex = 0
    $findingIndex = 0
    $scope = 'Section'
    $deviceId = ''

    if ($null -ne $NavigationState) {

        $sectionValue = Get-WinSecFindingProperty `
            -InputObject $NavigationState `
            -Name 'SectionIndex'

        $controlValue = Get-WinSecFindingProperty `
            -InputObject $NavigationState `
            -Name 'ControlIndex'

        $findingValue = Get-WinSecFindingProperty `
            -InputObject $NavigationState `
            -Name 'FindingsOffset'

        $scopeValue = Get-WinSecFindingProperty `
            -InputObject $NavigationState `
            -Name 'FindingsScope'

        $deviceValue = Get-WinSecFindingProperty `
            -InputObject $NavigationState `
            -Name 'SelectedDeviceId'

        if ($null -ne $sectionValue) {
            $sectionIndex = [int]$sectionValue
        }

        if ($null -ne $controlValue) {
            $controlIndex = [int]$controlValue
        }

        if ($null -ne $findingValue) {
            $findingIndex = [int]$findingValue
        }

        if ($scopeValue -eq 'Control') {
            $scope = 'Control'
        }

        if ($null -ne $deviceValue -and $deviceValue -isnot [string]) {
            throw 'Invalid selected finding device.'
        }
        if ($null -ne $scopeValue -and
            ($scopeValue -isnot [string] -or $scopeValue -cnotin @('Section','Control'))) {
            throw 'Invalid findings navigation scope.'
        }
        $deviceId = $deviceValue
    }

    return [PSCustomObject]@{
        DeviceId     = $deviceId
        SectionIndex = $sectionIndex
        ControlIndex = $controlIndex
        FindingIndex = $findingIndex
        Scope        = $scope
    }
}


# ------------------------------------------------------------
# Resolve framework references for one finding
# ------------------------------------------------------------

function Get-WinSecFindingFrameworkReferences {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Finding,

        [AllowNull()]
        [object]$Catalog = $null,

        [string]$Platform = 'Windows'
    )

    # Preserve references explicitly supplied by
    # the assessment engine.

    $existing = Get-WinSecFindingProperty `
        -InputObject $Finding `
        -Name 'FrameworkReferences'

    if ($null -ne $existing) {

        $references = @(
            $existing | Where-Object {
                $null -ne $_
            }
        )

        if ($references.Count -gt 0) {
            return $references
        }
    }

    $checkId = [string](
        Get-WinSecFindingProperty `
            -InputObject $Finding `
            -Name 'CheckId'
    )

    if ([string]::IsNullOrWhiteSpace($checkId)) {
        return
    }

    if ($null -eq $Catalog) {
        return
    }

    $command = Get-Command `
        -Name 'Get-WinSecCheckFrameworkReferences' `
        -CommandType Function `
        -ErrorAction SilentlyContinue

    if ($null -eq $command) {
        return
    }

    try {

        Get-WinSecCheckFrameworkReferences `
            -CheckId $checkId `
            -Platform $Platform `
            -Catalog $Catalog `
            -ErrorAction Stop
    }
    catch {

        Write-Verbose 'Framework mapping unavailable for the selected public record.'
    }
}


# ------------------------------------------------------------
# Prepare findings for the selected assessment
# ------------------------------------------------------------

function Get-WinSecSelectedFindings {
    [CmdletBinding()]
    param(
        [AllowNull()][psobject]$NavigationState = $null,
        [AllowEmptyCollection()][object[]]$SectionResults = @(),
        [AllowEmptyCollection()][object[]]$ControlResults = @(),
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [string]$ScanId = '',
        [string]$Platform = 'Windows'
    )

    $context = Get-WinSecFindingsContext -NavigationState $NavigationState
    $sections = @(Get-WinSecMainMenuSections -SectionResults $SectionResults)
    if ($sections.Count -eq 0) { return $null }
    $sectionIndex = [Math]::Max(0,[Math]::Min($context.SectionIndex,$sections.Count-1))
    $section = $sections[$sectionIndex]
    $view = [pscustomobject]@{
        Scope=$context.Scope; Title=$section.Name; DeviceId=$context.DeviceId
        ScanId=$ScanId; SectionKey=$section.Key; Score='NOT_SCORED'; Status=$section.Status
        Findings=@(); FrameworkStatus='UNAVAILABLE'; Warning=''
    }
    if ([string]::IsNullOrWhiteSpace($context.DeviceId)) {
        $view.Warning = 'No device selected. Select a device before viewing assessment findings.'
        return $view
    }

    # Snapshot data before reading properties. Both collectors and findings
    # belong to one assessment; this is not an entry point for internal evidence.
    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
    if ($null -eq (Get-Command 'Copy-WinSecResultData' -CommandType Function -ErrorAction SilentlyContinue)) {
        . (Join-Path $projectRoot 'src/Core/ResultModel.ps1')
    }
    $data = Copy-WinSecResultData -Value ([pscustomobject]@{ Controls=$ControlResults; Findings=$Findings })
    $pending = New-Object 'System.Collections.Generic.Stack[object]'
    $pending.Push($data)
    while ($pending.Count -gt 0) {
        $value = $pending.Pop()
        if ($null -eq $value -or $value -is [string] -or $value -is [ValueType]) { continue }
        if ($value -is [System.Collections.IList]) {
            foreach ($item in $value) { $pending.Push($item) }
            continue
        }
        $isDictionary = $value -is [System.Collections.IDictionary]
        $names = if ($isDictionary) { @($value.psbase.Keys) } else { @($value.PSObject.Properties.Name) }
        foreach ($name in $names) {
            if ($name -in @('Evidence','RawEvidence','OriginalResult','ObservedValue','ExpectedValue')) {
                throw 'Raw data is not allowed in public findings.'
            }
            if ($isDictionary) { $child = $value[$name] }
            else { $child = $value.PSObject.Properties[$name].Value }
            if ($name -in @('Score','OverallScore','ScoreValue','ScoreResult','ScoringPolicy') -and $null -ne $child) {
                throw 'Unapproved scoring data is not allowed in public findings.'
            }
            if ($name -in @('ScoringEnabled','ScoringEligible') -and ($child -isnot [bool] -or $child -ne $false)) {
                throw 'Scoring authorization is not allowed in public findings.'
            }
            $pending.Push($child)
        }
    }
    if ($ScanId -and -not (Test-WinSecResultText $ScanId)) { throw 'Invalid selected scan identifier.' }
    if (-not (Test-WinSecResultText $context.DeviceId)) { throw 'Invalid selected device identifier.' }

    try {
        if ($null -eq (Get-Command 'Get-WinSecCheckRegistry' -CommandType Function -ErrorAction SilentlyContinue)) {
            . (Join-Path $projectRoot 'src/Core/CheckRegistry.ps1')
        }
        $registry = Get-WinSecCheckRegistry -ProjectRoot $projectRoot
    }
    catch { throw 'Unable to load the finding control catalog.' }

    $kindNames = @{
        CONFIGURATION_DEVIATION='Configuration deviation'; EVIDENCE_GAP='Evidence gap'
        EVALUATION_UNAVAILABLE='Evaluation unavailable'; COLLECTION_ERROR='Collection error'
        CRITERION_PENDING='Criterion pending'; EVALUATION_PENDING='Evaluation pending'
        CATALOG_NOT_READY='Catalog not ready'; EVALUATION_NOT_TRUSTED='Evaluation not trusted'
        EVALUATION_DATA_ERROR='Evaluation data error'; EVALUATION_IDENTITY_ERROR='Evaluation identity error'
        DUPLICATE_CRITERION='Duplicate criterion'; UNCLASSIFIED='Unclassified record'
    }
    $statuses = @('PASS','FAIL','ERROR','UNKNOWN','NOT_EVALUATED','PENDING',
        'NOT_CHECKED','NOT_APPLICABLE','NOT_SELECTED','MANUAL','INFORMATIONAL')
    $checked = New-Object 'System.Collections.Generic.List[object]'
    $seenIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($finding in $data.Findings) {
        $id = $finding.FindingId
        if ($null -eq $id) { $id = $finding.Id }
        foreach ($identity in @($id,$finding.CheckId,$finding.DeviceId,$finding.ScanId)) {
            if (-not (Test-WinSecResultText $identity)) { throw 'Invalid public finding identity.' }
        }
        if ($finding.DeviceId -cne $context.DeviceId -or ($ScanId -and $finding.ScanId -cne $ScanId)) {
            throw 'Finding identity does not match the selected assessment.'
        }
        if (-not $seenIds.Add($id)) { throw 'Duplicate public finding identifier.' }
        $matches = @($registry.Checks | Where-Object { $_.CheckId -ceq $finding.CheckId })
        if ($matches.Count -ne 1) { throw 'Unknown or ambiguous finding control.' }
        $definition = $matches[0]
        if (($null -ne $finding.SectionKey -and ($finding.SectionKey -isnot [string] -or $finding.SectionKey -cne $definition.SectionKey)) -or
            ($null -ne $finding.ControlKey -and ($finding.ControlKey -isnot [string] -or $finding.ControlKey -cne $definition.ControlKey))) {
            throw 'Conflicting public finding control metadata.'
        }
        foreach ($name in @('Severity','Priority')) {
            if ($null -ne $finding.$name -and ($finding.$name -isnot [string] -or $finding.$name -cne 'UNASSIGNED')) {
                throw 'Unapproved public finding classification.'
            }
        }
        $kind = $finding.Kind
        if ($null -eq $kind) { $kind = 'UNCLASSIFIED' }
        if ($kind -isnot [string] -or $kind -cnotin @($kindNames.psbase.Keys)) { throw 'Invalid public finding kind.' }
        $evaluation = $finding.EvaluationStatus
        if ($null -eq $evaluation) { $evaluation = 'UNKNOWN' }
        if ($evaluation -isnot [string] -or $evaluation -cnotin $statuses) { throw 'Invalid public finding evaluation status.' }
        foreach ($name in @('Finding','Title','Description','Recommendation')) {
            $text = $finding.$name
            if ($null -ne $text -and ($text -isnot [string] -or $text.Length -gt 4096 -or
                $text -match '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')) {
                throw 'Finding display text must be bounded plain data.'
            }
        }
        $title = $finding.Finding
        if ([string]::IsNullOrWhiteSpace($title)) { $title = $finding.Title }
        if ([string]::IsNullOrWhiteSpace($title)) { $title = $kindNames[$kind] }
        $description = $finding.Description
        if ([string]::IsNullOrWhiteSpace($description)) {
            $description = 'Check: {0} | Kind: {1} | Evaluation: {2}' -f $definition.CheckId,$kind,$evaluation
        }
        $guidance = $null
        if ($null -ne $finding.Guidance) {
            $guidance = ConvertTo-WinSecPublicFindingGuidance -Finding $finding -Guidance $finding.Guidance
            $title = $guidance.CriterionTitle
            $description = 'Criterion: {0} | Policy: {1} / {2} | Evaluation: {3}' -f `
                $guidance.CriterionId,$guidance.CatalogId,$guidance.CatalogVersion,$evaluation
        }
        $row = [pscustomobject]@{
            Id=$id; FindingId=$id; Finding=$title; Description=$description
            ConfigurationState=if ($null -ne $guidance -and $kind -ceq 'CONFIGURATION_DEVIATION' -and $evaluation -ceq 'FAIL') {'MISCONFIGURED'} else {$evaluation}
            Kind=$kind; EvaluationStatus=$evaluation; Severity='UNASSIGNED'; Priority='UNASSIGNED'
            Evidence=''; Recommendation=if ($null -ne $guidance) {$guidance.Recommendation} else {$finding.Recommendation}
            Reference=if ($null -ne $guidance) {'{0} {1} / {2}: {3}' -f $guidance.Framework,$guidance.FrameworkVersion,$guidance.ReferenceId,$guidance.ReferenceUrl} else {''}
            FrameworkReferences=@()
            CheckId=$definition.CheckId; ControlKey=$definition.ControlKey; SectionKey=$definition.SectionKey
            DeviceId=$finding.DeviceId; ScanId=$finding.ScanId; Visible=$definition.Visible
        }
        if ($null -ne $guidance) { $row|Add-Member -NotePropertyName Guidance -NotePropertyValue $guidance }
        $checked.Add($row)
    }

    if (-not $ScanId) {
        $scanSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($finding in $checked) { $null = $scanSet.Add($finding.ScanId) }
        foreach ($collector in $data.Controls) {
            if (-not (Test-WinSecResultText $collector.ScanId)) { throw 'Invalid finding collector scan identifier.' }
            $null = $scanSet.Add($collector.ScanId)
        }
        $scanIds = @($scanSet)
        if ($scanIds.Count -gt 1) {
            $view.Warning = 'Multiple scan executions detected. Select a specific ScanId to view findings.'
            return $view
        }
        if ($scanIds.Count -eq 1) { $view.ScanId = $scanIds[0] }
    }
    $collected = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($collector in $data.Controls) {
        foreach ($identity in @($collector.DeviceId,$collector.ScanId,$collector.CheckId)) {
            if (-not (Test-WinSecResultText $identity)) { throw 'Invalid finding collector identity.' }
        }
        if ($collector.DeviceId -cne $context.DeviceId -or ($view.ScanId -and $collector.ScanId -cne $view.ScanId) -or
            -not $collected.Add($collector.CheckId)) { throw 'Collector identity does not match the finding assessment.' }
    }
    foreach ($finding in $checked) {
        if (-not $collected.Contains($finding.CheckId)) { throw 'Finding has no matching collected control.' }
    }
    $controls = @(Get-WinSecSectionControls -SectionKey $section.Key -ControlResults $data.Controls)
    $control = $null
    if ($context.Scope -ceq 'Control' -and $controls.Count -gt 0) {
        $control = $controls[[Math]::Max(0,[Math]::Min($context.ControlIndex,$controls.Count-1))]
        $view.Title = $control.Name
        $view.Status = $control.Status
    }
    $matched = @($checked | Where-Object {
        $_.Visible -and $_.SectionKey -ceq $section.Key -and
        ($context.Scope -ceq 'Section' -or ($null -ne $control -and $_.CheckId -ceq $control.CheckId))
    } | Sort-Object FindingId)

    # References are current catalog context, never a caller's compliance claim.
    $catalog = $null
    if ($matched.Count -gt 0 -and $null -ne (Get-Command 'Get-WinSecFrameworkCatalog' -CommandType Function -ErrorAction SilentlyContinue)) {
        try { $catalog = Get-WinSecFrameworkCatalog -ErrorAction Stop; $view.FrameworkStatus = 'LOADED' }
        catch { $view.FrameworkStatus = 'ERROR' }
    }
    foreach ($finding in $matched) {
        $references = @(Get-WinSecFindingFrameworkReferences -Finding ([pscustomobject]@{CheckId=$finding.CheckId}) -Catalog $catalog -Platform $Platform)
        $safeReferences = @(foreach ($reference in $references) {
            $copy = Copy-WinSecResultData -Value $reference
            if ($copy.CheckId -isnot [string] -or $copy.CheckId -cne $finding.CheckId) { throw 'Invalid finding reference identity.' }
            $fields = [ordered]@{}
            foreach ($name in @('FrameworkId','FrameworkName','FrameworkVersion','CheckId','ReferenceId')) {
                $value = $copy.$name
                if (-not (Test-WinSecResultText $value)) { throw 'Invalid public framework reference.' }
                $fields[$name] = $value
            }
            [pscustomobject]$fields
        })
        $finding.FrameworkReferences = $safeReferences
        $finding.PSObject.Properties.Remove('Visible')
    }
    # Classification remains owned by Core. Do not run the priority engine or
    # generate extra findings, scores, recommendations or synthetic compliance.
    $view.Findings = $matched
    return $view
}


# ------------------------------------------------------------
# Format framework references for display
# ------------------------------------------------------------

function Get-WinSecFindingReferenceLines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Finding
    )

    $lines = @(
        foreach ($reference in @($Finding.FrameworkReferences)) {

            if ($null -eq $reference) {
                continue
            }

            $framework = [string](
                Get-WinSecFindingProperty `
                    -InputObject $reference `
                    -Name 'FrameworkName'
            )

            if (-not $framework) {

                $framework = [string](
                    Get-WinSecFindingProperty `
                        -InputObject $reference `
                        -Name 'FrameworkId'
                )
            }

            $referenceId = [string](
                Get-WinSecFindingProperty `
                    -InputObject $reference `
                    -Name 'ReferenceId'
            )

            if (-not $referenceId) {

                $referenceId = [string](
                    Get-WinSecFindingProperty `
                        -InputObject $reference `
                        -Name 'id'
                )
            }

            if (-not $framework -or -not $referenceId) {
                continue
            }

            '{0}: {1}' -f $framework, $referenceId
        }
    )

    $legacyReference = [string]$Finding.Reference

    if ($legacyReference) {
        $lines += "Additional reference: $legacyReference"
    }

    return @(
        $lines | Select-Object -Unique
    )
}


# ------------------------------------------------------------
# Render a bounded text field
# ------------------------------------------------------------

function Write-WinSecFindingField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [AllowEmptyString()]
        [string]$Value = '',

        [ValidateRange(1, 10)]
        [int]$MaxLines = 1
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        $Value = 'Not provided'
    }

    $terminal = Get-WinSecTerminalSize

    $width = [Math]::Max(
        1,
        [int]$terminal.ContentWidth
    )

    $prefix = "${Label}: "

    $availableWidth = [Math]::Max(
        1,
        $width - $prefix.Length
    )

    # Keep evidence on logical display lines.
    $remaining = (
        $Value -replace '\s+', ' '
    ).Trim()

    for ($i = 0; $i -lt $MaxLines; $i++) {

        if (-not $remaining) {
            break
        }

        $take = [Math]::Min(
            $availableWidth,
            $remaining.Length
        )

        $part = $remaining.Substring(0, $take)

        if ($take -lt $remaining.Length) {

            $lastSpace = $part.LastIndexOf(' ')

            if ($lastSpace -gt 0) {
                $take = $lastSpace
                $part = $remaining.Substring(0, $take)
            }
        }

        $remaining = $remaining.Substring(
            $take
        ).TrimStart()

        # Show truncation on the final allocated line.
        if (
            $i -eq ($MaxLines - 1) -and
            $remaining.Length -gt 0
        ) {

            if ($part.Length -ge 3) {

                $part = $part.Substring(
                    0,
                    $part.Length - 3
                ) + '...'
            }
        }

        $line = if ($i -eq 0) {
            $prefix + $part
        }
        else {
            (' ' * $prefix.Length) + $part
        }

        Write-WinSecText `
            -Text $line `
            -Color Gray
    }
}


# ------------------------------------------------------------
# Determine available space for finding details
# ------------------------------------------------------------

function Get-WinSecFindingDetailPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Layout
    )

    # ContentRows already excludes banner, keyboard help
    # and the fixed screen reservations.

    $available = [int]$Layout.ContentRows

    $detailRows = 0
    $textLines = 0
    $referenceLines = 0

    # Expanded details on taller terminals
    if ($available -ge 24) {

        $detailRows = 13
        $textLines = 2
        $referenceLines = 2
    }
    elseif ($available -ge 16) {

        # Compact details
        $detailRows = 9
        $textLines = 1
        $referenceLines = 1
    }

    return [PSCustomObject]@{
        ShowDetails    = ($detailRows -gt 0)
        ReservedRows   = $detailRows
        TextLines      = $textLines
        ReferenceLines = $referenceLines
    }
}


# ------------------------------------------------------------
# Render selected finding details
# ------------------------------------------------------------

function Write-WinSecFindingDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Finding,

        [Parameter(Mandatory)]
        [psobject]$DetailPlan,

        [string]$FrameworkStatus = 'UNAVAILABLE'
    )

    if (-not $DetailPlan.ShowDetails) {
        return
    }

    Write-WinSecSectionTitle `
        -Title 'Finding Details'

    $priorityColor = 'Gray'

    if (
        Get-Command 'Get-WinSecPriorityColor' `
            -CommandType Function `
            -ErrorAction SilentlyContinue
    ) {

        $priorityColor = Get-WinSecPriorityColor `
            -Priority $Finding.Priority
    }

    Write-WinSecText `
        -Text "PRIORITY: $($Finding.Priority) | SEVERITY: $($Finding.Severity)" `
        -Color $priorityColor

    Write-WinSecFindingField `
        -Label 'Description' `
        -Value $Finding.Description `
        -MaxLines $DetailPlan.TextLines

    Write-WinSecFindingField `
        -Label 'Evidence' `
        -Value 'Not included in public results.' `
        -MaxLines $DetailPlan.TextLines

    Write-WinSecFindingField `
        -Label 'Recommendation' `
        -Value $Finding.Recommendation `
        -MaxLines $DetailPlan.TextLines

    # --------------------------------------------------------
    # Display configured framework references
    # --------------------------------------------------------

    $references = @(
        Get-WinSecFindingReferenceLines `
            -Finding $Finding
    )

    if ($references.Count -eq 0) {

        $message = 'No configured framework references.'

        if ($FrameworkStatus -ne 'LOADED') {
            $message = 'Framework catalog unavailable.'
        }

        Write-WinSecText `
            -Text $message `
            -Color DarkGray

        return
    }

    Write-WinSecText `
        -Text "FRAMEWORK REFERENCES (context only): $($references.Count)" `
        -Color DarkCyan

    foreach ($reference in (
        $references | Select-Object `
            -First $DetailPlan.ReferenceLines
    )) {

        Write-WinSecFindingField `
            -Label 'Ref' `
            -Value $reference `
            -MaxLines 1
    }
}


# ------------------------------------------------------------
# Render security findings screen
# ------------------------------------------------------------

function Show-WinSecFindings {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [AllowEmptyCollection()]
        [object[]]$SectionResults = @(),

        [AllowEmptyCollection()]
        [object[]]$ControlResults = @(),

        [AllowEmptyCollection()]
        [object[]]$Findings = @(),

        [string]$ScanId = '',

        [string]$Platform = 'Windows',

        [string]$Version = '0.9.0',
        [switch]$EnableRescan,
        [ValidateSet('Scan','Rescan')][string]$ScanAction = 'Scan',
        [switch]$EnableExport,
        [string]$Message = ''
    )

    # --------------------------------------------------------
    # Get assessment information
    # --------------------------------------------------------

    $assessment = Get-WinSecSelectedFindings `
        -NavigationState $NavigationState `
        -SectionResults $SectionResults `
        -ControlResults $ControlResults `
        -Findings $Findings `
        -ScanId $ScanId `
        -Platform $Platform

    # --------------------------------------------------------
    # Get adaptive layout
    # --------------------------------------------------------

    $baseLayout = Get-WinSecLayout `
        -Screen 'Findings' `
        -ReservedRows 12 -EnableExport:$EnableExport

    Clear-WinSecScreen

    # --------------------------------------------------------
    # Minimum terminal dimensions
    # --------------------------------------------------------

    if ($baseLayout.IsTooSmall) {

        Write-WinSecText `
            -Text 'WINSEC ANALYZER' `
            -Color Cyan `
            -Align Center

        Write-Host ''

        Write-WinSecText `
            -Text 'Terminal window is too small.' `
            -Color Yellow `
            -Align Center

        Write-WinSecText `
            -Text "Minimum: $($baseLayout.MinimumWidth) x $($baseLayout.MinimumHeight)" `
            -Color DarkGray `
            -Align Center

        return
    }

    if ($null -eq $assessment) {

        Write-WinSecText `
            -Text 'No assessment information available.' `
            -Color Yellow

        Write-WinSecKeyboardHelp -Screen 'Findings'

        return
    }

    # --------------------------------------------------------
    # Calculate detail area
    # --------------------------------------------------------

    $count = @($assessment.Findings).Count

    $detailPlan = Get-WinSecFindingDetailPlan `
        -Layout $baseLayout

    if ($count -eq 0) {

        $detailPlan = [PSCustomObject]@{
            ShowDetails    = $false
            ReservedRows   = 0
            TextLines      = 0
            ReferenceLines = 0
        }
    }

    # Reserve enough space for selected finding details.
    # The remaining content area belongs to the table.

    $reservedRows = (
        12 + $detailPlan.ReservedRows + [int](-not [string]::IsNullOrWhiteSpace($Message))
    )

    $layout = Get-WinSecLayout `
        -Screen 'Findings' `
        -BannerRows $baseLayout.BannerRows `
        -ReservedRows $reservedRows -EnableExport:$EnableExport

    # --------------------------------------------------------
    # Render adaptive project branding
    # --------------------------------------------------------

    if ($layout.BannerRows -gt 2) {

        Show-Banner -Version $Version
    }
    else {

        Write-WinSecText `
            -Text "WINSEC ANALYZER v$Version" `
            -Color Cyan `
            -Align Center

        Write-WinSecText `
            -Text 'mrRoot | Security Findings' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Display assessment context
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title "Findings - $($assessment.Title)"

    $deviceName = $assessment.DeviceId

    if ($null -ne $NavigationState) {

        $selectedName = [string](
            Get-WinSecFindingProperty `
                -InputObject $NavigationState `
                -Name 'SelectedDeviceName'
        )

        if ($selectedName) {
            $deviceName = $selectedName
        }
    }

    if (-not $deviceName) {
        $deviceName = 'NOT SELECTED'
    }

    $contextText = "DEVICE: $deviceName"

    if ($assessment.ScanId) {
        $contextText += " | SCAN: $($assessment.ScanId)"
    }

    Write-WinSecText `
        -Text $contextText `
        -Color Gray

    $statusColor = Get-WinSecStatusColor `
        -Status $assessment.Status

    Write-WinSecText `
        -Text "SCORE: $($assessment.Score) | STATUS: $($assessment.Status)" `
        -Color $statusColor

    Write-WinSecText `
        -Text "FINDINGS / DIAGNOSTICS: $count" `
        -Color Cyan

    # --------------------------------------------------------
    # Display assessment isolation warning
    # --------------------------------------------------------

    if ($assessment.Warning) {

        Write-WinSecFindingField `
            -Label 'Warning' `
            -Value $assessment.Warning `
            -MaxLines 1
    }

    if ($baseLayout.Height -ge 26) { Write-Host '' }

    # --------------------------------------------------------
    # Define responsive findings table
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Id'
            Header   = 'ID'
            Width    = 5
            MinWidth = 3
            MaxWidth = 8
            Priority = 1
        }

        @{
            Key      = 'ConfigurationState'
            Header   = 'State'
            Width    = 14
            MinWidth = 7
            MaxWidth = 14
            Priority = 2
        }

        @{
            Key      = 'Finding'
            Header   = 'Configuration / diagnostic'
            Width    = 46
            MinWidth = 14
            MaxWidth = 72
            Priority = 1
            Expand   = $true
        }
    )

    # --------------------------------------------------------
    # Restore finding selection
    # --------------------------------------------------------

    $context = Get-WinSecFindingsContext `
        -NavigationState $NavigationState

    $selectedIndex = 0

    if ($count -gt 0) {

        $selectedIndex = [Math]::Max(
            0,
            [Math]::Min(
                $context.FindingIndex,
                $count - 1
            )
        )
    }

    # --------------------------------------------------------
    # Calculate visible table rows
    # --------------------------------------------------------

    $maxRows = [Math]::Max(
        1,
        [int]$layout.MaxTableRows
    )

    # --------------------------------------------------------
    # Render prioritized security findings
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $assessment.Findings `
        -SelectedIndex $selectedIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Render details if vertical space is available
    # --------------------------------------------------------

    if (
        $count -gt 0 -and
        $detailPlan.ShowDetails
    ) {

        $selectedFinding = $assessment.Findings[
            $selectedIndex
        ]

        Write-WinSecFindingDetails `
            -Finding $selectedFinding `
            -DetailPlan $detailPlan `
            -FrameworkStatus $assessment.FrameworkStatus
    }

    # --------------------------------------------------------
    # Render empty assessment state
    # --------------------------------------------------------

    if ($count -eq 0 -and -not $assessment.Warning) {

        Write-WinSecText `
            -Text 'No findings available for this selection.' `
            -Color Yellow

        Write-WinSecText `
            -Text 'An empty list does not confirm a successful audit.' `
            -Color DarkGray
    }

    # --------------------------------------------------------
    # Render contextual keyboard help
    # --------------------------------------------------------

    if ($Message) { Write-WinSecFindingField -Label 'Export' -Value $Message -MaxLines 1 }
    Write-WinSecKeyboardHelp -Screen 'Findings' -EnableExport:$EnableExport
}
