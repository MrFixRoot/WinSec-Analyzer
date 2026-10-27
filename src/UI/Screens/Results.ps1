
# ============================================================
# WinSec Analyzer
# Component : Results
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Displays security controls for the selected section.
#
# Features:
# - Multi-device assessment context
# - Five security sections
# - Catalog identities and explicitly unscored control results
# - Adaptive terminal layout
# - Keyboard navigation
# - Persistent control selection
# ============================================================


# ------------------------------------------------------------
# Get security controls belonging to a section
# ------------------------------------------------------------

function Get-WinSecSectionControls {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SystemSecurity','NetworkSecurity','IdentityAccess','LoggingAuditing','ServicesHardening')]
        [string]$SectionKey,

        [AllowEmptyCollection()]
        [object[]]$ControlResults = @(),
        [AllowNull()][object]$ConfigurationAssessment = $null
    )

    # Use the validated catalog for display identities, never execution rights.
    # Loading CheckRegistry defines functions; it does not invoke any check.
    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
    try {
        if ($null -eq (Get-Command 'Get-WinSecCheckRegistry' -CommandType Function -ErrorAction SilentlyContinue)) {
            . (Join-Path $projectRoot 'src/Core/CheckRegistry.ps1')
        }
        $registry = Get-WinSecCheckRegistry -ProjectRoot $projectRoot
    }
    catch { throw 'Unable to load the control display catalog.' }
    $catalogChecks = @($registry.Checks)
    $definitions = @($catalogChecks | Where-Object {
        $_.SectionKey -eq $SectionKey -and $_.Visible -eq $true
    } | Sort-Object Order)

    # Validate all supplied records before producing any rows. The CLI has
    # already checked DeviceId/ScanId ownership; this layer resolves controls.
    $resultsById = @{}
    $displayFields = @('CheckId','Key','ControlKey','SectionKey','Name','Score','Status','ObservedStatus')
    $allowedStatuses = @('PASS','FAIL','ERROR','UNKNOWN','NOT_EVALUATED',
        'PENDING','NOT_CHECKED','NOT_APPLICABLE','NOT_SELECTED','MANUAL','INFORMATIONAL')
    if ($ControlResults.Count -gt 10000) { throw 'Too many control results.' }
    foreach ($result in $ControlResults) {
        if ($null -eq $result) { continue }
        $fields = @{}
        if ($result -is [System.Collections.IDictionary]) {
            foreach ($entry in $result.GetEnumerator()) {
                if ($entry.Key -isnot [string]) { throw 'Invalid control property name.' }
                if ($entry.Key -notin $displayFields) { continue }
                if ($fields.ContainsKey($entry.Key)) { throw 'Ambiguous control property.' }
                $fields[$entry.Key] = $entry.Value
            }
        }
        elseif ($result -is [pscustomobject]) {
            foreach ($property in $result.PSObject.Properties) {
                if ($property.Name -notin $displayFields) { continue }
                if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty) {
                    throw 'Control display requires plain data properties.'
                }
                $fields[$property.Name] = $property.Value
            }
        }
        else { throw 'Unsupported control result.' }

        $matches = @()
        if ($null -ne $fields.CheckId) {
            if ($fields.CheckId -isnot [string]) { throw 'Invalid control identifier.' }
            $matches = @($catalogChecks | Where-Object { $_.CheckId -ceq $fields.CheckId })
        }
        elseif ($null -ne $fields.Key -or $null -ne $fields.ControlKey) {
            $alias = $fields.Key
            if ($null -eq $alias) { $alias = $fields.ControlKey }
            if ($alias -isnot [string]) { throw 'Invalid control alias.' }
            $matches = @($catalogChecks | Where-Object { $_.ControlKey -ceq $alias })
        }
        elseif ($fields.Name -is [string]) {
            $matches = @($catalogChecks | Where-Object { $_.Name -ceq $fields.Name })
        }
        if ($matches.Count -ne 1) { throw 'Missing, unknown or ambiguous control identifier.' }
        $definition = $matches[0]
        foreach ($aliasName in @('Key','ControlKey')) {
            if ($null -ne $fields[$aliasName] -and
                ($fields[$aliasName] -isnot [string] -or $fields[$aliasName] -cne $definition.ControlKey)) {
                throw 'Conflicting control identifiers.'
            }
        }
        if ($null -ne $fields.SectionKey -and
            ($fields.SectionKey -isnot [string] -or $fields.SectionKey -cne $definition.SectionKey)) {
            throw 'Control result does not match its catalog section.'
        }
        if ($resultsById.ContainsKey($definition.CheckId)) { throw 'Duplicate control result.' }
        if ($null -ne $fields.Score) { throw 'Security scoring is not authorized in Results.' }
        foreach ($name in @('Status','ObservedStatus')) {
            if ($null -ne $fields[$name] -and
                ($fields[$name] -isnot [string] -or $fields[$name] -cnotin $allowedStatuses)) {
                throw 'Invalid public control status.'
            }
        }
        $resultsById[$definition.CheckId] = @{
            Status = $fields.Status
            ObservedStatus = $fields.ObservedStatus
        }
    }

    $index = 0
    foreach ($definition in $definitions) {
        $index++
        $status = if ($definition.ImplementationStatus -ceq 'PLANNED') { 'PLANNED' } else { 'PENDING' }
        $observed = $null
        if ($resultsById.ContainsKey($definition.CheckId)) {
            $result = $resultsById[$definition.CheckId]
            if ($null -ne $result.Status) { $status = $result.Status }
            $observed = $result.ObservedStatus
        }
        [pscustomobject]@{
            Id = '{0:D2}' -f $index
            Key = $definition.ControlKey
            CheckId = $definition.CheckId
            SectionKey = $definition.SectionKey
            Name = $definition.Name
            Score = if ($null -ne $ConfigurationAssessment) {Get-WinSecConfigurationScoreText $ConfigurationAssessment 'CONTROL' $definition.CheckId} else {'NOT_SCORED'}
            Status = $status
            ObservedStatus = $observed
            CheckFile = $definition.Script
        }
    }
}


# ------------------------------------------------------------
# Resolve independently sourced control rows
# ------------------------------------------------------------

function Get-WinSecResultsControlRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SectionKey,
        [AllowNull()][psobject]$NavigationState,
        [object[]]$ControlResults = @(),
        [AllowNull()][object]$ConfigurationAssessment = $null,
        [AllowEmptyCollection()][object[]]$ControlViews = @()
    )

    $rows = @(Get-WinSecSectionControls -SectionKey $SectionKey -ControlResults $ControlResults `
        -ConfigurationAssessment $ConfigurationAssessment)
    if ($ControlViews.Count -gt $rows.Count) { throw 'Too many control table sessions.' }
    if ($ControlViews.Count -eq 0) { return $rows }
    if ($null -eq (Get-Command Copy-WinSecResultData -CommandType Function -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot '../../Core/ResultModel.ps1')
    }
    $seen = @{}
    $ownedViews = Copy-WinSecResultData $ControlViews
    foreach ($view in $ownedViews) {
        if ($view -isnot [pscustomobject] -or @($view.PSObject.Properties).Count -ne 7 -or
            @($view.PSObject.Properties | Where-Object {$_.Name -cnotin @(
                'CheckId','DeviceId','ScanId','ScopeType','ScopeKey','ControlResults','ConfigurationAssessment')}).Count -gt 0 -or
            $view.CheckId -isnot [string] -or $seen.ContainsKey($view.CheckId) -or
            $null -eq $NavigationState -or $view.DeviceId -isnot [string] -or
            [string]::IsNullOrWhiteSpace($view.DeviceId) -or $view.DeviceId -cne $NavigationState.SelectedDeviceId -or
            $view.ScanId -isnot [string] -or [string]::IsNullOrWhiteSpace($view.ScanId)) {
            throw 'Invalid control table session identity.'
        }
        $matches = @($rows | Where-Object {$_.CheckId -ceq $view.CheckId})
        if ($matches.Count -ne 1) { throw 'Control table session belongs to another section.' }
        $seen[$view.CheckId] = $true
        # Null scope is supported only for legacy, unscored public records.
        $legacy = $null -eq $view.ScopeType -and $null -eq $view.ScopeKey -and $null -eq $view.ConfigurationAssessment
        if (-not $legacy -and ($view.ScopeType -isnot [string] -or $view.ScopeKey -isnot [string] -or -not (
            ($view.ScopeType -ceq 'DEVICE' -and $view.ScopeKey -ceq 'ALL') -or
            ($view.ScopeType -ceq 'SECTION' -and $view.ScopeKey -ceq $SectionKey) -or
            ($view.ScopeType -ceq 'CONTROL' -and $view.ScopeKey -ceq $view.CheckId)))) {
            throw 'Control table session scope mismatch.'
        }
        foreach ($record in @($view.ControlResults)) {
            if ($null -eq $record -or $record.DeviceId -isnot [string] -or $record.ScanId -isnot [string] -or
                $record.DeviceId -cne $view.DeviceId -or $record.ScanId -cne $view.ScanId) {
                throw 'Foreign record in control table session.'
            }
        }
        if ($null -ne $view.ConfigurationAssessment) {
            Assert-WinSecConfigurationViewContext $view.ConfigurationAssessment $NavigationState $view.ScanId
            if ($view.ConfigurationAssessment.ScopeType -cne $view.ScopeType -or
                $view.ConfigurationAssessment.ScopeKey -cne $view.ScopeKey) { throw 'Foreign control configuration scope.' }
        }
        $sourceRows = @(Get-WinSecSectionControls -SectionKey $SectionKey -ControlResults $view.ControlResults `
            -ConfigurationAssessment $view.ConfigurationAssessment)
        $source = @($sourceRows | Where-Object {$_.CheckId -ceq $view.CheckId})[0]
        $matches[0].Score = $source.Score
        $matches[0].Status = $source.Status
        $matches[0].ObservedStatus = $source.ObservedStatus
        # Keep provenance with each display row; historical sessions stay intact.
        $matches[0] | Add-Member -NotePropertyName DeviceId -NotePropertyValue $view.DeviceId
        $matches[0] | Add-Member -NotePropertyName ScanId -NotePropertyValue $view.ScanId
        $matches[0] | Add-Member -NotePropertyName SourceScopeType -NotePropertyValue $view.ScopeType
        $matches[0] | Add-Member -NotePropertyName SourceScopeKey -NotePropertyValue $view.ScopeKey
    }
    # Do not publish any rows until every session has been validated.
    return $rows
}

function Get-WinSecLatestSystemSecuritySummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$NavigationState,
        [AllowEmptyCollection()][object[]]$ControlViews = @()
    )
    # Display-only snapshot, never a public scan/session or an export source.
    # Reuse all row ownership, scope and reproducible-manifest checks first.
    $views = Copy-WinSecResultData $ControlViews
    $null = @(Get-WinSecResultsControlRows -SectionKey SystemSecurity -NavigationState $NavigationState -ControlViews $views)
    if ($views.Count -eq 0) { return $null }
    $sources = @($views | ForEach-Object {
        [pscustomobject]@{CheckId=$_.CheckId;ScanId=$_.ScanId;ScopeType=$_.ScopeType;ScopeKey=$_.ScopeKey}
    })
    $sourceByScan = @{}
    foreach ($view in $views) {
        $identity = ConvertTo-Json -InputObject @($view.ScopeType,$view.ScopeKey,$view.ConfigurationAssessment) -Depth 32 -Compress
        if ($sourceByScan.ContainsKey($view.ScanId) -and $sourceByScan[$view.ScanId] -cne $identity) {
            throw 'Contradictory sources share a scan identifier.'
        }
        $sourceByScan[$view.ScanId]=$identity
    }
    $scanCount = @($sources.ScanId | Sort-Object -Unique -CaseSensitive).Count
    $summary = [pscustomobject]@{Value=$null;Status='NOT_SCORED';Source='LATEST_CONTROLS';
        Reason='INCOMPLETE_CONTROLS';Sources=$sources;ScanCount=$scanCount}
    if ($views.Count -ne 3) { return $summary }
    $controls = @(); $contextKey = $null; $version = $null
    foreach ($view in $views) {
        if ($null -eq $view.ConfigurationAssessment) { return $summary }
        $assessment = ConvertTo-WinSecPublicConfigurationAssessment $view.ConfigurationAssessment $view.ConfigurationAssessment
        $control = @($assessment.Controls | Where-Object CheckId -CEQ $view.CheckId)
        if ($control.Count -ne 1 -or $control[0].Criteria.Count -eq 0) { return $summary }
        foreach ($criterion in $control[0].Criteria) {
            $key = ConvertTo-Json -InputObject @($assessment.CatalogVersion,$assessment.MethodologyId,
                $assessment.MethodologyVersion,$assessment.PolicySha256,$criterion.Profile,$criterion.OSRelease,$criterion.Edition) -Compress
            if ($null -ne $contextKey -and $key -cne $contextKey) {
                $summary.Reason='INCOMPATIBLE_CONTEXTS'; return $summary
            }
            $contextKey=$key
        }
        $version=$assessment.MethodologyVersion
        $controls += $control[0]
    }
    # Use original criterion fractions, avoiding a mean of rounded UI strings.
    $totals = Get-WinSecConfigurationSectionTotals -Controls $controls -MethodologyVersion $version
    $summary.Value=$totals.Value; $summary.Status=$totals.Status
    $summary.Reason=if ($totals.Status -ceq 'NOT_SCORED') {'INCOMPLETE_CONTROLS'} else {''}
    if ($scanCount -eq 1) { $summary.Source='SESSION' }
    return $summary
}

# ------------------------------------------------------------
# Get current device information
# ------------------------------------------------------------

function Get-WinSecResultsDevice {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null
    )

    $deviceId = ''
    $hostname = 'NOT SELECTED'

    if ($null -ne $NavigationState) {

        $deviceId = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SelectedDeviceId'

        $name = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SelectedDeviceName'

        if ($name) {
            $hostname = $name
        }
        elseif ($deviceId) {
            $hostname = $deviceId
        }
    }

    return [PSCustomObject]@{
        DeviceId = $deviceId
        Hostname = $hostname
    }
}


# ------------------------------------------------------------
# Render security section results
# ------------------------------------------------------------

function Show-WinSecResults {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [AllowEmptyCollection()]
        [object[]]$SectionResults = @(),

        [AllowEmptyCollection()]
        [object[]]$ControlResults = @(),

        [AllowNull()][object]$ConfigurationAssessment = $null,
        [AllowEmptyCollection()][object[]]$ControlViews = @(),
        [string]$ScanId = '',
        [string]$Version = '0.9.0',
        [ValidateLength(0,256)][ValidatePattern('\A[^\p{C}]*\z')][string]$SystemLabel = '',
        [switch]$EnableRescan,
        [ValidateSet('Scan','Rescan')][string]$ScanAction = 'Scan'
    )

    # --------------------------------------------------------
    # Resolve selected section
    # --------------------------------------------------------

    if ($null -ne $ConfigurationAssessment) {Assert-WinSecConfigurationViewContext $ConfigurationAssessment $NavigationState $ScanId}
    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $SectionResults -ConfigurationAssessment $ConfigurationAssessment
    )

    if ($sections.Count -eq 0) {

        Write-WinSecText `
            -Text 'No security sections available.' `
            -Color Yellow

        return
    }

    $sectionIndex = 0
    $controlIndex = 0

    if ($null -ne $NavigationState) {

        $sectionIndex = [int]$NavigationState.SectionIndex
        $controlIndex = [int]$NavigationState.ControlIndex
    }

    $sectionIndex = [Math]::Max(
        0,
        [Math]::Min($sectionIndex, $sections.Count - 1)
    )

    $section = $sections[$sectionIndex]

    # --------------------------------------------------------
    # Load section controls
    # --------------------------------------------------------

    $controls = @(
        Get-WinSecResultsControlRows `
            -SectionKey $section.Key `
            -ControlResults $ControlResults -ConfigurationAssessment $ConfigurationAssessment `
            -NavigationState $NavigationState -ControlViews $ControlViews
    )
    $latestSummary = $null
    if ($section.Key -ceq 'SystemSecurity' -and $ControlViews.Count -gt 0) {
        $latestSummary = Get-WinSecLatestSystemSecuritySummary -NavigationState $NavigationState -ControlViews $ControlViews
        $section.Score = if ($null -ne $latestSummary.Value) {
            $latestSummary.Value.ToString('0.##',[Globalization.CultureInfo]::InvariantCulture)+'/100'
        } else { 'NOT_SCORED' }
        $section.Status = $latestSummary.Status
    }

    if ($controls.Count -gt 0) {

        $controlIndex = [Math]::Max(
            0,
            [Math]::Min(
                $controlIndex,
                $controls.Count - 1
            )
        )
    }
    else {
        $controlIndex = -1
    }

    # --------------------------------------------------------
    # Get selected device
    # --------------------------------------------------------

    $device = Get-WinSecResultsDevice `
        -NavigationState $NavigationState

    # Resolve/validate display data before clearing or drawing the screen.
    $layout = Get-WinSecLayout -Screen 'Section'
    Clear-WinSecScreen
    if ($layout.IsTooSmall) {
        Write-WinSecText -Text 'WINSEC ANALYZER' -Color Cyan -Align Center
        Write-Host ''
        Write-WinSecText -Text 'Terminal window is too small.' -Color Yellow -Align Center
        Write-WinSecText -Text "Minimum: $($layout.MinimumWidth) x $($layout.MinimumHeight)" `
            -Color DarkGray -Align Center
        return
    }

    # --------------------------------------------------------
    # Render project banner
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
            -Text 'mrRoot | Security Assessment' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Render section heading
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title $section.Name

    Write-WinSecText `
        -Text "DEVICE: $($device.Hostname)" `
        -Color Gray
    if ($SystemLabel) { Write-WinSecText -Text ('CURRENT OS: ' + $SystemLabel) -Color Gray }

    $statusColor = Get-WinSecStatusColor `
        -Status $section.Status

    $summary = 'SECTION SCORE: {0} | STATUS: {1}' -f `
        $section.Score,
        $section.Status
    if ($null -ne $latestSummary -and $latestSummary.Source -ceq 'LATEST_CONTROLS') {
        $summary += ' | SOURCE: latest controls ('+$latestSummary.ScanCount+' scans)'
        if ($latestSummary.Reason -ceq 'INCOMPATIBLE_CONTEXTS') { $summary += ' | incompatible profiles or methodology' }
    }

    Write-WinSecText `
        -Text $summary `
        -Color $statusColor

    if ($layout.Height -ge 26) { Write-Host '' }

    # --------------------------------------------------------
    # Define adaptive security controls table
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Id'
            Header   = 'ID'
            Width    = 2
            MinWidth = 2
            MaxWidth = 2
            Priority = 1
        }

        @{
            Key      = 'Name'
            Header   = 'Security Control'
            Width    = 34
            MinWidth = 14
            MaxWidth = 50
            Priority = 1
            Expand   = $true
        }

        @{
            Key      = 'Score'
            Header   = 'Score'
            Width    = 10
            MinWidth = 10
            MaxWidth = 12
            Priority = 2
            Align    = 'Right'
        }

        @{
            Key      = 'Status'
            Header   = 'Status'
            Width    = 14
            MinWidth = 8
            MaxWidth = 16
            Priority = 3
            Align    = 'Center'
        }
    )

    # --------------------------------------------------------
    # Calculate visible table area
    # --------------------------------------------------------

    $hiddenKeys = @()

    if ($controls.Count -eq 0) {
        $hiddenKeys = @('UP/DOWN', 'F')
    }

    # Reserve actual space for heading, device,
    # score, table borders and a safety margin.

    $layout = Get-WinSecLayout `
        -Screen 'Section' `
        -BannerRows $layout.BannerRows `
        -HiddenKeys $hiddenKeys `
        -ReservedRows (13 + [int][bool]$SystemLabel)

    $maxRows = [Math]::Max(
        1,
        [int]$layout.MaxTableRows
    )

    # --------------------------------------------------------
    # Render controls and selection
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $controls `
        -SelectedIndex $controlIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Render contextual keyboard help
    # --------------------------------------------------------

    $scanText = if ($EnableRescan) { '[R] {0} Control' -f $ScanAction } else { '[R] {0} Control (unavailable)' -f $ScanAction }
    Write-WinSecText -Text $scanText -Color Cyan
    Write-WinSecKeyboardHelp `
        -Screen 'Section' `
        -HiddenKeys $hiddenKeys
}
