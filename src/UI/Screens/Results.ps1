
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
        [object[]]$ControlResults = @()
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
            Score = 'NOT_SCORED'
            Status = $status
            ObservedStatus = $observed
            CheckFile = $definition.Script
        }
    }
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

        [string]$Version = '0.9.0',
        [switch]$EnableRescan,
        [ValidateSet('Scan','Rescan')][string]$ScanAction = 'Scan'
    )

    # --------------------------------------------------------
    # Resolve selected section
    # --------------------------------------------------------

    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $SectionResults
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
        Get-WinSecSectionControls `
            -SectionKey $section.Key `
            -ControlResults $ControlResults
    )

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

    $statusColor = Get-WinSecStatusColor `
        -Status $section.Status

    $summary = 'SECTION SCORE: {0} | STATUS: {1}' -f `
        $section.Score,
        $section.Status

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
        $hiddenKeys = @('UP/DOWN', 'H', 'ENTER')
    }

    # Reserve actual space for heading, device,
    # score, table borders and a safety margin.

    $layout = Get-WinSecLayout `
        -Screen 'Section' `
        -BannerRows $layout.BannerRows `
        -HiddenKeys $hiddenKeys `
        -ReservedRows 13

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

    $scanText = if ($EnableRescan) { '[R] {0} Section' -f $ScanAction } else { '[R] {0} Section (unavailable)' -f $ScanAction }
    Write-WinSecText -Text $scanText -Color Cyan
    Write-WinSecKeyboardHelp `
        -Screen 'Section' `
        -HiddenKeys $hiddenKeys
}
