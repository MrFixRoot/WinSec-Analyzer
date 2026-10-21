
# ============================================================
# WinSec Analyzer
# Component : MainMenu
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Main security assessment dashboard.
#
# Features:
# - Multi-device assessment context
# - Five security sections
# - Explicit NOT_SCORED and assessment status
# - Adaptive terminal layout
# - Keyboard navigation highlighting
# - Context-aware keyboard shortcuts
# ============================================================


# ------------------------------------------------------------
# Get security sections and assessment results
# ------------------------------------------------------------

function Get-WinSecMainMenuSections {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$SectionResults = @()
    )

    # Main security categories
    $definitions = @(
        @{
            Id   = '01'
            Key  = 'SystemSecurity'
            Name = 'System Security'
        }
        @{
            Id   = '02'
            Key  = 'NetworkSecurity'
            Name = 'Network Security'
        }
        @{
            Id   = '03'
            Key  = 'IdentityAccess'
            Name = 'Identity & Access Security'
        }
        @{
            Id   = '04'
            Key  = 'LoggingAuditing'
            Name = 'Logging & Auditing'
        }
        @{
            Id   = '05'
            Key  = 'ServicesHardening'
            Name = 'Services & Hardening'
        }
    )

    # Read only data fields used by this view, without string coercion or
    # calculated getters. Validate the whole collection before emitting rows.
    $resultsByKey = @{}
    $displayFields = @('Key','SectionKey','Name','Id','Score','Status')
    $allowedStatuses = @('PENDING','NOT_SCORED','NOT_EVALUATED','UNKNOWN',
        'ERROR','NOT_SELECTED','NOT_CHECKED','NOT_APPLICABLE','MANUAL','INFORMATIONAL')
    if ($SectionResults.Count -gt 10000) { throw 'Too many section results.' }
    foreach ($candidate in $SectionResults) {
        if ($null -eq $candidate) { continue }
        $fields = @{}
        if ($candidate -is [System.Collections.IDictionary]) {
            foreach ($entry in $candidate.GetEnumerator()) {
                if ($entry.Key -isnot [string]) { throw 'Invalid section property name.' }
                if ($entry.Key -notin $displayFields) { continue }
                if ($fields.ContainsKey($entry.Key)) { throw 'Ambiguous section property.' }
                $fields[$entry.Key] = $entry.Value
            }
        }
        elseif ($candidate -is [pscustomobject]) {
            foreach ($property in $candidate.PSObject.Properties) {
                if ($property.Name -notin $displayFields) { continue }
                if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty) {
                    throw 'Section display requires plain data properties.'
                }
                $fields[$property.Name] = $property.Value
            }
        }
        else { throw 'Unsupported section result.' }

        $key = $null
        if ($null -ne $fields.Key -or $null -ne $fields.SectionKey) {
            foreach ($name in @('Key','SectionKey')) {
                if ($null -ne $fields[$name] -and
                    ($fields[$name] -isnot [string] -or
                        $fields[$name] -cnotin $definitions.Key)) {
                    throw 'Invalid section identifier.'
                }
            }
            if ($null -ne $fields.Key -and $null -ne $fields.SectionKey -and
                $fields.Key -cne $fields.SectionKey) { throw 'Conflicting section identifiers.' }
            $key = $fields.Key
            if ($null -eq $key) { $key = $fields.SectionKey }
        }
        elseif ($fields.Name -is [string]) {
            $match = @($definitions | Where-Object { $_.Name -ceq $fields.Name })
            if ($match.Count -eq 1) { $key = $match[0].Key }
        }
        elseif ($fields.Id -is [string]) {
            $match = @($definitions | Where-Object { $_.Id -ceq $fields.Id })
            if ($match.Count -eq 1) { $key = $match[0].Key }
        }
        if ($null -eq $key) { throw 'Missing or unknown section identifier.' }
        if ($resultsByKey.ContainsKey($key)) { throw 'Duplicate section result.' }
        if ($null -ne $fields.Score) { throw 'Security scoring is not authorized in MainMenu.' }
        $status = 'PENDING'
        if ($null -ne $fields.Status) {
            if ($fields.Status -isnot [string] -or $fields.Status -cnotin $allowedStatuses) {
                throw 'Invalid unscored section status.'
            }
            $status = $fields.Status
        }
        $resultsByKey[$key] = $status
    }

    foreach ($definition in $definitions) {
        $status = 'PENDING'
        if ($resultsByKey.ContainsKey($definition.Key)) { $status = $resultsByKey[$definition.Key] }

        # ----------------------------------------------------
        # Return normalized section
        # ----------------------------------------------------

        [PSCustomObject]@{
            Id     = $definition.Id
            Key    = $definition.Key
            Name   = $definition.Name
            Score  = 'NOT_SCORED'
            Status = $status
        }
    }
}


# ------------------------------------------------------------
# Resolve selected section index
# ------------------------------------------------------------

function Get-WinSecMainMenuSelectedIndex {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [int]$SectionCount = 5
    )

    if ($SectionCount -le 0) {
        return -1
    }

    $selectedIndex = 0

    if ($null -ne $NavigationState) {

        $rawIndex = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SectionIndex'

        $parsedIndex = 0

        if ([int]::TryParse(
            $rawIndex,
            [ref]$parsedIndex
        )) {
            $selectedIndex = $parsedIndex
        }
    }

    return [Math]::Max(
        0,
        [Math]::Min(
            $selectedIndex,
            $SectionCount - 1
        )
    )
}


# ------------------------------------------------------------
# Resolve active device information
# ------------------------------------------------------------

function Get-WinSecMainMenuDevice {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null
    )

    $deviceId = ''
    $hostname = ''

    if ($null -ne $NavigationState) {

        $deviceId = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SelectedDeviceId'

        $hostname = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SelectedDeviceName'
    }

    if ([string]::IsNullOrWhiteSpace($hostname)) {

        if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
            $hostname = $deviceId
        }
        else {
            $hostname = 'NOT SELECTED'
        }
    }

    return [PSCustomObject]@{
        DeviceId = $deviceId
        Hostname = $hostname
        Selected = (
            -not [string]::IsNullOrWhiteSpace($deviceId)
        )
    }
}


# ------------------------------------------------------------
# Maintain compatibility with existing UI components
# ------------------------------------------------------------


function Get-WinSecMainMenuHelpHeight {
    [CmdletBinding()]
    param(
        [int]$Width = 80,

        [switch]$EnableRescan
    )

    return Get-WinSecKeyboardHelpHeight `
        -Screen 'MainMenu' `
        -Width $Width `
        -EnableRescan:$EnableRescan
}



# ------------------------------------------------------------
# Render main security dashboard
# ------------------------------------------------------------

function Show-WinSecMainMenu {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [AllowEmptyCollection()]
        [object[]]$SectionResults = @(),

        [Nullable[int]]$OverallScore = $null,

        [string]$OverallStatus = 'PENDING',

        [string]$Version = '0.9.0',

        # Display-only authorization flag.
        # The caller must validate the selected target.
        [switch]$EnableRescan,

        [ValidateSet('Scan','Rescan')][string]$ScanAction = 'Scan'
    )

    # No caller-supplied number or success/failure label authorizes scoring.
    # Validate before clearing or drawing, including on a small terminal.
    if ($null -ne $OverallScore -or $OverallStatus -cnotin @('PENDING','NOT_SCORED')) {
        throw 'Invalid unscored MainMenu summary.'
    }
    $sections = @(
        Get-WinSecMainMenuSections -SectionResults $SectionResults
    )

    # --------------------------------------------------------
    # Get adaptive terminal layout
    # --------------------------------------------------------

    $layout = Get-WinSecLayout -Screen 'MainMenu'

    Clear-WinSecScreen

    # --------------------------------------------------------
    # Validate terminal dimensions
    # --------------------------------------------------------

    if ($layout.IsTooSmall) {

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
            -Text "Minimum: $($layout.MinimumWidth) x $($layout.MinimumHeight)" `
            -Color DarkGray `
            -Align Center

        Write-Host ''

        Write-WinSecText `
            -Text 'Please resize the terminal.' `
            -Color DarkGray `
            -Align Center

        return
    }

    # --------------------------------------------------------
    # Prepare device and section information
    # --------------------------------------------------------

    $device = Get-WinSecMainMenuDevice `
        -NavigationState $NavigationState

    $selectedIndex = Get-WinSecMainMenuSelectedIndex `
        -NavigationState $NavigationState `
        -SectionCount $sections.Count

    # --------------------------------------------------------
    # Determine vertical presentation mode
    # --------------------------------------------------------

    $compactVertical = (
        $layout.Height -lt 27
    )

    # --------------------------------------------------------
    # Render project branding
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
            -Text 'mrRoot | Windows Security Assessment' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Render dashboard heading
    # --------------------------------------------------------

    if ($compactVertical) {

        Write-WinSecText `
            -Text 'SECURITY ASSESSMENT' `
            -Color Cyan

        Write-WinSecDivider -Color DarkGray
    }
    else {

        Write-WinSecSectionTitle `
            -Title 'Security Assessment'
    }

    # --------------------------------------------------------
    # Display active device information
    # --------------------------------------------------------

    $deviceText = 'DEVICE: {0}' -f $device.Hostname

    $deviceColor = 'Gray'

    if (-not $device.Selected) {
        $deviceColor = 'Yellow'
    }

    Write-WinSecText `
        -Text $deviceText `
        -Color $deviceColor

    # --------------------------------------------------------
    # Display overall security score
    # --------------------------------------------------------

    $scoreText = 'NOT_SCORED'
    $status = $OverallStatus

    $statusColor = Get-WinSecStatusColor `
        -Status $status

    $summary = 'SECURITY SCORE: {0} | STATUS: {1}' -f `
        $scoreText,
        $status

    Write-WinSecText `
        -Text $summary `
        -Color $statusColor

    if (-not $compactVertical) {
        Write-Host ''
    }

    # --------------------------------------------------------
    # Define security sections table
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Id'
            Header   = 'ID'
            Width    = 2
            MinWidth = 2
            MaxWidth = 2
            Priority = 1
            Align    = 'Left'
        }

        @{
            Key      = 'Name'
            Header   = 'Security Section'
            Width    = 34
            MinWidth = 14
            MaxWidth = 50
            Priority = 1
            Align    = 'Left'
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
    # Calculate available space for table rows
    # --------------------------------------------------------

    # Compact presentation:
    # - Short heading
    # - Device and score
    # - Table borders
    # - Pagination allowance

    # Reserve one additional row for Scan / Rescan.
    $reservedRows = if ($compactVertical) {
        10
    }
    else {
        13
    }

    # Recalculate layout using actual content reservations.
    $layout = Get-WinSecLayout `
        -Screen 'MainMenu' `
        -ReservedRows $reservedRows

    $maxRows = [Math]::Max(
        1,
        [int]$layout.MaxTableRows
    )

    # --------------------------------------------------------
    # Render security sections
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $sections `
        -SelectedIndex $selectedIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Render Scan / Rescan shortcut
    # --------------------------------------------------------

    # This is a display-only shortcut.
    # Authorization remains in the CLI and ScanCoordinator.

    if ($EnableRescan.IsPresent -and $device.Selected) {

        Write-WinSecText `
            -Text ('[R] {0} Section' -f $ScanAction) `
            -Color Cyan
    }
    else {

        Write-WinSecText `
            -Text ('[R] {0} Section (unavailable)' -f $ScanAction) `
            -Color DarkGray
    }

    # --------------------------------------------------------
    # Render keyboard shortcuts
    # --------------------------------------------------------

    Write-WinSecKeyboardHelp `
        -Screen 'MainMenu' `
        -HiddenKeys @('R') `
        -EnableRescan:$EnableRescan
}
