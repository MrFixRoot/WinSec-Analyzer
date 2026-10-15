
# ============================================================
# WinSec Analyzer
# Component : Devices
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Multi-device security assessment interface.
#
# Features:
# - Device selection
# - Security scores
# - Assessment status
# - Last scan information
# - Adaptive terminal layout
# - Keyboard navigation
# - Automatic table resizing
# ============================================================


# ------------------------------------------------------------
# Normalize registered device information
# ------------------------------------------------------------

function Get-WinSecDeviceRows {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Devices = @()
    )

    $index = 0

    foreach ($device in $Devices) {

        if ($null -eq $device) {
            continue
        }

        $index++

        # Device identification
        $deviceId = Get-WinSecTableValue `
            -Row $device -Key 'DeviceId'

        $hostname = Get-WinSecTableValue `
            -Row $device -Key 'Hostname'

        if ([string]::IsNullOrWhiteSpace($hostname)) {
            $hostname = Get-WinSecTableValue `
                -Row $device -Key 'Name'
        }

        if ([string]::IsNullOrWhiteSpace($hostname)) {
            $hostname = 'UNKNOWN'
        }

        # Assessment mode
        $mode = Get-WinSecTableValue `
            -Row $device -Key 'Mode'

        if ([string]::IsNullOrWhiteSpace($mode)) {
            $mode = 'UNKNOWN'
        }

        # Security score
        $rawScore = Get-WinSecTableValue `
            -Row $device -Key 'Score'

        $score = '--/100'

        if (
            $rawScore -match
            '^\s*(\d{1,3})\s*(?:/100)?\s*$'
        ) {

            $numericScore = [int]$Matches[1]

            if ($numericScore -le 100) {
                $score = '{0}/100' -f $numericScore
            }
        }

        # Assessment status
        $status = Get-WinSecTableValue `
            -Row $device -Key 'Status'

        if ([string]::IsNullOrWhiteSpace($status)) {

            $status = if ($score -eq '--/100') {
                'PENDING'
            }
            else {
                'UNKNOWN'
            }
        }

        # Last assessment
        $lastScan = Get-WinSecTableValue `
            -Row $device -Key 'LastScan'

        if ([string]::IsNullOrWhiteSpace($lastScan)) {
            $lastScan = 'Never'
        }

        # Return normalized device
        [PSCustomObject]@{
            Id       = '{0:D2}' -f $index
            DeviceId = $deviceId
            Hostname = $hostname
            Mode     = $mode.ToUpperInvariant()
            Score    = $score
            Status   = $status.ToUpperInvariant()
            LastScan = $lastScan
        }
    }
}


# ------------------------------------------------------------
# Resolve selected device index
# ------------------------------------------------------------

function Get-WinSecSelectedDeviceIndex {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [int]$SelectedIndex = -1,

        [int]$DeviceCount = 0
    )

    if ($DeviceCount -le 0) {
        return -1
    }

    # Use navigation state when an index
    # has not been explicitly provided.

    if ($SelectedIndex -lt 0) {

        $SelectedIndex = 0

        if (
            $null -ne $NavigationState -and
            $null -ne $NavigationState.PSObject.Properties[
                'DeviceIndex'
            ]
        ) {
            $SelectedIndex = [int]$NavigationState.DeviceIndex
        }
    }

    # Keep selection inside valid boundaries
    return [Math]::Max(
        0,
        [Math]::Min(
            $SelectedIndex,
            $DeviceCount - 1
        )
    )
}


# ------------------------------------------------------------
# Render multi-device selection screen
# ------------------------------------------------------------

function Show-WinSecDevices {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [AllowEmptyCollection()]
        [object[]]$Devices = @(),

        [int]$SelectedIndex = -1,

        [string]$Version = '0.9.0'
    )

    # --------------------------------------------------------
    # Prepare device information
    # --------------------------------------------------------

    $rows = @(
        Get-WinSecDeviceRows -Devices $Devices
    )

    $deviceCount = $rows.Count

    # --------------------------------------------------------
    # Resolve selected device
    # --------------------------------------------------------

    $SelectedIndex = Get-WinSecSelectedDeviceIndex `
        -NavigationState $NavigationState `
        -SelectedIndex $SelectedIndex `
        -DeviceCount $deviceCount

    $selectedDevice = $null

    if ($SelectedIndex -ge 0) {
        $selectedDevice = $rows[$SelectedIndex]
    }

    # --------------------------------------------------------
    # Determine available keyboard commands
    # --------------------------------------------------------

    $hiddenKeys = @()

    if ($deviceCount -eq 0) {

        $hiddenKeys = @(
            'UP/DOWN'
            'ENTER'
        )
    }

    # --------------------------------------------------------
    # Get adaptive terminal layout
    # --------------------------------------------------------

    $layout = Get-WinSecLayout `
        -Screen 'Devices' `
        -HiddenKeys $hiddenKeys

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
    # Render adaptive project banner
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
            -Text 'mrRoot | Multi-Device Assessment' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Render screen heading
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title 'Managed Devices'

    Write-WinSecText `
        -Text "REGISTERED DEVICES: $deviceCount" `
        -Color Cyan

    if ($null -ne $selectedDevice) {

        $selectedText = 'SELECTED: {0} | MODE: {1}' -f `
            $selectedDevice.Hostname,
            $selectedDevice.Mode

        Write-WinSecText `
            -Text $selectedText `
            -Color Gray
    }
    else {

        Write-WinSecText `
            -Text 'SELECTED: NONE' `
            -Color Yellow
    }

    Write-Host ''

    # --------------------------------------------------------
    # Define adaptive table columns
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Id'
            Header   = 'ID'
            Width    = 3
            MinWidth = 2
            MaxWidth = 4
            Priority = 1
            Align    = 'Left'
        }

        @{
            Key      = 'Hostname'
            Header   = 'Device'
            Width    = 27
            MinWidth = 12
            MaxWidth = 45
            Priority = 1
            Align    = 'Left'
            Expand   = $true
        }

        @{
            Key      = 'Score'
            Header   = 'Score'
            Width    = 10
            MinWidth = 7
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

        @{
            Key      = 'Mode'
            Header   = 'Mode'
            Width    = 10
            MinWidth = 6
            MaxWidth = 12
            Priority = 4
            Align    = 'Center'
        }

        @{
            Key      = 'LastScan'
            Header   = 'Last Scan'
            Width    = 20
            MinWidth = 10
            MaxWidth = 24
            Priority = 5
            Align    = 'Left'
        }
    )

    # --------------------------------------------------------
    # Calculate visible table rows
    # --------------------------------------------------------

    $maxRows = [Math]::Max(
        1,
        [int]$layout.MaxTableRows
    )

    # --------------------------------------------------------
    # Render device table
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $rows `
        -SelectedIndex $SelectedIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Render contextual keyboard help
    # --------------------------------------------------------

    Write-WinSecKeyboardHelp `
        -Screen 'Devices' `
        -HiddenKeys $hiddenKeys
}
