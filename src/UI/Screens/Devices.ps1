
# ============================================================
# WinSec Analyzer
# Component : Devices
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Multi-device selection screen.
# Displays registered Windows devices, security scores,
# assessment status and last scan information.
#
# This component does not execute security assessments.
# ============================================================


# ------------------------------------------------------------
# Normalize device information for UI rendering
# ------------------------------------------------------------

function Get-WinSecDeviceRows {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Devices = @()
    )

    $index = 0

    $rows = @(
        foreach ($device in $Devices) {

            if ($null -eq $device) {
                continue
            }

            $index++

            # Device identity
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

            # Device assessment mode
            $mode = Get-WinSecTableValue `
                -Row $device -Key 'Mode'

            if ([string]::IsNullOrWhiteSpace($mode)) {
                $mode = 'UNKNOWN'
            }

            # Security score
            $rawScore = Get-WinSecTableValue `
                -Row $device -Key 'Score'

            $score = '--/100'
            $numericScore = 0

            if (
                [int]::TryParse(
                    $rawScore,
                    [ref]$numericScore
                ) -and
                $numericScore -ge 0 -and
                $numericScore -le 100
            ) {
                $score = '{0}/100' -f $numericScore
            }

            # Security assessment status
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

            # Last completed or attempted assessment
            $lastScan = Get-WinSecTableValue `
                -Row $device -Key 'LastScan'

            if ([string]::IsNullOrWhiteSpace($lastScan)) {
                $lastScan = 'Never'
            }

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
    )

    return $rows
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

    $terminal = Get-WinSecTerminalSize

    Clear-WinSecScreen

    # --------------------------------------------------------
    # Validate terminal dimensions
    # --------------------------------------------------------

    if (
        $terminal.Width -lt 40 -or
        $terminal.Height -lt 18
    ) {
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
            -Text 'Please resize the terminal.' `
            -Color DarkGray `
            -Align Center

        return
    }

    # --------------------------------------------------------
    # Render project banner
    # --------------------------------------------------------

    $bannerRows = 2

    if ($terminal.Height -ge 38) {

        Show-Banner -Version $Version

        $bannerRows = if ($terminal.Width -ge 55) {
            15
        }
        else {
            10
        }
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
    # Prepare registered devices
    # --------------------------------------------------------

    $rows = @(
        Get-WinSecDeviceRows -Devices $Devices
    )

    # --------------------------------------------------------
    # Resolve current selection
    # --------------------------------------------------------

    if ($SelectedIndex -lt 0) {

        $SelectedIndex = 0

        if (
            $null -ne $NavigationState -and
            $null -ne $NavigationState.PSObject.Properties['DeviceIndex']
        ) {
            $SelectedIndex = [int]$NavigationState.DeviceIndex
        }
    }

    if ($rows.Count -gt 0) {

        $SelectedIndex = [Math]::Max(
            0,
            [Math]::Min(
                $SelectedIndex,
                $rows.Count - 1
            )
        )
    }
    else {
        $SelectedIndex = -1
    }

    # --------------------------------------------------------
    # Render screen heading
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title 'Managed Devices'

    Write-WinSecText `
        -Text "REGISTERED DEVICES: $($rows.Count)" `
        -Color Cyan

    if ($rows.Count -gt 0) {

        $selected = $rows[$SelectedIndex]

        Write-WinSecText `
            -Text "SELECTED: $($selected.Hostname)" `
            -Color Gray
    }
    else {

        Write-WinSecText `
            -Text 'No devices registered.' `
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
        }

        @{
            Key      = 'Hostname'
            Header   = 'Device'
            Width    = 27
            MinWidth = 12
            MaxWidth = 45
            Priority = 1
            Expand   = $true
        }

        @{
            Key      = 'Mode'
            Header   = 'Mode'
            Width    = 10
            MinWidth = 6
            MaxWidth = 12
            Priority = 4
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
            Key      = 'LastScan'
            Header   = 'Last Scan'
            Width    = 20
            MinWidth = 10
            MaxWidth = 24
            Priority = 5
        }
    )

    # --------------------------------------------------------
    # Calculate visible table area
    # --------------------------------------------------------

    $reservedRows = 14

    $maxRows = [Math]::Max(
        1,
        $terminal.Height - $bannerRows - $reservedRows
    )

    # --------------------------------------------------------
    # Render devices table
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $rows `
        -SelectedIndex $SelectedIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Keyboard help
    # --------------------------------------------------------

    Write-Host ''

    Write-WinSecDivider -Color DarkGray

    if ($rows.Count -gt 0) {

        Write-WinSecText `
            -Text '[UP/DOWN] Navigate   [ENTER] Select Device   [Q] Exit' `
            -Color DarkGray
    }
    else {

        Write-WinSecText `
            -Text '[Q] Exit' `
            -Color DarkGray
    }
}
