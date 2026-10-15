
# ============================================================
# WinSec Analyzer
# Component : NavigationController
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Manages multi-device navigation, screen history,
# selected items and application commands.
#
# Navigation:
# Devices -> MainMenu -> Section -> Findings
# ESC returns to the previous screen.
# ============================================================


# ------------------------------------------------------------
# Initialize navigation state
# ------------------------------------------------------------

function New-WinSecNavigationState {
    [CmdletBinding()]
    param()

    return [PSCustomObject]@{

        Screen = 'Devices'

        # Device context
        DeviceIndex        = 0
        SelectedDeviceId   = $null
        SelectedDeviceName = $null

        # Security navigation
        SectionIndex  = 0
        ControlIndex  = 0
        SettingsIndex = 0

        # Findings navigation
        FindingsOffset = 0
        FindingsScope  = 'Section'

        # Screen navigation history
        History = [System.Collections.ArrayList]::new()

        # Pending application commands
        PendingCommand = $null
        PendingScope   = $null

        # Application lifecycle
        ExitRequested = $false
    }
}


# ------------------------------------------------------------
# Calculate next selected index
# ------------------------------------------------------------

function Get-WinSecNextIndex {
    [CmdletBinding()]
    param(
        [int]$CurrentIndex = 0,

        [int]$ItemCount = 0,

        [ValidateSet(-1, 1)]
        [int]$Direction = 1
    )

    if ($ItemCount -le 0) {
        return 0
    }

    $nextIndex = $CurrentIndex + $Direction

    # Circular navigation
    if ($nextIndex -ge $ItemCount) {
        return 0
    }

    if ($nextIndex -lt 0) {
        return ($ItemCount - 1)
    }

    return $nextIndex
}


# ------------------------------------------------------------
# Read device property
# ------------------------------------------------------------

function Get-WinSecNavigationDeviceValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Device,

        [Parameter(Mandatory)]
        [string]$Property
    )

    if ($null -eq $Device) {
        return ''
    }

    if ($Device -is [System.Collections.IDictionary]) {

        if ($Device.Contains($Property)) {
            return [string]$Device[$Property]
        }

        return ''
    }

    $value = $Device.PSObject.Properties[$Property]

    if ($null -ne $value -and $null -ne $value.Value) {
        return [string]$value.Value
    }

    return ''
}


# ------------------------------------------------------------
# Create navigation snapshot
# ------------------------------------------------------------

function Get-WinSecNavigationSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State
    )

    return [PSCustomObject]@{
        Screen             = $State.Screen

        DeviceIndex        = $State.DeviceIndex
        SelectedDeviceId   = $State.SelectedDeviceId
        SelectedDeviceName = $State.SelectedDeviceName

        SectionIndex       = $State.SectionIndex
        ControlIndex       = $State.ControlIndex
        SettingsIndex      = $State.SettingsIndex

        FindingsOffset     = $State.FindingsOffset
        FindingsScope      = $State.FindingsScope
    }
}


# ------------------------------------------------------------
# Navigate to another screen
# ------------------------------------------------------------

function Set-WinSecNavigationScreen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [ValidateSet(
            'Devices',
            'MainMenu',
            'Section',
            'Findings',
            'Audit',
            'Results',
            'Settings'
        )]
        [string]$Screen,

        [switch]$SkipHistory
    )

    if ($State.Screen -eq $Screen) {
        return $State
    }

    # Save previous screen and selections
    if (-not $SkipHistory) {

        $snapshot = Get-WinSecNavigationSnapshot `
            -State $State

        $null = $State.History.Add($snapshot)
    }

    $State.Screen = $Screen

    # Reset findings cursor on new entry
    if ($Screen -eq 'Findings') {
        $State.FindingsOffset = 0
    }

    return $State
}


# ------------------------------------------------------------
# Restore previous screen
# ------------------------------------------------------------

function Restore-WinSecNavigationScreen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State
    )

    # Restore most recent navigation snapshot
    if ($State.History.Count -gt 0) {

        $lastIndex = $State.History.Count - 1

        $previous = $State.History[$lastIndex]

        $State.History.RemoveAt($lastIndex)

        $State.Screen = $previous.Screen

        $State.DeviceIndex = $previous.DeviceIndex
        $State.SelectedDeviceId = $previous.SelectedDeviceId
        $State.SelectedDeviceName = $previous.SelectedDeviceName

        $State.SectionIndex = $previous.SectionIndex
        $State.ControlIndex = $previous.ControlIndex
        $State.SettingsIndex = $previous.SettingsIndex

        $State.FindingsOffset = $previous.FindingsOffset
        $State.FindingsScope = $previous.FindingsScope

        return $State
    }

    # Safe fallback when no history exists
    if ($State.Screen -eq 'MainMenu') {

        $State.Screen = 'Devices'
        $State.SelectedDeviceId = $null
        $State.SelectedDeviceName = $null
    }
    elseif ($State.Screen -ne 'Devices') {

        if ($State.SelectedDeviceId) {
            $State.Screen = 'MainMenu'
        }
        else {
            $State.Screen = 'Devices'
        }
    }

    return $State
}


# ------------------------------------------------------------
# Process navigation actions
# ------------------------------------------------------------

function Invoke-WinSecNavigationAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [string]$Action,

        [AllowEmptyCollection()]
        [object[]]$Devices = @(),

        [int]$SectionCount = 0,

        [int]$ControlCount = 0,

        [int]$FindingCount = 0,

        [int]$SettingsCount = 0
    )

    # Clear previously processed commands
    $State.PendingCommand = $null
    $State.PendingScope = $null

    if ($State.ExitRequested) {
        return $State
    }

    $deviceCount = @($Devices).Count

    $SectionCount = [Math]::Max(0, $SectionCount)
    $ControlCount = [Math]::Max(0, $ControlCount)
    $FindingCount = [Math]::Max(0, $FindingCount)
    $SettingsCount = [Math]::Max(0, $SettingsCount)

    # --------------------------------------------------------
    # Handle list navigation
    # --------------------------------------------------------

    if ($Action -in @('MoveUp', 'MoveDown')) {

        $direction = if ($Action -eq 'MoveUp') {
            -1
        }
        else {
            1
        }

        switch ($State.Screen) {

            'Devices' {

                $State.DeviceIndex = Get-WinSecNextIndex `
                    -CurrentIndex $State.DeviceIndex `
                    -ItemCount $deviceCount `
                    -Direction $direction
            }

            'MainMenu' {

                $State.SectionIndex = Get-WinSecNextIndex `
                    -CurrentIndex $State.SectionIndex `
                    -ItemCount $SectionCount `
                    -Direction $direction
            }

            'Section' {

                $State.ControlIndex = Get-WinSecNextIndex `
                    -CurrentIndex $State.ControlIndex `
                    -ItemCount $ControlCount `
                    -Direction $direction
            }

            'Results' {

                $State.ControlIndex = Get-WinSecNextIndex `
                    -CurrentIndex $State.ControlIndex `
                    -ItemCount $ControlCount `
                    -Direction $direction
            }

            'Settings' {

                $State.SettingsIndex = Get-WinSecNextIndex `
                    -CurrentIndex $State.SettingsIndex `
                    -ItemCount $SettingsCount `
                    -Direction $direction
            }
        }

        return $State
    }

    # --------------------------------------------------------
    # Process remaining actions
    # --------------------------------------------------------

    switch ($Action) {

        # ----------------------------------------------------
        # Open device or security section
        # ----------------------------------------------------

        'Open' {

            switch ($State.Screen) {

                'Devices' {

                    if ($deviceCount -le 0) {
                        break
                    }

                    $index = [Math]::Max(
                        0,
                        [Math]::Min(
                            [int]$State.DeviceIndex,
                            $deviceCount - 1
                        )
                    )

                    $device = $Devices[$index]

                    $deviceId = Get-WinSecNavigationDeviceValue `
                        -Device $device `
                        -Property 'DeviceId'

                    if ([string]::IsNullOrWhiteSpace($deviceId)) {
                        break
                    }

                    $hostname = Get-WinSecNavigationDeviceValue `
                        -Device $device `
                        -Property 'Hostname'

                    if (-not $hostname) {
                        $hostname = Get-WinSecNavigationDeviceValue `
                            -Device $device `
                            -Property 'Name'
                    }

                    if (-not $hostname) {
                        $hostname = $deviceId
                    }

                    # Save Devices screen before changing context
                    $State = Set-WinSecNavigationScreen `
                        -State $State `
                        -Screen 'MainMenu'

                    # Set active device
                    $State.DeviceIndex = $index
                    $State.SelectedDeviceId = $deviceId
                    $State.SelectedDeviceName = $hostname

                    # Initialize device navigation
                    $State.SectionIndex = 0
                    $State.ControlIndex = 0
                    $State.FindingsOffset = 0
                    $State.FindingsScope = 'Section'

                    # Request device-specific results
                    $State.PendingCommand = 'SelectDevice'
                    $State.PendingScope = 'Device'
                }

                'MainMenu' {

                    if ($SectionCount -gt 0) {

                        $State = Set-WinSecNavigationScreen `
                            -State $State `
                            -Screen 'Section'

                        $State.ControlIndex = 0
                    }
                }
            }
        }

        # ----------------------------------------------------
        # Open security findings
        # ----------------------------------------------------

        'ShowFindings' {

            switch ($State.Screen) {

                'MainMenu' {

                    if ($SectionCount -gt 0) {

                        $State = Set-WinSecNavigationScreen `
                            -State $State `
                            -Screen 'Findings'

                        $State.FindingsScope = 'Section'
                    }
                }

                'Section' {

                    if ($ControlCount -gt 0) {

                        $State = Set-WinSecNavigationScreen `
                            -State $State `
                            -Screen 'Findings'

                        $State.FindingsScope = 'Control'
                    }
                }

                'Results' {

                    if ($ControlCount -gt 0) {

                        $State = Set-WinSecNavigationScreen `
                            -State $State `
                            -Screen 'Findings'

                        $State.FindingsScope = 'Control'
                    }
                }
            }
        }

        # ----------------------------------------------------
        # Scroll through findings
        # ----------------------------------------------------

        'ScrollUp' {

            if ($State.Screen -eq 'Findings') {

                $State.FindingsOffset = [Math]::Max(
                    0,
                    $State.FindingsOffset - 1
                )
            }
        }

        'ScrollDown' {

            if ($State.Screen -eq 'Findings') {

                $maximum = [Math]::Max(
                    0,
                    $FindingCount - 1
                )

                $State.FindingsOffset = [Math]::Min(
                    $maximum,
                    $State.FindingsOffset + 1
                )
            }
        }

        # ----------------------------------------------------
        # Export security report
        # ----------------------------------------------------

        'ExportTXT' {

            switch ($State.Screen) {

                'MainMenu' {

                    if ($SectionCount -gt 0) {

                        $State.PendingCommand = 'ExportTXT'
                        $State.PendingScope = 'Section'
                    }
                }

                'Section' {

                    if ($SectionCount -gt 0) {

                        $State.PendingCommand = 'ExportTXT'
                        $State.PendingScope = 'Section'
                    }
                }

                'Results' {

                    if ($SectionCount -gt 0) {

                        $State.PendingCommand = 'ExportTXT'
                        $State.PendingScope = 'Section'
                    }
                }

                'Findings' {

                    $State.PendingCommand = 'ExportTXT'
                    $State.PendingScope = $State.FindingsScope
                }
            }
        }

        # ----------------------------------------------------
        # Request security rescan
        # ----------------------------------------------------

        'Rescan' {

            if (
                $State.Screen -eq 'MainMenu' -and
                $State.SelectedDeviceId
            ) {

                $State.PendingCommand = 'Rescan'
                $State.PendingScope = 'Device'
            }
        }

        # ----------------------------------------------------
        # Select application setting
        # ----------------------------------------------------

        'Select' {

            if (
                $State.Screen -eq 'Settings' -and
                $SettingsCount -gt 0
            ) {

                $State.PendingCommand = 'SelectSetting'
                $State.PendingScope = 'Settings'
            }
        }

        # ----------------------------------------------------
        # Return to previous screen
        # ----------------------------------------------------

        'Back' {

            if ($State.Screen -ne 'Devices') {

                $State = Restore-WinSecNavigationScreen `
                    -State $State
            }
        }

        # ----------------------------------------------------
        # Exit application
        # ----------------------------------------------------

        'Exit' {

            if ($State.Screen -in @('Devices', 'MainMenu')) {

                $State.ExitRequested = $true

                $State.PendingCommand = 'Exit'
                $State.PendingScope = 'Application'
            }
        }

        default {
            # Ignore unsupported actions
        }
    }

    return $State
}
