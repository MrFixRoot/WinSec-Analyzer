
# ============================================================
# WinSec Analyzer
# Component : NavigationController
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Manages multi-device navigation, screen transitions,
# selected items and pending application commands.
# ============================================================


# ------------------------------------------------------------
# Initialize navigation state
# ------------------------------------------------------------

function New-WinSecNavigationState {
    [CmdletBinding()]
    param()

    return [PSCustomObject]@{

        # Initial screen
        Screen = 'Devices'

        # Device selection
        DeviceIndex        = 0
        SelectedDeviceId   = $null
        SelectedDeviceName = $null

        # Security section navigation
        SectionIndex  = 0
        ControlIndex  = 0
        SettingsIndex = 0

        # Findings navigation
        FindingsOffset = 0
        FindingsScope  = 'Section'

        # Application commands
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

    # Circular navigation
    $nextIndex = $CurrentIndex + $Direction

    if ($nextIndex -ge $ItemCount) {
        return 0
    }

    if ($nextIndex -lt 0) {
        return ($ItemCount - 1)
    }

    return $nextIndex
}


# ------------------------------------------------------------
# Read a device property
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
# Change active screen
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
        [string]$Screen
    )

    $State.Screen = $Screen

    if ($Screen -eq 'Findings') {
        $State.FindingsOffset = 0
    }

    return $State
}


# ------------------------------------------------------------
# Process navigation action
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

    # Reset previous command
    $State.PendingCommand = $null
    $State.PendingScope = $null

    if ($State.ExitRequested) {
        return $State
    }

    # Normalize item counts
    $deviceCount = @($Devices).Count

    $SectionCount = [Math]::Max(0, $SectionCount)
    $ControlCount = [Math]::Max(0, $ControlCount)
    $FindingCount = [Math]::Max(0, $FindingCount)
    $SettingsCount = [Math]::Max(0, $SettingsCount)

    switch ($Action) {

        # ----------------------------------------------------
        # Navigate up
        # ----------------------------------------------------

        'MoveUp' {

            switch ($State.Screen) {

                'Devices' {
                    $State.DeviceIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.DeviceIndex `
                        -ItemCount $deviceCount `
                        -Direction -1
                }

                'MainMenu' {
                    $State.SectionIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.SectionIndex `
                        -ItemCount $SectionCount `
                        -Direction -1
                }

                { $_ -in @('Section', 'Results') } {
                    $State.ControlIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.ControlIndex `
                        -ItemCount $ControlCount `
                        -Direction -1
                }

                'Settings' {
                    $State.SettingsIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.SettingsIndex `
                        -ItemCount $SettingsCount `
                        -Direction -1
                }
            }
        }

        # ----------------------------------------------------
        # Navigate down
        # ----------------------------------------------------

        'MoveDown' {

            switch ($State.Screen) {

                'Devices' {
                    $State.DeviceIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.DeviceIndex `
                        -ItemCount $deviceCount `
                        -Direction 1
                }

                'MainMenu' {
                    $State.SectionIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.SectionIndex `
                        -ItemCount $SectionCount `
                        -Direction 1
                }

                { $_ -in @('Section', 'Results') } {
                    $State.ControlIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.ControlIndex `
                        -ItemCount $ControlCount `
                        -Direction 1
                }

                'Settings' {
                    $State.SettingsIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.SettingsIndex `
                        -ItemCount $SettingsCount `
                        -Direction 1
                }
            }
        }

        # ----------------------------------------------------
        # Select device or open section
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

                    $hostname = Get-WinSecNavigationDeviceValue `
                        -Device $device `
                        -Property 'Hostname'

                    if ([string]::IsNullOrWhiteSpace($hostname)) {
                        $hostname = Get-WinSecNavigationDeviceValue `
                            -Device $device `
                            -Property 'Name'
                    }

                    # Require an identifiable registered device
                    if ([string]::IsNullOrWhiteSpace($deviceId)) {
                        break
                    }

                    $State.DeviceIndex = $index
                    $State.SelectedDeviceId = $deviceId
                    $State.SelectedDeviceName = $hostname

                    # Reset security navigation
                    $State.SectionIndex = 0
                    $State.ControlIndex = 0
                    $State.FindingsOffset = 0
                    $State.FindingsScope = 'Section'

                    $State.Screen = 'MainMenu'

                    # Request loading of device-specific data
                    $State.PendingCommand = 'SelectDevice'
                    $State.PendingScope = 'Device'
                }

                'MainMenu' {

                    if ($SectionCount -gt 0) {

                        $State.ControlIndex = 0

                        $State.Screen = 'Section'
                    }
                }
            }
        }

        # ----------------------------------------------------
        # Show findings
        # ----------------------------------------------------

        'ShowFindings' {

            switch ($State.Screen) {

                'MainMenu' {

                    if ($SectionCount -gt 0) {

                        $State.FindingsScope = 'Section'

                        $State = Set-WinSecNavigationScreen `
                            -State $State `
                            -Screen 'Findings'
                    }
                }

                { $_ -in @('Section', 'Results') } {

                    if ($ControlCount -gt 0) {

                        $State.FindingsScope = 'Control'

                        $State = Set-WinSecNavigationScreen `
                            -State $State `
                            -Screen 'Findings'
                    }
                }
            }
        }

        # ----------------------------------------------------
        # Scroll findings
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
        # Export security assessment
        # ----------------------------------------------------

        'ExportTXT' {

            switch ($State.Screen) {

                'MainMenu' {

                    if ($SectionCount -gt 0) {
                        $State.PendingCommand = 'ExportTXT'
                        $State.PendingScope = 'Section'
                    }
                }

                { $_ -in @('Section', 'Results') } {

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
        # Request new assessment
        # ----------------------------------------------------

        'Rescan' {

            if ($State.Screen -eq 'MainMenu') {

                $State.PendingCommand = 'Rescan'
                $State.PendingScope = 'Device'
            }
        }

        # ----------------------------------------------------
        # Select setting
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
        # Return to dashboard or device selection
        # ----------------------------------------------------

        'Back' {

            switch ($State.Screen) {

                'MainMenu' {

                    $State.Screen = 'Devices'

                    # Clear active device context
                    $State.SelectedDeviceId = $null
                    $State.SelectedDeviceName = $null

                    $State.SectionIndex = 0
                    $State.ControlIndex = 0
                }

                'Devices' {
                    # No previous screen
                }

                default {

                    # Return directly to dashboard
                    $State.Screen = 'MainMenu'
                    $State.FindingsOffset = 0
                }
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

        # ----------------------------------------------------
        # Ignore unsupported actions
        # ----------------------------------------------------

        default {
            # No action required
        }
    }

    return $State
}
