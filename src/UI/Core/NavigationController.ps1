
# ============================================================
# WinSec Analyzer
# Component : NavigationController
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Manages UI navigation, screen transitions,
# selected items and navigation commands.
# ============================================================


# ------------------------------------------------------------
# Create navigation state
# ------------------------------------------------------------

function New-WinSecNavigationState {
    [CmdletBinding()]
    param()

    return [PSCustomObject]@{

        # Current screen
        Screen = 'MainMenu'

        # Selected items
        SectionIndex = 0
        ControlIndex = 0
        SettingsIndex = 0

        # Findings navigation
        FindingsOffset = 0
        FindingsScope  = 'Section'

        # Commands to be processed by other modules
        PendingCommand = $null
        PendingScope   = $null

        # Application lifecycle
        ExitRequested = $false
    }
}


# ------------------------------------------------------------
# Calculate selected index
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
# Change active screen
# ------------------------------------------------------------

function Set-WinSecNavigationScreen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [ValidateSet(
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

    if ($Screen -eq 'MainMenu') {
        $State.FindingsOffset = 0
    }

    if ($Screen -eq 'Findings') {
        $State.FindingsOffset = 0
    }

    return $State
}


# ------------------------------------------------------------
# Process keyboard navigation action
# ------------------------------------------------------------

function Invoke-WinSecNavigationAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [string]$Action,

        [int]$SectionCount = 0,

        [int]$ControlCount = 0,

        [int]$FindingCount = 0,

        [int]$SettingsCount = 0
    )

    # Reset previous pending command
    $State.PendingCommand = $null
    $State.PendingScope = $null

    if ($State.ExitRequested) {
        return $State
    }

    # Normalize item counts
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

                'MainMenu' {
                    $State.SectionIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.SectionIndex `
                        -ItemCount $SectionCount `
                        -Direction -1
                }

                'Section' {
                    $State.ControlIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.ControlIndex `
                        -ItemCount $ControlCount `
                        -Direction -1
                }

                'Results' {
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

                'MainMenu' {
                    $State.SectionIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.SectionIndex `
                        -ItemCount $SectionCount `
                        -Direction 1
                }

                'Section' {
                    $State.ControlIndex = Get-WinSecNextIndex `
                        -CurrentIndex $State.ControlIndex `
                        -ItemCount $ControlCount `
                        -Direction 1
                }

                'Results' {
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
        # Open selected section
        # ----------------------------------------------------

        'Open' {

            if (
                $State.Screen -eq 'MainMenu' -and
                $SectionCount -gt 0
            ) {
                $State.ControlIndex = 0

                $State = Set-WinSecNavigationScreen `
                    -State $State `
                    -Screen 'Section'
            }
        }

        # ----------------------------------------------------
        # Show security findings
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

                'Section' {

                    if ($ControlCount -gt 0) {

                        $State.FindingsScope = 'Control'

                        $State = Set-WinSecNavigationScreen `
                            -State $State `
                            -Screen 'Findings'
                    }
                }

                'Results' {

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
        # Scroll findings up
        # ----------------------------------------------------

        'ScrollUp' {

            if ($State.Screen -eq 'Findings') {

                $State.FindingsOffset = [Math]::Max(
                    0,
                    $State.FindingsOffset - 1
                )
            }
        }

        # ----------------------------------------------------
        # Scroll findings down
        # ----------------------------------------------------

        'ScrollDown' {

            if ($State.Screen -eq 'Findings') {

                $maxOffset = [Math]::Max(
                    0,
                    $FindingCount - 1
                )

                $State.FindingsOffset = [Math]::Min(
                    $maxOffset,
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

                'Findings' {

                    $State.PendingCommand = 'ExportTXT'
                    $State.PendingScope = $State.FindingsScope
                }

                'Results' {

                    $State.PendingCommand = 'ExportTXT'
                    $State.PendingScope = 'Section'
                }
            }
        }

        # ----------------------------------------------------
        # Request new security assessment
        # ----------------------------------------------------

        'Rescan' {

            if ($State.Screen -eq 'MainMenu') {

                $State.PendingCommand = 'Rescan'
                $State.PendingScope = 'All'
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
        # Return to main dashboard
        # ----------------------------------------------------

        'Back' {

            if ($State.Screen -ne 'MainMenu') {

                $State = Set-WinSecNavigationScreen `
                    -State $State `
                    -Screen 'MainMenu'
            }
        }

        # ----------------------------------------------------
        # Exit application
        # ----------------------------------------------------

        'Exit' {

            if ($State.Screen -eq 'MainMenu') {

                $State.ExitRequested = $true
                $State.PendingCommand = 'Exit'
                $State.PendingScope = 'Application'
            }
        }

        # ----------------------------------------------------
        # Ignore unknown keyboard actions
        # ----------------------------------------------------

        default {
            # No navigation action required
        }
    }

    return $State
}
