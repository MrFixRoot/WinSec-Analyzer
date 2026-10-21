
# ============================================================
# WinSec Analyzer
# Component : KeyboardHelp
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Context-aware keyboard shortcuts for the terminal UI.
#
# Supports:
# - Multi-device navigation
# - Screen history navigation
# - Adaptive terminal layouts
# - Conditional availability of commands
# ============================================================


# ------------------------------------------------------------
# Get available keyboard shortcuts
# ------------------------------------------------------------

function Get-WinSecKeyboardShortcuts {
    [CmdletBinding()]
    param(
        [ValidateSet(
            'Devices',
            'MainMenu',
            'Section',
            'Findings',
            'Audit',
            'Results',
            'Settings'
        )]
        [string]$Screen = 'Devices',

        [switch]$EnableExport,

        [switch]$EnableRescan,

        [switch]$EnableSettingsEdit
    )

    $shortcuts = switch ($Screen) {

        # ----------------------------------------------------
        # Device selection
        # ----------------------------------------------------

        'Devices' {
            @(
                @{
                    Key    = 'UP/DOWN'
                    Action = 'Navigate'
                }
                @{
                    Key    = 'ENTER'
                    Action = 'Select Device'
                }
                @{ Key = 'F2'; Action = 'Rename Device' }
                @{
                    Key    = 'DEL/SUPR'
                    Action = 'Delete Device'
                }
                @{
                    Key    = 'Q'
                    Action = 'Exit'
                }
            )
        }

        # ----------------------------------------------------
        # Main dashboard
        # ----------------------------------------------------

        'MainMenu' {

            $items = @(
                @{
                    Key    = 'UP/DOWN'
                    Action = 'Navigate'
                }
                @{
                    Key    = 'ENTER'
                    Action = 'Open Section'
                }
                @{
                    Key    = 'F'
                    Action = 'Open Findings'
                }
            )

            if ($EnableRescan) {
                $items += @{
                    Key    = 'R'
                    Action = 'Rescan'
                }
            }

            $items += @(
                @{
                    Key    = 'ESC'
                    Action = 'Back'
                }
                @{
                    Key    = 'Q'
                    Action = 'Exit'
                }
            )

            $items
        }

        # ----------------------------------------------------
        # Security section
        # ----------------------------------------------------

        'Section' {

            $items = @(
                @{
                    Key    = 'UP/DOWN'
                    Action = 'Navigate'
                }
                @{
                    Key    = 'F'
                    Action = 'Open Findings'
                }
            )

            $items += @{
                Key    = 'ESC'
                Action = 'Back'
            }

            $items
        }

        # ----------------------------------------------------
        # Security findings
        # ----------------------------------------------------

        'Findings' {

            $items = @(
                @{
                    Key    = 'UP/DOWN'
                    Action = 'Scroll'
                }
            )

            if ($EnableExport) {
                $items += @{
                    Key    = 'P'
                    Action = 'Export MD'
                }
            }

            $items += @{
                Key    = 'ESC'
                Action = 'Back'
            }

            $items
        }

        # ----------------------------------------------------
        # Audit progress
        # ----------------------------------------------------

        'Audit' {
            @(
                @{
                    Key    = 'ESC'
                    Action = 'Back'
                }
            )
        }

        # ----------------------------------------------------
        # Assessment results
        # ----------------------------------------------------

        'Results' {

            $items = @(
                @{
                    Key    = 'UP/DOWN'
                    Action = 'Navigate'
                }
                @{
                    Key    = 'F'
                    Action = 'Open Findings'
                }
            )

            $items += @{
                Key    = 'ESC'
                Action = 'Back'
            }

            $items
        }

        # ----------------------------------------------------
        # Application settings
        # ----------------------------------------------------

        'Settings' {

            $items = @(
                @{
                    Key    = 'UP/DOWN'
                    Action = 'Navigate'
                }
            )

            if ($EnableSettingsEdit) {
                $items += @{
                    Key    = 'ENTER'
                    Action = 'Select'
                }
            }

            $items += @{
                Key    = 'ESC'
                Action = 'Back'
            }

            $items
        }
    }

    return @($shortcuts)
}


# ------------------------------------------------------------
# Build shortcut labels
# ------------------------------------------------------------

function Get-WinSecKeyboardLabels {
    [CmdletBinding()]
    param(
        [ValidateSet(
            'Devices',
            'MainMenu',
            'Section',
            'Findings',
            'Audit',
            'Results',
            'Settings'
        )]
        [string]$Screen = 'Devices',

        [string[]]$HiddenKeys = @(),

        [switch]$EnableExport,

        [switch]$EnableRescan,

        [switch]$EnableSettingsEdit
    )

    $shortcuts = @(
        Get-WinSecKeyboardShortcuts `
            -Screen $Screen `
            -EnableExport:$EnableExport `
            -EnableRescan:$EnableRescan `
            -EnableSettingsEdit:$EnableSettingsEdit
    )

    $labels = @(
        foreach ($shortcut in $shortcuts) {

            if ($shortcut.Key -in $HiddenKeys) {
                continue
            }

            '[{0}] {1}' -f `
                $shortcut.Key,
                $shortcut.Action
        }
    )

    return $labels
}


# ------------------------------------------------------------
# Calculate keyboard help height
# ------------------------------------------------------------

function Get-WinSecKeyboardHelpHeight {
    [CmdletBinding()]
    param(
        [ValidateSet(
            'Devices',
            'MainMenu',
            'Section',
            'Findings',
            'Audit',
            'Results',
            'Settings'
        )]
        [string]$Screen = 'Devices',

        [string[]]$HiddenKeys = @(),

        [int]$Width = 0,

        [switch]$EnableExport,

        [switch]$EnableRescan,

        [switch]$EnableSettingsEdit
    )

    if ($Width -le 0) {
        $Width = (Get-WinSecTerminalSize).ContentWidth
    }

    $Width = [Math]::Max(1, $Width)

    $labels = @(
        Get-WinSecKeyboardLabels `
            -Screen $Screen `
            -HiddenKeys $HiddenKeys `
            -EnableExport:$EnableExport `
            -EnableRescan:$EnableRescan `
            -EnableSettingsEdit:$EnableSettingsEdit
    )

    if ($labels.Count -eq 0) {
        return 0
    }

    $lines = 1
    $currentLength = 0

    foreach ($label in $labels) {

        $labelLength = $label.Length

        if ($currentLength -eq 0) {
            $currentLength = $labelLength
            continue
        }

        $nextLength = $currentLength + 3 + $labelLength

        if ($nextLength -le $Width) {

            $currentLength = $nextLength
        }
        else {

            $lines++
            $currentLength = $labelLength
        }
    }

    # Blank line + divider + shortcut lines
    return (2 + $lines)
}


# ------------------------------------------------------------
# Render contextual keyboard help
# ------------------------------------------------------------

function Write-WinSecKeyboardHelp {
    [CmdletBinding()]
    param(
        [ValidateSet(
            'Devices',
            'MainMenu',
            'Section',
            'Findings',
            'Audit',
            'Results',
            'Settings'
        )]
        [string]$Screen = 'Devices',

        [string[]]$HiddenKeys = @(),

        [switch]$EnableExport,

        [switch]$EnableRescan,

        [switch]$EnableSettingsEdit
    )

    $terminal = Get-WinSecTerminalSize

    $width = [Math]::Max(
        1,
        $terminal.ContentWidth
    )

    $labels = @(
        Get-WinSecKeyboardLabels `
            -Screen $Screen `
            -HiddenKeys $HiddenKeys `
            -EnableExport:$EnableExport `
            -EnableRescan:$EnableRescan `
            -EnableSettingsEdit:$EnableSettingsEdit
    )

    if ($labels.Count -eq 0) {
        return
    }

    Write-Host ''

    Write-WinSecDivider -Color DarkGray

    $separator = '   '
    $line = ''

    foreach ($label in $labels) {

        if ([string]::IsNullOrEmpty($line)) {
            $line = $label
            continue
        }

        $candidate = $line + $separator + $label

        if ($candidate.Length -le $width) {

            $line = $candidate
        }
        else {

            Write-WinSecText `
                -Text $line `
                -Color DarkGray

            $line = $label
        }
    }

    if (-not [string]::IsNullOrEmpty($line)) {

        Write-WinSecText `
            -Text $line `
            -Color DarkGray
    }
}
