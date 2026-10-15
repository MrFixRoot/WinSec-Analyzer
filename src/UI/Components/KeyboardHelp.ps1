
# ============================================================
# WinSec Analyzer
# Component : KeyboardHelp
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Context-aware keyboard shortcuts for terminal UI.
# Supports multi-device navigation and adaptive layouts.
# ============================================================


# ------------------------------------------------------------
# Get available shortcuts for current screen
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
        [string]$Screen = 'Devices'
    )

    $shortcuts = switch ($Screen) {

        'Devices' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Navigate' }
                @{ Key = 'ENTER';   Action = 'Select Device' }
                @{ Key = 'Q';       Action = 'Exit' }
            )
        }

        'MainMenu' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Navigate' }
                @{ Key = 'ENTER';   Action = 'Open Section' }
                @{ Key = 'H';       Action = 'Findings' }
                @{ Key = 'P';       Action = 'Export TXT' }
                @{ Key = 'R';       Action = 'Rescan' }
                @{ Key = 'ESC';     Action = 'Devices' }
                @{ Key = 'Q';       Action = 'Exit' }
            )
        }

        'Section' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Navigate' }
                @{ Key = 'H';       Action = 'Findings' }
                @{ Key = 'P';       Action = 'Export TXT' }
                @{ Key = 'ESC';     Action = 'Dashboard' }
            )
        }

        'Findings' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Scroll' }
                @{ Key = 'P';       Action = 'Export TXT' }
                @{ Key = 'ESC';     Action = 'Dashboard' }
            )
        }

        'Audit' {
            @(
                @{ Key = 'ESC'; Action = 'Dashboard' }
            )
        }

        'Results' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Navigate' }
                @{ Key = 'H';       Action = 'Findings' }
                @{ Key = 'P';       Action = 'Export TXT' }
                @{ Key = 'ESC';     Action = 'Dashboard' }
            )
        }

        'Settings' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Navigate' }
                @{ Key = 'ENTER';   Action = 'Select' }
                @{ Key = 'ESC';     Action = 'Dashboard' }
            )
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

        [string[]]$HiddenKeys = @()
    )

    $shortcuts = @(
        Get-WinSecKeyboardShortcuts -Screen $Screen
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
# Calculate keyboard help lines
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

        [int]$Width = 0
    )

    if ($Width -le 0) {
        $Width = (Get-WinSecTerminalSize).ContentWidth
    }

    $Width = [Math]::Max(1, $Width)

    $labels = @(
        Get-WinSecKeyboardLabels `
            -Screen $Screen `
            -HiddenKeys $HiddenKeys
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

        $requiredLength = $currentLength + 3 + $labelLength

        if ($requiredLength -le $Width) {
            $currentLength = $requiredLength
        }
        else {
            $lines++
            $currentLength = $labelLength
        }
    }

    # Blank line + separator + shortcut lines
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

        [string[]]$HiddenKeys = @()
    )

    $terminal = Get-WinSecTerminalSize

    $width = [Math]::Max(
        1,
        $terminal.ContentWidth
    )

    $labels = @(
        Get-WinSecKeyboardLabels `
            -Screen $Screen `
            -HiddenKeys $HiddenKeys
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
