
# ============================================================
# WinSec Analyzer
# Component : KeyboardHelp
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Context-aware keyboard shortcuts displayed in terminal.
# ============================================================


# ------------------------------------------------------------
# Get available keyboard shortcuts by screen
# ------------------------------------------------------------

function Get-WinSecKeyboardShortcuts {
    [CmdletBinding()]
    param(
        [ValidateSet(
            'MainMenu',
            'Section',
            'Findings',
            'Audit',
            'Results',
            'Settings'
        )]
        [string]$Screen = 'MainMenu'
    )

    $shortcuts = switch ($Screen) {

        'MainMenu' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Navigate' }
                @{ Key = 'ENTER';   Action = 'Open' }
                @{ Key = 'H';       Action = 'Findings' }
                @{ Key = 'P';       Action = 'Export TXT' }
                @{ Key = 'R';       Action = 'Rescan' }
                @{ Key = 'Q';       Action = 'Exit' }
            )
        }

        'Section' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Navigate' }
                @{ Key = 'H';       Action = 'Findings' }
                @{ Key = 'P';       Action = 'Export TXT' }
                @{ Key = 'ESC';     Action = 'Main Menu' }
            )
        }

        'Findings' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Scroll' }
                @{ Key = 'P';       Action = 'Export TXT' }
                @{ Key = 'ESC';     Action = 'Back' }
            )
        }

        'Audit' {
            @(
                @{ Key = 'ESC'; Action = 'Back' }
            )
        }

        'Results' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Navigate' }
                @{ Key = 'H';       Action = 'Findings' }
                @{ Key = 'P';       Action = 'Export TXT' }
                @{ Key = 'ESC';     Action = 'Main Menu' }
            )
        }

        'Settings' {
            @(
                @{ Key = 'UP/DOWN'; Action = 'Navigate' }
                @{ Key = 'ENTER';   Action = 'Select' }
                @{ Key = 'ESC';     Action = 'Back' }
            )
        }
    }

    return $shortcuts
}


# ------------------------------------------------------------
# Display keyboard shortcuts
# ------------------------------------------------------------

function Write-WinSecKeyboardHelp {
    [CmdletBinding()]
    param(
        [ValidateSet(
            'MainMenu',
            'Section',
            'Findings',
            'Audit',
            'Results',
            'Settings'
        )]
        [string]$Screen = 'MainMenu',

        [string[]]$HiddenKeys = @()
    )

    $terminal = Get-WinSecTerminalSize
    $width = $terminal.ContentWidth

    $shortcuts = @(
        Get-WinSecKeyboardShortcuts -Screen $Screen
    )

    # Remove shortcuts disabled by the current screen
    $shortcuts = @(
        $shortcuts | Where-Object {
            $_.Key -notin $HiddenKeys
        }
    )

    Write-Host ''
    Write-WinSecDivider -Color DarkGray

    if ($shortcuts.Count -eq 0) {
        return
    }

    # Build shortcut labels
    $items = @(
        foreach ($shortcut in $shortcuts) {
            '[{0}] {1}' -f $shortcut.Key, $shortcut.Action
        }
    )

    $separator = '   '
    $line = ''

    # Wrap shortcut text without breaking individual labels
    foreach ($item in $items) {

        if ([string]::IsNullOrEmpty($line)) {
            $line = $item
            continue
        }

        $candidate = $line + $separator + $item

        if ($candidate.Length -le $width) {
            $line = $candidate
        }
        else {
            Write-WinSecText `
                -Text $line `
                -Color DarkGray

            $line = $item
        }
    }

    if (-not [string]::IsNullOrEmpty($line)) {
        Write-WinSecText `
            -Text $line `
            -Color DarkGray
    }
}
