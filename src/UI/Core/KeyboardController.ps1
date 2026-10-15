
# ============================================================
# WinSec Analyzer
# Component : KeyboardController
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Handles keyboard input and translates keystrokes
# into navigation actions.
# ============================================================


# ------------------------------------------------------------
# Read keyboard input
# ------------------------------------------------------------

function Read-WinSecKey {
    [CmdletBinding()]
    param()

    try {
        # Native console input
        $keyInfo = [Console]::ReadKey($true)

        return $keyInfo.Key.ToString().ToUpperInvariant()
    }
    catch {
        # PowerShell host fallback
        try {
            $keyInfo = $Host.UI.RawUI.ReadKey(
                'NoEcho,IncludeKeyDown'
            )

            $virtualKey = $keyInfo.VirtualKeyCode

            switch ($virtualKey) {
                38 { return 'UPARROW' }
                40 { return 'DOWNARROW' }
                37 { return 'LEFTARROW' }
                39 { return 'RIGHTARROW' }
                13 { return 'ENTER' }
                27 { return 'ESCAPE' }
                33 { return 'PAGEUP' }
                34 { return 'PAGEDOWN' }
                36 { return 'HOME' }
                35 { return 'END' }
            }

            $character = [string]$keyInfo.Character

            if (-not [string]::IsNullOrEmpty($character)) {
                return $character.ToUpperInvariant()
            }

            return 'UNKNOWN'
        }
        catch {
            throw 'Unable to read keyboard input from this terminal.'
        }
    }
}


# ------------------------------------------------------------
# Resolve keyboard action
# ------------------------------------------------------------

function Get-WinSecKeyAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,

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

    $Key = $Key.ToUpperInvariant()

    # Global navigation keys
    switch ($Key) {

        'UPARROW' {
            if ($Screen -eq 'Findings') {
                return 'ScrollUp'
            }

            if ($Screen -in @(
                'MainMenu',
                'Section',
                'Results',
                'Settings'
            )) {
                return 'MoveUp'
            }
        }

        'DOWNARROW' {
            if ($Screen -eq 'Findings') {
                return 'ScrollDown'
            }

            if ($Screen -in @(
                'MainMenu',
                'Section',
                'Results',
                'Settings'
            )) {
                return 'MoveDown'
            }
        }

        'ESCAPE' {
            if ($Screen -ne 'MainMenu') {
                return 'Back'
            }
        }
    }

    # Screen-specific keyboard actions
    switch ($Screen) {

        'MainMenu' {
            switch ($Key) {
                'ENTER' { return 'Open' }
                'H'     { return 'ShowFindings' }
                'P'     { return 'ExportTXT' }
                'R'     { return 'Rescan' }
                'Q'     { return 'Exit' }
            }
        }

        'Section' {
            switch ($Key) {
                'H' { return 'ShowFindings' }
                'P' { return 'ExportTXT' }
            }
        }

        'Findings' {
            switch ($Key) {
                'P' { return 'ExportTXT' }
            }
        }

        'Audit' {
            # Escape is handled globally.
        }

        'Results' {
            switch ($Key) {
                'H' { return 'ShowFindings' }
                'P' { return 'ExportTXT' }
            }
        }

        'Settings' {
            switch ($Key) {
                'ENTER' { return 'Select' }
            }
        }
    }

    return 'None'
}


# ------------------------------------------------------------
# Get normalized keyboard event
# ------------------------------------------------------------

function Get-WinSecKeyboardAction {
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

    $key = Read-WinSecKey

    $action = Get-WinSecKeyAction `
        -Key $key `
        -Screen $Screen

    return [PSCustomObject]@{
        Screen = $Screen
        Key    = $key
        Action = $action
    }
}
