
# ============================================================
# WinSec Analyzer
# Component : KeyboardController
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Captures keyboard input and translates keystrokes
# into UI navigation actions.
#
# Supports multi-device navigation.
# ============================================================


# ------------------------------------------------------------
# Read keyboard input
# ------------------------------------------------------------

function Read-WinSecKey {
    [CmdletBinding()]
    param()

    try {

        # Read keyboard input without displaying characters.
        $keyInfo = [Console]::ReadKey($true)

        return $keyInfo.Key.ToString().ToUpperInvariant()
    }
    catch {

        # Fallback for PowerShell hosts without direct
        # console keyboard support.

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

    $Key = $Key.ToUpperInvariant()

    # --------------------------------------------------------
    # Global navigation controls
    # --------------------------------------------------------

    switch ($Key) {

        'UPARROW' {

            if ($Screen -eq 'Findings') {
                return 'ScrollUp'
            }

            if ($Screen -in @(
                'Devices',
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
                'Devices',
                'MainMenu',
                'Section',
                'Results',
                'Settings'
            )) {
                return 'MoveDown'
            }
        }

        'ESCAPE' {

            if ($Screen -ne 'Devices') {
                return 'Back'
            }
        }
    }

    # --------------------------------------------------------
    # Screen-specific keyboard controls
    # --------------------------------------------------------

    switch ($Screen) {

        # ----------------------------------------------------
        # Device selection screen
        # ----------------------------------------------------

        'Devices' {

            switch ($Key) {

                'ENTER' {
                    return 'Open'
                }

                'Q' {
                    return 'Exit'
                }
            }
        }

        # ----------------------------------------------------
        # Main security dashboard
        # ----------------------------------------------------

        'MainMenu' {

            switch ($Key) {

                'ENTER' {
                    return 'Open'
                }

                'H' {
                    return 'ShowFindings'
                }

                'P' {
                    return 'ExportTXT'
                }

                'R' {
                    return 'Rescan'
                }

                'Q' {
                    return 'Exit'
                }
            }
        }

        # ----------------------------------------------------
        # Security section
        # ----------------------------------------------------

        'Section' {

            switch ($Key) {

                'H' {
                    return 'ShowFindings'
                }

                'P' {
                    return 'ExportTXT'
                }
            }
        }

        # ----------------------------------------------------
        # Findings details
        # ----------------------------------------------------

        'Findings' {

            switch ($Key) {

                'P' {
                    return 'ExportTXT'
                }
            }
        }

        # ----------------------------------------------------
        # Audit progress
        # ----------------------------------------------------

        'Audit' {

            # Escape is handled by global navigation.
            # Audit cancellation is not implemented here.
        }

        # ----------------------------------------------------
        # Security results
        # ----------------------------------------------------

        'Results' {

            switch ($Key) {

                'H' {
                    return 'ShowFindings'
                }

                'P' {
                    return 'ExportTXT'
                }
            }
        }

        # ----------------------------------------------------
        # Application settings
        # ----------------------------------------------------

        'Settings' {

            switch ($Key) {

                'ENTER' {
                    return 'Select'
                }
            }
        }
    }

    # Ignore unsupported keyboard input
    return 'None'
}


# ------------------------------------------------------------
# Generate normalized keyboard event
# ------------------------------------------------------------

function Get-WinSecKeyboardAction {
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
