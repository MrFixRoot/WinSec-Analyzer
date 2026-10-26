
# ============================================================
# WinSec Analyzer
# Component : KeyboardController
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Centralized keyboard input interpretation.
#
# Features:
# - Arrow key navigation
# - Enter selection
# - ESC navigation history
# - Context-aware shortcuts
# - Optional export and rescan commands
# - Protection against unintended modifier shortcuts
# - PowerShell 5.1+ compatibility
#
# This component does not read keyboard input directly.
# ResizeHandler is responsible for input polling.
# ============================================================


# ------------------------------------------------------------
# Get supported keyboard action for a screen
# ------------------------------------------------------------

function Test-WinSecKeyboardActionAllowed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'Devices',
            'MainMenu',
            'Section',
            'Results',
            'Findings',
            'Audit',
            'Settings'
        )]
        [string]$Screen,

        [Parameter(Mandatory)]
        [ValidateSet(
            'MoveUp',
            'MoveDown',
            'ScrollUp',
            'ScrollDown',
            'Open',
            'Select',
            'Back',
            'Exit',
            'ShowFindings',
            'ExportMD',
            'DeleteDevice',
            'RenameDevice',
            'Rescan'
        )]
        [string]$Action,

        [switch]$EnableExport,

        [switch]$EnableRescan,

        [switch]$EnableSettingsEdit
    )

    switch ($Action) {
        'DeleteDevice' { return ($Screen -ceq 'Devices') }
        'RenameDevice' { return ($Screen -ceq 'Devices') }

        # ----------------------------------------------------
        # List navigation
        # ----------------------------------------------------

        'MoveUp' {

            return (
                $Screen -in @(
                    'Devices',
                    'MainMenu',
                    'Section',
                    'Results',
                    'Settings'
                )
            )
        }

        'MoveDown' {

            return (
                $Screen -in @(
                    'Devices',
                    'MainMenu',
                    'Section',
                    'Results',
                    'Settings'
                )
            )
        }

        # ----------------------------------------------------
        # Finding navigation
        # ----------------------------------------------------

        'ScrollUp' {
            return ($Screen -eq 'Findings')
        }

        'ScrollDown' {
            return ($Screen -eq 'Findings')
        }

        # ----------------------------------------------------
        # Selection
        # ----------------------------------------------------

        'Open' {

            return (
                $Screen -in @(
                    'Devices',
                    'MainMenu'
                )
            )
        }

        'Select' {

            return (
                $Screen -eq 'Settings' -and
                [bool]$EnableSettingsEdit
            )
        }

        # ----------------------------------------------------
        # Navigation history
        # ----------------------------------------------------

        'Back' {

            return (
                $Screen -ne 'Devices'
            )
        }

        # ----------------------------------------------------
        # Application exit
        # ----------------------------------------------------

        'Exit' {

            return (
                $Screen -in @(
                    'Devices',
                    'MainMenu'
                )
            )
        }

        # ----------------------------------------------------
        # Security findings
        # ----------------------------------------------------

        'ShowFindings' {

            return (
                $Screen -in @(
                    'MainMenu',
                    'Section',
                    'Results'
                )
            )
        }

        # ----------------------------------------------------
        # Report export
        # ----------------------------------------------------

        'ExportMD' {
            return ([bool]$EnableExport -and $Screen -eq 'Findings')
        }

        # ----------------------------------------------------
        # Security rescan
        # ----------------------------------------------------

        'Rescan' {

            return (
                [bool]$EnableRescan -and
                $Screen -in @('Devices','MainMenu','Section','Results')
            )
        }
    }

    return $false
}


# ------------------------------------------------------------
# Convert raw keyboard information into an action
# ------------------------------------------------------------

function ConvertTo-WinSecKeyboardAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$KeyInfo,

        [Parameter(Mandatory)]
        [ValidateSet(
            'Devices',
            'MainMenu',
            'Section',
            'Results',
            'Findings',
            'Audit',
            'Settings'
        )]
        [string]$Screen,

        [switch]$EnableExport,

        [switch]$EnableRescan,

        [switch]$EnableSettingsEdit
    )

    # --------------------------------------------------------
    # Ignore key release events
    # --------------------------------------------------------

    $keyDownProperty = $KeyInfo.PSObject.Properties[
        'KeyDown'
    ]

    if (
        $null -ne $keyDownProperty -and
        $keyDownProperty.Value -eq $false
    ) {
        return 'None'
    }

    # --------------------------------------------------------
    # Ignore Ctrl and Alt combinations
    # --------------------------------------------------------

    $modifierProperty = $KeyInfo.PSObject.Properties[
        'ControlKeyState'
    ]

    if ($null -ne $modifierProperty) {

        $modifierState = 0

        try {
            $modifierState = [int]$modifierProperty.Value
        }
        catch {
            return 'None'
        }

        # ControlKeyStates flags:
        # 0x01 = RightAltPressed
        # 0x02 = LeftAltPressed
        # 0x04 = RightCtrlPressed
        # 0x08 = LeftCtrlPressed

        if (($modifierState -band 0x0F) -ne 0) {
            return 'None'
        }
    }

    # --------------------------------------------------------
    # Read virtual key code
    # --------------------------------------------------------

    $virtualKey = 0

    $virtualKeyProperty = $KeyInfo.PSObject.Properties[
        'VirtualKeyCode'
    ]

    if ($null -ne $virtualKeyProperty) {

        try {
            $virtualKey = [int]$virtualKeyProperty.Value
        }
        catch {
            return 'None'
        }
    }

    $action = 'None'

    # --------------------------------------------------------
    # Interpret navigation keys
    # --------------------------------------------------------

    switch ($virtualKey) {

        # Up Arrow
        38 {

            if ($Screen -eq 'Findings') {
                $action = 'ScrollUp'
            }
            else {
                $action = 'MoveUp'
            }
        }

        # Down Arrow
        40 {

            if ($Screen -eq 'Findings') {
                $action = 'ScrollDown'
            }
            else {
                $action = 'MoveDown'
            }
        }

        # Enter
        13 {

            if ($Screen -eq 'Settings') {
                $action = 'Select'
            }
            else {
                $action = 'Open'
            }
        }

        # Escape
        27 {
            $action = 'Back'
        }

        # Delete / Supr (VK_DELETE)
        113 { $action = 'RenameDevice' }
        46 {
            $action = 'DeleteDevice'
        }
    }

    # --------------------------------------------------------
    # Interpret character shortcuts
    # --------------------------------------------------------

    if ($action -eq 'None') {

        $character = ''

        $characterProperty = $KeyInfo.PSObject.Properties[
            'Character'
        ]

        if ($null -ne $characterProperty) {

            $character = [string](
                $characterProperty.Value
            )
        }

        if (-not [string]::IsNullOrEmpty($character)) {

            switch ($character.ToUpperInvariant()) {

                'Q' {
                    $action = 'Exit'
                }

                'F' {
                    $action = 'ShowFindings'
                }

                'P' {
                    $action = 'ExportMD'
                }

                'R' {
                    $action = 'Rescan'
                }
            }
        }
    }

    # --------------------------------------------------------
    # Reject unsupported keys
    # --------------------------------------------------------

    if ($action -eq 'None') {
        return 'None'
    }

    # --------------------------------------------------------
    # Validate action for the current screen
    # --------------------------------------------------------

    $allowed = Test-WinSecKeyboardActionAllowed `
        -Screen $Screen `
        -Action $action `
        -EnableExport:$EnableExport `
        -EnableRescan:$EnableRescan `
        -EnableSettingsEdit:$EnableSettingsEdit

    if (-not $allowed) {
        return 'None'
    }

    return $action
}


# ------------------------------------------------------------
# Get keyboard action and its execution context
# ------------------------------------------------------------

function Get-WinSecKeyboardAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$KeyInfo,

        [Parameter(Mandatory)]
        [ValidateSet(
            'Devices',
            'MainMenu',
            'Section',
            'Results',
            'Findings',
            'Audit',
            'Settings'
        )]
        [string]$Screen,

        [switch]$EnableExport,

        [switch]$EnableRescan,

        [switch]$EnableSettingsEdit
    )

    $action = ConvertTo-WinSecKeyboardAction `
        -KeyInfo $KeyInfo `
        -Screen $Screen `
        -EnableExport:$EnableExport `
        -EnableRescan:$EnableRescan `
        -EnableSettingsEdit:$EnableSettingsEdit

    $requiresRedraw = (
        $action -ne 'None'
    )

    $isNavigation = (
        $action -in @(
            'MoveUp',
            'MoveDown',
            'ScrollUp',
            'ScrollDown',
            'Open',
            'Select',
            'Back',
            'ShowFindings'
        )
    )

    $isCommand = (
        $action -in @(
            'Exit',
            'ExportMD',
            'DeleteDevice',
            'RenameDevice',
            'Rescan'
        )
    )

    return [PSCustomObject]@{
        Action         = $action
        Screen         = $Screen
        RequiresRedraw = $requiresRedraw
        IsNavigation   = $isNavigation
        IsCommand      = $isCommand
    }
}


# ------------------------------------------------------------
# Test keyboard controller configuration
# ------------------------------------------------------------

function Test-WinSecKeyboardController {
    [CmdletBinding()]
    param()

    $tests = @(
        @{
            Name   = 'Up arrow on Devices'
            Screen = 'Devices'
            Code   = 38
            Char   = [char]0
            Expect = 'MoveUp'
        }

        @{
            Name   = 'Down arrow on Findings'
            Screen = 'Findings'
            Code   = 40
            Char   = [char]0
            Expect = 'ScrollDown'
        }

        @{
            Name   = 'Enter on MainMenu'
            Screen = 'MainMenu'
            Code   = 13
            Char   = [char]13
            Expect = 'Open'
        }

        @{
            Name   = 'ESC on Findings'
            Screen = 'Findings'
            Code   = 27
            Char   = [char]27
            Expect = 'Back'
        }

        @{
            Name   = 'ESC on Devices'
            Screen = 'Devices'
            Code   = 27
            Char   = [char]27
            Expect = 'None'
        }

        @{
            Name   = 'F on Section'
            Screen = 'Section'
            Code   = 70
            Char   = [char]'F'
            Expect = 'ShowFindings'
        }

        @{
            Name   = 'Q on Devices'
            Screen = 'Devices'
            Code   = 81
            Char   = [char]'Q'
            Expect = 'Exit'
        }

        @{
            Name   = 'P disabled'
            Screen = 'Findings'
            Code   = 80
            Char   = [char]'P'
            Expect = 'None'
        }

        @{
            Name   = 'R disabled'
            Screen = 'MainMenu'
            Code   = 82
            Char   = [char]'R'
            Expect = 'None'
        }
    )

    $results = @(
        foreach ($test in $tests) {

            $keyInfo = [PSCustomObject]@{
                VirtualKeyCode  = $test.Code
                Character       = $test.Char
                ControlKeyState = 0
                KeyDown         = $true
            }

            $actual = ConvertTo-WinSecKeyboardAction `
                -KeyInfo $keyInfo `
                -Screen $test.Screen

            [PSCustomObject]@{
                Test     = $test.Name
                Expected = $test.Expect
                Actual   = $actual
                Passed   = ($actual -eq $test.Expect)
            }
        }
    )

    return $results
}
