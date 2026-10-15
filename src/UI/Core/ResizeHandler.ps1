
# ============================================================
# WinSec Analyzer
# Component : ResizeHandler
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Detects terminal resizing and requests UI redraws.
# Works with TerminalRenderer and KeyboardController.
# ============================================================


# ------------------------------------------------------------
# Initialize terminal resize tracking
# ------------------------------------------------------------

function New-WinSecResizeState {
    [CmdletBinding()]
    param()

    $terminal = Get-WinSecTerminalSize

    return [PSCustomObject]@{
        Width         = [int]$terminal.Width
        Height        = [int]$terminal.Height
        LastResize    = [DateTime]::UtcNow
        ResizeCount   = 0
        RedrawRequired = $false
    }
}


# ------------------------------------------------------------
# Check whether terminal dimensions changed
# ------------------------------------------------------------

function Test-WinSecTerminalResize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State
    )

    $terminal = Get-WinSecTerminalSize

    $newWidth  = [int]$terminal.Width
    $newHeight = [int]$terminal.Height

    $changed = (
        $newWidth -ne $State.Width -or
        $newHeight -ne $State.Height
    )

    if (-not $changed) {
        return $false
    }

    $State.Width = $newWidth
    $State.Height = $newHeight

    $State.LastResize = [DateTime]::UtcNow
    $State.ResizeCount++
    $State.RedrawRequired = $true

    return $true
}


# ------------------------------------------------------------
# Request UI redraw
# ------------------------------------------------------------

function Request-WinSecRedraw {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State
    )

    $State.RedrawRequired = $true
}


# ------------------------------------------------------------
# Clear redraw request after rendering
# ------------------------------------------------------------

function Reset-WinSecRedraw {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State
    )

    $State.RedrawRequired = $false
}


# ------------------------------------------------------------
# Get current terminal resize information
# ------------------------------------------------------------

function Get-WinSecResizeInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State
    )

    return [PSCustomObject]@{
        Width          = $State.Width
        Height         = $State.Height
        ResizeCount    = $State.ResizeCount
        LastResize     = $State.LastResize
        RedrawRequired = $State.RedrawRequired
    }
}


# ------------------------------------------------------------
# Wait for keyboard input or terminal resize
# ------------------------------------------------------------

function Wait-WinSecUIEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$ResizeState,

        [ValidateSet(
            'MainMenu',
            'Section',
            'Findings',
            'Audit',
            'Results',
            'Settings'
        )]
        [string]$Screen = 'MainMenu',

        [ValidateRange(25, 1000)]
        [int]$PollIntervalMs = 100
    )

    # Determine whether non-blocking keyboard polling
    # is supported by the current PowerShell host.

    $canPollKeyboard = $true

    try {
        $null = [Console]::KeyAvailable
    }
    catch {
        $canPollKeyboard = $false
    }

    # Fallback for terminals that cannot poll input.
    # In this mode resizing is detected after a keypress.

    if (-not $canPollKeyboard) {

        $keyboardEvent = Get-WinSecKeyboardAction `
            -Screen $Screen

        $resized = Test-WinSecTerminalResize `
            -State $ResizeState

        return [PSCustomObject]@{
            EventType      = 'Key'
            Screen         = $Screen
            Key            = $keyboardEvent.Key
            Action         = $keyboardEvent.Action
            ResizeDetected = $resized
            Width          = $ResizeState.Width
            Height         = $ResizeState.Height
        }
    }

    # Non-blocking event loop.
    # Detect both resizing and keyboard actions.

    while ($true) {

        # Check for terminal dimension changes.

        $resized = Test-WinSecTerminalResize `
            -State $ResizeState

        if ($resized) {

            return [PSCustomObject]@{
                EventType      = 'Resize'
                Screen         = $Screen
                Key            = $null
                Action         = 'Redraw'
                ResizeDetected = $true
                Width          = $ResizeState.Width
                Height         = $ResizeState.Height
            }
        }

        # Check keyboard input without blocking.

        try {
            if ([Console]::KeyAvailable) {

                $keyboardEvent = Get-WinSecKeyboardAction `
                    -Screen $Screen

                return [PSCustomObject]@{
                    EventType      = 'Key'
                    Screen         = $Screen
                    Key            = $keyboardEvent.Key
                    Action         = $keyboardEvent.Action
                    ResizeDetected = $false
                    Width          = $ResizeState.Width
                    Height         = $ResizeState.Height
                }
            }
        }
        catch {

            # Switch to blocking keyboard input when
            # the terminal does not support polling.

            $keyboardEvent = Get-WinSecKeyboardAction `
                -Screen $Screen

            $resized = Test-WinSecTerminalResize `
                -State $ResizeState

            return [PSCustomObject]@{
                EventType      = 'Key'
                Screen         = $Screen
                Key            = $keyboardEvent.Key
                Action         = $keyboardEvent.Action
                ResizeDetected = $resized
                Width          = $ResizeState.Width
                Height         = $ResizeState.Height
            }
        }

        # Reduce CPU usage while waiting for events.

        Start-Sleep -Milliseconds $PollIntervalMs
    }
}
