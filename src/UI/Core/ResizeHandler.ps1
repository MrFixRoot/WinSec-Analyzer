
# ============================================================
# WinSec Analyzer
# Component : ResizeHandler
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Detects terminal resizing and manages UI redraw events.
# Supports multi-device navigation and adaptive screens.
# ============================================================


# ------------------------------------------------------------
# Initialize terminal resize tracking
# ------------------------------------------------------------

function New-WinSecResizeState {
    [CmdletBinding()]
    param()

    $terminal = Get-WinSecTerminalSize

    return [PSCustomObject]@{
        Width          = [int]$terminal.Width
        Height         = [int]$terminal.Height
        LastResize     = $null
        ResizeCount    = 0
        RedrawRequired = $false
    }
}


# ------------------------------------------------------------
# Detect terminal dimension changes
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

    # Update current terminal dimensions
    $State.Width = $newWidth
    $State.Height = $newHeight

    # Update resize tracking
    $State.LastResize = [DateTime]::UtcNow
    $State.ResizeCount++
    $State.RedrawRequired = $true

    return $true
}


# ------------------------------------------------------------
# Request screen redraw
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
# Reset redraw flag after rendering
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
# Get terminal resize information
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
# Create standardized UI event
# ------------------------------------------------------------

function New-WinSecUIEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Key', 'Resize')]
        [string]$EventType,

        [Parameter(Mandatory)]
        [string]$Screen,

        [AllowNull()]
        [string]$Key = $null,

        [string]$Action = 'None',

        [bool]$ResizeDetected = $false,

        [Parameter(Mandatory)]
        [psobject]$ResizeState
    )

    return [PSCustomObject]@{
        EventType      = $EventType
        Screen         = $Screen
        Key            = $Key
        Action         = $Action
        ResizeDetected = $ResizeDetected
        Width          = $ResizeState.Width
        Height         = $ResizeState.Height
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
            'Devices',
            'MainMenu',
            'Section',
            'Findings',
            'Audit',
            'Results',
            'Settings'
        )]
        [string]$Screen = 'Devices',

        [ValidateRange(25, 1000)]
        [int]$PollIntervalMs = 100
    )

    # --------------------------------------------------------
    # Check non-blocking console input availability
    # --------------------------------------------------------

    $canPollKeyboard = $true

    try {
        $null = [Console]::KeyAvailable
    }
    catch {
        $canPollKeyboard = $false
    }

    # --------------------------------------------------------
    # Fallback for unsupported terminal hosts
    # --------------------------------------------------------

    if (-not $canPollKeyboard) {

        $keyboardEvent = Get-WinSecKeyboardAction `
            -Screen $Screen

        $resized = Test-WinSecTerminalResize `
            -State $ResizeState

        return New-WinSecUIEvent `
            -EventType 'Key' `
            -Screen $Screen `
            -Key $keyboardEvent.Key `
            -Action $keyboardEvent.Action `
            -ResizeDetected $resized `
            -ResizeState $ResizeState
    }

    # --------------------------------------------------------
    # Non-blocking event loop
    # --------------------------------------------------------

    while ($true) {

        # ----------------------------------------------------
        # Detect terminal resizing
        # ----------------------------------------------------

        $resized = Test-WinSecTerminalResize `
            -State $ResizeState

        if ($resized) {

            return New-WinSecUIEvent `
                -EventType 'Resize' `
                -Screen $Screen `
                -Action 'Redraw' `
                -ResizeDetected $true `
                -ResizeState $ResizeState
        }

        # ----------------------------------------------------
        # Detect keyboard input
        # ----------------------------------------------------

        try {

            if ([Console]::KeyAvailable) {

                $keyboardEvent = Get-WinSecKeyboardAction `
                    -Screen $Screen

                return New-WinSecUIEvent `
                    -EventType 'Key' `
                    -Screen $Screen `
                    -Key $keyboardEvent.Key `
                    -Action $keyboardEvent.Action `
                    -ResizeState $ResizeState
            }
        }
        catch {

            # Fallback to blocking keyboard input
            $keyboardEvent = Get-WinSecKeyboardAction `
                -Screen $Screen

            $resized = Test-WinSecTerminalResize `
                -State $ResizeState

            return New-WinSecUIEvent `
                -EventType 'Key' `
                -Screen $Screen `
                -Key $keyboardEvent.Key `
                -Action $keyboardEvent.Action `
                -ResizeDetected $resized `
                -ResizeState $ResizeState
        }

        # ----------------------------------------------------
        # Reduce CPU consumption while waiting
        # ----------------------------------------------------

        Start-Sleep -Milliseconds $PollIntervalMs
    }
}
