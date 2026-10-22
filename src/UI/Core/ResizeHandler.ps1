
# ============================================================
# WinSec Analyzer
# Component : ResizeHandler
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Detects terminal resizing and requests screen redraws.
#
# Features:
# - Dynamic terminal size detection
# - Automatic redraw support
# - Navigation state preservation
# - Non-blocking keyboard polling
# - PowerShell 5.1+ compatibility
#
# This component does not modify terminal dimensions.
# ============================================================


# ------------------------------------------------------------
# Get current terminal dimensions
# ------------------------------------------------------------

function Get-WinSecResizeSnapshot {
    [CmdletBinding()]
    param()

    try {

        $terminal = Get-WinSecTerminalSize

        if ($null -eq $terminal) {
            throw 'Terminal dimensions are unavailable.'
        }

        $width = [int]$terminal.Width
        $height = [int]$terminal.Height

        if ($width -le 0 -or $height -le 0) {
            throw 'Invalid terminal dimensions.'
        }

        $contentWidth = [int]$terminal.ContentWidth

        if ($contentWidth -le 0) {
            $contentWidth = [Math]::Max(
                1,
                $width - 2
            )
        }

        return [PSCustomObject]@{
            Width        = $width
            Height       = $height
            ContentWidth = $contentWidth
        }
    }
    catch {

        throw (
            'Unable to determine terminal size: {0}' -f `
                $_.Exception.Message
        )
    }
}


# ------------------------------------------------------------
# Initialize resize tracking state
# ------------------------------------------------------------

function New-WinSecResizeState {
    [CmdletBinding()]
    param()

    $snapshot = Get-WinSecResizeSnapshot

    return [PSCustomObject]@{

        Width = $snapshot.Width

        Height = $snapshot.Height

        ContentWidth = $snapshot.ContentWidth

        # Avoid recursive rendering
        IsRendering = $false

        # Resize tracking
        ResizeCount = 0

        LastResizeUTC = $null

        # Last successful redraw
        LastRenderUTC = $null
    }
}


# ------------------------------------------------------------
# Detect terminal dimension changes
# ------------------------------------------------------------

function Test-WinSecTerminalResize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$ResizeState
    )

    $snapshot = Get-WinSecResizeSnapshot

    $changed = (
        $snapshot.Width -ne $ResizeState.Width -or
        $snapshot.Height -ne $ResizeState.Height -or
        $snapshot.ContentWidth -ne $ResizeState.ContentWidth
    )

    return [bool]$changed
}


# ------------------------------------------------------------
# Synchronize stored terminal dimensions
# ------------------------------------------------------------

function Update-WinSecResizeState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$ResizeState,

        [AllowNull()]
        [psobject]$Snapshot = $null
    )

    if ($null -eq $Snapshot) {
        $Snapshot = Get-WinSecResizeSnapshot
    }

    $ResizeState.Width = [int]$Snapshot.Width

    $ResizeState.Height = [int]$Snapshot.Height

    $ResizeState.ContentWidth = [int]$Snapshot.ContentWidth

    return $ResizeState
}


# ------------------------------------------------------------
# Handle a detected resize and redraw active screen
# ------------------------------------------------------------

function Invoke-WinSecResizeHandler {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$ResizeState,

        [Parameter(Mandatory)]
        [scriptblock]$RenderAction,

        [AllowNull()]
        [psobject]$NavigationState = $null,

        [switch]$Force
    )

    # --------------------------------------------------------
    # Prevent recursive or overlapping redraw requests
    # --------------------------------------------------------

    if ($ResizeState.IsRendering) {
        return $false
    }

    $snapshot = Get-WinSecResizeSnapshot

    # --------------------------------------------------------
    # Compare current size with previous dimensions
    # --------------------------------------------------------

    $resized = (
        $snapshot.Width -ne $ResizeState.Width -or
        $snapshot.Height -ne $ResizeState.Height -or
        $snapshot.ContentWidth -ne $ResizeState.ContentWidth
    )

    if (-not $resized -and -not $Force) {
        return $false
    }

    # --------------------------------------------------------
    # Request screen redraw
    # --------------------------------------------------------

    $ResizeState.IsRendering = $true

    try {

        # RenderAction receives the existing navigation
        # state, preserving the current user selection.
        #
        # Screens must obtain their new dimensions
        # through Get-WinSecLayout.
        #
        # Rendering must not execute a new audit.

        $null = & $RenderAction $NavigationState

        # ----------------------------------------------------
        # Save the dimensions used for this redraw
        # ----------------------------------------------------

        $null = Update-WinSecResizeState `
            -ResizeState $ResizeState `
            -Snapshot $snapshot

        $ResizeState.LastRenderUTC = [DateTime]::UtcNow

        if ($resized) {

            $ResizeState.ResizeCount++

            $ResizeState.LastResizeUTC = [DateTime]::UtcNow
        }

        return $true
    }
    finally {

        $ResizeState.IsRendering = $false
    }
}


# ------------------------------------------------------------
# Read keyboard input while monitoring terminal resizing
# ------------------------------------------------------------

function Read-WinSecPendingKey {
    [CmdletBinding()]
    param([AllowNull()][object]$InputUI = $null)
    # A single non-blocking poll, used only during a confirmed scan.
    try {
        $rawUI = if ($null -eq $InputUI) { $Host.UI.RawUI } else { $InputUI }
        if ($null -eq $rawUI) { throw 'No interactive keyboard.' }
        $keyAvailable = $rawUI.KeyAvailable
        if ($keyAvailable -isnot [bool]) { throw 'Invalid keyboard availability.' }
        if (-not $keyAvailable) { return $null }
        # KeyAvailable includes releases. Filtering them here can block until
        # the next press; callers already ignore events with KeyDown=false.
        return $rawUI.ReadKey('NoEcho,IncludeKeyDown,IncludeKeyUp')
    }
    catch { throw 'Unable to read scan keyboard input.' }
}

function Read-WinSecResizeAwareKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$ResizeState,

        [Parameter(Mandatory)]
        [scriptblock]$RenderAction,

        [AllowNull()]
        [psobject]$NavigationState = $null,

        [ValidateRange(50, 1000)]
        [int]$PollIntervalMilliseconds = 150,

        [AllowNull()]
        [object]$InputUI = $null
    )

    # --------------------------------------------------------
    # Verify interactive console availability
    # --------------------------------------------------------

    $rawUI = if ($null -eq $InputUI) { $Host.UI.RawUI } else { $InputUI }

    if ($null -eq $rawUI) {

        throw (
            'Interactive console input is unavailable. ' +
            'WinSec Analyzer requires a supported terminal.'
        )
    }

    # --------------------------------------------------------
    # Wait for a key without blocking resize detection
    # --------------------------------------------------------

    while ($true) {

        # ----------------------------------------------------
        # Check whether the terminal was resized
        # ----------------------------------------------------

        $null = Invoke-WinSecResizeHandler `
            -ResizeState $ResizeState `
            -NavigationState $NavigationState `
            -RenderAction $RenderAction

        # ----------------------------------------------------
        # Check for keyboard input
        # ----------------------------------------------------

        try {

            $keyAvailable = $rawUI.KeyAvailable
            if ($keyAvailable -isnot [bool]) { throw 'Invalid keyboard availability.' }
        }
        catch {

            throw (
                'This PowerShell host does not support ' +
                'non-blocking keyboard input: {0}' -f `
                    $_.Exception.Message
            )
        }

        if ($keyAvailable) {

            # Return the native PowerShell key information.
            # KeyboardController remains responsible for
            # translating the key into a navigation action, ignoring releases.
            # Accept both event types so a buffered release cannot block redraws.

            return $rawUI.ReadKey(
                'NoEcho,IncludeKeyDown,IncludeKeyUp'
            )
        }

        # ----------------------------------------------------
        # Limit polling to avoid unnecessary CPU usage
        # ----------------------------------------------------

        Start-Sleep `
            -Milliseconds $PollIntervalMilliseconds
    }
}


# ------------------------------------------------------------
# Return resize diagnostics
# ------------------------------------------------------------

function Get-WinSecResizeStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$ResizeState
    )

    $snapshot = Get-WinSecResizeSnapshot

    $pendingResize = (
        $snapshot.Width -ne $ResizeState.Width -or
        $snapshot.Height -ne $ResizeState.Height -or
        $snapshot.ContentWidth -ne $ResizeState.ContentWidth
    )

    return [PSCustomObject]@{
        CurrentWidth   = $snapshot.Width
        CurrentHeight  = $snapshot.Height

        PreviousWidth  = $ResizeState.Width
        PreviousHeight = $ResizeState.Height

        ResizeCount    = $ResizeState.ResizeCount

        PendingResize  = $pendingResize
        IsRendering    = $ResizeState.IsRendering

        LastResizeUTC  = $ResizeState.LastResizeUTC
        LastRenderUTC  = $ResizeState.LastRenderUTC
    }
}
