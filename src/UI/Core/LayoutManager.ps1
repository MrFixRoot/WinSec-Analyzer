
# ============================================================
# WinSec Analyzer
# Component : LayoutManager
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Manages adaptive terminal layouts and screen dimensions.
#
# Supports:
# - Multi-device interface
# - Dynamic terminal resizing
# - Adaptive banner dimensions
# - Scrollable tables
# - Context-aware keyboard help
# ============================================================


# ------------------------------------------------------------
# Get screen layout
# ------------------------------------------------------------

function Get-WinSecLayout {
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

        [int]$BannerRows = -1,

        [int]$HelpRows = -1,

        [int]$ReservedRows = -1,

        [string[]]$HiddenKeys = @(),

        [switch]$EnableExport,

        [switch]$EnableRescan,

        [switch]$EnableSettingsEdit
    )

    # --------------------------------------------------------
    # Get current terminal dimensions
    # --------------------------------------------------------

    $terminal = Get-WinSecTerminalSize

    $width = [Math]::Max(1, [int]$terminal.Width)
    $height = [Math]::Max(1, [int]$terminal.Height)

    $contentWidth = [Math]::Max(
        1,
        [int]$terminal.ContentWidth
    )

    # --------------------------------------------------------
    # Determine terminal layout mode
    # --------------------------------------------------------

    $mode = 'Full'

    if ($width -lt 100 -or $height -lt 35) {
        $mode = 'Compact'
    }

    if ($width -lt 60 -or $height -lt 20) {
        $mode = 'Minimal'
    }

    # --------------------------------------------------------
    # Define minimum screen dimensions
    # --------------------------------------------------------

    $minimumHeight = switch ($Screen) {
        'Devices'  { 22 }
        'MainMenu' { 17 }
        'Section'  { 20 }
        'Findings' { 20 }
        'Audit'    { 18 }
        'Results'  { 20 }
        'Settings' { 20 }
    }

    $minimumWidth = 40

    $isTooSmall = (
        $width -lt $minimumWidth -or
        $height -lt $minimumHeight
    )

    # --------------------------------------------------------
    # Calculate banner dimensions
    # --------------------------------------------------------

    if ($BannerRows -lt 0) {

        # Match the rendering thresholds used
        # by the existing UI screens.

        $fullBannerHeight = switch ($Screen) {
            'Devices'  { 40 }
            'MainMenu' { 34 }
            'Section'  { 34 }
            'Findings' { 46 }
            'Audit'    { 42 }
            'Results'  { 34 }
            'Settings' { 34 }
        }

        if ($height -ge $fullBannerHeight) {

            # Banner.ps1:
            # Full ASCII banner: 15 lines
            # Narrow ASCII banner: 10 lines

            if ($width -ge 55) {
                $BannerRows = 15
            }
            else {
                $BannerRows = 10
            }
        }
        else {
            # Compact branding: two lines
            $BannerRows = 2
        }
    }

    # --------------------------------------------------------
    # Calculate keyboard help dimensions
    # --------------------------------------------------------

    if ($HelpRows -lt 0) {

        $helpCommand = Get-Command `
            -Name 'Get-WinSecKeyboardHelpHeight' `
            -CommandType Function `
            -ErrorAction SilentlyContinue

        if ($null -ne $helpCommand) {

            $helpParams = @{
                Screen             = $Screen
                Width              = $contentWidth
                HiddenKeys         = $HiddenKeys
                EnableExport       = [bool]$EnableExport
                EnableRescan       = [bool]$EnableRescan
                EnableSettingsEdit = [bool]$EnableSettingsEdit
            }

            $HelpRows = [int](
                Get-WinSecKeyboardHelpHeight @helpParams
            )
        }
        else {

            # Fallback until KeyboardHelp is loaded
            $HelpRows = 3

            if ($width -lt 60) {
                $HelpRows = 5
            }
        }
    }

    # --------------------------------------------------------
    # Define screen-specific reserved space
    # --------------------------------------------------------

    if ($ReservedRows -lt 0) {

        $ReservedRows = switch ($Screen) {

            'Devices' {
                # Heading, device summary,
                # table borders and safety margin
                13
            }

            'MainMenu' {
                5
            }

            'Section' {
                5
            }

            'Findings' {
                7
            }

            'Audit' {
                4
            }

            'Results' {
                5
            }

            'Settings' {
                4
            }
        }
    }

    # --------------------------------------------------------
    # Normalize reserved dimensions
    # --------------------------------------------------------

    $BannerRows = [Math]::Max(0, $BannerRows)
    $HelpRows = [Math]::Max(0, $HelpRows)
    $ReservedRows = [Math]::Max(0, $ReservedRows)

    # --------------------------------------------------------
    # Calculate available vertical space
    # --------------------------------------------------------

    $usedRows = (
        $BannerRows +
        $HelpRows +
        $ReservedRows
    )

    $availableRows = [Math]::Max(
        0,
        $height - $usedRows
    )

    # --------------------------------------------------------
    # Configure adaptive horizontal spacing
    # --------------------------------------------------------

    $indent = 2
    $columnGap = 3

    switch ($mode) {

        'Compact' {
            $indent = 1
            $columnGap = 2
        }

        'Minimal' {
            $indent = 0
            $columnGap = 1
        }
    }

    $usableWidth = [Math]::Max(
        1,
        $contentWidth - $indent
    )

    # --------------------------------------------------------
    # Return calculated layout
    # --------------------------------------------------------

    return [PSCustomObject]@{

        Screen          = $Screen
        Mode            = $mode

        Width           = $width
        Height          = $height
        ContentWidth    = $contentWidth
        UsableWidth     = $usableWidth

        BannerRows      = $BannerRows
        HelpRows        = $HelpRows
        ReservedRows    = $ReservedRows

        ContentRows     = $availableRows
        MaxTableRows    = $availableRows

        Indent          = $indent
        ColumnGap       = $columnGap

        MinimumWidth    = $minimumWidth
        MinimumHeight   = $minimumHeight

        IsCompact       = ($mode -ne 'Full')
        IsMinimal       = ($mode -eq 'Minimal')
        IsTooSmall      = $isTooSmall

        HasTableSpace   = (
            $availableRows -gt 0 -and
            -not $isTooSmall
        )
    }
}


# ------------------------------------------------------------
# Calculate visible items for scrollable lists
# ------------------------------------------------------------

function Get-WinSecVisibleRange {
    [CmdletBinding()]
    param(
        [int]$ItemCount = 0,

        [int]$SelectedIndex = -1,

        [int]$ScrollOffset = 0,

        [int]$VisibleRows = 10
    )

    $ItemCount = [Math]::Max(0, $ItemCount)

    if ($ItemCount -eq 0) {

        return [PSCustomObject]@{
            StartIndex        = 0
            EndIndexExclusive = 0
            VisibleCount      = 0
            ScrollOffset      = 0
            CanScrollUp       = $false
            CanScrollDown     = $false
        }
    }

    $VisibleRows = [Math]::Max(1, $VisibleRows)

    $maximumOffset = [Math]::Max(
        0,
        $ItemCount - $VisibleRows
    )

    # --------------------------------------------------------
    # Normalize current scroll position
    # --------------------------------------------------------

    $startIndex = [Math]::Max(
        0,
        [Math]::Min(
            $ScrollOffset,
            $maximumOffset
        )
    )

    # --------------------------------------------------------
    # Keep selected item visible
    # --------------------------------------------------------

    if (
        $SelectedIndex -ge 0 -and
        $SelectedIndex -lt $ItemCount
    ) {

        if ($SelectedIndex -lt $startIndex) {
            $startIndex = $SelectedIndex
        }

        if (
            $SelectedIndex -ge
            ($startIndex + $VisibleRows)
        ) {
            $startIndex = (
                $SelectedIndex - $VisibleRows + 1
            )
        }
    }

    # --------------------------------------------------------
    # Prevent scrolling outside available items
    # --------------------------------------------------------

    $startIndex = [Math]::Max(
        0,
        [Math]::Min(
            $startIndex,
            $maximumOffset
        )
    )

    $endIndex = [Math]::Min(
        $ItemCount,
        $startIndex + $VisibleRows
    )

    # --------------------------------------------------------
    # Return visible item range
    # --------------------------------------------------------

    return [PSCustomObject]@{
        StartIndex        = $startIndex
        EndIndexExclusive = $endIndex
        VisibleCount      = ($endIndex - $startIndex)
        ScrollOffset      = $startIndex
        CanScrollUp       = ($startIndex -gt 0)
        CanScrollDown     = ($endIndex -lt $ItemCount)
    }
}


# ------------------------------------------------------------
# Get recommended table height
# ------------------------------------------------------------

function Get-WinSecTableHeight {
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

        [int]$BannerRows = -1,

        [int]$HelpRows = -1,

        [int]$ReservedRows = -1
    )

    $layout = Get-WinSecLayout `
        -Screen $Screen `
        -BannerRows $BannerRows `
        -HelpRows $HelpRows `
        -ReservedRows $ReservedRows

    if ($layout.IsTooSmall) {
        return 0
    }

    return [int]$layout.MaxTableRows
}
