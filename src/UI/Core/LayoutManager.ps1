
# ============================================================
# WinSec Analyzer
# Component : LayoutManager
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Calculates adaptive screen layouts, available space
# and visible table ranges for the terminal UI.
# ============================================================


# ------------------------------------------------------------
# Get layout configuration for current screen
# ------------------------------------------------------------

function Get-WinSecLayout {
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

        [int]$BannerRows = -1,

        [int]$HelpRows = -1,

        [int]$ReservedRows = -1
    )

    # Get current terminal dimensions
    $terminal = Get-WinSecTerminalSize

    $width = [int]$terminal.Width
    $height = [int]$terminal.Height

    $contentWidth = [int]$terminal.ContentWidth

    # Determine layout mode
    $mode = 'Full'

    if ($width -lt 100 -or $height -lt 35) {
        $mode = 'Compact'
    }

    if ($width -lt 60 -or $height -lt 20) {
        $mode = 'Minimal'
    }

    # Current Banner.ps1 renders 15 lines in full mode
    # and 10 lines for narrow terminals.
    if ($BannerRows -lt 0) {
        if ($width -ge 55) {
            $BannerRows = 15
        }
        else {
            $BannerRows = 10
        }
    }

    # Reserve keyboard help area
    if ($HelpRows -lt 0) {
        if ($width -lt 60) {
            $HelpRows = 5
        }
        elseif ($Screen -eq 'MainMenu') {
            $HelpRows = 4
        }
        else {
            $HelpRows = 3
        }
    }

    # Screen-specific content reservations
    if ($ReservedRows -lt 0) {
        $ReservedRows = switch ($Screen) {
            'MainMenu' { 5 }
            'Section'  { 5 }
            'Findings' { 7 }
            'Audit'    { 4 }
            'Results'  { 5 }
            'Settings' { 4 }
        }
    }

    $BannerRows = [Math]::Max(0, $BannerRows)
    $HelpRows = [Math]::Max(0, $HelpRows)
    $ReservedRows = [Math]::Max(0, $ReservedRows)

    # Calculate available vertical space
    $usedRows = $BannerRows +
                $HelpRows +
                $ReservedRows

    $availableRows = [Math]::Max(
        0,
        $height - $usedRows
    )

    # Calculate horizontal spacing
    $indent = 2
    $gap = 3

    if ($mode -eq 'Compact') {
        $indent = 1
        $gap = 2
    }

    if ($mode -eq 'Minimal') {
        $indent = 0
        $gap = 1
    }

    # Evaluate terminal usability
    $isTooSmall = (
        $width -lt 40 -or
        $height -lt 15
    )

    return [PSCustomObject]@{
        Screen          = $Screen
        Mode            = $mode

        Width           = $width
        Height          = $height
        ContentWidth    = $contentWidth

        BannerRows      = $BannerRows
        HelpRows        = $HelpRows
        ReservedRows    = $ReservedRows

        ContentRows     = $availableRows
        MaxTableRows    = $availableRows

        Indent          = $indent
        ColumnGap       = $gap

        IsCompact       = ($mode -ne 'Full')
        IsMinimal       = ($mode -eq 'Minimal')
        IsTooSmall      = $isTooSmall
        HasTableSpace   = ($availableRows -gt 0)
    }
}


# ------------------------------------------------------------
# Calculate visible items in a scrollable list
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

    $maxOffset = [Math]::Max(
        0,
        $ItemCount - $VisibleRows
    )

    $startIndex = [Math]::Max(
        0,
        [Math]::Min($ScrollOffset, $maxOffset)
    )

    # Keep selected item inside visible viewport
    if (
        $SelectedIndex -ge 0 -and
        $SelectedIndex -lt $ItemCount
    ) {
        if ($SelectedIndex -lt $startIndex) {
            $startIndex = $SelectedIndex
        }

        if ($SelectedIndex -ge ($startIndex + $VisibleRows)) {
            $startIndex = $SelectedIndex - $VisibleRows + 1
        }
    }

    $startIndex = [Math]::Max(
        0,
        [Math]::Min($startIndex, $maxOffset)
    )

    $endIndex = [Math]::Min(
        $ItemCount,
        $startIndex + $VisibleRows
    )

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
# Get recommended table height for a screen
# ------------------------------------------------------------

function Get-WinSecTableHeight {
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

        [int]$BannerRows = -1,

        [int]$HelpRows = -1,

        [int]$ReservedRows = -1
    )

    $layout = Get-WinSecLayout `
        -Screen $Screen `
        -BannerRows $BannerRows `
        -HelpRows $HelpRows `
        -ReservedRows $ReservedRows

    return [int]$layout.MaxTableRows
}
