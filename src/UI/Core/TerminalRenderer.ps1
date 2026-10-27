
# ============================================================
# WinSec Analyzer
# Component : TerminalRenderer
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Core rendering utilities for the PowerShell terminal.
# ============================================================


# ------------------------------------------------------------
# Get terminal dimensions
# ------------------------------------------------------------

function Get-WinSecTerminalSize {
    [CmdletBinding()]
    param()

    $width  = 80
    $height = 25

    try {
        $size = $Host.UI.RawUI.WindowSize

        if ($size.Width -gt 0) {
            $width = [int]$size.Width
        }

        if ($size.Height -gt 0) {
            $height = [int]$size.Height
        }
    }
    catch {
        try {
            $width  = [Console]::WindowWidth
            $height = [Console]::WindowHeight
        }
        catch {
            # Keep default dimensions
        }
    }

    return [PSCustomObject]@{
        Width        = $width
        Height       = $height
        ContentWidth = [Math]::Max(1, $width - 1)
        IsCompact    = ($width -lt 80)
    }
}


# ------------------------------------------------------------
# Clear terminal screen
# ------------------------------------------------------------

function Clear-WinSecScreen {
    [CmdletBinding()]
    param()

    try {
        Clear-Host
    }
    catch {
        Write-Host ""
    }
}


# ------------------------------------------------------------
# Format text for terminal width
# ------------------------------------------------------------

function Format-WinSecLine {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Text = '',

        [ValidateSet('Left', 'Center', 'Right')]
        [string]$Align = 'Left',

        [int]$Indent = 0,

        [int]$Width = 0
    )

    if ($Width -le 0) {
        $Width = (Get-WinSecTerminalSize).ContentWidth
    }

    $Width = [Math]::Max(1, $Width)

    $Indent = [Math]::Max(
        0,
        [Math]::Min($Indent, $Width - 1)
    )

    $availableWidth = $Width - $Indent

    # Remove line breaks and tabs
    $Text = $Text -replace '\r|\n', ' '
    $Text = $Text.Replace("`t", '    ')

    # Prevent terminal overflow
    if ($Text.Length -gt $availableWidth) {

        if ($availableWidth -gt 3) {
            $Text = $Text.Substring(
                0,
                $availableWidth - 3
            ) + '...'
        }
        else {
            $Text = $Text.Substring(0, $availableWidth)
        }
    }

    $padding = 0

    switch ($Align) {

        'Center' {
            $padding = [Math]::Floor(
                ($availableWidth - $Text.Length) / 2
            )
        }

        'Right' {
            $padding = $availableWidth - $Text.Length
        }
    }

    return (' ' * ($Indent + $padding)) + $Text
}


# ------------------------------------------------------------
# Write formatted text
# ------------------------------------------------------------

function Write-WinSecText {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Text = '',

        [ConsoleColor]$Color = 'Gray',

        [ValidateSet('Left', 'Center', 'Right')]
        [string]$Align = 'Left',

        [int]$Indent = 0
    )

    $line = Format-WinSecLine `
        -Text $Text `
        -Align $Align `
        -Indent $Indent

    Write-Host $line -ForegroundColor $Color
}


# ------------------------------------------------------------
# Draw horizontal separator
# ------------------------------------------------------------

function Write-WinSecDivider {
    [CmdletBinding()]
    param(
        [ValidateSet('Single', 'Double', 'Dashed')]
        [string]$Style = 'Single',

        [ConsoleColor]$Color = 'DarkGray',

        [int]$Indent = 0
    )

    $width = (Get-WinSecTerminalSize).ContentWidth

    $Indent = [Math]::Max(
        0,
        [Math]::Min($Indent, $width - 1)
    )

    $length = [Math]::Max(1, $width - $Indent)

    $character = switch ($Style) {
        'Double' { '=' }
        'Dashed' { '-' }
        default  { [string][char]0x2500 }
    }

    $line = (' ' * $Indent) +
            ($character * $length)

    Write-Host $line -ForegroundColor $Color
}


# ------------------------------------------------------------
# Draw section title
# ------------------------------------------------------------

function Write-WinSecSectionTitle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [ConsoleColor]$Color = 'Cyan'
    )

    Write-Host ''

    Write-WinSecText `
        -Text $Title.ToUpperInvariant() `
        -Color $Color

    Write-WinSecDivider

    Write-Host ''
}


# ------------------------------------------------------------
# Resolve security status color
# ------------------------------------------------------------

function Get-WinSecStatusColor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Status
    )

    switch ($Status.ToUpperInvariant()) {

        'PASS'           { return 'Green' }
        'FAIL'           { return 'Red' }
        'WARNING'        { return 'Yellow' }
        'ERROR'          { return 'Red' }
        'RUNNING'        { return 'Cyan' }
        'PENDING'        { return 'Red' }
        'PARTIAL'        { return 'Yellow' }
        'COMPLETE'       { return 'Green' }
        'LIVE'           { return 'Green' }
        'RECORDS'        { return 'DarkBlue' }
        'NOT_APPLICABLE' { return 'DarkGray' }
        'UNKNOWN'        { return 'DarkGray' }

        default          { return 'Gray' }
    }
}


# ------------------------------------------------------------
# Write security status
# ------------------------------------------------------------

function Write-WinSecStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Status,

        [ValidateSet('Left', 'Center', 'Right')]
        [string]$Align = 'Left',

        [int]$Indent = 0
    )

    $color = Get-WinSecStatusColor -Status $Status

    Write-WinSecText `
        -Text $Status.ToUpperInvariant() `
        -Color $color `
        -Align $Align `
        -Indent $Indent
}
