
# ============================================================
# WinSec Analyzer
# Component : Table
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Adaptive terminal tables for security results.
# ============================================================


# ------------------------------------------------------------
# Get property value from an object or hashtable
# ------------------------------------------------------------

function Get-WinSecTableValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Row,

        [Parameter(Mandatory)]
        [string]$Key
    )

    if ($null -eq $Row) {
        return ''
    }

    if ($Row -is [System.Collections.IDictionary]) {
        if ($Row.Contains($Key)) {
            return [string]$Row[$Key]
        }

        return ''
    }

    $property = $Row.PSObject.Properties[$Key]

    if ($null -ne $property) {
        if ($null -ne $property.Value) {
            return [string]$property.Value
        }
    }

    return ''
}


# ------------------------------------------------------------
# Format individual table cell
# ------------------------------------------------------------

function Format-WinSecTableCell {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Text = '',

        [int]$Width = 10,

        [ValidateSet('Left', 'Center', 'Right')]
        [string]$Align = 'Left'
    )

    $Width = [Math]::Max(1, $Width)

    $Text = $Text -replace '\r|\n', ' '
    $Text = $Text.Replace("`t", ' ')

    if ($Text.Length -gt $Width) {
        if ($Width -gt 3) {
            $Text = $Text.Substring(0, $Width - 3) + '...'
        }
        else {
            $Text = $Text.Substring(0, $Width)
        }
    }

    $remaining = $Width - $Text.Length

    switch ($Align) {
        'Right' {
            return $Text.PadLeft($Width)
        }

        'Center' {
            $left = [Math]::Floor($remaining / 2)
            $right = $remaining - $left

            return (' ' * $left) + $Text + (' ' * $right)
        }

        default {
            return $Text.PadRight($Width)
        }
    }
}


# ------------------------------------------------------------
# Render adaptive table
# ------------------------------------------------------------

function Write-WinSecTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Columns,

        [AllowEmptyCollection()]
        [object[]]$Rows = @(),

        [int]$SelectedIndex = -1,

        [int]$ScrollOffset = 0,

        [int]$MaxRows = 0,

        [switch]$NoHeader
    )

    $terminal = Get-WinSecTerminalSize

    $availableWidth = [int]$terminal.ContentWidth

    if ($availableWidth -lt 25) {
        Write-WinSecText `
            -Text 'Terminal too narrow. Please resize.' `
            -Color Yellow

        return
    }

    $gap = 2
    $markerWidth = 2

    $contentWidth = $availableWidth - $markerWidth

    $layouts = [System.Collections.Generic.List[object]]::new()

    $order = 0

    # Build column definitions
    foreach ($column in $Columns) {

        $key = Get-WinSecTableValue -Row $column -Key 'Key'

        if ([string]::IsNullOrWhiteSpace($key)) {
            continue
        }

        $header = Get-WinSecTableValue -Row $column -Key 'Header'

        if ([string]::IsNullOrWhiteSpace($header)) {
            $header = $key
        }

        $desiredText = Get-WinSecTableValue -Row $column -Key 'Width'
        $minText = Get-WinSecTableValue -Row $column -Key 'MinWidth'
        $maxText = Get-WinSecTableValue -Row $column -Key 'MaxWidth'
        $priorityText = Get-WinSecTableValue -Row $column -Key 'Priority'
        $align = Get-WinSecTableValue -Row $column -Key 'Align'
        $expandText = Get-WinSecTableValue -Row $column -Key 'Expand'

        $minWidth = 4
        $maxWidth = 72
        $priority = 50 + $order
        $expand = $false

        if ($minText -match '^\d+$') {
            $minWidth = [Math]::Max(1, [int]$minText)
        }

        if ($maxText -match '^\d+$') {
            $maxWidth = [Math]::Max($minWidth, [int]$maxText)
        }

        if ($priorityText -match '^\d+$') {
            $priority = [int]$priorityText
        }

        if ($expandText -eq 'True') {
            $expand = $true
        }

        if ($align -notin @('Left', 'Center', 'Right')) {
            $align = 'Left'
        }

        # Determine natural column width
        $naturalWidth = $header.Length

        foreach ($row in $Rows) {
            $value = Get-WinSecTableValue -Row $row -Key $key

            $naturalWidth = [Math]::Max(
                $naturalWidth,
                [Math]::Min($value.Length, $maxWidth)
            )
        }

        $desiredWidth = $naturalWidth

        if ($desiredText -match '^\d+$') {
            $desiredWidth = [int]$desiredText
        }

        $desiredWidth = [Math]::Max(
            $minWidth,
            [Math]::Min($desiredWidth, $maxWidth)
        )

        $layouts.Add([PSCustomObject]@{
            Key       = $key
            Header    = $header
            Width     = $desiredWidth
            MinWidth  = $minWidth
            MaxWidth  = $maxWidth
            Priority  = $priority
            Order     = $order
            Align     = $align
            Expand    = $expand
        })

        $order++
    }

    if ($layouts.Count -eq 0) {
        Write-WinSecText -Text 'No table columns defined.' -Color Yellow
        return
    }

    # Calculate total width
    $requiredWidth = 0

    foreach ($layout in $layouts) {
        $requiredWidth += $layout.Width
    }

    $requiredWidth += $gap * ($layouts.Count - 1)

    # Resize columns to fit terminal
    while ($requiredWidth -gt $contentWidth) {

        $candidate = $null
        $largestSlack = 0

        foreach ($layout in $layouts) {
            $slack = $layout.Width - $layout.MinWidth

            if ($slack -gt $largestSlack) {
                $largestSlack = $slack
                $candidate = $layout
            }
        }

        if ($null -ne $candidate) {
            $reduction = [Math]::Min(
                $largestSlack,
                $requiredWidth - $contentWidth
            )

            $candidate.Width -= $reduction
            $requiredWidth -= $reduction
            continue
        }

        # Hide lower-priority columns if necessary
        if ($layouts.Count -gt 1) {

            $removeIndex = 0
            $highestPriority = [int]::MinValue

            for ($i = 0; $i -lt $layouts.Count; $i++) {
                if ($layouts[$i].Priority -ge $highestPriority) {
                    $highestPriority = $layouts[$i].Priority
                    $removeIndex = $i
                }
            }

            $layouts.RemoveAt($removeIndex)

            $requiredWidth = $gap * ($layouts.Count - 1)

            foreach ($layout in $layouts) {
                $requiredWidth += $layout.Width
            }
        }
        else {
            $layouts[0].Width = [Math]::Max(1, $contentWidth)
            $requiredWidth = $layouts[0].Width
            break
        }
    }

    # Expand flexible column when space is available
    $extraWidth = $contentWidth - $requiredWidth

    if ($extraWidth -gt 0) {
        foreach ($layout in $layouts) {
            if ($layout.Expand) {
                $growth = [Math]::Min(
                    $extraWidth,
                    $layout.MaxWidth - $layout.Width
                )

                if ($growth -gt 0) {
                    $layout.Width += $growth
                    $requiredWidth += $growth
                }

                break
            }
        }
    }

    $tableWidth = $markerWidth + $requiredWidth
    $separator = '-' * $tableWidth

    # Table header
    if (-not $NoHeader) {

        Write-Host $separator -ForegroundColor DarkGray
        Write-Host (' ' * $markerWidth) -NoNewline

        for ($i = 0; $i -lt $layouts.Count; $i++) {

            $layout = $layouts[$i]

            $cell = Format-WinSecTableCell `
                -Text $layout.Header.ToUpperInvariant() `
                -Width $layout.Width `
                -Align $layout.Align

            Write-Host $cell -ForegroundColor DarkCyan -NoNewline

            if ($i -lt $layouts.Count - 1) {
                Write-Host (' ' * $gap) -NoNewline
            }
        }

        Write-Host ''
        Write-Host $separator -ForegroundColor DarkGray
    }

    # Handle empty results
    if ($Rows.Count -eq 0) {
        Write-WinSecText -Text 'No results available.' -Color DarkGray
        Write-Host $separator -ForegroundColor DarkGray
        return
    }

    # Calculate visible rows
    if ($MaxRows -le 0) {
        $MaxRows = [Math]::Max(
            3,
            $terminal.Height - 15
        )
    }

    $MaxRows = [Math]::Max(1, $MaxRows)

    $maxOffset = [Math]::Max(0, $Rows.Count - $MaxRows)

    $startIndex = [Math]::Max(
        0,
        [Math]::Min($ScrollOffset, $maxOffset)
    )

    # Keep selected row visible
    if ($SelectedIndex -ge 0 -and $SelectedIndex -lt $Rows.Count) {

        if ($SelectedIndex -lt $startIndex) {
            $startIndex = $SelectedIndex
        }

        if ($SelectedIndex -ge ($startIndex + $MaxRows)) {
            $startIndex = $SelectedIndex - $MaxRows + 1
        }
    }

    $endIndex = [Math]::Min(
        $Rows.Count,
        $startIndex + $MaxRows
    )

    # Render visible rows
    for ($rowIndex = $startIndex; $rowIndex -lt $endIndex; $rowIndex++) {

        $row = $Rows[$rowIndex]

        $isSelected = ($rowIndex -eq $SelectedIndex)

        if ($isSelected) {
            Write-Host '> ' -ForegroundColor Cyan -NoNewline
        }
        else {
            Write-Host '  ' -NoNewline
        }

        for ($i = 0; $i -lt $layouts.Count; $i++) {

            $layout = $layouts[$i]

            $value = Get-WinSecTableValue `
                -Row $row `
                -Key $layout.Key

            $cell = Format-WinSecTableCell `
                -Text $value `
                -Width $layout.Width `
                -Align $layout.Align

            $color = 'Gray'

            if ($isSelected) {
                $color = 'Cyan'
            }

            # Automatic security status coloring
            if ($layout.Key -in @('Status', 'State')) {
                $color = Get-WinSecStatusColor -Status $value
            }

            Write-Host $cell -ForegroundColor $color -NoNewline

            if ($i -lt $layouts.Count - 1) {
                Write-Host (' ' * $gap) -NoNewline
            }
        }

        Write-Host ''
    }

    Write-Host $separator -ForegroundColor DarkGray

    # Pagination information
    if ($Rows.Count -gt $MaxRows) {

        $pagination = 'Showing {0}-{1} of {2}' -f `
            ($startIndex + 1),
            $endIndex,
            $Rows.Count

        Write-WinSecText `
            -Text $pagination `
            -Color DarkGray
    }
}
