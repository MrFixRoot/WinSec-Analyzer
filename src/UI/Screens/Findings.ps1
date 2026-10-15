
# ============================================================
# WinSec Analyzer
# Component : Findings
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Displays security findings, severity, recommendations
# and references for the selected section or control.
# ============================================================


# ------------------------------------------------------------
# Get findings for the current selection
# ------------------------------------------------------------

function Get-WinSecSelectedFindings {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [object[]]$SectionResults = @(),

        [object[]]$ControlResults = @(),

        [object[]]$Findings = @()
    )

    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $SectionResults
    )

    if ($sections.Count -eq 0) {
        return $null
    }

    # Resolve selected section
    $sectionIndex = 0
    $controlIndex = 0
    $scope = 'Section'

    if ($null -ne $NavigationState) {
        $sectionIndex = [int]$NavigationState.SectionIndex
        $controlIndex = [int]$NavigationState.ControlIndex

        if ($NavigationState.FindingsScope -eq 'Control') {
            $scope = 'Control'
        }
    }

    $sectionIndex = [Math]::Max(
        0,
        [Math]::Min($sectionIndex, $sections.Count - 1)
    )

    $section = $sections[$sectionIndex]

    # Resolve selected control
    $control = $null

    if ($scope -eq 'Control') {

        $controls = @(
            Get-WinSecSectionControls `
                -SectionKey $section.Key `
                -ControlResults $ControlResults
        )

        if ($controls.Count -gt 0) {

            $controlIndex = [Math]::Max(
                0,
                [Math]::Min($controlIndex, $controls.Count - 1)
            )

            $control = $controls[$controlIndex]
        }
    }

    # Determine assessment context
    $title = $section.Name
    $score = $section.Score
    $status = $section.Status

    if ($null -ne $control) {
        $title = $control.Name
        $score = $control.Score
        $status = $control.Status
    }

    # Filter actual findings
    $filteredCount = 0
    $filtered = @(
        foreach ($finding in $Findings) {

            $findingSection = Get-WinSecTableValue `
                -Row $finding -Key 'SectionKey'

            $findingControl = Get-WinSecTableValue `
                -Row $finding -Key 'ControlKey'

            # Never mix findings from different sections
            if ($findingSection -ne $section.Key) {
                continue
            }

            # Control scope shows only the selected control
            if ($scope -eq 'Control') {

                if ($null -eq $control) {
                    continue
                }

                if ($findingControl -ne $control.Key) {
                    continue
                }
            }

            $id = Get-WinSecTableValue `
                -Row $finding -Key 'Id'

            $severity = Get-WinSecTableValue `
                -Row $finding -Key 'Severity'

            $name = Get-WinSecTableValue `
                -Row $finding -Key 'Finding'

            $description = Get-WinSecTableValue `
                -Row $finding -Key 'Description'

            $recommendation = Get-WinSecTableValue `
                -Row $finding -Key 'Recommendation'

            $reference = Get-WinSecTableValue `
                -Row $finding -Key 'Reference'

            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = Get-WinSecTableValue `
                    -Row $finding -Key 'Title'
            }

            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = $description
            }

            if ([string]::IsNullOrWhiteSpace($severity)) {
                $severity = 'UNKNOWN'
            }

            if ([string]::IsNullOrWhiteSpace($id)) {
                $id = '{0:D3}' -f ($filteredCount + 1)
            }

            $filteredCount++

            [PSCustomObject]@{
                Id             = $id
                Severity       = $severity.ToUpperInvariant()
                Finding        = $name
                Description    = $description
                Recommendation = $recommendation
                Reference      = $reference
                SectionKey     = $section.Key
                ControlKey     = $findingControl
            }
        }
    )

    return [PSCustomObject]@{
        Scope      = $scope
        Title      = $title
        SectionKey = $section.Key
        ControlKey = if ($null -ne $control) {
            $control.Key
        } else {
            $null
        }
        Score      = $score
        Status     = $status
        Findings   = $filtered
    }
}


# ------------------------------------------------------------
# Display a finding detail field with word wrapping
# ------------------------------------------------------------

function Write-WinSecFindingField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [AllowEmptyString()]
        [string]$Value = '',

        [int]$MaxLines = 2
    )

    $width = (Get-WinSecTerminalSize).ContentWidth

    $prefix = "${Label}: "
    $indent = ' ' * $prefix.Length

    $usableWidth = [Math]::Max(
        1,
        $width - $prefix.Length
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        $Value = 'Not provided'
    }

    $remaining = ($Value -replace '\s+', ' ').Trim()

    for ($i = 0; $i -lt $MaxLines; $i++) {

        if ([string]::IsNullOrEmpty($remaining)) {
            break
        }

        $take = [Math]::Min(
            $usableWidth,
            $remaining.Length
        )

        $part = $remaining.Substring(0, $take)

        # Prefer wrapping on spaces
        if ($take -lt $remaining.Length) {

            $lastSpace = $part.LastIndexOf(' ')

            if ($lastSpace -gt 0) {
                $take = $lastSpace
                $part = $remaining.Substring(0, $take)
            }
        }

        $remaining = $remaining.Substring($take).TrimStart()

        if (
            $i -eq ($MaxLines - 1) -and
            $remaining.Length -gt 0
        ) {
            if ($part.Length -gt 3) {
                $part = $part.Substring(0, $part.Length - 3) + '...'
            }
        }

        if ($i -eq 0) {
            $line = $prefix + $part
        }
        else {
            $line = $indent + $part
        }

        Write-WinSecText `
            -Text $line `
            -Color Gray
    }
}


# ------------------------------------------------------------
# Render findings screen
# ------------------------------------------------------------

function Show-WinSecFindings {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [object[]]$SectionResults = @(),

        [object[]]$ControlResults = @(),

        [object[]]$Findings = @(),

        [string]$Version = '0.9.0'
    )

    $terminal = Get-WinSecTerminalSize

    Clear-WinSecScreen

    # Validate terminal size
    if (
        $terminal.Width -lt 40 -or
        $terminal.Height -lt 20
    ) {
        Write-WinSecText `
            -Text 'WINSEC ANALYZER' `
            -Color Cyan `
            -Align Center

        Write-Host ''

        Write-WinSecText `
            -Text 'Terminal window is too small.' `
            -Color Yellow `
            -Align Center

        return
    }

    # Get findings and score
    $assessment = Get-WinSecSelectedFindings `
        -NavigationState $NavigationState `
        -SectionResults $SectionResults `
        -ControlResults $ControlResults `
        -Findings $Findings

    if ($null -eq $assessment) {
        Write-WinSecText `
            -Text 'No assessment data available.' `
            -Color Yellow

        return
    }

    # --------------------------------------------------------
    # Render branding
    # --------------------------------------------------------

    $bannerRows = 2

    if ($terminal.Height -ge 34) {

        Show-Banner -Version $Version

        $bannerRows = if ($terminal.Width -ge 55) {
            15
        }
        else {
            10
        }
    }
    else {
        Write-WinSecText `
            -Text "WINSEC ANALYZER v$Version" `
            -Color Cyan `
            -Align Center

        Write-WinSecText `
            -Text 'mrRoot | Security Findings' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Assessment information
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title "Findings - $($assessment.Title)"

    $statusColor = Get-WinSecStatusColor `
        -Status $assessment.Status

    Write-WinSecText `
        -Text "SCORE: $($assessment.Score)  |  STATUS: $($assessment.Status)" `
        -Color $statusColor

    Write-WinSecText `
        -Text "FINDINGS: $($assessment.Findings.Count)" `
        -Color DarkGray

    Write-Host ''

    # --------------------------------------------------------
    # Findings table
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Id'
            Header   = 'ID'
            Width    = 5
            MinWidth = 3
            MaxWidth = 8
            Priority = 1
        }

        @{
            Key      = 'Severity'
            Header   = 'Severity'
            Width    = 10
            MinWidth = 8
            MaxWidth = 12
            Priority = 2
        }

        @{
            Key      = 'Finding'
            Header   = 'Security Finding'
            Width    = 46
            MinWidth = 15
            MaxWidth = 72
            Priority = 1
            Expand   = $true
        }

        @{
            Key      = 'Recommendation'
            Header   = 'Recommendation'
            Width    = 35
            MinWidth = 14
            MaxWidth = 60
            Priority = 4
        }

        @{
            Key      = 'Reference'
            Header   = 'Reference'
            Width    = 20
            MinWidth = 10
            MaxWidth = 35
            Priority = 5
        }
    )

    $selectedIndex = 0

    if ($null -ne $NavigationState) {
        $selectedIndex = [int]$NavigationState.FindingsOffset
    }

    $count = $assessment.Findings.Count

    if ($count -gt 0) {
        $selectedIndex = [Math]::Max(
            0,
            [Math]::Min($selectedIndex, $count - 1)
        )
    }

    $layout = Get-WinSecLayout `
        -Screen 'Findings' `
        -BannerRows $bannerRows `
        -ReservedRows 14

    $maxRows = [Math]::Max(
        1,
        $layout.ContentRows
    )

    Write-WinSecTable `
        -Columns $columns `
        -Rows $assessment.Findings `
        -SelectedIndex $selectedIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Detailed information for selected finding
    # --------------------------------------------------------

    if (
        $count -gt 0 -and
        $terminal.Height -ge 25
    ) {

        $selectedFinding = $assessment.Findings[$selectedIndex]

        Write-WinSecSectionTitle `
            -Title 'Finding Details'

        Write-WinSecFindingField `
            -Label 'Description' `
            -Value $selectedFinding.Description `
            -MaxLines 2

        Write-WinSecFindingField `
            -Label 'Recommendation' `
            -Value $selectedFinding.Recommendation `
            -MaxLines 2

        Write-WinSecFindingField `
            -Label 'Reference' `
            -Value $selectedFinding.Reference `
            -MaxLines 1
    }

    if ($count -eq 0) {
        Write-Host ''

        Write-WinSecText `
            -Text 'No findings have been provided for this selection.' `
            -Color Yellow

        Write-WinSecText `
            -Text 'This does not indicate a successful security audit.' `
            -Color DarkGray
    }

    # --------------------------------------------------------
    # Keyboard shortcuts
    # --------------------------------------------------------

    Write-WinSecKeyboardHelp -Screen 'Findings'
}
