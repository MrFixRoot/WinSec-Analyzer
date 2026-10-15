
# ============================================================
# WinSec Analyzer
# Component : MainMenu
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Main security dashboard with section scores,
# keyboard navigation highlighting and adaptive layout.
# ============================================================


# ------------------------------------------------------------
# Define main security sections
# ------------------------------------------------------------

function Get-WinSecMainMenuSections {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$SectionResults = @()
    )

    $definitions = @(
        @{ Id = '01'; Key = 'SystemSecurity';    Name = 'System Security' }
        @{ Id = '02'; Key = 'NetworkSecurity';   Name = 'Network Security' }
        @{ Id = '03'; Key = 'IdentityAccess';    Name = 'Identity & Access Security' }
        @{ Id = '04'; Key = 'LoggingAuditing';   Name = 'Logging & Auditing' }
        @{ Id = '05'; Key = 'ServicesHardening'; Name = 'Services & Hardening' }
    )

    $sections = @(
        foreach ($definition in $definitions) {

            $result = $null

            foreach ($candidate in $SectionResults) {

                $candidateId = Get-WinSecTableValue `
                    -Row $candidate -Key 'Id'

                $candidateKey = Get-WinSecTableValue `
                    -Row $candidate -Key 'Key'

                $candidateName = Get-WinSecTableValue `
                    -Row $candidate -Key 'Name'

                if (
                    $candidateId -eq $definition.Id -or
                    $candidateKey -eq $definition.Key -or
                    $candidateName -eq $definition.Name
                ) {
                    $result = $candidate
                    break
                }
            }

            # No audit results available by default.
            $score = '--/100'
            $status = 'PENDING'

            if ($null -ne $result) {

                $rawScore = Get-WinSecTableValue `
                    -Row $result -Key 'Score'

                $rawStatus = Get-WinSecTableValue `
                    -Row $result -Key 'Status'

                $numericScore = 0

                if (
                    [int]::TryParse(
                        $rawScore,
                        [ref]$numericScore
                    ) -and
                    $numericScore -ge 0 -and
                    $numericScore -le 100
                ) {
                    $score = '{0}/100' -f $numericScore
                }

                if (-not [string]::IsNullOrWhiteSpace($rawStatus)) {
                    $status = $rawStatus.ToUpperInvariant()
                }
                elseif ($score -ne '--/100') {
                    $status = 'UNKNOWN'
                }
            }

            [PSCustomObject]@{
                Id     = $definition.Id
                Key    = $definition.Key
                Name   = $definition.Name
                Score  = $score
                Status = $status
            }
        }
    )

    return $sections
}


# ------------------------------------------------------------
# Calculate keyboard help height
# ------------------------------------------------------------

function Get-WinSecMainMenuHelpHeight {
    [CmdletBinding()]
    param(
        [int]$Width = 80
    )

    $Width = [Math]::Max(1, $Width)

    $shortcuts = @(
        Get-WinSecKeyboardShortcuts -Screen 'MainMenu'
    )

    $lines = 1
    $currentLength = 0

    foreach ($shortcut in $shortcuts) {

        $label = '[{0}] {1}' -f `
            $shortcut.Key,
            $shortcut.Action

        if ($currentLength -eq 0) {
            $currentLength = $label.Length
            continue
        }

        $nextLength = $currentLength + 3 + $label.Length

        if ($nextLength -le $Width) {
            $currentLength = $nextLength
        }
        else {
            $lines++
            $currentLength = $label.Length
        }
    }

    # Blank line + divider + shortcut lines
    return (2 + $lines)
}


# ------------------------------------------------------------
# Render main dashboard
# ------------------------------------------------------------

function Show-WinSecMainMenu {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [AllowEmptyCollection()]
        [object[]]$SectionResults = @(),

        [Nullable[int]]$OverallScore = $null,

        [string]$OverallStatus = 'PENDING',

        [string]$Version = '0.9.0'
    )

    $terminal = Get-WinSecTerminalSize

    $width = $terminal.Width
    $height = $terminal.Height

    Clear-WinSecScreen

    # --------------------------------------------------------
    # Validate terminal dimensions
    # --------------------------------------------------------

    if ($width -lt 40 -or $height -lt 17) {

        Write-WinSecText `
            -Text 'WINSEC ANALYZER' `
            -Align Center `
            -Color Cyan

        Write-Host ''

        Write-WinSecText `
            -Text 'Terminal window is too small.' `
            -Color Yellow `
            -Align Center

        Write-WinSecText `
            -Text 'Please resize the terminal.' `
            -Color DarkGray `
            -Align Center

        return
    }

    # --------------------------------------------------------
    # Render project branding
    # --------------------------------------------------------

    $bannerRows = 2

    if ($height -ge 34) {

        Show-Banner -Version $Version

        $bannerRows = if ($width -ge 55) { 15 } else { 10 }
    }
    else {

        Write-WinSecText `
            -Text "WINSEC ANALYZER v$Version" `
            -Color Cyan `
            -Align Center

        Write-WinSecText `
            -Text 'mrRoot | Windows Security Assessment' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Display security assessment score
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title 'Security Assessment'

    $scoreText = '--/100'

    if (
        $null -ne $OverallScore -and
        $OverallScore -ge 0 -and
        $OverallScore -le 100
    ) {
        $scoreText = '{0}/100' -f $OverallScore
    }

    $statusText = $OverallStatus.ToUpperInvariant()

    $statusColor = Get-WinSecStatusColor `
        -Status $statusText

    $summaryText = 'SECURITY SCORE: {0}  |  STATUS: {1}' -f `
        $scoreText,
        $statusText

    Write-WinSecText `
        -Text $summaryText `
        -Color $statusColor

    Write-Host ''

    # --------------------------------------------------------
    # Prepare security sections
    # --------------------------------------------------------

    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $SectionResults
    )

    # --------------------------------------------------------
    # Obtain current selection
    # --------------------------------------------------------

    $selectedIndex = 0

    if ($null -ne $NavigationState) {

        $rawIndex = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SectionIndex'

        $parsedIndex = 0

        if ([int]::TryParse($rawIndex, [ref]$parsedIndex)) {
            $selectedIndex = $parsedIndex
        }
    }

    $selectedIndex = [Math]::Max(
        0,
        [Math]::Min($selectedIndex, $sections.Count - 1)
    )

    # --------------------------------------------------------
    # Define dashboard columns
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Id'
            Header   = 'ID'
            Width    = 2
            MinWidth = 2
            MaxWidth = 2
            Priority = 1
            Align    = 'Left'
        }

        @{
            Key      = 'Name'
            Header   = 'Security Section'
            Width    = 34
            MinWidth = 14
            MaxWidth = 50
            Priority = 2
            Align    = 'Left'
            Expand   = $true
        }

        @{
            Key      = 'Score'
            Header   = 'Score'
            Width    = 10
            MinWidth = 7
            MaxWidth = 12
            Priority = 3
            Align    = 'Right'
        }

        @{
            Key      = 'Status'
            Header   = 'Status'
            Width    = 14
            MinWidth = 8
            MaxWidth = 14
            Priority = 4
            Align    = 'Center'
        }
    )

    # --------------------------------------------------------
    # Calculate available display space
    # --------------------------------------------------------

    $helpRows = Get-WinSecMainMenuHelpHeight `
        -Width $terminal.ContentWidth

    $layout = Get-WinSecLayout `
        -Screen 'MainMenu' `
        -BannerRows $bannerRows `
        -HelpRows $helpRows `
        -ReservedRows 6

    # Table headers and separators consume four lines.
    $tableRows = [Math]::Max(
        1,
        $layout.ContentRows - 4
    )

    # --------------------------------------------------------
    # Render section scores
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $sections `
        -SelectedIndex $selectedIndex `
        -MaxRows $tableRows

    # --------------------------------------------------------
    # Display context-aware keyboard shortcuts
    # --------------------------------------------------------

    Write-WinSecKeyboardHelp -Screen 'MainMenu'
}
