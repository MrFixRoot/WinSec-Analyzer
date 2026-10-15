
# ============================================================
# WinSec Analyzer
# Component : MainMenu
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Main security assessment dashboard.
#
# Features:
# - Multi-device assessment context
# - Five security sections
# - Security scores and assessment status
# - Adaptive terminal layout
# - Keyboard navigation highlighting
# - Context-aware keyboard shortcuts
# ============================================================


# ------------------------------------------------------------
# Get security sections and assessment results
# ------------------------------------------------------------

function Get-WinSecMainMenuSections {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$SectionResults = @()
    )

    # Main security categories
    $definitions = @(
        @{
            Id   = '01'
            Key  = 'SystemSecurity'
            Name = 'System Security'
        }
        @{
            Id   = '02'
            Key  = 'NetworkSecurity'
            Name = 'Network Security'
        }
        @{
            Id   = '03'
            Key  = 'IdentityAccess'
            Name = 'Identity & Access Security'
        }
        @{
            Id   = '04'
            Key  = 'LoggingAuditing'
            Name = 'Logging & Auditing'
        }
        @{
            Id   = '05'
            Key  = 'ServicesHardening'
            Name = 'Services & Hardening'
        }
    )

    foreach ($definition in $definitions) {

        $result = $null

        # ----------------------------------------------------
        # Match section with assessment data
        # ----------------------------------------------------

        foreach ($candidate in $SectionResults) {

            if ($null -eq $candidate) {
                continue
            }

            $candidateId = Get-WinSecTableValue `
                -Row $candidate -Key 'Id'

            $candidateKey = Get-WinSecTableValue `
                -Row $candidate -Key 'Key'

            $candidateName = Get-WinSecTableValue `
                -Row $candidate -Key 'Name'

            # Prefer stable section identifiers.
            $matched = $false

            if ($candidateKey) {

                $matched = (
                    $candidateKey -eq $definition.Key
                )
            }
            elseif ($candidateName) {

                $matched = (
                    $candidateName -eq $definition.Name
                )
            }
            elseif ($candidateId) {

                $matched = (
                    $candidateId -eq $definition.Id
                )
            }

            if ($matched) {
                $result = $candidate
                break
            }
        }

        # ----------------------------------------------------
        # Default state: no assessment performed
        # ----------------------------------------------------

        $score = '--/100'
        $status = 'PENDING'

        if ($null -ne $result) {

            $rawScore = Get-WinSecTableValue `
                -Row $result -Key 'Score'

            $rawStatus = Get-WinSecTableValue `
                -Row $result -Key 'Status'

            # Accept numerical scores between 0 and 100.
            if (
                $rawScore -match
                '^\s*(100|[1-9]?\d)\s*(?:/100)?\s*$'
            ) {

                $numericScore = [int]$Matches[1]

                $score = '{0}/100' -f $numericScore
            }

            # Never infer PASS or FAIL from score alone.
            if (-not [string]::IsNullOrWhiteSpace($rawStatus)) {

                $status = $rawStatus.Trim().ToUpperInvariant()
            }
            elseif ($score -ne '--/100') {

                $status = 'UNKNOWN'
            }
        }

        # ----------------------------------------------------
        # Return normalized section
        # ----------------------------------------------------

        [PSCustomObject]@{
            Id     = $definition.Id
            Key    = $definition.Key
            Name   = $definition.Name
            Score  = $score
            Status = $status
        }
    }
}


# ------------------------------------------------------------
# Resolve selected section index
# ------------------------------------------------------------

function Get-WinSecMainMenuSelectedIndex {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [int]$SectionCount = 5
    )

    if ($SectionCount -le 0) {
        return -1
    }

    $selectedIndex = 0

    if ($null -ne $NavigationState) {

        $rawIndex = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SectionIndex'

        $parsedIndex = 0

        if ([int]::TryParse(
            $rawIndex,
            [ref]$parsedIndex
        )) {
            $selectedIndex = $parsedIndex
        }
    }

    return [Math]::Max(
        0,
        [Math]::Min(
            $selectedIndex,
            $SectionCount - 1
        )
    )
}


# ------------------------------------------------------------
# Resolve active device information
# ------------------------------------------------------------

function Get-WinSecMainMenuDevice {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null
    )

    $deviceId = ''
    $hostname = ''

    if ($null -ne $NavigationState) {

        $deviceId = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SelectedDeviceId'

        $hostname = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SelectedDeviceName'
    }

    if ([string]::IsNullOrWhiteSpace($hostname)) {

        if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
            $hostname = $deviceId
        }
        else {
            $hostname = 'NOT SELECTED'
        }
    }

    return [PSCustomObject]@{
        DeviceId = $deviceId
        Hostname = $hostname
        Selected = (
            -not [string]::IsNullOrWhiteSpace($deviceId)
        )
    }
}


# ------------------------------------------------------------
# Maintain compatibility with existing UI components
# ------------------------------------------------------------

function Get-WinSecMainMenuHelpHeight {
    [CmdletBinding()]
    param(
        [int]$Width = 80
    )

    return Get-WinSecKeyboardHelpHeight `
        -Screen 'MainMenu' `
        -Width $Width
}


# ------------------------------------------------------------
# Render main security dashboard
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

    # --------------------------------------------------------
    # Get adaptive terminal layout
    # --------------------------------------------------------

    $layout = Get-WinSecLayout -Screen 'MainMenu'

    Clear-WinSecScreen

    # --------------------------------------------------------
    # Validate terminal dimensions
    # --------------------------------------------------------

    if ($layout.IsTooSmall) {

        Write-WinSecText `
            -Text 'WINSEC ANALYZER' `
            -Color Cyan `
            -Align Center

        Write-Host ''

        Write-WinSecText `
            -Text 'Terminal window is too small.' `
            -Color Yellow `
            -Align Center

        Write-WinSecText `
            -Text "Minimum: $($layout.MinimumWidth) x $($layout.MinimumHeight)" `
            -Color DarkGray `
            -Align Center

        Write-Host ''

        Write-WinSecText `
            -Text 'Please resize the terminal.' `
            -Color DarkGray `
            -Align Center

        return
    }

    # --------------------------------------------------------
    # Prepare device and section information
    # --------------------------------------------------------

    $device = Get-WinSecMainMenuDevice `
        -NavigationState $NavigationState

    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $SectionResults
    )

    $selectedIndex = Get-WinSecMainMenuSelectedIndex `
        -NavigationState $NavigationState `
        -SectionCount $sections.Count

    # --------------------------------------------------------
    # Determine vertical presentation mode
    # --------------------------------------------------------

    $compactVertical = (
        $layout.Height -lt 27
    )

    # --------------------------------------------------------
    # Render project branding
    # --------------------------------------------------------

    if ($layout.BannerRows -gt 2) {

        Show-Banner -Version $Version
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
    # Render dashboard heading
    # --------------------------------------------------------

    if ($compactVertical) {

        Write-WinSecText `
            -Text 'SECURITY ASSESSMENT' `
            -Color Cyan

        Write-WinSecDivider -Color DarkGray
    }
    else {

        Write-WinSecSectionTitle `
            -Title 'Security Assessment'
    }

    # --------------------------------------------------------
    # Display active device information
    # --------------------------------------------------------

    $deviceText = 'DEVICE: {0}' -f $device.Hostname

    $deviceColor = 'Gray'

    if (-not $device.Selected) {
        $deviceColor = 'Yellow'
    }

    Write-WinSecText `
        -Text $deviceText `
        -Color $deviceColor

    # --------------------------------------------------------
    # Display overall security score
    # --------------------------------------------------------

    $scoreText = '--/100'

    if (
        $null -ne $OverallScore -and
        $OverallScore -ge 0 -and
        $OverallScore -le 100
    ) {

        $scoreText = '{0}/100' -f $OverallScore
    }

    $status = 'PENDING'

    if (-not [string]::IsNullOrWhiteSpace($OverallStatus)) {

        $status = $OverallStatus.Trim().ToUpperInvariant()
    }

    $statusColor = Get-WinSecStatusColor `
        -Status $status

    $summary = 'SECURITY SCORE: {0} | STATUS: {1}' -f `
        $scoreText,
        $status

    Write-WinSecText `
        -Text $summary `
        -Color $statusColor

    if (-not $compactVertical) {
        Write-Host ''
    }

    # --------------------------------------------------------
    # Define security sections table
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
            Priority = 1
            Align    = 'Left'
            Expand   = $true
        }

        @{
            Key      = 'Score'
            Header   = 'Score'
            Width    = 10
            MinWidth = 7
            MaxWidth = 12
            Priority = 2
            Align    = 'Right'
        }

        @{
            Key      = 'Status'
            Header   = 'Status'
            Width    = 14
            MinWidth = 8
            MaxWidth = 16
            Priority = 3
            Align    = 'Center'
        }
    )

    # --------------------------------------------------------
    # Calculate available space for table rows
    # --------------------------------------------------------

    # Compact presentation:
    # - Short heading
    # - Device and score
    # - Table borders
    # - Pagination allowance

    $reservedRows = if ($compactVertical) {
        9
    }
    else {
        12
    }

    # Recalculate layout using actual content reservations.
    $layout = Get-WinSecLayout `
        -Screen 'MainMenu' `
        -ReservedRows $reservedRows

    $maxRows = [Math]::Max(
        1,
        [int]$layout.MaxTableRows
    )

    # --------------------------------------------------------
    # Render security sections
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $sections `
        -SelectedIndex $selectedIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Render keyboard shortcuts
    # --------------------------------------------------------

    Write-WinSecKeyboardHelp -Screen 'MainMenu'
}
