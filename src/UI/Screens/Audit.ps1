
# ============================================================
# WinSec Analyzer
# Component : Audit
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Displays security assessment progress, current checks,
# execution status and audit messages.
# ============================================================


# ------------------------------------------------------------
# Get audit execution information
# ------------------------------------------------------------

function Get-WinSecAuditInfo {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$AuditState = $null
    )

    $status = 'PENDING'
    $currentCheck = 'Not started'
    $message = 'Waiting for security assessment.'
    $completed = 0
    $total = 0
    $startedAt = ''
    $hasProgress = $false

    if ($null -ne $AuditState) {

        $rawStatus = Get-WinSecTableValue `
            -Row $AuditState -Key 'Status'

        $rawCheck = Get-WinSecTableValue `
            -Row $AuditState -Key 'CurrentCheck'

        $rawMessage = Get-WinSecTableValue `
            -Row $AuditState -Key 'Message'

        $rawCompleted = Get-WinSecTableValue `
            -Row $AuditState -Key 'CompletedChecks'

        $rawTotal = Get-WinSecTableValue `
            -Row $AuditState -Key 'TotalChecks'

        $startedAt = Get-WinSecTableValue `
            -Row $AuditState -Key 'StartedAt'

        if (-not [string]::IsNullOrWhiteSpace($rawStatus)) {
            $status = $rawStatus.ToUpperInvariant()
        }

        if (-not [string]::IsNullOrWhiteSpace($rawCheck)) {
            $currentCheck = $rawCheck
        }

        if (-not [string]::IsNullOrWhiteSpace($rawMessage)) {
            $message = $rawMessage
        }

        $parsed = 0

        if ([int]::TryParse($rawTotal, [ref]$parsed)) {
            $total = [Math]::Max(0, $parsed)
        }

        $parsed = 0

        if ([int]::TryParse($rawCompleted, [ref]$parsed)) {
            $completed = [Math]::Max(0, $parsed)
        }

        if ($total -gt 0) {
            $completed = [Math]::Min($completed, $total)
            $hasProgress = $true
        }
    }

    $percentage = 0

    if ($hasProgress) {
        $percentage = [int][Math]::Round(
            ($completed / $total) * 100
        )
    }

    return [PSCustomObject]@{
        Status          = $status
        CurrentCheck    = $currentCheck
        Message         = $message
        CompletedChecks = $completed
        TotalChecks     = $total
        Percentage      = $percentage
        HasProgress     = $hasProgress
        StartedAt       = $startedAt
    }
}


# ------------------------------------------------------------
# Draw progress bar
# ------------------------------------------------------------

function Write-WinSecAuditProgress {
    [CmdletBinding()]
    param(
        [int]$Percentage = 0,

        [bool]$HasProgress = $false
    )

    $terminal = Get-WinSecTerminalSize

    $barWidth = [Math]::Max(
        8,
        [Math]::Min(40, $terminal.ContentWidth - 12)
    )

    if (-not $HasProgress) {
        Write-WinSecText `
            -Text 'PROGRESS: Not available' `
            -Color DarkGray

        return
    }

    $Percentage = [Math]::Max(
        0,
        [Math]::Min(100, $Percentage)
    )

    $filled = [int][Math]::Floor(
        ($Percentage / 100) * $barWidth
    )

    $empty = $barWidth - $filled

    $bar = ('#' * $filled) + ('-' * $empty)

    $color = 'Cyan'

    if ($Percentage -eq 100) {
        $color = 'Green'
    }

    Write-WinSecText `
        -Text ("[{0}] {1}%" -f $bar, $Percentage) `
        -Color $color
}


# ------------------------------------------------------------
# Normalize check execution results
# ------------------------------------------------------------

function Get-WinSecAuditRows {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$CheckResults = @()
    )

    $index = 0

    $rows = @(
        foreach ($check in $CheckResults) {

            $index++

            $name = Get-WinSecTableValue `
                -Row $check -Key 'Name'

            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = Get-WinSecTableValue `
                    -Row $check -Key 'Check'
            }

            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = 'Unknown Check'
            }

            $status = Get-WinSecTableValue `
                -Row $check -Key 'Status'

            if ([string]::IsNullOrWhiteSpace($status)) {
                $status = 'PENDING'
            }

            $detail = Get-WinSecTableValue `
                -Row $check -Key 'Message'

            [PSCustomObject]@{
                Id     = '{0:D2}' -f $index
                Name   = $name
                Status = $status.ToUpperInvariant()
                Detail = $detail
            }
        }
    )

    return $rows
}


# ------------------------------------------------------------
# Render security audit screen
# ------------------------------------------------------------

function Show-WinSecAudit {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$AuditState = $null,

        [AllowEmptyCollection()]
        [object[]]$CheckResults = @(),

        [string]$Version = '0.9.0'
    )

    $terminal = Get-WinSecTerminalSize

    Clear-WinSecScreen

    # --------------------------------------------------------
    # Validate terminal dimensions
    # --------------------------------------------------------

    if (
        $terminal.Width -lt 40 -or
        $terminal.Height -lt 18
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

    # --------------------------------------------------------
    # Render banner
    # --------------------------------------------------------

    $bannerRows = 2

    if ($terminal.Height -ge 42) {

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
            -Text 'mrRoot | Security Assessment' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Get current audit information
    # --------------------------------------------------------

    $audit = Get-WinSecAuditInfo `
        -AuditState $AuditState

    Write-WinSecSectionTitle `
        -Title 'Security Audit'

    # --------------------------------------------------------
    # Display execution status
    # --------------------------------------------------------

    $statusColor = Get-WinSecStatusColor `
        -Status $audit.Status

    switch ($audit.Status) {
        'COMPLETED' { $statusColor = 'Green' }
        'CANCELLED' { $statusColor = 'Yellow' }
        'FAILED'    { $statusColor = 'Red' }
    }

    Write-WinSecText `
        -Text "AUDIT STATUS: $($audit.Status)" `
        -Color $statusColor

    # --------------------------------------------------------
    # Display assessment progress
    # --------------------------------------------------------

    Write-WinSecAuditProgress `
        -Percentage $audit.Percentage `
        -HasProgress $audit.HasProgress

    if ($audit.HasProgress) {

        $counter = 'CHECKS: {0} / {1}' -f `
            $audit.CompletedChecks,
            $audit.TotalChecks

        Write-WinSecText `
            -Text $counter `
            -Color DarkGray
    }

    Write-WinSecText `
        -Text "CURRENT: $($audit.CurrentCheck)" `
        -Color Gray

    Write-WinSecText `
        -Text "MESSAGE: $($audit.Message)" `
        -Color DarkGray

    Write-Host ''

    # --------------------------------------------------------
    # Prepare check results
    # --------------------------------------------------------

    $rows = @(
        Get-WinSecAuditRows `
            -CheckResults $CheckResults
    )

    # --------------------------------------------------------
    # Define table columns
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Id'
            Header   = 'ID'
            Width    = 3
            MinWidth = 2
            Priority = 1
        }

        @{
            Key      = 'Name'
            Header   = 'Security Check'
            Width    = 30
            MinWidth = 12
            MaxWidth = 50
            Priority = 2
            Expand   = $true
        }

        @{
            Key      = 'Status'
            Header   = 'Status'
            Width    = 12
            MinWidth = 8
            Priority = 3
        }

        @{
            Key      = 'Detail'
            Header   = 'Detail'
            Width    = 35
            MinWidth = 10
            MaxWidth = 60
            Priority = 4
        }
    )

    # --------------------------------------------------------
    # Calculate available table height
    # --------------------------------------------------------

    $layout = Get-WinSecLayout `
        -Screen 'Audit' `
        -BannerRows $bannerRows `
        -ReservedRows 12

    $maxRows = [Math]::Max(
        1,
        $layout.ContentRows
    )

    # --------------------------------------------------------
    # Render check execution table
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $rows `
        -SelectedIndex -1 `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Display keyboard shortcuts
    # --------------------------------------------------------

    Write-WinSecKeyboardHelp -Screen 'Audit'
}
