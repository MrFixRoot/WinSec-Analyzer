
# ============================================================
# WinSec Analyzer
# Component : Results
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Displays security controls for the selected section.
#
# Features:
# - Multi-device assessment context
# - Five security sections
# - Individual control scores
# - Adaptive terminal layout
# - Keyboard navigation
# - Persistent control selection
# ============================================================


# ------------------------------------------------------------
# Get security controls belonging to a section
# ------------------------------------------------------------

function Get-WinSecSectionControls {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'SystemSecurity',
            'NetworkSecurity',
            'IdentityAccess',
            'LoggingAuditing',
            'ServicesHardening'
        )]
        [string]$SectionKey,

        [AllowEmptyCollection()]
        [object[]]$ControlResults = @()
    )

    # --------------------------------------------------------
    # Security control definitions
    # --------------------------------------------------------

    $definitions = switch ($SectionKey) {

        'SystemSecurity' {
            @(
                @{
                    Key = 'Defender'
                    Name = 'Windows Defender'
                    File = 'src/Checks/Defender/Test-Defender.ps1'
                }
                @{
                    Key = 'BitLocker'
                    Name = 'BitLocker'
                    File = 'src/Checks/BitLocker/Test-BitLocker.ps1'
                }
                @{
                    Key = 'WindowsUpdate'
                    Name = 'Windows Update'
                    File = 'src/Checks/System/Test-WindowsUpdate.ps1'
                }
            )
        }

        'NetworkSecurity' {
            @(
                @{
                    Key = 'Firewall'
                    Name = 'Windows Firewall'
                    File = 'src/Checks/Firewall/Test-Firewall.ps1'
                }
                @{
                    Key = 'SMBv1'
                    Name = 'SMBv1'
                    File = 'src/Checks/Network/Test-SMBv1.ps1'
                }
                @{
                    Key = 'RemoteDesktop'
                    Name = 'Remote Desktop'
                    File = 'src/Checks/Network/Test-RDP.ps1'
                }
                @{
                    Key = 'OpenPorts'
                    Name = 'Open Ports'
                    File = 'src/Checks/Network/Test-OpenPorts.ps1'
                }
                @{
                    Key = 'NetworkConfiguration'
                    Name = 'Network Configuration'
                    File = ''
                }
            )
        }

        'IdentityAccess' {
            @(
                @{
                    Key = 'LocalAdministrators'
                    Name = 'Local Administrators'
                    File = 'src/Checks/Accounts/Test-LocalAdmins.ps1'
                }
                @{
                    Key = 'GuestAccount'
                    Name = 'Guest Account'
                    File = 'src/Checks/Accounts/Test-GuestAccount.ps1'
                }
                @{
                    Key = 'PasswordPolicy'
                    Name = 'Password Policies'
                    File = 'src/Checks/Policies/Test-PasswordPolicy.ps1'
                }
            )
        }

        'LoggingAuditing' {
            @(
                @{
                    Key = 'PowerShellLogging'
                    Name = 'PowerShell Logging'
                    File = 'src/Checks/System/Test-PowerShellLogging.ps1'
                }
                @{
                    Key = 'AuditPolicy'
                    Name = 'Windows Audit Policies'
                    File = 'src/Checks/Policies/Test-AuditPolicy.ps1'
                }
            )
        }

        'ServicesHardening' {
            @(
                @{
                    Key = 'WindowsServices'
                    Name = 'Windows Services'
                    File = ''
                }
            )
        }
    }

    # --------------------------------------------------------
    # Normalize controls and assessment results
    # --------------------------------------------------------

    $index = 0

    foreach ($definition in $definitions) {

        $index++

        $score = '--/100'

        $status = if ($definition.File) {
            'PENDING'
        }
        else {
            'PLANNED'
        }

        $checkId = ''

        foreach ($result in $ControlResults) {

            if ($null -eq $result) {
                continue
            }

            $resultSection = Get-WinSecTableValue `
                -Row $result -Key 'SectionKey'

            $resultKey = Get-WinSecTableValue `
                -Row $result -Key 'Key'

            $resultName = Get-WinSecTableValue `
                -Row $result -Key 'Name'

            # Prevent matching another section's results
            if (
                $resultSection -and
                $resultSection -ne $SectionKey
            ) {
                continue
            }

            if (
                $resultKey -ne $definition.Key -and
                $resultName -ne $definition.Name
            ) {
                continue
            }

            # Read actual assessment score
            $rawScore = Get-WinSecTableValue `
                -Row $result -Key 'Score'

            if (
                $rawScore -match
                '^\s*(100|[1-9]?\d)\s*(?:/100)?\s*$'
            ) {
                $score = '{0}/100' -f [int]$Matches[1]
            }

            # Read actual assessment status
            $rawStatus = Get-WinSecTableValue `
                -Row $result -Key 'Status'

            if ($rawStatus) {
                $status = $rawStatus.Trim().ToUpperInvariant()
            }
            elseif ($score -ne '--/100') {
                $status = 'UNKNOWN'
            }

            $checkId = Get-WinSecTableValue `
                -Row $result -Key 'CheckId'

            break
        }

        [PSCustomObject]@{
            Id         = '{0:D2}' -f $index
            Key        = $definition.Key
            CheckId    = $checkId
            SectionKey = $SectionKey
            Name       = $definition.Name
            Score      = $score
            Status     = $status
            CheckFile  = $definition.File
        }
    }
}


# ------------------------------------------------------------
# Get current device information
# ------------------------------------------------------------

function Get-WinSecResultsDevice {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null
    )

    $deviceId = ''
    $hostname = 'NOT SELECTED'

    if ($null -ne $NavigationState) {

        $deviceId = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SelectedDeviceId'

        $name = Get-WinSecTableValue `
            -Row $NavigationState `
            -Key 'SelectedDeviceName'

        if ($name) {
            $hostname = $name
        }
        elseif ($deviceId) {
            $hostname = $deviceId
        }
    }

    return [PSCustomObject]@{
        DeviceId = $deviceId
        Hostname = $hostname
    }
}


# ------------------------------------------------------------
# Render security section results
# ------------------------------------------------------------

function Show-WinSecResults {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [AllowEmptyCollection()]
        [object[]]$SectionResults = @(),

        [AllowEmptyCollection()]
        [object[]]$ControlResults = @(),

        [string]$Version = '0.9.0'
    )

    # --------------------------------------------------------
    # Get terminal layout
    # --------------------------------------------------------

    $layout = Get-WinSecLayout -Screen 'Section'

    Clear-WinSecScreen

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

        return
    }

    # --------------------------------------------------------
    # Resolve selected section
    # --------------------------------------------------------

    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $SectionResults
    )

    if ($sections.Count -eq 0) {

        Write-WinSecText `
            -Text 'No security sections available.' `
            -Color Yellow

        return
    }

    $sectionIndex = 0
    $controlIndex = 0

    if ($null -ne $NavigationState) {

        $sectionIndex = [int]$NavigationState.SectionIndex
        $controlIndex = [int]$NavigationState.ControlIndex
    }

    $sectionIndex = [Math]::Max(
        0,
        [Math]::Min($sectionIndex, $sections.Count - 1)
    )

    $section = $sections[$sectionIndex]

    # --------------------------------------------------------
    # Load section controls
    # --------------------------------------------------------

    $controls = @(
        Get-WinSecSectionControls `
            -SectionKey $section.Key `
            -ControlResults $ControlResults
    )

    if ($controls.Count -gt 0) {

        $controlIndex = [Math]::Max(
            0,
            [Math]::Min(
                $controlIndex,
                $controls.Count - 1
            )
        )
    }
    else {
        $controlIndex = -1
    }

    # --------------------------------------------------------
    # Get selected device
    # --------------------------------------------------------

    $device = Get-WinSecResultsDevice `
        -NavigationState $NavigationState

    # --------------------------------------------------------
    # Render project banner
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
            -Text 'mrRoot | Security Assessment' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Render section heading
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title $section.Name

    Write-WinSecText `
        -Text "DEVICE: $($device.Hostname)" `
        -Color Gray

    $statusColor = Get-WinSecStatusColor `
        -Status $section.Status

    $summary = 'SECTION SCORE: {0} | STATUS: {1}' -f `
        $section.Score,
        $section.Status

    Write-WinSecText `
        -Text $summary `
        -Color $statusColor

    Write-Host ''

    # --------------------------------------------------------
    # Define adaptive security controls table
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Id'
            Header   = 'ID'
            Width    = 2
            MinWidth = 2
            MaxWidth = 2
            Priority = 1
        }

        @{
            Key      = 'Name'
            Header   = 'Security Control'
            Width    = 34
            MinWidth = 14
            MaxWidth = 50
            Priority = 1
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
    # Calculate visible table area
    # --------------------------------------------------------

    $hiddenKeys = @()

    if ($controls.Count -eq 0) {
        $hiddenKeys = @('UP/DOWN', 'H')
    }

    # Reserve actual space for heading, device,
    # score, table borders and a safety margin.

    $layout = Get-WinSecLayout `
        -Screen 'Section' `
        -BannerRows $layout.BannerRows `
        -HiddenKeys $hiddenKeys `
        -ReservedRows 12

    $maxRows = [Math]::Max(
        1,
        [int]$layout.MaxTableRows
    )

    # --------------------------------------------------------
    # Render controls and selection
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $controls `
        -SelectedIndex $controlIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Render contextual keyboard help
    # --------------------------------------------------------

    Write-WinSecKeyboardHelp `
        -Screen 'Section' `
        -HiddenKeys $hiddenKeys
}
