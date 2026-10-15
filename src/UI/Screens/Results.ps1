
# ============================================================
# WinSec Analyzer
# Component : Results
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Displays security controls, scores and assessment
# results for the selected security section.
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

    $definitions = @()

    switch ($SectionKey) {

        'SystemSecurity' {
            $definitions = @(
                @{
                    Id = '01'
                    Key = 'Defender'
                    Name = 'Windows Defender'
                    CheckFile = 'src/Checks/Defender/Test-Defender.ps1'
                }
                @{
                    Id = '02'
                    Key = 'BitLocker'
                    Name = 'BitLocker'
                    CheckFile = 'src/Checks/BitLocker/Test-BitLocker.ps1'
                }
                @{
                    Id = '03'
                    Key = 'WindowsUpdate'
                    Name = 'Windows Update'
                    CheckFile = 'src/Checks/System/Test-WindowsUpdate.ps1'
                }
            )
        }

        'NetworkSecurity' {
            $definitions = @(
                @{
                    Id = '01'
                    Key = 'Firewall'
                    Name = 'Windows Firewall'
                    CheckFile = 'src/Checks/Firewall/Test-Firewall.ps1'
                }
                @{
                    Id = '02'
                    Key = 'SMBv1'
                    Name = 'SMBv1'
                    CheckFile = 'src/Checks/Network/Test-SMBv1.ps1'
                }
                @{
                    Id = '03'
                    Key = 'RemoteDesktop'
                    Name = 'Remote Desktop'
                    CheckFile = 'src/Checks/Network/Test-RDP.ps1'
                }
                @{
                    Id = '04'
                    Key = 'OpenPorts'
                    Name = 'Open Ports'
                    CheckFile = 'src/Checks/Network/Test-OpenPorts.ps1'
                }
                @{
                    Id = '05'
                    Key = 'NetworkConfiguration'
                    Name = 'Network Configuration'
                    CheckFile = ''
                }
            )
        }

        'IdentityAccess' {
            $definitions = @(
                @{
                    Id = '01'
                    Key = 'LocalAdministrators'
                    Name = 'Local Administrators'
                    CheckFile = 'src/Checks/Accounts/Test-LocalAdmins.ps1'
                }
                @{
                    Id = '02'
                    Key = 'GuestAccount'
                    Name = 'Guest Account'
                    CheckFile = 'src/Checks/Accounts/Test-GuestAccount.ps1'
                }
                @{
                    Id = '03'
                    Key = 'PasswordPolicy'
                    Name = 'Password Policies'
                    CheckFile = 'src/Checks/Policies/Test-PasswordPolicy.ps1'
                }
            )
        }

        'LoggingAuditing' {
            $definitions = @(
                @{
                    Id = '01'
                    Key = 'PowerShellLogging'
                    Name = 'PowerShell Logging'
                    CheckFile = 'src/Checks/System/Test-PowerShellLogging.ps1'
                }
                @{
                    Id = '02'
                    Key = 'AuditPolicy'
                    Name = 'Windows Audit Policies'
                    CheckFile = 'src/Checks/Policies/Test-AuditPolicy.ps1'
                }
            )
        }

        'ServicesHardening' {
            $definitions = @(
                @{
                    Id = '01'
                    Key = 'WindowsServices'
                    Name = 'Windows Services'
                    CheckFile = ''
                }
            )
        }
    }

    $controls = @(
        foreach ($definition in $definitions) {

            $score = '--/100'

            if ([string]::IsNullOrWhiteSpace($definition.CheckFile)) {
                $status = 'PLANNED'
            }
            else {
                $status = 'PENDING'
            }

            # Match real audit results by section and control
            foreach ($result in $ControlResults) {

                $resultSection = Get-WinSecTableValue `
                    -Row $result `
                    -Key 'SectionKey'

                $resultKey = Get-WinSecTableValue `
                    -Row $result `
                    -Key 'Key'

                $resultName = Get-WinSecTableValue `
                    -Row $result `
                    -Key 'Name'

                if (
                    -not [string]::IsNullOrWhiteSpace($resultSection) -and
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

                $rawScore = Get-WinSecTableValue `
                    -Row $result `
                    -Key 'Score'

                $rawStatus = Get-WinSecTableValue `
                    -Row $result `
                    -Key 'Status'

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

                break
            }

            [PSCustomObject]@{
                Id         = $definition.Id
                Key        = $definition.Key
                SectionKey = $SectionKey
                Name       = $definition.Name
                Score      = $score
                Status     = $status
                CheckFile  = $definition.CheckFile
            }
        }
    )

    return $controls
}


# ------------------------------------------------------------
# Render selected security section
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

    $terminal = Get-WinSecTerminalSize

    Clear-WinSecScreen

    # --------------------------------------------------------
    # Validate terminal dimensions
    # --------------------------------------------------------

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

        Write-WinSecText `
            -Text 'Please resize the terminal.' `
            -Color DarkGray `
            -Align Center

        return
    }

    # --------------------------------------------------------
    # Resolve selected security section
    # --------------------------------------------------------

    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $SectionResults
    )

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

    $controls = @(
        Get-WinSecSectionControls `
            -SectionKey $section.Key `
            -ControlResults $ControlResults
    )

    # --------------------------------------------------------
    # Render project banner
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
            -Text 'mrRoot | Windows Security Assessment' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Section heading and assessment score
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title $section.Name

    $statusColor = Get-WinSecStatusColor `
        -Status $section.Status

    $summary = 'SECTION SCORE: {0}  |  STATUS: {1}' -f `
        $section.Score,
        $section.Status

    Write-WinSecText `
        -Text $summary `
        -Color $statusColor

    Write-Host ''

    # --------------------------------------------------------
    # Define adaptive table columns
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
            Width    = 32
            MinWidth = 14
            MaxWidth = 50
            Priority = 2
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
    # Calculate table layout
    # --------------------------------------------------------

    $layout = Get-WinSecLayout `
        -Screen 'Section' `
        -BannerRows $bannerRows `
        -ReservedRows 10

    $maxRows = [Math]::Max(
        1,
        $layout.ContentRows
    )

    # Clamp selected control index
    if ($controls.Count -gt 0) {

        $controlIndex = [Math]::Max(
            0,
            [Math]::Min($controlIndex, $controls.Count - 1)
        )
    }

    # --------------------------------------------------------
    # Render security controls
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $controls `
        -SelectedIndex $controlIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Display contextual keyboard shortcuts
    # --------------------------------------------------------

    Write-WinSecKeyboardHelp -Screen 'Section'
}
