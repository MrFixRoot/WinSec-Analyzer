
# ============================================================
# WinSec Analyzer
# Component : Settings
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Displays UI configuration and project settings
# with adaptive terminal rendering.
# ============================================================


# ------------------------------------------------------------
# Resolve UI configuration path
# ------------------------------------------------------------

function Get-WinSecUIConfigPath {
    [CmdletBinding()]
    param()

    # src/UI/Screens -> Project root
    $projectRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..\..')
    )

    return Join-Path $projectRoot 'config\ui.json'
}


# ------------------------------------------------------------
# Convert configuration properties into table rows
# ------------------------------------------------------------

function ConvertTo-WinSecSettingsRows {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Data,

        [string]$Prefix = ''
    )

    if ($null -eq $Data) {
        return
    }

    $properties = @()

    if ($Data -is [System.Collections.IDictionary]) {

        $properties = @(
            foreach ($key in $Data.Keys) {
                [PSCustomObject]@{
                    Name  = [string]$key
                    Value = $Data[$key]
                }
            }
        )
    }
    elseif ($Data -is [PSCustomObject]) {
        $properties = @($Data.PSObject.Properties)
    }
    else {
        return
    }

    foreach ($property in $properties) {

        $name = [string]$property.Name
        $value = $property.Value

        # Do not display potentially sensitive values
        if (
            $name -match '(?i)password|secret|token|credential|api.?key|private.?key'
        ) {
            continue
        }

        $fullName = if ($Prefix) {
            "$Prefix.$name"
        }
        else {
            $name
        }

        # Process nested configuration objects
        if (
            $value -is [System.Collections.IDictionary] -or
            $value -is [PSCustomObject]
        ) {
            ConvertTo-WinSecSettingsRows `
                -Data $value `
                -Prefix $fullName

            continue
        }

        # Format configuration value
        $displayValue = ''

        if ($null -eq $value) {
            $displayValue = 'Not set'
        }
        elseif ($value -is [bool]) {
            $displayValue = $value.ToString().ToLowerInvariant()
        }
        elseif ($value -is [array]) {
            $displayValue = (
                $value | ForEach-Object {
                    if ($_ -is [string] -or $_ -is [ValueType]) {
                        [string]$_
                    }
                    else {
                        '[object]'
                    }
                }
            ) -join ', '
        }
        else {
            $displayValue = [string]$value
        }

        [PSCustomObject]@{
            Setting = $fullName
            Value   = $displayValue
        }
    }
}


# ------------------------------------------------------------
# Read UI configuration
# ------------------------------------------------------------

function Get-WinSecUISettings {
    [CmdletBinding()]
    param(
        [string]$ConfigPath = (Get-WinSecUIConfigPath)
    )

    $rows = @()
    $message = ''
    $loaded = $false

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {

        $message = 'UI configuration file was not found.'
    }
    else {

        try {
            $content = Get-Content `
                -LiteralPath $ConfigPath `
                -Raw `
                -Encoding UTF8 `
                -ErrorAction Stop

            $data = ConvertFrom-Json `
                -InputObject $content `
                -ErrorAction Stop

            $rows = @(
                ConvertTo-WinSecSettingsRows -Data $data
            )

            $loaded = $true

            if ($rows.Count -eq 0) {
                $message = 'No displayable UI settings found.'
            }
            else {
                $message = 'UI configuration loaded successfully.'
            }
        }
        catch {
            $message = 'Unable to read UI configuration JSON.'
        }
    }

    return [PSCustomObject]@{
        Path    = $ConfigPath
        Loaded  = $loaded
        Message = $message
        Rows    = $rows
    }
}


# ------------------------------------------------------------
# Render settings screen
# ------------------------------------------------------------

function Show-WinSecSettings {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [string]$Version = '0.9.0',

        [string]$ConfigPath = (Get-WinSecUIConfigPath)
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
            -Text 'mrRoot | Configuration' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Load configuration
    # --------------------------------------------------------

    $settings = Get-WinSecUISettings `
        -ConfigPath $ConfigPath

    # --------------------------------------------------------
    # Render settings information
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title 'UI Settings'

    Write-WinSecText `
        -Text 'MODE: READ ONLY' `
        -Color Yellow

    Write-WinSecText `
        -Text "SOURCE: $($settings.Path)" `
        -Color DarkGray

    $messageColor = 'Green'

    if (-not $settings.Loaded) {
        $messageColor = 'Yellow'
    }

    Write-WinSecText `
        -Text $settings.Message `
        -Color $messageColor

    Write-Host ''

    # --------------------------------------------------------
    # Prepare table columns
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Setting'
            Header   = 'Configuration'
            Width    = 38
            MinWidth = 15
            MaxWidth = 55
            Priority = 1
            Expand   = $true
        }

        @{
            Key      = 'Value'
            Header   = 'Current Value'
            Width    = 35
            MinWidth = 12
            MaxWidth = 65
            Priority = 2
        }
    )

    # --------------------------------------------------------
    # Resolve current selection
    # --------------------------------------------------------

    $selectedIndex = -1

    if (
        $null -ne $NavigationState -and
        $settings.Rows.Count -gt 0
    ) {

        $selectedIndex = [Math]::Max(
            0,
            [Math]::Min(
                [int]$NavigationState.SettingsIndex,
                $settings.Rows.Count - 1
            )
        )
    }

    # --------------------------------------------------------
    # Calculate available layout
    # --------------------------------------------------------

    $layout = Get-WinSecLayout `
        -Screen 'Settings' `
        -BannerRows $bannerRows `
        -ReservedRows 9 `
        -HelpRows 4

    $maxRows = [Math]::Max(
        1,
        $layout.ContentRows
    )

    # --------------------------------------------------------
    # Render configuration table
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $settings.Rows `
        -SelectedIndex $selectedIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Keyboard help
    # --------------------------------------------------------

    # ENTER remains disabled until configuration editing
    # is implemented and connected to its controller.

    Write-WinSecKeyboardHelp `
        -Screen 'Settings' `
        -HiddenKeys @('ENTER')
}
