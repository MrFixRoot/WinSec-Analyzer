
# ============================================================
# WinSec Analyzer
# Component : Invoke-WinSecCLI
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Main interactive terminal controller.
#
# Features:
# - Centralized keyboard controller
# - Multi-device assessment navigation
# - Device-specific results and findings
# - Navigation history
# - Resize-aware terminal rendering
# - Persistent screen selection
#
# Security:
# - Read-only interface
# - No audits during rendering
# - No automatic remote connections
# - No mixing of device or scan evidence
# ============================================================


# ------------------------------------------------------------
# Read an object or dictionary property
# ------------------------------------------------------------

function Get-WinSecCLIValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {

        foreach ($key in $InputObject.Keys) {

            if (
                [string]::Equals(
                    [string]$key,
                    $Name,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            ) {
                return $InputObject[$key]
            }
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}


# ------------------------------------------------------------
# Load registered devices
# ------------------------------------------------------------

function Get-WinSecCLIDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [AllowEmptyCollection()]
        [object[]]$Devices = @()
    )

    $source = @(
        $Devices | Where-Object {
            $null -ne $_
        }
    )

    # --------------------------------------------------------
    # Load configured targets when none were supplied
    # --------------------------------------------------------

    if ($source.Count -eq 0) {

        $targetsPath = Join-Path `
            -Path $ProjectRoot `
            -ChildPath 'config/targets.json'

        if (
            Test-Path -LiteralPath $targetsPath -PathType Leaf
        ) {

            try {

                $content = Get-Content `
                    -LiteralPath $targetsPath `
                    -Raw `
                    -Encoding UTF8 `
                    -ErrorAction Stop

                $configuration = ConvertFrom-Json `
                    -InputObject $content `
                    -ErrorAction Stop

                if ($configuration -is [array]) {

                    $source = @($configuration)
                }
                else {

                    $entries = Get-WinSecCLIValue `
                        -InputObject $configuration `
                        -Name 'targets'

                    if ($null -eq $entries) {

                        $entries = Get-WinSecCLIValue `
                            -InputObject $configuration `
                            -Name 'devices'
                    }

                    if ($null -ne $entries) {
                        $source = @($entries)
                    }
                }
            }
            catch {

                throw (
                    'Unable to load targets.json: {0}' -f `
                        $_.Exception.Message
                )
            }
        }
    }

    # --------------------------------------------------------
    # Normalize devices and reject duplicate identifiers
    # --------------------------------------------------------

    $registered = New-Object `
        'System.Collections.Generic.List[object]'

    $knownIds = @{}

    foreach ($device in $source) {

        if ($null -eq $device) {
            continue
        }

        $deviceId = [string](
            Get-WinSecCLIValue `
                -InputObject $device `
                -Name 'DeviceId'
        )

        if (-not $deviceId) {

            $deviceId = [string](
                Get-WinSecCLIValue `
                    -InputObject $device `
                    -Name 'Id'
            )
        }

        if ([string]::IsNullOrWhiteSpace($deviceId)) {
            continue
        }

        if ($knownIds.ContainsKey($deviceId)) {
            continue
        }

        $knownIds[$deviceId] = $true

        $hostname = [string](
            Get-WinSecCLIValue `
                -InputObject $device `
                -Name 'Hostname'
        )

        if (-not $hostname) {

            $hostname = [string](
                Get-WinSecCLIValue `
                    -InputObject $device `
                    -Name 'Name'
            )
        }

        if (-not $hostname) {
            $hostname = $deviceId
        }

        $mode = [string](
            Get-WinSecCLIValue `
                -InputObject $device `
                -Name 'Mode'
        )

        if (-not $mode) {
            $mode = 'UNKNOWN'
        }

        $score = Get-WinSecCLIValue `
            -InputObject $device `
            -Name 'Score'

        $status = [string](
            Get-WinSecCLIValue `
                -InputObject $device `
                -Name 'Status'
        )

        if (-not $status) {
            $status = 'PENDING'
        }

        $lastScan = [string](
            Get-WinSecCLIValue `
                -InputObject $device `
                -Name 'LastScan'
        )

        if (-not $lastScan) {
            $lastScan = 'Never'
        }

        $scanId = [string](
            Get-WinSecCLIValue `
                -InputObject $device `
                -Name 'ScanId'
        )

        if (-not $scanId) {

            $scanId = [string](
                Get-WinSecCLIValue `
                    -InputObject $device `
                    -Name 'LastScanId'
            )
        }

        $registered.Add(
            [PSCustomObject]@{
                DeviceId = $deviceId
                Hostname = $hostname
                Name     = $hostname
                Mode     = $mode
                Score    = $score
                Status   = $status
                LastScan = $lastScan
                ScanId   = $scanId
            }
        )
    }

    # --------------------------------------------------------
    # First-time installation: local device placeholder
    # --------------------------------------------------------

    if ($registered.Count -eq 0) {

        $hostname = [string]$env:COMPUTERNAME

        if (-not $hostname) {
            $hostname = [Environment]::MachineName
        }

        $registered.Add(
            [PSCustomObject]@{
                DeviceId = "local:$hostname"
                Hostname = $hostname
                Name     = $hostname
                Mode     = 'LOCAL'
                Score    = $null
                Status   = 'PENDING'
                LastScan = 'Never'
                ScanId   = ''
            }
        )
    }

    return $registered.ToArray()
}


# ------------------------------------------------------------
# Filter assessment records by device and scan
# ------------------------------------------------------------

function Get-WinSecCLIRecords {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Records = @(),

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [AllowEmptyString()]
        [string]$ScanId = ''
    )

    foreach ($record in $Records) {

        if ($null -eq $record) {
            continue
        }

        $recordDevice = [string](
            Get-WinSecCLIValue `
                -InputObject $record `
                -Name 'DeviceId'
        )

        $recordScan = [string](
            Get-WinSecCLIValue `
                -InputObject $record `
                -Name 'ScanId'
        )

        if (
            $recordDevice -eq $DeviceId -and
            $recordScan -eq $ScanId
        ) {
            $record
        }
    }
}


# ------------------------------------------------------------
# Resolve assessment belonging to the selected device
# ------------------------------------------------------------

function Get-WinSecCLIActiveAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Context
    )

    $deviceId = [string]$State.SelectedDeviceId

    $empty = [PSCustomObject]@{
        SectionResults = @()
        ControlResults = @()
        Findings       = @()

        ScanId         = ''
        OverallScore   = $null
        OverallStatus  = 'PENDING'

        Warning        = ''
    }

    if (-not $deviceId) {
        return $empty
    }

    # --------------------------------------------------------
    # Collect only records belonging to the active device
    # --------------------------------------------------------

    $allRecords = @(
        @($Context.SectionResults) +
        @($Context.ControlResults) +
        @($Context.Findings)
    )

    $deviceRecords = @(
        foreach ($record in $allRecords) {

            if ($null -eq $record) {
                continue
            }

            $recordDevice = [string](
                Get-WinSecCLIValue `
                    -InputObject $record `
                    -Name 'DeviceId'
            )

            if ($recordDevice -eq $deviceId) {
                $record
            }
        }
    )

    # --------------------------------------------------------
    # Determine scan identifier
    # --------------------------------------------------------

    $selectedScan = [string]$Context.ScanId

    $scanIds = @(
        $deviceRecords | ForEach-Object {

            $value = [string](
                Get-WinSecCLIValue `
                    -InputObject $_ `
                    -Name 'ScanId'
            )

            if ($value) {
                $value
            }
            else {
                '__UNSPECIFIED_SCAN__'
            }

        } | Select-Object -Unique
    )

    # Never combine findings from separate executions.
    if (-not $selectedScan) {

        if ($scanIds.Count -gt 1) {

            $empty.Warning = (
                'Multiple scan executions were found. ' +
                'Specify a ScanId to view one assessment.'
            )

            return $empty
        }

        if (
            $scanIds.Count -eq 1 -and
            $scanIds[0] -ne '__UNSPECIFIED_SCAN__'
        ) {
            $selectedScan = $scanIds[0]
        }
    }

    # --------------------------------------------------------
    # Filter all assessment collections
    # --------------------------------------------------------

    $sectionResults = @(
        Get-WinSecCLIRecords `
            -Records $Context.SectionResults `
            -DeviceId $deviceId `
            -ScanId $selectedScan
    )

    $controlResults = @(
        Get-WinSecCLIRecords `
            -Records $Context.ControlResults `
            -DeviceId $deviceId `
            -ScanId $selectedScan
    )

    $findings = @(
        Get-WinSecCLIRecords `
            -Records $Context.Findings `
            -DeviceId $deviceId `
            -ScanId $selectedScan
    )

    # --------------------------------------------------------
    # Resolve device score for matching assessment only
    # --------------------------------------------------------

    $overallScore = $null
    $overallStatus = 'PENDING'

    $selectedDevice = @(
        $Context.Devices | Where-Object {
            $_.DeviceId -eq $deviceId
        }
    ) | Select-Object -First 1

    if ($null -ne $selectedDevice) {

        $deviceScan = [string]$selectedDevice.ScanId

        if (
            $selectedScan -and
            $deviceScan -eq $selectedScan
        ) {

            $scoreText = [string]$selectedDevice.Score

            $scoreText = $scoreText -replace '/100$', ''

            $scoreValue = 0

            if (
                [int]::TryParse(
                    $scoreText,
                    [ref]$scoreValue
                ) -and
                $scoreValue -ge 0 -and
                $scoreValue -le 100
            ) {

                $overallScore = $scoreValue
                $overallStatus = [string]$selectedDevice.Status
            }
        }
    }

    return [PSCustomObject]@{
        SectionResults = $sectionResults
        ControlResults = $controlResults
        Findings       = $findings

        ScanId         = $selectedScan
        OverallScore   = $overallScore
        OverallStatus  = $overallStatus

        Warning        = ''
    }
}


# ------------------------------------------------------------
# Render current application screen
# ------------------------------------------------------------

function Show-WinSecCLICurrentScreen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Context
    )

    # --------------------------------------------------------
    # Devices do not require an assessment
    # --------------------------------------------------------

    if ($State.Screen -eq 'Devices') {

        Show-WinSecDevices `
            -NavigationState $State `
            -Devices $Context.Devices `
            -Version $Context.Version

        return
    }

    $assessment = Get-WinSecCLIActiveAssessment `
        -State $State `
        -Context $Context

    # --------------------------------------------------------
    # Block ambiguous multi-scan views
    # --------------------------------------------------------

    if ($assessment.Warning) {

        Clear-WinSecScreen

        Write-WinSecText `
            -Text 'WINSEC ANALYZER' `
            -Color Cyan `
            -Align Center

        Write-Host ''

        Write-WinSecText `
            -Text 'Assessment selection required' `
            -Color Yellow

        Write-Host ''

        Write-WinSecText `
            -Text $assessment.Warning `
            -Color Gray

        Write-Host ''

        Write-WinSecKeyboardHelp `
            -Screen $State.Screen

        return
    }

    # --------------------------------------------------------
    # Render the active screen
    # --------------------------------------------------------

    switch ($State.Screen) {

        'MainMenu' {

            Show-WinSecMainMenu `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -OverallScore $assessment.OverallScore `
                -OverallStatus $assessment.OverallStatus `
                -Version $Context.Version
        }

        'Section' {

            Show-WinSecResults `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -ControlResults $assessment.ControlResults `
                -Version $Context.Version
        }

        'Results' {

            Show-WinSecResults `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -ControlResults $assessment.ControlResults `
                -Version $Context.Version
        }

        'Findings' {

            Show-WinSecFindings `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -ControlResults $assessment.ControlResults `
                -Findings $assessment.Findings `
                -ScanId $assessment.ScanId `
                -Version $Context.Version
        }

        default {

            Clear-WinSecScreen

            Write-WinSecText `
                -Text 'WINSEC ANALYZER' `
                -Color Cyan `
                -Align Center

            Write-Host ''

            Write-WinSecText `
                -Text "SCREEN: $($State.Screen)" `
                -Color Gray

            Write-WinSecText `
                -Text 'Screen integration pending.' `
                -Color Yellow

            Write-Host ''

            Write-WinSecText `
                -Text '[ESC] Back' `
                -Color DarkGray
        }
    }
}


# ------------------------------------------------------------
# Calculate navigation boundaries
# ------------------------------------------------------------

function Get-WinSecCLINavigationCounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Context
    )

    $assessment = Get-WinSecCLIActiveAssessment `
        -State $State `
        -Context $Context

    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $assessment.SectionResults
    )

    $controls = @()
    $section = $null

    # --------------------------------------------------------
    # Resolve selected security section
    # --------------------------------------------------------

    if ($sections.Count -gt 0) {

        $sectionIndex = [Math]::Max(
            0,
            [Math]::Min(
                [int]$State.SectionIndex,
                $sections.Count - 1
            )
        )

        $section = $sections[$sectionIndex]

        $controls = @(
            Get-WinSecSectionControls `
                -SectionKey $section.Key `
                -ControlResults $assessment.ControlResults
        )
    }

    # --------------------------------------------------------
    # Count findings for current selection
    # --------------------------------------------------------

    $findingCount = 0

    if ($null -ne $section) {

        $selectedControl = $null

        if (
            $State.FindingsScope -eq 'Control' -and
            $controls.Count -gt 0
        ) {

            $controlIndex = [Math]::Max(
                0,
                [Math]::Min(
                    [int]$State.ControlIndex,
                    $controls.Count - 1
                )
            )

            $selectedControl = $controls[$controlIndex]
        }

        foreach ($finding in $assessment.Findings) {

            $findingSection = [string](
                Get-WinSecCLIValue `
                    -InputObject $finding `
                    -Name 'SectionKey'
            )

            if ($findingSection -ne $section.Key) {
                continue
            }

            if ($null -ne $selectedControl) {

                $findingControl = [string](
                    Get-WinSecCLIValue `
                        -InputObject $finding `
                        -Name 'ControlKey'
                )

                $findingCheck = [string](
                    Get-WinSecCLIValue `
                        -InputObject $finding `
                        -Name 'CheckId'
                )

                $controlMatch = (
                    $findingControl -eq $selectedControl.Key -or
                    (
                        $selectedControl.CheckId -and
                        $findingCheck -eq $selectedControl.CheckId
                    )
                )

                if (-not $controlMatch) {
                    continue
                }
            }

            $findingCount++
        }
    }

    return [PSCustomObject]@{
        SectionCount  = $sections.Count
        ControlCount  = $controls.Count
        FindingCount  = $findingCount
        SettingsCount = 0
    }
}


# ------------------------------------------------------------
# Main interactive application controller
# ------------------------------------------------------------

function Invoke-WinSecCLI {
    [CmdletBinding()]
    param(
        [Alias('ProjectPath', 'RootPath')]
        [string]$ProjectRoot = (
            [System.IO.Path]::GetFullPath(
                (Join-Path $PSScriptRoot '..\..')
            )
        ),

        [AllowEmptyCollection()]
        [object[]]$Devices = @(),

        [AllowEmptyCollection()]
        [object[]]$SectionResults = @(),

        [AllowEmptyCollection()]
        [object[]]$ControlResults = @(),

        [AllowEmptyCollection()]
        [object[]]$Findings = @(),

        [string]$ScanId = '',

        [string]$Version = '0.9.0'
    )

    $ProjectRoot = [System.IO.Path]::GetFullPath(
        $ProjectRoot
    )

    # --------------------------------------------------------
    # Load UI components and controllers
    # --------------------------------------------------------

    $modules = @(
        'src/UI/Core/TerminalRenderer.ps1'

        'src/UI/Components/Banner.ps1'
        'src/UI/Components/Table.ps1'
        'src/UI/Components/KeyboardHelp.ps1'

        'src/UI/Core/LayoutManager.ps1'
        'src/UI/Core/KeyboardController.ps1'
        'src/UI/Core/NavigationController.ps1'
        'src/UI/Core/ResizeHandler.ps1'

        'src/UI/Screens/MainMenu.ps1'
        'src/UI/Screens/Results.ps1'
        'src/UI/Screens/Devices.ps1'
        'src/UI/Screens/Findings.ps1'
    )

    foreach ($module in $modules) {

        $path = Join-Path `
            -Path $ProjectRoot `
            -ChildPath $module

        if (-not (
            Test-Path -LiteralPath $path -PathType Leaf
        )) {

            throw "Required module not found: $path"
        }

        . $path
    }

    # --------------------------------------------------------
    # Validate required functions
    # --------------------------------------------------------

    $requiredCommands = @(
        'Get-WinSecTerminalSize'
        'Get-WinSecLayout'

        'New-WinSecNavigationState'
        'Invoke-WinSecNavigationAction'

        'New-WinSecResizeState'
        'Read-WinSecResizeAwareKey'

        'Get-WinSecKeyboardAction'
        'ConvertTo-WinSecKeyboardAction'

        'Show-WinSecDevices'
        'Show-WinSecMainMenu'
        'Show-WinSecResults'
        'Show-WinSecFindings'
    )

    foreach ($commandName in $requiredCommands) {

        $command = Get-Command `
            -Name $commandName `
            -CommandType Function `
            -ErrorAction SilentlyContinue

        if ($null -eq $command) {

            throw (
                "Required function unavailable: $commandName"
            )
        }
    }

    # --------------------------------------------------------
    # Load device registry
    # --------------------------------------------------------

    $registeredDevices = @(
        Get-WinSecCLIDevices `
            -ProjectRoot $ProjectRoot `
            -Devices $Devices
    )

    # --------------------------------------------------------
    # Initialize navigation and resize state
    # --------------------------------------------------------

    $navigationState = New-WinSecNavigationState

    $resizeState = New-WinSecResizeState

    # --------------------------------------------------------
    # Initialize assessment context
    # --------------------------------------------------------

    $context = [PSCustomObject]@{
        ProjectRoot    = $ProjectRoot
        Version        = $Version

        Devices        = $registeredDevices

        SectionResults = @($SectionResults)
        ControlResults = @($ControlResults)
        Findings       = @($Findings)

        ScanId         = $ScanId
    }

    # --------------------------------------------------------
    # Define reusable screen renderer
    # --------------------------------------------------------

    $renderAction = {

        param($CurrentState)

        Show-WinSecCLICurrentScreen `
            -State $CurrentState `
            -Context $context
    }

    # --------------------------------------------------------
    # Render initial device selection screen
    # --------------------------------------------------------

    $null = & $renderAction $navigationState

    # --------------------------------------------------------
    # Interactive application loop
    # --------------------------------------------------------

    while (-not $navigationState.ExitRequested) {

        # ----------------------------------------------------
        # Read keyboard input with resize monitoring
        # ----------------------------------------------------

        $keyInfo = Read-WinSecResizeAwareKey `
            -ResizeState $resizeState `
            -RenderAction $renderAction `
            -NavigationState $navigationState

        # ----------------------------------------------------
        # Get action from centralized KeyboardController
        # ----------------------------------------------------

        $keyboardEvent = Get-WinSecKeyboardAction `
            -KeyInfo $keyInfo `
            -Screen $navigationState.Screen

        # Disabled or unsupported key
        if ($keyboardEvent.Action -eq 'None') {
            continue
        }

        # ----------------------------------------------------
        # Determine navigation boundaries
        # ----------------------------------------------------

        $counts = Get-WinSecCLINavigationCounts `
            -State $navigationState `
            -Context $context

        # ----------------------------------------------------
        # Apply navigation action
        # ----------------------------------------------------

        $null = Invoke-WinSecNavigationAction `
            -State $navigationState `
            -Action $keyboardEvent.Action `
            -Devices $registeredDevices `
            -SectionCount $counts.SectionCount `
            -ControlCount $counts.ControlCount `
            -FindingCount $counts.FindingCount `
            -SettingsCount $counts.SettingsCount

        # ----------------------------------------------------
        # Handle application lifecycle
        # ----------------------------------------------------

        if ($navigationState.ExitRequested) {
            break
        }

        # ----------------------------------------------------
        # Process device selection
        # ----------------------------------------------------

        if ($navigationState.PendingCommand -eq 'SelectDevice') {

            # The active device is already stored in
            # NavigationState.SelectedDeviceId.
            #
            # Assessment data is filtered dynamically.

            $navigationState.PendingCommand = $null
            $navigationState.PendingScope = $null
        }

        # ----------------------------------------------------
        # Keep unavailable operations disabled
        # ----------------------------------------------------

        if (
            $navigationState.PendingCommand -in @(
                'ExportTXT',
                'Rescan',
                'SelectSetting'
            )
        ) {

            # Export, rescan and settings editing
            # must be explicitly enabled only after
            # their implementations are connected.

            $navigationState.PendingCommand = $null
            $navigationState.PendingScope = $null
        }

        # ----------------------------------------------------
        # Redraw using the existing navigation state
        # ----------------------------------------------------

        if ($keyboardEvent.RequiresRedraw) {

            $null = & $renderAction $navigationState
        }
    }

    # --------------------------------------------------------
    # Close interactive session
    # --------------------------------------------------------

    Clear-WinSecScreen

    Write-WinSecText `
        -Text 'WinSec Analyzer session closed.' `
        -Color DarkGray
}
