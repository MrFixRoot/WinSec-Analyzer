
# ============================================================
# WinSec Analyzer
# Component : Invoke-WinSecCLI
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Main terminal interface controller.
# Supports multi-device navigation, security dashboards,
# findings, keyboard events and responsive layouts.
# ============================================================


# ------------------------------------------------------------
# Resolve project root
# ------------------------------------------------------------

$script:WinSecCLIProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)


# ------------------------------------------------------------
# Load UI components
# ------------------------------------------------------------

$script:WinSecUIComponents = @(
    'src/UI/Core/TerminalRenderer.ps1'
    'src/UI/Components/Banner.ps1'
    'src/UI/Components/Table.ps1'
    'src/UI/Components/KeyboardHelp.ps1'

    'src/UI/Core/KeyboardController.ps1'
    'src/UI/Core/NavigationController.ps1'
    'src/UI/Core/LayoutManager.ps1'
    'src/UI/Core/ResizeHandler.ps1'

    'src/UI/Screens/Devices.ps1'
    'src/UI/Screens/MainMenu.ps1'
    'src/UI/Screens/Results.ps1'
    'src/UI/Screens/Findings.ps1'
    'src/UI/Screens/Audit.ps1'
    'src/UI/Screens/Settings.ps1'
)

foreach ($component in $script:WinSecUIComponents) {

    $path = Join-Path `
        -Path $script:WinSecCLIProjectRoot `
        -ChildPath $component

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required UI component not found: $component"
    }

    . $path
}


# ------------------------------------------------------------
# Get registered devices
# ------------------------------------------------------------

function Get-WinSecCLIDevices {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Devices = @()
    )

    # Until TargetRegistry is connected, use the local
    # device when no explicit devices are provided.

    if ($Devices.Count -eq 0) {

        $hostname = [Environment]::MachineName

        return [PSCustomObject]@{
            DeviceId = "local:$hostname"
            Hostname = $hostname
            Mode     = 'LOCAL'
            Score    = $null
            Status   = 'PENDING'
            LastScan = $null
        }
    }

    $seen = @{}

    foreach ($device in $Devices) {

        if ($null -eq $device) {
            continue
        }

        $deviceId = (
            Get-WinSecTableValue `
                -Row $device -Key 'DeviceId'
        ).Trim()

        if ([string]::IsNullOrWhiteSpace($deviceId)) {
            continue
        }

        # Prevent duplicate device identifiers
        if ($seen.ContainsKey($deviceId)) {
            continue
        }

        $seen[$deviceId] = $true

        $hostname = Get-WinSecTableValue `
            -Row $device -Key 'Hostname'

        if ([string]::IsNullOrWhiteSpace($hostname)) {
            $hostname = Get-WinSecTableValue `
                -Row $device -Key 'Name'
        }

        if ([string]::IsNullOrWhiteSpace($hostname)) {
            $hostname = $deviceId
        }

        $mode = Get-WinSecTableValue `
            -Row $device -Key 'Mode'

        if ([string]::IsNullOrWhiteSpace($mode)) {
            $mode = 'UNKNOWN'
        }

        $status = Get-WinSecTableValue `
            -Row $device -Key 'Status'

        if ([string]::IsNullOrWhiteSpace($status)) {
            $status = 'PENDING'
        }

        [PSCustomObject]@{
            DeviceId = $deviceId
            Hostname = $hostname
            Mode     = $mode
            Score    = Get-WinSecTableValue `
                -Row $device -Key 'Score'
            Status   = $status
            LastScan = Get-WinSecTableValue `
                -Row $device -Key 'LastScan'
        }
    }
}


# ------------------------------------------------------------
# Get selected device
# ------------------------------------------------------------

function Get-WinSecCLISelectedDevice {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Devices = @(),

        [AllowNull()]
        [string]$DeviceId = $null
    )

    if ([string]::IsNullOrWhiteSpace($DeviceId)) {
        return $null
    }

    foreach ($device in $Devices) {

        if ($device.DeviceId -eq $DeviceId) {
            return $device
        }
    }

    return $null
}


# ------------------------------------------------------------
# Filter assessment data by device
# ------------------------------------------------------------

function Get-WinSecCLIDeviceResults {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Results = @(),

        [AllowNull()]
        [string]$DeviceId = $null
    )

    if ([string]::IsNullOrWhiteSpace($DeviceId)) {
        return
    }

    foreach ($result in $Results) {

        if ($null -eq $result) {
            continue
        }

        $resultDeviceId = Get-WinSecTableValue `
            -Row $result -Key 'DeviceId'

        # Records without DeviceId are not assigned
        # automatically to any selected device.

        if ($resultDeviceId -eq $DeviceId) {
            $result
        }
    }
}


# ------------------------------------------------------------
# Get device assessment summary
# ------------------------------------------------------------

function Get-WinSecCLIAssessmentSummary {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Device = $null
    )

    $score = $null
    $status = 'PENDING'

    if ($null -ne $Device) {

        $rawScore = Get-WinSecTableValue `
            -Row $Device -Key 'Score'

        $rawStatus = Get-WinSecTableValue `
            -Row $Device -Key 'Status'

        $parsedScore = 0

        if (
            [int]::TryParse(
                $rawScore,
                [ref]$parsedScore
            ) -and
            $parsedScore -ge 0 -and
            $parsedScore -le 100
        ) {
            $score = $parsedScore
        }

        if (-not [string]::IsNullOrWhiteSpace($rawStatus)) {
            $status = $rawStatus.ToUpperInvariant()
        }
    }

    return [PSCustomObject]@{
        Score  = $score
        Status = $status
    }
}


# ------------------------------------------------------------
# Get navigation context
# ------------------------------------------------------------

function Get-WinSecCLIContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$NavigationState,

        [object[]]$SectionResults = @(),

        [object[]]$ControlResults = @(),

        [object[]]$Findings = @()
    )

    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $SectionResults
    )

    $sectionCount = $sections.Count
    $controlCount = 0
    $findingCount = 0

    if ($sectionCount -gt 0) {

        $index = [Math]::Max(
            0,
            [Math]::Min(
                [int]$NavigationState.SectionIndex,
                $sectionCount - 1
            )
        )

        $section = $sections[$index]

        $controls = @(
            Get-WinSecSectionControls `
                -SectionKey $section.Key `
                -ControlResults $ControlResults
        )

        $controlCount = $controls.Count
    }

    if ($NavigationState.Screen -eq 'Findings') {

        $assessment = Get-WinSecSelectedFindings `
            -NavigationState $NavigationState `
            -SectionResults $SectionResults `
            -ControlResults $ControlResults `
            -Findings $Findings

        if ($null -ne $assessment) {
            $findingCount = $assessment.Findings.Count
        }
    }

    return [PSCustomObject]@{
        SectionCount  = $sectionCount
        ControlCount  = $controlCount
        FindingCount  = $findingCount
        SettingsCount = 0
    }
}


# ------------------------------------------------------------
# Show informational message
# ------------------------------------------------------------

function Show-WinSecCLIMessage {
    [CmdletBinding()]
    param(
        [string]$Title = 'Information',

        [string]$Message = '',

        [ConsoleColor]$Color = 'Yellow'
    )

    Clear-WinSecScreen

    Write-WinSecText `
        -Text 'WINSEC ANALYZER' `
        -Color Cyan `
        -Align Center

    Write-Host ''

    Write-WinSecSectionTitle -Title $Title

    Write-WinSecText `
        -Text $Message `
        -Color $Color

    Write-Host ''

    Write-WinSecDivider

    Write-WinSecText `
        -Text '[ANY KEY] Return' `
        -Color DarkGray

    $null = Read-WinSecKey
}


# ------------------------------------------------------------
# Render current screen
# ------------------------------------------------------------

function Show-WinSecCLIActiveScreen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$NavigationState,

        [object[]]$Devices = @(),

        [object[]]$SectionResults = @(),

        [object[]]$ControlResults = @(),

        [object[]]$Findings = @(),

        [AllowNull()]
        [object]$SelectedDevice = $null,

        [string]$Version = '0.9.0'
    )

    # Keep device identity visible in terminal title
    try {
        $windowTitle = "WinSec Analyzer v$Version"

        if ($null -ne $SelectedDevice) {
            $windowTitle += " | $($SelectedDevice.Hostname)"
        }

        $Host.UI.RawUI.WindowTitle = $windowTitle
    }
    catch {
        # Some hosts do not support title changes
    }

    switch ($NavigationState.Screen) {

        'Devices' {

            Show-WinSecDevices `
                -NavigationState $NavigationState `
                -Devices $Devices `
                -Version $Version
        }

        'MainMenu' {

            $summary = Get-WinSecCLIAssessmentSummary `
                -Device $SelectedDevice

            $parameters = @{
                NavigationState = $NavigationState
                SectionResults  = $SectionResults
                OverallStatus   = $summary.Status
                Version         = $Version
            }

            if ($null -ne $summary.Score) {
                $parameters.OverallScore = $summary.Score
            }

            Show-WinSecMainMenu @parameters
        }

        { $_ -in @('Section', 'Results') } {

            Show-WinSecResults `
                -NavigationState $NavigationState `
                -SectionResults $SectionResults `
                -ControlResults $ControlResults `
                -Version $Version
        }

        'Findings' {

            Show-WinSecFindings `
                -NavigationState $NavigationState `
                -SectionResults $SectionResults `
                -ControlResults $ControlResults `
                -Findings $Findings `
                -Version $Version
        }

        'Audit' {

            Show-WinSecAudit -Version $Version
        }

        'Settings' {

            Show-WinSecSettings `
                -NavigationState $NavigationState `
                -Version $Version
        }

        default {

            throw "Unknown UI screen: $($NavigationState.Screen)"
        }
    }
}


# ------------------------------------------------------------
# Main application controller
# ------------------------------------------------------------

function Invoke-WinSecCLI {
    [CmdletBinding()]
    param(
        [string]$Version = '0.9.0',

        [AllowEmptyCollection()]
        [object[]]$Devices = @(),

        [AllowEmptyCollection()]
        [object[]]$SectionResults = @(),

        [AllowEmptyCollection()]
        [object[]]$ControlResults = @(),

        [AllowEmptyCollection()]
        [object[]]$Findings = @()
    )

    # --------------------------------------------------------
    # Initialize device registry
    # --------------------------------------------------------

    $registeredDevices = @(
        Get-WinSecCLIDevices -Devices $Devices
    )

    if ($registeredDevices.Count -eq 0) {
        throw 'No valid devices are registered.'
    }

    # --------------------------------------------------------
    # Initialize navigation and resize state
    # --------------------------------------------------------

    $navigation = New-WinSecNavigationState
    $resizeState = New-WinSecResizeState

    # --------------------------------------------------------
    # Application event loop
    # --------------------------------------------------------

    while (-not $navigation.ExitRequested) {

        # Resolve active device
        $selectedDevice = Get-WinSecCLISelectedDevice `
            -Devices $registeredDevices `
            -DeviceId $navigation.SelectedDeviceId

        # Prevent displaying another device's data
        if (
            $navigation.Screen -ne 'Devices' -and
            $null -eq $selectedDevice
        ) {
            $navigation.Screen = 'Devices'
            $navigation.SelectedDeviceId = $null
            $navigation.SelectedDeviceName = $null
        }

        # ----------------------------------------------------
        # Load device-specific assessment data
        # ----------------------------------------------------

        $deviceSections = @()
        $deviceControls = @()
        $deviceFindings = @()

        if ($null -ne $selectedDevice) {

            $deviceId = $selectedDevice.DeviceId

            $deviceSections = @(
                Get-WinSecCLIDeviceResults `
                    -Results $SectionResults `
                    -DeviceId $deviceId
            )

            $deviceControls = @(
                Get-WinSecCLIDeviceResults `
                    -Results $ControlResults `
                    -DeviceId $deviceId
            )

            $deviceFindings = @(
                Get-WinSecCLIDeviceResults `
                    -Results $Findings `
                    -DeviceId $deviceId
            )
        }

        # ----------------------------------------------------
        # Render screen
        # ----------------------------------------------------

        Show-WinSecCLIActiveScreen `
            -NavigationState $navigation `
            -Devices $registeredDevices `
            -SectionResults $deviceSections `
            -ControlResults $deviceControls `
            -Findings $deviceFindings `
            -SelectedDevice $selectedDevice `
            -Version $Version

        Reset-WinSecRedraw -State $resizeState

        # ----------------------------------------------------
        # Wait for keyboard input or resize
        # ----------------------------------------------------

        $uiEvent = Wait-WinSecUIEvent `
            -ResizeState $resizeState `
            -Screen $navigation.Screen

        if ($uiEvent.EventType -eq 'Resize') {
            continue
        }

        if ($uiEvent.ResizeDetected) {
            Request-WinSecRedraw -State $resizeState
        }

        if (
            [string]::IsNullOrWhiteSpace($uiEvent.Action) -or
            $uiEvent.Action -eq 'None'
        ) {
            continue
        }

        # ----------------------------------------------------
        # Calculate navigation context
        # ----------------------------------------------------

        $context = Get-WinSecCLIContext `
            -NavigationState $navigation `
            -SectionResults $deviceSections `
            -ControlResults $deviceControls `
            -Findings $deviceFindings

        # ----------------------------------------------------
        # Process navigation
        # ----------------------------------------------------

        $navigation = Invoke-WinSecNavigationAction `
            -State $navigation `
            -Action $uiEvent.Action `
            -Devices $registeredDevices `
            -SectionCount $context.SectionCount `
            -ControlCount $context.ControlCount `
            -FindingCount $context.FindingCount `
            -SettingsCount $context.SettingsCount

        # ----------------------------------------------------
        # Process application commands
        # ----------------------------------------------------

        $command = $navigation.PendingCommand

        if ([string]::IsNullOrWhiteSpace($command)) {
            continue
        }

        switch ($command) {

            'SelectDevice' {

                # The next rendering cycle automatically
                # loads data filtered by SelectedDeviceId.
            }

            'ExportTXT' {

                Show-WinSecCLIMessage `
                    -Title 'Export Report' `
                    -Message 'TXT export is not connected yet.'
            }

            'Rescan' {

                Show-WinSecCLIMessage `
                    -Title 'Security Assessment' `
                    -Message 'The audit engine is not connected yet.'
            }

            'SelectSetting' {

                Show-WinSecCLIMessage `
                    -Title 'Settings' `
                    -Message 'Configuration editing is not available yet.'
            }

            'Exit' {

                $navigation.ExitRequested = $true
            }
        }

        # Clear processed command
        $navigation.PendingCommand = $null
        $navigation.PendingScope = $null
    }

    # --------------------------------------------------------
    # Clean application exit
    # --------------------------------------------------------

    Clear-WinSecScreen

    Write-WinSecText `
        -Text 'WINSEC ANALYZER' `
        -Color Cyan `
        -Align Center

    Write-Host ''

    Write-WinSecText `
        -Text 'Session closed.' `
        -Color DarkGray `
        -Align Center

    Write-Host ''
}


# ------------------------------------------------------------
# Direct execution support
# ------------------------------------------------------------

# Direct:
# .\src\CLI\Invoke-WinSecCLI.ps1
#
# Dot-source:
# . .\src\CLI\Invoke-WinSecCLI.ps1
# Invoke-WinSecCLI

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-WinSecCLI
}
