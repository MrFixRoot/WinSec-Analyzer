
# ============================================================
# WinSec Analyzer
# Component : Invoke-WinSecCLI
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Main terminal UI controller.
# Integrates rendering, navigation, keyboard input,
# terminal resizing and security assessment screens.
# ============================================================


# ------------------------------------------------------------
# Resolve project root
# ------------------------------------------------------------

$script:WinSecCLIProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)


# ------------------------------------------------------------
# Load UI components in dependency order
# ------------------------------------------------------------

function Import-WinSecUIComponents {
    [CmdletBinding()]
    param()

    $components = @(
        'src/UI/Core/TerminalRenderer.ps1'
        'src/UI/Components/Banner.ps1'
        'src/UI/Components/Table.ps1'
        'src/UI/Components/KeyboardHelp.ps1'

        'src/UI/Core/KeyboardController.ps1'
        'src/UI/Core/NavigationController.ps1'
        'src/UI/Core/LayoutManager.ps1'
        'src/UI/Core/ResizeHandler.ps1'

        'src/UI/Screens/MainMenu.ps1'
        'src/UI/Screens/Results.ps1'
        'src/UI/Screens/Findings.ps1'
        'src/UI/Screens/Audit.ps1'
        'src/UI/Screens/Settings.ps1'
    )

    foreach ($component in $components) {

        $path = Join-Path `
            -Path $script:WinSecCLIProjectRoot `
            -ChildPath $component

        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required UI component not found: $component"
        }

        # Load functions into the calling scope.
        . $path
    }
}


# ------------------------------------------------------------
# Display informational messages
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
        -Text '[ANY KEY] Return to dashboard' `
        -Color DarkGray

    $null = Read-WinSecKey
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

        $sectionIndex = [Math]::Max(
            0,
            [Math]::Min(
                [int]$NavigationState.SectionIndex,
                $sectionCount - 1
            )
        )

        $section = $sections[$sectionIndex]

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
# Render active UI screen
# ------------------------------------------------------------

function Show-WinSecActiveScreen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$NavigationState,

        [object[]]$SectionResults = @(),

        [object[]]$ControlResults = @(),

        [object[]]$Findings = @(),

        [Nullable[int]]$OverallScore = $null,

        [string]$OverallStatus = 'PENDING',

        [string]$Version = '0.9.0'
    )

    switch ($NavigationState.Screen) {

        'MainMenu' {

            $parameters = @{
                NavigationState = $NavigationState
                SectionResults  = $SectionResults
                OverallStatus   = $OverallStatus
                Version         = $Version
            }

            if ($null -ne $OverallScore) {
                $parameters.OverallScore = $OverallScore
            }

            Show-WinSecMainMenu @parameters
        }

        'Section' {

            # Section screen is rendered by Results.ps1
            Show-WinSecResults `
                -NavigationState $NavigationState `
                -SectionResults $SectionResults `
                -ControlResults $ControlResults `
                -Version $Version
        }

        'Results' {

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

            $NavigationState.Screen = 'MainMenu'

            Show-WinSecMainMenu `
                -NavigationState $NavigationState `
                -SectionResults $SectionResults `
                -Version $Version
        }
    }
}


# ------------------------------------------------------------
# Main CLI execution
# ------------------------------------------------------------

function Invoke-WinSecCLI {
    [CmdletBinding()]
    param(
        [string]$Version = '0.9.0',

        [object[]]$SectionResults = @(),

        [object[]]$ControlResults = @(),

        [object[]]$Findings = @(),

        [Nullable[int]]$OverallScore = $null,

        [string]$OverallStatus = 'PENDING'
    )

    # --------------------------------------------------------
    # Load application components
    # --------------------------------------------------------

    try {
        # Dot-source in this function's scope so the
        # loaded functions remain available during execution.
        . Import-WinSecUIComponents
    }
    catch {
        Write-Host ''
        Write-Host 'WINSEC ANALYZER - STARTUP ERROR' `
            -ForegroundColor Red

        Write-Host $_.Exception.Message `
            -ForegroundColor Yellow

        return
    }

    # --------------------------------------------------------
    # Initialize application state
    # --------------------------------------------------------

    $navigation = New-WinSecNavigationState

    $resizeState = New-WinSecResizeState

    # --------------------------------------------------------
    # Main application event loop
    # --------------------------------------------------------

    while (-not $navigation.ExitRequested) {

        # Render current screen
        Show-WinSecActiveScreen `
            -NavigationState $navigation `
            -SectionResults $SectionResults `
            -ControlResults $ControlResults `
            -Findings $Findings `
            -OverallScore $OverallScore `
            -OverallStatus $OverallStatus `
            -Version $Version

        # Clear completed redraw request
        Reset-WinSecRedraw -State $resizeState

        # ----------------------------------------------------
        # Wait for keyboard input or terminal resize
        # ----------------------------------------------------

        $uiEvent = Wait-WinSecUIEvent `
            -ResizeState $resizeState `
            -Screen $navigation.Screen

        # Redraw when terminal dimensions change
        if ($uiEvent.EventType -eq 'Resize') {
            continue
        }

        if ($uiEvent.ResizeDetected) {
            Request-WinSecRedraw -State $resizeState
        }

        # Ignore unsupported keys
        if (
            [string]::IsNullOrWhiteSpace($uiEvent.Action) -or
            $uiEvent.Action -eq 'None'
        ) {
            continue
        }

        # ----------------------------------------------------
        # Resolve navigation context
        # ----------------------------------------------------

        $context = Get-WinSecCLIContext `
            -NavigationState $navigation `
            -SectionResults $SectionResults `
            -ControlResults $ControlResults `
            -Findings $Findings

        # ----------------------------------------------------
        # Process keyboard action
        # ----------------------------------------------------

        $navigation = Invoke-WinSecNavigationAction `
            -State $navigation `
            -Action $uiEvent.Action `
            -SectionCount $context.SectionCount `
            -ControlCount $context.ControlCount `
            -FindingCount $context.FindingCount `
            -SettingsCount $context.SettingsCount

        # ----------------------------------------------------
        # Process pending application commands
        # ----------------------------------------------------

        $command = $navigation.PendingCommand

        if (-not [string]::IsNullOrWhiteSpace($command)) {

            switch ($command) {

                'ExportTXT' {

                    # ExportService.ps1 will handle actual
                    # report generation in a later stage.

                    Show-WinSecCLIMessage `
                        -Title 'Export Report' `
                        -Message 'TXT export is not connected yet.'
                }

                'Rescan' {

                    # AuditEngine.ps1 will execute real
                    # security checks once integrated.

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
# Allow direct execution for UI testing
# ------------------------------------------------------------

# Direct execution:
#   .\src\CLI\Invoke-WinSecCLI.ps1
#
# Dot-source without automatic execution:
#   . .\src\CLI\Invoke-WinSecCLI.ps1
#   Invoke-WinSecCLI

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-WinSecCLI
}
