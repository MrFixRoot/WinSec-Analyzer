
# ============================================================
# WinSec Analyzer
# Test Suite : BasicIntegration
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Basic integration verification without Pester.
#
# Compatible with Windows PowerShell 5.1+
# No administrative privileges required.
# .\tests\Integration\BasicIntegration.Tests.ps1
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)

$script:Passed = 0
$script:Failed = 0

# ------------------------------------------------------------
# Test utilities
# ------------------------------------------------------------

function Assert-WinSecTest {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-WinSecTest {
    param(
        [string]$Name,
        [scriptblock]$Test
    )

    try {
        & $Test

        $script:Passed++

        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:Failed++

        Write-Host "[FAIL] $Name" -ForegroundColor Red
        Write-Host "       $($_.Exception.Message)" `
            -ForegroundColor DarkGray
    }
}

function New-WinSecTestKey {
    param(
        [int]$Code,
        [char]$Character = [char]0,
        [int]$Modifiers = 0
    )

    return [PSCustomObject]@{
        VirtualKeyCode  = $Code
        Character       = $Character
        ControlKeyState = $Modifiers
        KeyDown         = $true
    }
}

# ------------------------------------------------------------
# Load application components
# ------------------------------------------------------------

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
    'src/CLI/Invoke-WinSecCLI.ps1'
)

Write-Host ''
Write-Host 'WINSEC ANALYZER - BASIC INTEGRATION TESTS' `
    -ForegroundColor Cyan

Write-Host ('=' * 45) -ForegroundColor DarkGray
Write-Host ''

foreach ($module in $modules) {

    $path = Join-Path $projectRoot $module

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required file not found: $module"
    }

    try {
        . $path
    }
    catch {
        throw "Unable to load ${module}: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------
# 1. Keyboard integration
# ------------------------------------------------------------

Write-Host '[1] KEYBOARD' -ForegroundColor Cyan

Invoke-WinSecTest 'Arrow Up on Devices' {

    $key = New-WinSecTestKey -Code 38

    $action = ConvertTo-WinSecKeyboardAction `
        -KeyInfo $key -Screen 'Devices'

    Assert-WinSecTest ($action -eq 'MoveUp') `
        "Expected MoveUp, received $action"
}

Invoke-WinSecTest 'Arrow Down on MainMenu' {

    $key = New-WinSecTestKey -Code 40

    $action = ConvertTo-WinSecKeyboardAction `
        -KeyInfo $key -Screen 'MainMenu'

    Assert-WinSecTest ($action -eq 'MoveDown') `
        "Expected MoveDown, received $action"
}

Invoke-WinSecTest 'Enter selects a device' {

    $key = New-WinSecTestKey -Code 13

    $action = ConvertTo-WinSecKeyboardAction `
        -KeyInfo $key -Screen 'Devices'

    Assert-WinSecTest ($action -eq 'Open') `
        "Expected Open, received $action"
}

Invoke-WinSecTest 'ESC returns from Findings' {

    $key = New-WinSecTestKey -Code 27

    $action = ConvertTo-WinSecKeyboardAction `
        -KeyInfo $key -Screen 'Findings'

    Assert-WinSecTest ($action -eq 'Back') `
        "Expected Back, received $action"
}

Invoke-WinSecTest 'H opens security findings' {

    $key = New-WinSecTestKey `
        -Code 72 -Character 'H'

    $action = ConvertTo-WinSecKeyboardAction `
        -KeyInfo $key -Screen 'Section'

    Assert-WinSecTest ($action -eq 'ShowFindings') `
        "Expected ShowFindings, received $action"
}

Invoke-WinSecTest 'Q exits from Devices' {

    $key = New-WinSecTestKey `
        -Code 81 -Character 'Q'

    $action = ConvertTo-WinSecKeyboardAction `
        -KeyInfo $key -Screen 'Devices'

    Assert-WinSecTest ($action -eq 'Exit') `
        "Expected Exit, received $action"
}

Invoke-WinSecTest 'P and R remain disabled' {

    $exportKey = New-WinSecTestKey `
        -Code 80 -Character 'P'

    $rescanKey = New-WinSecTestKey `
        -Code 82 -Character 'R'

    $exportAction = ConvertTo-WinSecKeyboardAction `
        -KeyInfo $exportKey -Screen 'Findings'

    $rescanAction = ConvertTo-WinSecKeyboardAction `
        -KeyInfo $rescanKey -Screen 'MainMenu'

    Assert-WinSecTest (
        $exportAction -eq 'None' -and
        $rescanAction -eq 'None'
    ) 'Unavailable commands must remain disabled.'
}

Invoke-WinSecTest 'Ctrl shortcuts are ignored' {

    $key = New-WinSecTestKey `
        -Code 72 -Character 'H' -Modifiers 8

    $action = ConvertTo-WinSecKeyboardAction `
        -KeyInfo $key -Screen 'Section'

    Assert-WinSecTest ($action -eq 'None') `
        'Ctrl+H should not trigger findings.'
}

Write-Host ''

# ------------------------------------------------------------
# 2. Navigation integration
# ------------------------------------------------------------

Write-Host '[2] NAVIGATION' -ForegroundColor Cyan

$testDevices = @(
    [PSCustomObject]@{
        DeviceId = 'TEST-PC-01'
        Hostname = 'TEST-PC-01'
    }
    [PSCustomObject]@{
        DeviceId = 'TEST-PC-02'
        Hostname = 'TEST-PC-02'
    }
)

Invoke-WinSecTest 'Device selection opens dashboard' {

    $state = New-WinSecNavigationState

    $null = Invoke-WinSecNavigationAction `
        -State $state `
        -Action 'Open' `
        -Devices $testDevices

    Assert-WinSecTest (
        $state.Screen -eq 'MainMenu' -and
        $state.SelectedDeviceId -eq 'TEST-PC-01'
    ) 'Device context was not preserved.'
}

Invoke-WinSecTest 'Complete navigation and ESC history' {

    $state = New-WinSecNavigationState

    $null = Invoke-WinSecNavigationAction `
        -State $state -Action 'Open' `
        -Devices $testDevices

    $state.SectionIndex = 2

    $null = Invoke-WinSecNavigationAction `
        -State $state -Action 'Open' `
        -SectionCount 5

    $state.ControlIndex = 1

    $null = Invoke-WinSecNavigationAction `
        -State $state -Action 'ShowFindings' `
        -ControlCount 3

    Assert-WinSecTest (
        $state.Screen -eq 'Findings' -and
        $state.FindingsScope -eq 'Control'
    ) 'Findings screen did not open correctly.'

    $null = Invoke-WinSecNavigationAction `
        -State $state -Action 'Back'

    Assert-WinSecTest (
        $state.Screen -eq 'Section' -and
        $state.ControlIndex -eq 1 -and
        $state.SectionIndex -eq 2
    ) 'ESC did not restore the selected control.'

    $null = Invoke-WinSecNavigationAction `
        -State $state -Action 'Back'

    Assert-WinSecTest (
        $state.Screen -eq 'MainMenu' -and
        $state.SectionIndex -eq 2 -and
        $state.SelectedDeviceId -eq 'TEST-PC-01'
    ) 'ESC did not restore the dashboard context.'

    $null = Invoke-WinSecNavigationAction `
        -State $state -Action 'Back'

    Assert-WinSecTest (
        $state.Screen -eq 'Devices'
    ) 'ESC did not return to Devices.'
}

Invoke-WinSecTest 'Finding selection scrolls correctly' {

    $state = New-WinSecNavigationState

    $state.Screen = 'Findings'

    $null = Invoke-WinSecNavigationAction `
        -State $state `
        -Action 'ScrollDown' `
        -FindingCount 3

    Assert-WinSecTest (
        $state.FindingsOffset -eq 1
    ) 'Finding cursor did not advance.'

    $null = Invoke-WinSecNavigationAction `
        -State $state `
        -Action 'ScrollUp' `
        -FindingCount 3

    Assert-WinSecTest (
        $state.FindingsOffset -eq 0
    ) 'Finding cursor did not return.'
}

Invoke-WinSecTest 'Five security sections are registered' {

    $sections = @(
        Get-WinSecMainMenuSections
    )

    Assert-WinSecTest (
        $sections.Count -eq 5
    ) "Expected 5 sections, found $($sections.Count)."

    foreach ($section in $sections) {

        $controls = @(
            Get-WinSecSectionControls `
                -SectionKey $section.Key
        )

        Assert-WinSecTest (
            $controls.Count -gt 0
        ) "Section $($section.Key) has no controls."
    }
}

Write-Host ''

# ------------------------------------------------------------
# 3. Adaptive layout and resize integration
# ------------------------------------------------------------

Write-Host '[3] LAYOUT AND RESIZE' -ForegroundColor Cyan

# Replace terminal measurements temporarily.
# This does not resize or modify the real terminal.

$originalTerminalFunction = (
    Get-Command 'Get-WinSecTerminalSize' `
        -CommandType Function
).ScriptBlock

$script:WinSecMockWidth = 120
$script:WinSecMockHeight = 55
$script:WinSecTestRenderCount = 0

try {

    Set-Item `
        -Path Function:\Get-WinSecTerminalSize `
        -Value {

            [PSCustomObject]@{
                Width = $script:WinSecMockWidth
                Height = $script:WinSecMockHeight
                ContentWidth = [Math]::Max(
                    1,
                    $script:WinSecMockWidth - 2
                )
            }
        }

    Invoke-WinSecTest 'Full terminal layout' {

        $script:WinSecMockWidth = 120
        $script:WinSecMockHeight = 55

        $layout = Get-WinSecLayout -Screen 'Devices'

        Assert-WinSecTest (
            $layout.Mode -eq 'Full' -and
            $layout.MaxTableRows -gt 0 -and
            -not $layout.IsTooSmall
        ) 'Full layout dimensions are incorrect.'
    }

    Invoke-WinSecTest 'Compact terminal layout' {

        $script:WinSecMockWidth = 78
        $script:WinSecMockHeight = 28

        $layout = Get-WinSecLayout -Screen 'Devices'

        Assert-WinSecTest (
            $layout.Mode -eq 'Compact' -and
            $layout.MaxTableRows -gt 0
        ) 'Compact layout dimensions are incorrect.'
    }

    Invoke-WinSecTest 'Minimal terminal layout' {

        $script:WinSecMockWidth = 45
        $script:WinSecMockHeight = 24

        $layout = Get-WinSecLayout -Screen 'Devices'

        Assert-WinSecTest (
            $layout.Mode -eq 'Minimal' -and
            -not $layout.IsTooSmall
        ) 'Minimal layout dimensions are incorrect.'
    }

    Invoke-WinSecTest 'Undersized terminal detection' {

        $script:WinSecMockWidth = 38
        $script:WinSecMockHeight = 18

        $layout = Get-WinSecLayout -Screen 'Devices'

        Assert-WinSecTest (
            $layout.IsTooSmall
        ) 'Small terminal was not detected.'
    }

    Invoke-WinSecTest 'Resize triggers exactly one redraw' {

        $script:WinSecMockWidth = 100
        $script:WinSecMockHeight = 40
        $script:WinSecTestRenderCount = 0

        $resizeState = New-WinSecResizeState

        $navigation = New-WinSecNavigationState
        $navigation.Screen = 'Findings'
        $navigation.SectionIndex = 2
        $navigation.ControlIndex = 1
        $navigation.SelectedDeviceId = 'TEST-PC-01'

        $renderAction = {
            param($State)

            $script:WinSecTestRenderCount++
        }

        # Simulate maximizing the terminal.
        $script:WinSecMockWidth = 140
        $script:WinSecMockHeight = 60

        $first = Invoke-WinSecResizeHandler `
            -ResizeState $resizeState `
            -NavigationState $navigation `
            -RenderAction $renderAction

        $second = Invoke-WinSecResizeHandler `
            -ResizeState $resizeState `
            -NavigationState $navigation `
            -RenderAction $renderAction

        Assert-WinSecTest (
            $first -eq $true -and
            $second -eq $false -and
            $script:WinSecTestRenderCount -eq 1
        ) 'Resize produced an incorrect redraw count.'

        Assert-WinSecTest (
            $navigation.Screen -eq 'Findings' -and
            $navigation.SectionIndex -eq 2 -and
            $navigation.ControlIndex -eq 1 -and
            $navigation.SelectedDeviceId -eq 'TEST-PC-01'
        ) 'Resize changed the navigation state.'
    }
}
finally {

    # Restore original terminal measurements.
    Set-Item `
        -Path Function:\Get-WinSecTerminalSize `
        -Value $originalTerminalFunction
}

Write-Host ''

# ------------------------------------------------------------
# 4. Multi-device assessment isolation
# ------------------------------------------------------------

Write-Host '[4] ASSESSMENT ISOLATION' -ForegroundColor Cyan

Invoke-WinSecTest 'Results remain isolated by DeviceId' {

    $state = New-WinSecNavigationState

    $state.SelectedDeviceId = 'TEST-PC-01'

    $context = [PSCustomObject]@{
        ScanId = ''

        Devices = @(
            [PSCustomObject]@{
                DeviceId = 'TEST-PC-01'
                ScanId = 'SCAN-01'
                Score = 90
                Status = 'PASS'
            }
            [PSCustomObject]@{
                DeviceId = 'TEST-PC-02'
                ScanId = 'SCAN-02'
                Score = 40
                Status = 'FAIL'
            }
        )

        SectionResults = @(
            [PSCustomObject]@{
                DeviceId = 'TEST-PC-01'
                ScanId = 'SCAN-01'
                Key = 'SystemSecurity'
                Score = $null
                Status = 'NOT_SCORED'
            }
            [PSCustomObject]@{
                DeviceId = 'TEST-PC-02'
                ScanId = 'SCAN-02'
                Key = 'SystemSecurity'
                Score = $null
                Status = 'NOT_SCORED'
            }
        )

        ControlResults = @()

        Findings = @(
            [PSCustomObject]@{
                DeviceId = 'TEST-PC-01'
                ScanId = 'SCAN-01'
                SectionKey = 'SystemSecurity'
                Severity = 'LOW'
            }
            [PSCustomObject]@{
                DeviceId = 'TEST-PC-02'
                ScanId = 'SCAN-02'
                SectionKey = 'SystemSecurity'
                Severity = 'HIGH'
            }
        )
    }

    $assessment = Get-WinSecCLIActiveAssessment `
        -State $state `
        -Context $context

    Assert-WinSecTest (
        $assessment.ScanId -eq 'SCAN-01' -and
        $assessment.SectionResults.Count -eq 1 -and
        $assessment.Findings.Count -eq 1 -and
        $null -eq $assessment.OverallScore -and
        $assessment.OverallStatus -eq 'NOT_SCORED' -and
        $null -eq $assessment.SectionResults[0].Score
    ) 'Assessment data crossed device boundaries.'

    Assert-WinSecTest (
        $assessment.Findings[0].DeviceId -eq 'TEST-PC-01'
    ) 'A finding belongs to the wrong device.'
}

Invoke-WinSecTest 'Legacy section scores cannot authorize a scored assessment' {
    $state = New-WinSecNavigationState
    $state.SelectedDeviceId = 'TEST-PC-01'
    $context = [pscustomobject]@{
        ScanId = 'SCAN-01'
        Devices = @()
        SectionResults = @(
            [pscustomobject]@{
                DeviceId = 'TEST-PC-01'
                ScanId = 'SCAN-01'
                Key = 'SystemSecurity'
                Score = 90
            }
        )
        ControlResults = @()
        Findings = @()
    }
    $rejected = $false
    $assessment = $null
    try {
        $assessment = Get-WinSecCLIActiveAssessment `
            -State $state -Context $context
    }
    catch {
        $rejected = $true
    }

    Assert-WinSecTest (
        $rejected -and $null -eq $assessment
    ) 'An unapproved section score reached the assessment.'
}

Invoke-WinSecTest 'Different scans are not combined' {

    $state = New-WinSecNavigationState
    $state.SelectedDeviceId = 'TEST-PC-01'

    $context = [PSCustomObject]@{
        ScanId = ''
        Devices = @()
        SectionResults = @()
        ControlResults = @()

        Findings = @(
            [PSCustomObject]@{
                DeviceId = 'TEST-PC-01'
                ScanId = 'SCAN-01'
            }
            [PSCustomObject]@{
                DeviceId = 'TEST-PC-01'
                ScanId = 'SCAN-02'
            }
        )
    }

    $assessment = Get-WinSecCLIActiveAssessment `
        -State $state `
        -Context $context

    Assert-WinSecTest (
        $assessment.Warning -ne '' -and
        $assessment.Findings.Count -eq 0
    ) 'Different scan executions were combined.'
}

# ------------------------------------------------------------
# 5. Finding prioritization
# ------------------------------------------------------------

Write-Host ''
Write-Host '[5] FINDING PRIORITIZATION' -ForegroundColor Cyan

Invoke-WinSecTest 'Findings are ordered by severity' {

    $command = Get-Command `
        -Name 'Invoke-WinSecFindingPrioritization' `
        -CommandType Function `
        -ErrorAction Stop

    $sample = @(
        [PSCustomObject]@{
            Id = 'F-LOW'
            Severity = 'LOW'
        }
        [PSCustomObject]@{
            Id = 'F-CRITICAL'
            Severity = 'CRITICAL'
        }
        [PSCustomObject]@{
            Id = 'F-HIGH'
            Severity = 'HIGH'
        }
    )

    $result = @(
        Invoke-WinSecFindingPrioritization `
            -Findings $sample
    )

    Assert-WinSecTest (
        $result.Count -eq 3 -and
        $result[0].Id -eq 'F-CRITICAL' -and
        $result[0].Priority -eq 'P1' -and
        $result[1].Priority -eq 'P2' -and
        $result[2].Priority -eq 'P4'
    ) 'Finding priority order is incorrect.'
}

# ------------------------------------------------------------
# Final summary
# ------------------------------------------------------------

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 45) -ForegroundColor DarkGray
Write-Host 'BASIC INTEGRATION TEST SUMMARY' `
    -ForegroundColor Cyan

Write-Host ''
Write-Host "Total tests : $total"
Write-Host "Passed      : $script:Passed" `
    -ForegroundColor Green

$failureColor = if ($script:Failed -gt 0) {
    'Red'
}
else {
    'Green'
}

Write-Host "Failed      : $script:Failed" `
    -ForegroundColor $failureColor

Write-Host ''

if ($script:Failed -gt 0) {
    throw "$($script:Failed) integration test(s) failed."
}

Write-Host 'Basic integration checks passed.' `
    -ForegroundColor Green

Write-Host ''
Write-Host 'Next: perform manual terminal interaction tests.' `
    -ForegroundColor DarkGray
