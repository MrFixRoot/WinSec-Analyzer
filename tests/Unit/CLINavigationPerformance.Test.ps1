# Navigation counts for ordinary keys must not rebuild public assessments/exports.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1')){. (Join-Path $root $file)}
function Get-WinSecCLIActiveAssessment {throw 'DEEP_ASSESSMENT_REQUESTED'}
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Get-MpComputerStatus {throw 'Unexpected Windows query.'}
function Get-MpPreference {throw 'Unexpected Windows query.'}
$script:passed=0;$script:failed=0
function Assert-WinSecFastNavigation {param([bool]$Value);if(-not $Value){throw 'Fast navigation assertion failed.'}}
function Test-WinSecFastNavigation {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
Test-WinSecFastNavigation 'Moving and opening sections uses catalog counts without preparing findings' {
    $state=New-WinSecNavigationState;$state.Screen='MainMenu';$state.SelectedDeviceId='local:SYNTHETIC-NAVIGATION'
    $c=Get-WinSecCLINavigationCounts $state ([pscustomobject]@{}) -Action MoveDown
    Assert-WinSecFastNavigation ($c.SectionCount -eq 5 -and $c.FindingCount -eq 0)
    $null=Invoke-WinSecNavigationAction $state Open -SectionCount $c.SectionCount
    Assert-WinSecFastNavigation ($state.Screen -ceq 'Section')
}
Test-WinSecFastNavigation 'Moving controls and opening Findings preserves control boundaries' {
    $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId='local:SYNTHETIC-NAVIGATION'
    $c=Get-WinSecCLINavigationCounts $state ([pscustomobject]@{}) -Action MoveDown
    Assert-WinSecFastNavigation ($c.ControlCount -eq 3 -and $c.FindingCount -eq 0)
    $null=Invoke-WinSecNavigationAction $state MoveDown -ControlCount $c.ControlCount
    Assert-WinSecFastNavigation ($state.ControlIndex -eq 1)
    $null=Invoke-WinSecNavigationAction $state ShowFindings -ControlCount $c.ControlCount
    Assert-WinSecFastNavigation ($state.Screen -ceq 'Findings' -and $state.FindingsScope -ceq 'Control')
}
Test-WinSecFastNavigation 'Scrolling up does not require rebuilding the findings count' {
    $state=New-WinSecNavigationState;$state.Screen='Findings';$state.FindingsOffset=3
    $c=Get-WinSecCLINavigationCounts $state ([pscustomobject]@{}) -Action ScrollUp
    $null=Invoke-WinSecNavigationAction $state ScrollUp -FindingCount $c.FindingCount
    Assert-WinSecFastNavigation ($state.FindingsOffset -eq 2)
}
foreach($navigationAction in @('ScrollDown','')) {
    Test-WinSecFastNavigation ('Scroll bounds and compatibility calls still validate the full assessment: '+$navigationAction) {
        $state=New-WinSecNavigationState;$state.Screen='Findings';$caught=$false
        try{$null=Get-WinSecCLINavigationCounts $state ([pscustomobject]@{}) -Action $navigationAction}
        catch{$caught=$_.Exception.Message -ceq 'DEEP_ASSESSMENT_REQUESTED'}
        Assert-WinSecFastNavigation $caught
    }
}
[Console]::WriteLine(('CLI navigation performance: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'CLI navigation performance tests failed.'}
