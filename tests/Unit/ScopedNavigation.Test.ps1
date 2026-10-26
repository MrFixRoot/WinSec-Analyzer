# Scope resolution and keyboard contracts only; no scans or persistence.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ResultModel.ps1','src/CLI/Invoke-WinSecCLI.ps1',
    'src/UI/Core/KeyboardController.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1')){. (Join-Path $root $file)}
$script:passed=0;$script:failed=0
function Test-WinSecScopedKeys {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function Assert-WinSecScopedKeys {param([bool]$Condition);if(-not $Condition){throw 'Scoped keyboard assertion failed.'}}
function Invoke-WinSecCoordinatedScan {throw 'Unexpected scan.'}
foreach($screen in @('Devices','MainMenu','Section','Results')){
    Test-WinSecScopedKeys ('R requires backend eligibility on '+$screen) {
        $event=[pscustomobject]@{VirtualKeyCode=82;Character='R';KeyDown=$true;ControlKeyState=0}
        Assert-WinSecScopedKeys ((ConvertTo-WinSecKeyboardAction -KeyInfo $event -Screen $screen) -ceq 'None' -and
            (ConvertTo-WinSecKeyboardAction -KeyInfo $event -Screen $screen -EnableRescan) -ceq 'Rescan')
    }
}
foreach($screen in @('Section','Results')){
    Test-WinSecScopedKeys ('F opens findings and Enter is inactive on control list: '+$screen) {
        $state=New-WinSecNavigationState;$state.Screen=$screen;$state.ControlIndex=1
        $event=[pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0}
        $action=ConvertTo-WinSecKeyboardAction -KeyInfo $event -Screen $screen
        Assert-WinSecScopedKeys ($action -ceq 'None')
        $event.VirtualKeyCode=70;$event.Character='F'
        $action=ConvertTo-WinSecKeyboardAction -KeyInfo $event -Screen $screen
        $null=Invoke-WinSecNavigationAction -State $state -Action $action -ControlCount 3
        Assert-WinSecScopedKeys ($state.Screen -ceq 'Findings' -and $state.FindingsScope -ceq 'Control' -and
            $state.ControlIndex -eq 1 -and $null -eq $state.PendingCommand)
        $null=Invoke-WinSecNavigationAction -State $state -Action Back
        Assert-WinSecScopedKeys ($state.Screen -ceq $screen -and $state.ControlIndex -eq 1)
    }
}
foreach($spec in @(@{Screen='Section';SectionIndex=-1},@{Screen='Section';SectionIndex=5},
    @{Screen='Section';SectionIndex='0'},@{Screen='Findings';SectionIndex=0;FindingsScope='Unknown'},
    @{Screen='Findings';SectionIndex=0;FindingsScope='Control';ControlIndex=-1},
    @{Screen='Findings';SectionIndex=0;FindingsScope='Control';ControlIndex=999},
    @{Screen='Findings';SectionIndex=0;FindingsScope='Control';ControlIndex=@(0)},@{Screen='Unknown'})){
    Test-WinSecScopedKeys 'Invalid selections cannot silently scan a clamped or different target' {
        $caught=$false
        try{$null=Get-WinSecCLIScanScope -State ([pscustomobject]$spec)}catch{$caught=$true}
        Assert-WinSecScopedKeys $caught
    }
}
Test-WinSecScopedKeys 'Section/control resolution uses stable catalog identities for all controls' {
    $sections=@(Get-WinSecMainMenuSections)
    $count=0
    for($s=0;$s -lt $sections.Count;$s++){
        $controls=@(Get-WinSecSectionControls -SectionKey $sections[$s].Key)
        for($c=0;$c -lt $controls.Count;$c++){
            $scope=Get-WinSecCLIScanScope -State ([pscustomobject]@{Screen='Section';SectionIndex=$s;ControlIndex=$c})
            Assert-WinSecScopedKeys ($scope.ScopeType -ceq 'CONTROL' -and $scope.ScopeKey -ceq $controls[$c].CheckId)
            $count++
        }
    }
    Assert-WinSecScopedKeys ($count -eq 14)
}
Test-WinSecScopedKeys 'Findings disables R and H; P exports only when enabled' {
    foreach($spec in @(@{Code=82;Char='R'},@{Code=72;Char='H'},@{Code=13;Char=''},@{Code=80;Char='P'})) {
        $key=[pscustomobject]@{VirtualKeyCode=$spec.Code;Character=$spec.Char;ControlKeyState=0;KeyDown=$true}
        Assert-WinSecScopedKeys ((ConvertTo-WinSecKeyboardAction -KeyInfo $key -Screen Findings -EnableRescan) -ceq 'None')
    }
    $key=[pscustomobject]@{VirtualKeyCode=80;Character='P';ControlKeyState=0;KeyDown=$true}
    Assert-WinSecScopedKeys ((ConvertTo-WinSecKeyboardAction -KeyInfo $key -Screen Findings -EnableExport) -ceq 'ExportMD')
}
Test-WinSecScopedKeys 'Removed TXT shortcut cannot export even with export eligibility' {
    foreach($screen in @('Devices','MainMenu','Section','Results','Findings')) {
        $key=[pscustomobject]@{VirtualKeyCode=84;Character='T';ControlKeyState=0;KeyDown=$true}
        Assert-WinSecScopedKeys ((ConvertTo-WinSecKeyboardAction -KeyInfo $key -Screen $screen -EnableExport) -ceq 'None')
    }
}
Test-WinSecScopedKeys 'Legacy TXT navigation requests cannot queue an export' {
    foreach($screen in @('Devices','MainMenu','Section','Results','Findings')) {
        $state=New-WinSecNavigationState;$state.Screen=$screen
        $null=Invoke-WinSecNavigationAction -State $state -Action ExportTXT -SectionCount 5 -ControlCount 3
        Assert-WinSecScopedKeys ($null -eq $state.PendingCommand -and $null -eq $state.PendingScope -and $state.Screen -ceq $screen)
    }
}
Test-WinSecScopedKeys 'Device scan follows highlighted row even before opening it' {
    $state=[pscustomobject]@{Screen='Devices';DeviceIndex=1;SelectedDeviceId='local:OLD'}
    $id=Get-WinSecCLIScanDeviceId $state @([pscustomobject]@{DeviceId='local:OLD'},[pscustomobject]@{DeviceId='local:NEW'})
    Assert-WinSecScopedKeys ($id -ceq 'local:NEW' -and (Get-WinSecCLIScanScope $state).ScopeType -ceq 'DEVICE')
    $state.DeviceIndex=-1;$caught=$false;try{$null=Get-WinSecCLIScanDeviceId $state @()}catch{$caught=$true}
    Assert-WinSecScopedKeys $caught
}
Test-WinSecScopedKeys 'Length-prefixed scope keys distinguish devices sections and controls' {
    $keys=@((Get-WinSecCLIScopeKey 'local:A' SECTION SystemSecurity),
        (Get-WinSecCLIScopeKey 'local:A' CONTROL WSA-SYS-001),
        (Get-WinSecCLIScopeKey 'local:B' SECTION SystemSecurity))
    Assert-WinSecScopedKeys (@($keys|Select-Object -Unique).Count -eq 3)
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if($script:failed -gt 0){throw "$script:failed scoped keyboard test(s) failed."}
