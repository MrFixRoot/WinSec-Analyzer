# Descubrimiento y selector reales con 101 perfiles; teclado y terminal sintéticos.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/UI/Screens/AssessmentProfileSelection.ps1')
function Get-CimInstance {throw 'Unexpected Windows query in profile UI integration.'}
function Get-MpComputerStatus {throw 'Unexpected Defender query in profile UI integration.'}
function Get-MpPreference {throw 'Unexpected Defender query in profile UI integration.'}
$profiles=@(Get-WinSecAssessmentProfileOptions $root @('WSA-SYS-001'))
$request=[pscustomobject]@{Operation='SCAN';ReadOnly=$true;DeviceId='local:PROFILE-MATRIX';Hostname='SYNTHETIC';
    ScopeType='CONTROL';ScopeKey='WSA-SYS-001';Checks=@([pscustomobject]@{CheckId='WSA-SYS-001';SectionKey='SystemSecurity'})}
$script:passed=0;$script:failed=0
function Assert-WinSecMatrixUI {param([bool]$Value);if(-not $Value){throw 'Profile matrix UI assertion failed.'}}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear()}
function Write-WinSecText {param($Text,$Color);$script:lines.Add([string]$Text)}
function New-WinSecResizeState {[pscustomobject]@{}}
function Invoke-WinSecResizeHandler {param($ResizeState,$RenderAction);return $false}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if($script:keys.Count -eq 0){throw 'Synthetic profile key queue exhausted.'}
    $key=$script:keys.Dequeue()
    if($null -ne $key.Terminal){$script:terminal=$key.Terminal;$null=& $RenderAction $null}
    $key
}
function Add-WinSecMatrixUIKey {
    param([int]$Code,[string]$Character='',[object]$Terminal=$null)
    $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$Code;Character=$Character;Terminal=$Terminal;KeyDown=$true;ControlKeyState=0})
}
function Test-WinSecMatrixUI {
    param([string]$Name,[scriptblock]$Action)
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=50}
    $script:lines=New-Object 'System.Collections.Generic.List[string]'
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
Test-WinSecMatrixUI 'Up selects the last of 101 profiles with an exact preview and unchanged caller data' {
    $before=Get-WinSecPublicHistoryJson $profiles
    Add-WinSecMatrixUIKey 38;Add-WinSecMatrixUIKey 13
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    $plan=Get-WinSecAssessmentProfilePlan $root @('WSA-SYS-001') $answer.Selection.Profile
    Assert-WinSecMatrixUI ($profiles.Count -eq 101 -and $answer.Confirmed -ceq $true -and
        $answer.Selection.Profile -ceq 'WSA-W11-24H2-IOT-ENT-LTSC-DEF-BASE' -and
        $answer.Selection.Policies[0].CatalogSha256 -ceq $plan.Preview.Policies[0].CatalogSha256 -and
        $before -ceq (Get-WinSecPublicHistoryJson $profiles) -and ($script:lines -join '|').Contains('Choice 102 / 102'))
}
Test-WinSecMatrixUI 'All 102 choices wrap back to collection only without implicit selection' {
    for($i=0;$i -le $profiles.Count;$i++){Add-WinSecMatrixUIKey 40}
    Add-WinSecMatrixUIKey 13
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI ($answer.Confirmed -ceq $true -and $null -eq $answer.Selection -and $script:keys.Count -eq 0)
}
foreach($code in @(78,27)) {
    Test-WinSecMatrixUI 'N or Esc cancels after choosing the last expanded profile' {
        Add-WinSecMatrixUIKey 38;Add-WinSecMatrixUIKey $code $(if($code -eq 78){'n'}else{''})
        $answer=Show-WinSecAssessmentProfileSelection $request $profiles
        Assert-WinSecMatrixUI ($answer.Confirmed -ceq $false -and $null -eq $answer.Selection)
    }
}
Test-WinSecMatrixUI 'Tiny terminal cannot confirm a hidden profile and remains bounded' {
    $script:terminal=[pscustomobject]@{Width=16;ContentWidth=15;Height=5}
    Add-WinSecMatrixUIKey 38;Add-WinSecMatrixUIKey 13;Add-WinSecMatrixUIKey 27
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI (-not $answer.Confirmed -and $script:lines.Count -lt 5 -and @($script:lines|Where-Object Length -GT 15).Count -eq 0)
}
Test-WinSecMatrixUI 'Resizing preserves the expanded choice and still requires fresh Enter' {
    $script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=10}
    Add-WinSecMatrixUIKey 38;Add-WinSecMatrixUIKey 13
    Add-WinSecMatrixUIKey 0 '' ([pscustomobject]@{Width=120;ContentWidth=119;Height=50})
    Add-WinSecMatrixUIKey 13
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI ($answer.Confirmed -ceq $true -and $answer.Selection.Profile -ceq $profiles[-1].Profile -and $script:keys.Count -eq 0)
}
[Console]::WriteLine(('Profile matrix UI integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Profile matrix UI integration failed.'}
