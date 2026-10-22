# Synthetic keyboard/terminal only. Never writes reports, changes Windows or runs scans.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/TargetRegistry.ps1','src/Core/ResultModel.ps1','src/UI/Screens/ExportFrameworkSelection.ps1')) {
    . (Join-Path $root $file)
}
$script:passed=0;$script:failed=0;$script:keys=New-Object 'System.Collections.Generic.Queue[object]'
function Assert-WinSecExportChoice {param([bool]$Condition);if(-not $Condition){throw 'Export choice assertion failed.'}}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines=@()}
function Write-WinSecText {param($Text,$Color);$script:lines+=$Text}
function New-WinSecResizeState {[pscustomobject]@{}}
function Invoke-WinSecResizeHandler {
    param($ResizeState,$RenderAction)
    if($script:rerender){$script:rerender=$false;$null=& $RenderAction $null;return $true};return $false
}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if($script:keys.Count -eq 0){throw 'Synthetic key queue exhausted.'}
    $key=$script:keys.Dequeue()
    if($null -ne $key.Terminal){$script:terminal=$key.Terminal;$script:rerender=$true}
    $key
}
function New-WinSecExportChoiceKey {
    param([int]$Code,[string]$Character='',[object]$Terminal=$null)
    [pscustomobject]@{VirtualKeyCode=$Code;Character=$Character;KeyDown=$true;ControlKeyState=0;Terminal=$Terminal}
}
function Test-WinSecExportChoice {
    param([string]$Name,[scriptblock]$Action)
    $script:terminal=[pscustomobject]@{Width=100;ContentWidth=99;Height=35};$script:rerender=$false;$script:keys.Clear()
    $script:selection=[pscustomobject]@{DeviceId='local:EXPORT-CHOICE';ScanId='export-choice-1';ScopeType='CONTROL';ScopeKey='WSA-SYS-001'}
    try {$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch {$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
foreach($index in 0..3) {
    foreach($code in @(13,89)) {
        Test-WinSecExportChoice ('Each framework shows its benefit and requires Y/Enter: '+$index+' / '+$code) {
            $options=@(Get-WinSecExportFrameworkOptions);$before=ConvertTo-Json $script:selection -Compress
            for($i=0;$i -lt $index;$i++) {$script:keys.Enqueue((New-WinSecExportChoiceKey 40))}
            $script:keys.Enqueue((New-WinSecExportChoiceKey $code $(if($code -eq 89){'y'}else{''})))
            $answer=Show-WinSecExportFrameworkSelection $script:selection
            Assert-WinSecExportChoice ($answer.Confirmed -ceq $true -and $answer.FrameworkId -ceq $options[$index].Id -and
                ($script:lines -join '|').Contains($options[$index].Benefit) -and ($script:lines -join '|').Contains('PENDING') -and
                $before -ceq (ConvertTo-Json $script:selection -Compress))
        }
    }
}
foreach($code in @(78,27)) {
    Test-WinSecExportChoice 'N and Escape cancel after navigating without choosing a framework' {
        $script:keys.Enqueue((New-WinSecExportChoiceKey 40));$script:keys.Enqueue((New-WinSecExportChoiceKey $code $(if($code -eq 78){'n'}else{''})))
        $answer=Show-WinSecExportFrameworkSelection $script:selection
        Assert-WinSecExportChoice ($answer.Confirmed -ceq $false -and $null -eq $answer.FrameworkId)
    }
}
Test-WinSecExportChoice 'Up wraps from first to last framework' {
    $script:keys.Enqueue((New-WinSecExportChoiceKey 38));$script:keys.Enqueue((New-WinSecExportChoiceKey 13))
    Assert-WinSecExportChoice ((Show-WinSecExportFrameworkSelection $script:selection).FrameworkId -ceq 'mitre-attack')
}
Test-WinSecExportChoice 'Modified keys and releases do not confirm an export' {
    $key=New-WinSecExportChoiceKey 13;$key.KeyDown=$false;$script:keys.Enqueue($key)
    $key=New-WinSecExportChoiceKey 89 'y';$key.ControlKeyState=4;$script:keys.Enqueue($key)
    $script:keys.Enqueue((New-WinSecExportChoiceKey 27))
    Assert-WinSecExportChoice (-not (Show-WinSecExportFrameworkSelection $script:selection).Confirmed -and $script:keys.Count -eq 0)
}
foreach($size in @(@{W=40;H=10},@{W=16;H=5},@{W=1;H=1})) {
    Test-WinSecExportChoice 'A truncated or tiny screen cannot export with Enter and warnings stay bounded' {
        $script:terminal=[pscustomobject]@{Width=$size.W;ContentWidth=$size.W;Height=$size.H}
        $script:keys.Enqueue((New-WinSecExportChoiceKey 13));$script:keys.Enqueue((New-WinSecExportChoiceKey 27))
        $answer=Show-WinSecExportFrameworkSelection $script:selection
        Assert-WinSecExportChoice (-not $answer.Confirmed -and $script:lines.Count -lt $size.H -and
            @($script:lines|Where-Object {$_.Length -gt $size.W}).Count -eq 0)
    }
}
Test-WinSecExportChoice 'Resize preserves selection and still requires a fresh confirmation key' {
    $script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=10}
    $script:keys.Enqueue((New-WinSecExportChoiceKey 40));$script:keys.Enqueue((New-WinSecExportChoiceKey 13))
    $script:keys.Enqueue((New-WinSecExportChoiceKey 0 '' ([pscustomobject]@{Width=100;ContentWidth=99;Height=35})))
    $script:keys.Enqueue((New-WinSecExportChoiceKey 13))
    $answer=Show-WinSecExportFrameworkSelection $script:selection
    Assert-WinSecExportChoice ($answer.FrameworkId -ceq 'cis-controls' -and $script:keys.Count -eq 0)
}
Test-WinSecExportChoice 'Unsafe identity and calculated properties fail before display' {
    $script:selection.DeviceId="bad`nID";$rejected=$false
    try {$null=Show-WinSecExportFrameworkSelection $script:selection}catch {$rejected=$true}
    Assert-WinSecExportChoice $rejected
    $script:selection.DeviceId='local:EXPORT-CHOICE';$script:getterCalls=0
    $script:selection|Add-Member -MemberType ScriptProperty -Name Extra -Value {$script:getterCalls++;throw 'PRIVATE-GETTER'}
    $rejected=$false;try {$null=Show-WinSecExportFrameworkSelection $script:selection}catch {$rejected=$true}
    Assert-WinSecExportChoice ($rejected -and $script:getterCalls -eq 0)
}
Write-Host ('Export framework: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Export framework selection tests failed.'}
