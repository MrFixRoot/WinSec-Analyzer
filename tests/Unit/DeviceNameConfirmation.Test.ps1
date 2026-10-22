# Diálogo real con teclado/terminal simulados; ninguna escritura ni auditoría.
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/TargetRegistry.ps1')
. (Join-Path $root 'src/Core/ResultModel.ps1')
. (Join-Path $root 'src/UI/Screens/DeviceName.ps1')
$script:passed=0;$script:failed=0
function Assert-WinSecNameDialog {param([bool]$Value);if(-not $Value){throw 'Device name dialog assertion failed.'}}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear()}
function Write-WinSecText {param($Text,$Color);$script:lines.Add($Text)}
function New-WinSecResizeState {[pscustomobject]@{}}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if(-not $script:keys.Count){throw 'Synthetic dialog keys exhausted.'}
    $key=$script:keys.Dequeue();if($key -is [scriptblock]){return & $key};return $key
}
function Add-WinSecNameDialogKey {
    param([int]$Code=13,[string]$Char='', [int]$Modifiers=0,[bool]$Down=$true)
    $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$Code;Character=$Char;ControlKeyState=$Modifiers;KeyDown=$Down})
}
function Test-WinSecNameDialogCase {
    param([string]$Name,[scriptblock]$Action)
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]';$script:lines=New-Object 'System.Collections.Generic.List[string]'
    $script:terminal=[pscustomobject]@{Width=80;ContentWidth=79;Height=26}
    $script:request=[pscustomobject]@{DeviceId=('local:hw1-'+('c'*64));DisplayName='Original name'}
    try{$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
foreach($confirm in @(@{Code=13;Char=''},@{Code=89;Char='y'})){
    Test-WinSecNameDialogCase 'Enter reviews and saves; Y cannot approve a reviewed name' {
        foreach($c in 'My device'.ToCharArray()){Add-WinSecNameDialogKey 0 ([string]$c)}
        Add-WinSecNameDialogKey;Add-WinSecNameDialogKey $confirm.Code $confirm.Char
        if($confirm.Code -eq 89){Add-WinSecNameDialogKey}
        $before=ConvertTo-Json $script:request -Compress
        $answer=Show-WinSecDeviceNameEditor $script:request
        Assert-WinSecNameDialog ($answer.DisplayName -ceq 'My device' -and $answer.DeviceId -ceq $script:request.DeviceId -and
            $before -ceq (ConvertTo-Json $script:request -Compress) -and $script:keys.Count -eq 0)
    }
}
foreach($cancel in @(@{Code=27;Char=''},@{Code=78;Char='n'})){
    Test-WinSecNameDialogCase 'Escape cancels a reviewed edit; N is ignored' {
        Add-WinSecNameDialogKey;Add-WinSecNameDialogKey $cancel.Code $cancel.Char
        if($cancel.Code -eq 78){Add-WinSecNameDialogKey 27}
        Assert-WinSecNameDialog ($null -eq (Show-WinSecDeviceNameEditor $script:request))
        Assert-WinSecNameDialog ($script:keys.Count -eq 0)
    }
}
foreach($modifier in @(1,2,4,8)){
    Test-WinSecNameDialogCase 'Alt and Ctrl cannot confirm a renamed device' {
        Add-WinSecNameDialogKey;Add-WinSecNameDialogKey 13 '' $modifier;Add-WinSecNameDialogKey 27
        Assert-WinSecNameDialog ($null -eq (Show-WinSecDeviceNameEditor $script:request))
    }
}
Test-WinSecNameDialogCase 'Key releases cannot approve the change' {
    Add-WinSecNameDialogKey;Add-WinSecNameDialogKey 13 '' 0 $false;Add-WinSecNameDialogKey 27
    Assert-WinSecNameDialog ($null -eq (Show-WinSecDeviceNameEditor $script:request))
}
Test-WinSecNameDialogCase 'Small terminal prevents approval even after a resize until a new visible confirmation' {
    $script:terminal=[pscustomobject]@{Width=30;ContentWidth=29;Height=10}
    Add-WinSecNameDialogKey;Add-WinSecNameDialogKey 89 y
    $script:keys.Enqueue({$script:terminal=[pscustomobject]@{Width=80;ContentWidth=79;Height=26};[pscustomobject]@{VirtualKeyCode=13;Character='';ControlKeyState=0;KeyDown=$true}})
    Add-WinSecNameDialogKey 27
    Assert-WinSecNameDialog ($null -eq (Show-WinSecDeviceNameEditor $script:request))
}
Test-WinSecNameDialogCase 'Delete edits text inside the dialog and never requests device deletion' {
    Add-WinSecNameDialogKey 46;Add-WinSecNameDialogKey 0 X;Add-WinSecNameDialogKey;Add-WinSecNameDialogKey
    Assert-WinSecNameDialog ((Show-WinSecDeviceNameEditor $script:request).DisplayName -ceq 'X')
}
foreach($arrow in @(37,38,39,40)){
    Test-WinSecNameDialogCase ('Arrows select Cancel in the review; Enter discards the name: '+$arrow) {
        Add-WinSecNameDialogKey;Add-WinSecNameDialogKey $arrow;Add-WinSecNameDialogKey
        Assert-WinSecNameDialog ($null -eq (Show-WinSecDeviceNameEditor $script:request) -and
            ($script:lines -join '|').Contains('> [ Cancel ]'))
    }
}
Test-WinSecNameDialogCase 'Accept can be selected again without Y or N changing the reviewed name' {
    Add-WinSecNameDialogKey;Add-WinSecNameDialogKey 40;Add-WinSecNameDialogKey 38
    Add-WinSecNameDialogKey 89 Y;Add-WinSecNameDialogKey 78 N;Add-WinSecNameDialogKey
    $answer=Show-WinSecDeviceNameEditor $script:request
    Assert-WinSecNameDialog ($answer.DisplayName -ceq 'Original name' -and $script:keys.Count -eq 0 -and
        ($script:lines -join '|').Contains('> [ Accept ]'))
}
Test-WinSecNameDialogCase 'Y and N remain ordinary letters while typing a device name' {
    Add-WinSecNameDialogKey 89 Y;Add-WinSecNameDialogKey 78 N;Add-WinSecNameDialogKey;Add-WinSecNameDialogKey
    Assert-WinSecNameDialog ((Show-WinSecDeviceNameEditor $script:request).DisplayName -ceq 'YN')
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if($script:failed){throw 'Device name dialog tests failed.'}
