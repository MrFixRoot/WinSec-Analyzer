# Real readers/cancellation/navigation with a Windows-like RawUI in memory.
# No actual console reads, Windows queries, configuration or persistent writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ResultModel.ps1','src/UI/Core/ResizeHandler.ps1','src/UI/Core/KeyboardController.ps1',
    'src/UI/Screens/ScanProgress.ps1','tests/Fixtures/RawUIKeyboardMemory.ps1')){. (Join-Path $root $file)}
$script:pendingReader=(Get-Command Read-WinSecPendingKey).ScriptBlock
$script:passed=0;$script:failed=0
function Assert-WinSecInput {param([bool]$Value);if(-not $Value){throw 'Keyboard input assertion failed.'}}
function Get-WinSecTerminalSize {$script:terminal}
function Test-WinSecInput {
    param([string]$Name,[scriptblock]$Action)
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    $script:inputUI=New-WinSecRawUIKeyboardFixture -Keys $script:keys
    $script:terminal=[pscustomobject]@{Width=80;ContentWidth=79;Height=25}
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
function Add-WinSecInputKey {
    param([int]$Code,[bool]$KeyDown=$true,[int]$Modifiers=0)
    $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$Code;Character='';KeyDown=$KeyDown;ControlKeyState=$Modifiers})
}
Test-WinSecInput 'Empty input returns immediately without invoking a blocking read' {
    $key=Read-WinSecPendingKey -InputUI $script:inputUI
    Assert-WinSecInput ($null -eq $key -and $script:inputUI.ReadCalls -eq 0)
}
foreach($code in @(13,89,27)) {
    Test-WinSecInput ('A buffered key release returns without waiting for another press: '+$code) {
        Add-WinSecInputKey $code $false
        $key=Read-WinSecPendingKey -InputUI $script:inputUI
        Assert-WinSecInput ($key.KeyDown -ceq $false -and $script:keys.Count -eq 0 -and $script:inputUI.BlockedReads -eq 0)
    }
}
Test-WinSecInput 'Released Enter and Escape cannot request cancellation; a later pressed Escape still does' {
    function Read-WinSecPendingKey {& $script:pendingReader -InputUI $script:inputUI}
    $state=New-WinSecScanProgressState -DeviceId 'local:KEY-INPUT' -ScopeLabel 'Control'
    Add-WinSecInputKey 13 $false;Add-WinSecInputKey 27 $false;Add-WinSecInputKey 27 $true 4
    Assert-WinSecInput (-not(Test-WinSecScanProgressCancellation $state) -and $script:inputUI.BlockedReads -eq 0)
    Add-WinSecInputKey 27
    Assert-WinSecInput (Test-WinSecScanProgressCancellation $state)
}
Test-WinSecInput 'Resize-aware input returns key releases to the caller instead of blocking its resize loop' {
    Add-WinSecInputKey 13 $false
    $resize=New-WinSecResizeState
    $key=Read-WinSecResizeAwareKey -ResizeState $resize -RenderAction {} -InputUI $script:inputUI
    Assert-WinSecInput ($key.KeyDown -ceq $false -and $script:inputUI.BlockedReads -eq 0 -and
        (ConvertTo-WinSecKeyboardAction -KeyInfo $key -Screen MainMenu) -ceq 'None')
}
Test-WinSecInput 'A buffered press remains available after a release and is returned exactly once' {
    Add-WinSecInputKey 13 $false;Add-WinSecInputKey 27
    $released=Read-WinSecPendingKey -InputUI $script:inputUI
    $pressed=Read-WinSecPendingKey -InputUI $script:inputUI
    Assert-WinSecInput ($released.KeyDown -ceq $false -and $pressed.KeyDown -ceq $true -and
        $pressed.VirtualKeyCode -eq 27 -and $script:inputUI.ReadCalls -eq 2 -and $script:keys.Count -eq 0)
}
Test-WinSecInput 'Releasing a key does not prevent the next small-terminal redraw or change selection' {
    $resize=New-WinSecResizeState
    $state=[pscustomobject]@{ControlIndex=2}
    $script:redraws=0
    $render={param($Navigation);$script:redraws++;Assert-WinSecInput ($Navigation.ControlIndex -eq 2)}
    Add-WinSecInputKey 13 $false
    $null=Read-WinSecResizeAwareKey -ResizeState $resize -RenderAction $render -NavigationState $state -InputUI $script:inputUI
    $script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=10}
    Add-WinSecInputKey 27
    $key=Read-WinSecResizeAwareKey -ResizeState $resize -RenderAction $render -NavigationState $state -InputUI $script:inputUI
    Assert-WinSecInput ($script:redraws -eq 1 -and $resize.Width -eq 40 -and $resize.Height -eq 10 -and
        $key.KeyDown -ceq $true -and $key.VirtualKeyCode -eq 27 -and $state.ControlIndex -eq 2)
}
Test-WinSecInput 'An input provider failure remains a safe error instead of implying no cancellation' {
    $script:inputUI.PSObject.Properties.Remove('KeyAvailable')
    $script:inputUI|Add-Member -MemberType ScriptProperty -Name KeyAvailable -Value {throw 'PRIVATE-INPUT-ERROR'}
    $caught=$false
    try{$null=Read-WinSecPendingKey -InputUI $script:inputUI}catch{$caught=$true;Assert-WinSecInput ($_.Exception.Message -notmatch 'PRIVATE-INPUT-ERROR')}
    Assert-WinSecInput $caught
}
Test-WinSecInput 'Resize-aware input rejects unavailable keyboard state instead of polling forever' {
    $script:inputUI.PSObject.Properties.Remove('KeyAvailable')
    $script:inputUI|Add-Member -MemberType NoteProperty -Name KeyAvailable -Value $null
    $caught=$false
    try{$null=Read-WinSecResizeAwareKey -ResizeState (New-WinSecResizeState) -RenderAction {} -InputUI $script:inputUI}
    catch{$caught=$true}
    Assert-WinSecInput ($caught -and $script:inputUI.ReadCalls -eq 0)
}
Test-WinSecInput 'A failing key read aborts safely without exposing the provider error' {
    Add-WinSecInputKey 27
    $script:inputUI|Add-Member -Force -MemberType ScriptMethod -Name ReadKey -Value {param($Options);throw 'PRIVATE-READ-ERROR'}
    $caught=$false
    try{$null=Read-WinSecPendingKey -InputUI $script:inputUI}catch{$caught=$true;Assert-WinSecInput ($_.Exception.Message -notmatch 'PRIVATE-READ-ERROR')}
    Assert-WinSecInput $caught
}
[Console]::WriteLine(('Keyboard input: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Keyboard input tests failed.'}
