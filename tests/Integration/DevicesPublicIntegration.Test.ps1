# Registry -> CLI -> Devices/layout/table with a simulated terminal.
# Synthetic inventory only; no startup, scans, deletion or persistence.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @(
    'src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/TerminalRenderer.ps1',
    'src/UI/Components/Banner.ps1','src/UI/Components/Table.ps1','src/UI/Components/KeyboardHelp.ps1',
    'src/UI/Core/LayoutManager.ps1','src/UI/Core/KeyboardController.ps1',
    'src/UI/Core/NavigationController.ps1','src/UI/Core/ResizeHandler.ps1','src/UI/Screens/Devices.ps1'
)) {. (Join-Path $root $file)}
$script:passed=0; $script:failed=0; $script:scanCalls=0; $script:deleteCalls=0; $script:renderCalls=0
$script:lines=New-Object 'System.Collections.Generic.List[string]'
$script:fragment=New-Object Text.StringBuilder
function Assert-WinSecDevicesIntegration {param([bool]$Condition);if(-not $Condition){throw 'Devices integration assertion failed.'}}
function Test-WinSecDevicesIntegration {
    param([string]$Name,[scriptblock]$Action)
    try {$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch {$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:renderCalls++;$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
function Invoke-WinSecCoordinatedScan {$script:scanCalls++;throw 'Unexpected scan.'}
function Invoke-WinSecAudit {$script:scanCalls++;throw 'Unexpected collector.'}
function Remove-WinSecDevice {$script:deleteCalls++;throw 'Unexpected deletion.'}
function Set-WinSecDevicesTestTerminal {
    param([int]$Width,[int]$Height)
    $script:terminal=[pscustomobject]@{Width=$Width;Height=$Height;ContentWidth=$Width-1}
}
$devices=@(1..16|ForEach-Object {
    [pscustomobject]@{DeviceId=('local:SYNTHETIC-{0:D2}' -f $_);Hostname=('SYNTHETIC-{0:D2}' -f $_);
        Mode='LOCAL';Score=100;Status='PASS';LastScan='SYNTHETIC-DEVICES-PRIVATE';ScanId='foreign';
        Evidence=@{Secret='SYNTHETIC-DEVICES-PRIVATE'}}
})
$state=New-WinSecNavigationState
$state.DeviceIndex=12
$context=[pscustomobject]@{Version='0.9.0';Devices=$devices;LastDeviceMessage='';
    ActiveScanByDevice=@{'foreign'='foreign-session'};
    PublicScans=@{'unrelated'=@{Evidence='SYNTHETIC-DEVICES-PRIVATE'}}}
$before=ConvertTo-Json -InputObject @($state,$context) -Depth 12 -Compress
Test-WinSecDevicesIntegration 'Real CLI registry normalization retains every device without importing assessment metadata' {
    $registered=@(Get-WinSecCLIDevices -ProjectRoot $root -Devices $devices)
    $rows=@(Get-WinSecDeviceRows -Devices $registered)
    Assert-WinSecDevicesIntegration ($rows.Count -eq 16 -and
        @($registered|Where-Object{$null -ne $_.Score -or $_.Status -cne 'PENDING' -or $_.ScanId -cne ''}).Count -eq 0 -and
        @($rows|Where-Object{$_.Score -cne 'NOT_SCORED' -or $_.LastScan -cne 'Not loaded'}).Count -eq 0 -and
        $before -ceq (ConvertTo-Json -InputObject @($state,$context) -Depth 12 -Compress))
}
foreach($size in @(@{Width=120;Height=45},@{Width=80;Height=26},@{Width=40;Height=22})) {
    Test-WinSecDevicesIntegration ('Unscored inventory and selected row fit simulated width '+$size.Width) {
        Set-WinSecDevicesTestTerminal -Width $size.Width -Height $size.Height
        Show-WinSecCLICurrentScreen -State $state -Context $context
        $text=$script:lines -join '|'
        Assert-WinSecDevicesIntegration ($text -match 'NOT_SCORED' -and $text -match 'SELECTED: SYNTHETIC-13' -and
            $text -notmatch '\d+/100|--/100|SYNTHETIC-DEVICES-PRIVATE|\bPASS\b' -and
            $script:lines.Count -le $script:terminal.Height -and
            @($script:lines|Where-Object{$_.Length -gt $script:terminal.ContentWidth}).Count -eq 0 -and
            $script:scanCalls -eq 0 -and $script:deleteCalls -eq 0 -and
            $before -ceq (ConvertTo-Json -InputObject @($state,$context) -Depth 12 -Compress))
    }
}
Test-WinSecDevicesIntegration 'Expanded table distinguishes unloaded history from a claim that no scan ever occurred' {
    Set-WinSecDevicesTestTerminal -Width 120 -Height 45
    Show-WinSecCLICurrentScreen -State $state -Context $context
    Assert-WinSecDevicesIntegration (($script:lines -join '|') -match 'Not loaded' -and
        ($script:lines -join '|') -notmatch '\bNever\b')
}
Test-WinSecDevicesIntegration 'A status message fits the minimum supported terminal without executing actions' {
    Set-WinSecDevicesTestTerminal -Width 40 -Height 22
    Show-WinSecDevices -NavigationState $state -Devices $devices -Message 'Operation cancelled.'
    Assert-WinSecDevicesIntegration (($script:lines -join '|') -match 'Operation cancelled' -and
        $script:lines.Count -le 22 -and $script:scanCalls -eq 0 -and $script:deleteCalls -eq 0)
}
Test-WinSecDevicesIntegration 'Too-small terminal asks for resize and preserves the complete inventory' {
    Set-WinSecDevicesTestTerminal -Width 38 -Height 18
    Show-WinSecCLICurrentScreen -State $state -Context $context
    Assert-WinSecDevicesIntegration (($script:lines -join '|') -match 'Terminal window is too small' -and
        ($script:lines -join '|') -notmatch 'SYNTHETIC-13|SYNTHETIC-DEVICES-PRIVATE' -and
        $before -ceq (ConvertTo-Json -InputObject @($state,$context) -Depth 12 -Compress))
}
Test-WinSecDevicesIntegration 'Resize redraws once, retaining selection and inventory without scanning or deleting' {
    Set-WinSecDevicesTestTerminal -Width 40 -Height 22
    $resize=New-WinSecResizeState
    Set-WinSecDevicesTestTerminal -Width 80 -Height 26
    $renders=$script:renderCalls
    $render={param($State);Show-WinSecCLICurrentScreen -State $State -Context $context}
    $first=Invoke-WinSecResizeHandler -ResizeState $resize -NavigationState $state -RenderAction $render
    $second=Invoke-WinSecResizeHandler -ResizeState $resize -NavigationState $state -RenderAction $render
    Assert-WinSecDevicesIntegration ($first -and -not $second -and $script:renderCalls -eq ($renders+1) -and
        $script:scanCalls -eq 0 -and $script:deleteCalls -eq 0 -and
        $before -ceq (ConvertTo-Json -InputObject @($state,$context) -Depth 12 -Compress))
}
Test-WinSecDevicesIntegration 'Empty inventory hides device open/delete actions without fabricating assessments' {
    Set-WinSecDevicesTestTerminal -Width 80 -Height 26
    Show-WinSecDevices
    $text=$script:lines -join '|'
    Assert-WinSecDevicesIntegration ($text -match 'REGISTERED DEVICES: 0' -and $text -match 'SELECTED: NONE' -and
        $text -notmatch 'DEL/SUPR|Open Device|\d+/100|--/100' -and $script:deleteCalls -eq 0)
}
Test-WinSecDevicesIntegration 'Arrow and Enter navigation use the matching inventory identity and preserve session maps' {
    $navigation=New-WinSecNavigationState
    $null=Invoke-WinSecNavigationAction -State $navigation -Action MoveDown -Devices $devices
    $null=Invoke-WinSecNavigationAction -State $navigation -Action Open -Devices $devices
    Assert-WinSecDevicesIntegration ($navigation.Screen -ceq 'MainMenu' -and
        $navigation.SelectedDeviceId -ceq $devices[1].DeviceId -and $navigation.DeviceIndex -eq 1)
    $null=Invoke-WinSecNavigationAction -State $navigation -Action Back -Devices $devices
    Assert-WinSecDevicesIntegration ($navigation.Screen -ceq 'Devices' -and $navigation.DeviceIndex -eq 1 -and
        $before -ceq (ConvertTo-Json -InputObject @($state,$context) -Depth 12 -Compress))
}
Test-WinSecDevicesIntegration 'Physical Supr/Del queues a confirmation request and does not perform deletion' {
    $navigation=New-WinSecNavigationState
    $key=[pscustomobject]@{VirtualKeyCode=46;Character=[char]0;ControlKeyState=0;KeyDown=$true}
    $action=ConvertTo-WinSecKeyboardAction -KeyInfo $key -Screen Devices
    $null=Invoke-WinSecNavigationAction -State $navigation -Action $action -Devices $devices
    Assert-WinSecDevicesIntegration ($action -ceq 'DeleteDevice' -and
        $navigation.PendingCommand -ceq 'DeleteDevice' -and $script:deleteCalls -eq 0 -and $script:scanCalls -eq 0)
    $key.VirtualKeyCode=68;$key.Character=[char]'D'
    Assert-WinSecDevicesIntegration ((ConvertTo-WinSecKeyboardAction -KeyInfo $key -Screen Devices) -ceq 'None')
}
Test-WinSecDevicesIntegration 'Invalid later device rejects before clearing the screen or drawing earlier devices' {
    $renders=$script:renderCalls;$script:lines.Clear();$caught=$null
    try {Show-WinSecDevices -Devices @($devices[0],@{DeviceId=$devices[0].DeviceId})} catch {$caught=$_}
    Assert-WinSecDevicesIntegration ($null -ne $caught -and $script:renderCalls -eq $renders -and
        $script:lines.Count -eq 0 -and $script:scanCalls -eq 0 -and $script:deleteCalls -eq 0)
}
[Console]::WriteLine('Passed: '+$script:passed)
[Console]::WriteLine('Failed: '+$script:failed)
if($script:failed -gt 0){throw "$script:failed Devices integration test(s) failed."}
