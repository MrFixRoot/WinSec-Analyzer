# Real CLI/presentation with cached synthetic metadata; no startup, OS or scans.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1',
    'src/UI/Core/TerminalRenderer.ps1','src/UI/Core/LayoutManager.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/KeyboardController.ps1','src/UI/Components/Banner.ps1','src/UI/Components/Table.ps1',
    'src/UI/Components/KeyboardHelp.ps1','src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1',
    'src/UI/Screens/Findings.ps1')){. (Join-Path $root $file)}
$script:passed=0;$script:failed=0;$script:queries=0
$deviceId='local:hw1-'+('a'*64)
function Assert-WinSecSystemUI {param([bool]$Value);if(-not $Value){throw 'System summary UI assertion failed.'}}
function Get-CimInstance {$script:queries++;throw 'Unexpected OS query while drawing.'}
function Invoke-WinSecCoordinatedScan {throw 'Unexpected scan.'}
function Get-WinSecCLIScanPresentation {param($State,$Context);@{EnableRescan=$false;ScanAction='Scan'}}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
function Test-WinSecSystemUI {
    param([string]$Name,[scriptblock]$Action)
    $script:state=New-WinSecNavigationState
    $script:state.SelectedDeviceId=$deviceId;$script:state.SelectedDeviceName='SYNTHETIC'
    $script:context=[pscustomobject]@{Version='0.9.0';Devices=@();ScanCoordinator=$null;ActiveScanByDevice=@{};PublicScans=@{};
        SectionResults=@();ControlResults=@();Findings=@();ScanId='';LastScanMessage='';
        LocalSystemInfo=[pscustomobject]@{DeviceId=$deviceId;Label='Pro 22H2 | build: 22621'}}
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=45}
    $script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
foreach($screen in @('MainMenu','Section')){
    foreach($size in @(@{W=120;H=45},@{W=80;H=26},@{W=40;H=20})){
        Test-WinSecSystemUI ('The cached OS appears below the device and fits '+$screen+' '+$size.W+'x'+$size.H) {
            $script:state.Screen=$screen
            $script:terminal=[pscustomobject]@{Width=$size.W;ContentWidth=$size.W-1;Height=$size.H}
            $before=ConvertTo-Json @($script:state,$script:context) -Depth 15 -Compress
            Show-WinSecCLICurrentScreen $script:state $script:context
            $deviceLine=@($script:lines|Where-Object {$_ -match 'DEVICE: SYNTHETIC'})[0]
            $index=$script:lines.IndexOf($deviceLine)
            Assert-WinSecSystemUI ($index -ge 0 -and $script:lines[$index+1].Trim() -ceq 'CURRENT OS: Pro 22H2 | build: 22621' -and
                $script:lines.Count -le $size.H -and @($script:lines|Where-Object {$_.Length -gt ($size.W-1)}).Count -eq 0 -and
                $script:queries -eq 0 -and $before -ceq (ConvertTo-Json @($script:state,$script:context) -Depth 15 -Compress))
        }
    }
}
Test-WinSecSystemUI 'Historical devices never display the current machines version' {
    $script:state.Screen='Section';$script:state.SelectedDeviceId='local:hw1-'+('b'*64)
    Show-WinSecCLICurrentScreen $script:state $script:context
    Assert-WinSecSystemUI (($script:lines -join '|') -notmatch 'Pro 22H2|22621' -and $script:queries -eq 0)
}
Test-WinSecSystemUI 'Esc from an actual Findings view restores and redraws its control list without new queries' {
    $script:state.Screen='Section';$script:state.ControlIndex=1
    $null=Set-WinSecNavigationScreen $script:state Findings
    $script:state.FindingsScope='Control'
    Show-WinSecCLICurrentScreen $script:state $script:context
    $key=[pscustomobject]@{VirtualKeyCode=27;Character=[char]27;KeyDown=$true;ControlKeyState=0}
    Assert-WinSecSystemUI (Invoke-WinSecCLIBackNavigation $key $script:state)
    Show-WinSecCLICurrentScreen $script:state $script:context
    Assert-WinSecSystemUI ($script:state.Screen -ceq 'Section' -and $script:state.ControlIndex -eq 1 -and
        ($script:lines -join '|') -match 'System Security' -and $script:queries -eq 0 -and $script:context.PublicScans.Count -eq 0)
}
[Console]::WriteLine(('Local system summary UI integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Local system summary UI integration failed.'}
