[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/CLI/FrameworkWorkflow.ps1',
    'src/UI/Core/TerminalRenderer.ps1','src/UI/Core/LayoutManager.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Components/Table.ps1','src/UI/Components/Banner.ps1','src/UI/Components/KeyboardHelp.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Devices.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/FrameworkFindings.ps1','tests/Fixtures/FrameworkWorkflowMemory.ps1')){. (Join-Path $root $file)}
function Get-WinSecWorkflowHardwareFixture {'local:hw1-'+('b'*64)}
Set-Alias -Name Get-WinSecLocalHardwareDeviceId -Value Get-WinSecWorkflowHardwareFixture -Scope Script
function Get-CimInstance {throw 'Unexpected native query.'}
function Get-MpComputerStatus {throw 'Unexpected native query.'}
function Get-MpPreference {throw 'Unexpected native query.'}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$script:colors.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator));$script:colors.Add([string]$ForegroundColor)
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
$script:passed=0;$script:failed=0
function Assert-WorkflowUI {param([bool]$Value);if(-not $Value){throw 'Workflow UI assertion failed.'}}
function Test-WorkflowUI {
    param($Name,[scriptblock]$Action)
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55;IsCompact=$false}
    $script:lines=New-Object 'Collections.Generic.List[string]';$script:colors=New-Object 'Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
function New-WorkflowUIContext {
    $c=New-WinSecScanCoordinator -ProjectRoot $root
    $ctx=[pscustomobject]@{ProjectRoot=$root;Version='0.9.0';ScanCoordinator=$c;Devices=@([pscustomobject]@{DeviceId=(Get-WinSecWorkflowHardwareFixture);Hostname='SYNTHETIC';DisplayName='SYNTHETIC';Mode='LOCAL';Enabled=$true});
        PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};FrameworkWorkflowEnabled=$true;LocalDeviceId=(Get-WinSecWorkflowHardwareFixture);
        LastScanMessage='';LastDeviceMessage='';LastExportMessage='';LocalSystemInfo=$null}
    foreach($id in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')) {
        $f=New-WinSecFrameworkWorkflowFixture $id ('ui-'+$id);$d=$f.Session.DeviceId;$s=$f.Session.ScanId
        $c.Sessions[(Get-WinSecScanSessionKey $d $s)]=[pscustomobject]@{DeviceId=$d;ScanId=$s;Session=$f.Session;HistoryOrigin='LIVE'}
        $ctx.PublicScans[('{0}:{1}{2}:{3}' -f $d.Length,$d,$s.Length,$s)]=$f.Source.PublicResult
        $ctx.ActiveScanByScope[(Get-WinSecCLIScopeKey $d CONTROL $id)]=$s
    }
    return $ctx
}
Test-WorkflowUI 'Completion and origin colors follow the new contract' {
    Assert-WorkflowUI ((Get-WinSecStatusColor PENDING) -ceq 'Red' -and (Get-WinSecStatusColor PARTIAL) -ceq 'Yellow' -and
        (Get-WinSecStatusColor COMPLETE) -ceq 'Green' -and (Get-WinSecStatusColor LIVE) -ceq 'Green' -and (Get-WinSecStatusColor RECORDS) -ceq 'DarkBlue')
}
Test-WorkflowUI 'Device, section and control screens hide every numeric rating and color stored records' {
    $ctx=New-WorkflowUIContext;$state=New-WinSecNavigationState;$state.SelectedDeviceId=$ctx.LocalDeviceId;$state.SelectedDeviceName='SYNTHETIC'
    foreach($entry in $ctx.ScanCoordinator.Sessions.Values){$entry.HistoryOrigin='PUBLIC_STORE'}
    foreach($screen in @('Devices','MainMenu','Section')) {
        $state.Screen=$screen;Show-WinSecCLICurrentScreen $state $ctx;$text=$script:lines -join '|'
        Assert-WorkflowUI ($text -notmatch 'SCORE|/100|NOT_SCORED|Config %' -and $text.Contains('COMPLETE') -and $text.Contains('RECORDS') -and $script:colors.Contains('DarkBlue'))
    }
}
Test-WorkflowUI 'Mixed sources are records and an unfinished section is partial' {
    $ctx=New-WorkflowUIContext;$state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$ctx.LocalDeviceId
    $rows=@(Get-WinSecWorkflowControlRows $state $ctx)
    Assert-WorkflowUI ((Get-WinSecWorkflowAggregateState $rows) -ceq 'COMPLETE' -and (Get-WinSecWorkflowAggregateMode $rows) -ceq 'LIVE')
    $rows[0].Mode='RECORDS';Assert-WorkflowUI ((Get-WinSecWorkflowAggregateMode $rows) -ceq 'RECORDS')
    $rows[0].Status='PENDING';Assert-WorkflowUI ((Get-WinSecWorkflowAggregateState $rows) -ceq 'PARTIAL')
    foreach($row in $rows){$row.Status='PENDING'};Assert-WorkflowUI ((Get-WinSecWorkflowAggregateState $rows) -ceq 'PENDING' -and (Get-WinSecWorkflowAggregateMode $rows) -ceq '-')
}
Test-WorkflowUI 'Findings remain interactive and Esc restores the previous screen without collection' {
    $ctx=New-WorkflowUIContext;$state=New-WinSecNavigationState;$state.SelectedDeviceId=$ctx.LocalDeviceId;$state.Screen='MainMenu'
    $sources=@(Get-WinSecWorkflowSources $state $ctx);$reports=@(foreach($id in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')){(New-WinSecFrameworkWorkflowFixture $id ('ui-'+$id)).Report})
    # Reuse source timestamps for the independently created typed snapshots.
    foreach($r in $reports){$source=@($sources|Where-Object CheckId -CEQ $r.CheckId)[0];$r.CompletedAtUTC=$source.CompletedAtUTC;$r.CollectedAtUTC=$source.CompletedAtUTC;$r.StartedAtUTC=$source.PublicResult.StartedAtUTC}
    $a=New-WinSecFrameworkAnalysis $root $ctx.LocalDeviceId SYNTHETIC SECTION SystemSecurity nist-csf $sources $reports
    $ctx|Add-Member FrameworkFindings $a;$ctx|Add-Member FrameworkSourcesStamp (Get-WinSecWorkflowSourceStamp $sources)
    $null=Invoke-WinSecNavigationAction $state ShowFindings -SectionCount 5
    $counts=Get-WinSecCLINavigationCounts $state $ctx
    Assert-WorkflowUI ($counts.FindingCount -eq $a.Rows.Count -and $a.Rows.Count -gt 1)
    $null=Invoke-WinSecNavigationAction $state ScrollDown -FindingCount $counts.FindingCount
    Show-WinSecCLICurrentScreen $state $ctx
    Assert-WorkflowUI ($state.FindingsOffset -eq 1 -and ($script:lines -join '|').Contains('[P] Print report') -and ($script:lines -join '|') -notmatch 'SCORE|/100')
    foreach($size in @(@{W=40;H=12},@{W=40;H=20},@{W=80;H=25})) {
        $script:terminal=[pscustomobject]@{Width=$size.W;ContentWidth=($size.W-1);Height=$size.H}
        Show-WinSecCLICurrentScreen $state $ctx
        Assert-WorkflowUI (@($script:lines|Where-Object {$_.Length -gt ($size.W-1)}).Count -eq 0 -and
            $script:lines.Count -lt $size.H -and $state.Screen -ceq 'Findings' -and $state.FindingsOffset -eq 1)
    }
    $null=Invoke-WinSecNavigationAction $state Back;Assert-WorkflowUI ($state.Screen -ceq 'MainMenu')
}
foreach($size in @(@{W=1;H=1},@{W=40;H=12},@{W=80;H=25},@{W=120;H=55})) {
    Test-WorkflowUI ('Progress fits the terminal without fabricated counts '+$size.W+'x'+$size.H) {
        $script:terminal=[pscustomobject]@{Width=$size.W;ContentWidth=[Math]::Max(1,$size.W-1);Height=$size.H}
        Show-WinSecFrameworkProgress ([pscustomobject]@{Completed=2;Total=4})
        Assert-WorkflowUI (@($script:lines|Where-Object {$_.Length -gt [Math]::Max(1,$size.W-1)}).Count -eq 0 -and $script:lines.Count -lt $size.H)
        if($size.W -ge 40 -and $size.H -ge 12){Assert-WorkflowUI (($script:lines -join '|').Contains('50%'))}
    }
}
[Console]::WriteLine(('Framework workflow UI: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Workflow UI tests failed.'}
