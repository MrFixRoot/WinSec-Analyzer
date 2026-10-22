# Independent public row sessions only; no Windows queries, scans or writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ResultModel.ps1','src/CLI/Invoke-WinSecCLI.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1')){. (Join-Path $root $file)}
$script:passed=0;$script:failed=0
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Invoke-WinSecCoordinatedScan {throw 'Unexpected scan.'}
function Assert-WinSecRowSession {param([bool]$Value);if(-not $Value){throw 'Control row session assertion failed.'}}
function New-WinSecRowSession {
    param([string]$Id='defender-session',[string]$ScopeType='CONTROL',[string]$ScopeKey='WSA-SYS-001')
    [pscustomobject]@{DeviceId='local:synthetic';ScanId=$Id;PublicProjection=$true;ContainsRawEvidence=$false;
        ScoringEligible=$false;OverallScore=$null;OverallStatus='NOT_SCORED';ScopeType=$ScopeType;ScopeKey=$ScopeKey;
        SectionResults=@();Findings=@();ControlResults=@([pscustomobject]@{CheckId='WSA-SYS-001';
            DeviceId='local:synthetic';ScanId=$Id;SectionKey='SystemSecurity';Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL'})}
}
function New-WinSecRowContext {
    $p=New-WinSecRowSession
    $key='{0}:{1}{2}:{3}' -f $p.DeviceId.Length,$p.DeviceId,$p.ScanId.Length,$p.ScanId
    [pscustomobject]@{PublicScans=@{$key=$p};ActiveScanByDevice=@{};
        ActiveScanByScope=@{(Get-WinSecCLIScopeKey $p.DeviceId CONTROL WSA-SYS-001)=$p.ScanId};
        ScanId='';SectionResults=@();ControlResults=@();Findings=@()}
}
function Test-WinSecRowSession {
    param([string]$Name,[scriptblock]$Action)
    $script:state=[pscustomobject]@{Screen='Section';SelectedDeviceId='local:synthetic';SectionIndex=0;ControlIndex=0}
    $script:ctx=New-WinSecRowContext
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-WinSecRowSession 'Moving the cursor never changes the public session of another row' {
    $snapshot=ConvertTo-Json $ctx -Depth 30 -Compress
    foreach($index in @(0,1,2,0)) {
        $state.ControlIndex=$index
        $views=@(Get-WinSecCLIControlViews $state $ctx)
        $rows=@(Get-WinSecResultsControlRows SystemSecurity $state -ControlViews $views)
        Assert-WinSecRowSession ($rows[0].Status -ceq 'INFORMATIONAL' -and $rows[0].ScanId -ceq 'defender-session' -and
            $rows[0].DeviceId -ceq $state.SelectedDeviceId -and $rows[1].Status -ceq 'PENDING' -and
            $rows[1].Score -ceq 'NOT_SCORED' -and $state.ControlIndex -eq $index)
    }
    Assert-WinSecRowSession ($snapshot -ceq (ConvertTo-Json $ctx -Depth 30 -Compress))
}
Test-WinSecRowSession 'Different controls retain different sessions without exchanging status or provenance' {
    $p=New-WinSecRowSession 'bitlocker-public-session' CONTROL WSA-SYS-002
    $p.ControlResults[0].CheckId='WSA-SYS-002';$p.ControlResults[0].Status='NOT_EVALUATED'
    $p.ControlResults[0].ObservedStatus='NOT_CHECKED'
    $key='{0}:{1}{2}:{3}' -f $p.DeviceId.Length,$p.DeviceId,$p.ScanId.Length,$p.ScanId
    $ctx.PublicScans[$key]=$p;$ctx.ActiveScanByScope[(Get-WinSecCLIScopeKey $p.DeviceId CONTROL WSA-SYS-002)]=$p.ScanId
    foreach($index in @(0,1,2)) {
        $state.ControlIndex=$index
        $rows=@(Get-WinSecResultsControlRows SystemSecurity $state -ControlViews @(Get-WinSecCLIControlViews $state $ctx))
        Assert-WinSecRowSession ($rows[0].Status -ceq 'INFORMATIONAL' -and $rows[0].ScanId -ceq 'defender-session' -and
            $rows[1].Status -ceq 'NOT_EVALUATED' -and $rows[1].ScanId -ceq $p.ScanId -and $rows[1].Score -ceq 'NOT_SCORED')
    }
}
foreach($scope in @('SECTION','DEVICE')) {
    Test-WinSecRowSession ('Rows fall back only to their own section or device: '+$scope) {
        $key=if($scope -ceq 'SECTION'){'SystemSecurity'}else{'ALL'}
        $p=New-WinSecRowSession 'fallback' $scope $key
        $sessionKey='{0}:{1}{2}:{3}' -f $p.DeviceId.Length,$p.DeviceId,$p.ScanId.Length,$p.ScanId
        $ctx.PublicScans=@{$sessionKey=$p};$ctx.ActiveScanByScope=@{}
        if($scope -ceq 'SECTION'){$ctx.ActiveScanByScope[(Get-WinSecCLIScopeKey $p.DeviceId $scope $key)]=$p.ScanId}
        else{$ctx.ActiveScanByDevice[$p.DeviceId]=$p.ScanId}
        $views=@(Get-WinSecCLIControlViews $state $ctx)
        $rows=@(Get-WinSecResultsControlRows SystemSecurity $state -ControlViews $views)
        Assert-WinSecRowSession ($views.Count -eq 3 -and $rows[0].ScanId -ceq 'fallback' -and
            $rows[0].SourceScopeType -ceq $scope -and $rows[1].Score -ceq 'NOT_SCORED')
    }
}
foreach($kind in @('ForeignDevice','ForeignScan','WrongControl','WrongSection','WrongScope','ArrayScope','Duplicate','UnknownField','UnapprovedScore')) {
    Test-WinSecRowSession ('Invalid row sessions publish no rows: '+$kind) {
        $views=@(Get-WinSecCLIControlViews $state $ctx)
        switch($kind) {
            ForeignDevice {$views[0].DeviceId='local:other'}
            ForeignScan {$views[0].ScanId='another-scan'}
            WrongControl {$views[0].CheckId='WSA-SYS-002'}
            WrongSection {$views[0].CheckId='WSA-NET-001'}
            WrongScope {$views[0].ScopeType='SECTION';$views[0].ScopeKey='NetworkSecurity'}
            ArrayScope {$views[0].ScopeType=@('CONTROL')}
            Duplicate {$views+=Copy-WinSecResultData $views[0]}
            UnknownField {$views[0]|Add-Member RawEvidence 'PRIVATE-ROW-REJECT'}
            UnapprovedScore {$views[0].ControlResults[0]|Add-Member Score 100}
        }
        $published=New-Object 'System.Collections.Generic.List[object]';$caught=$false
        try{Get-WinSecResultsControlRows SystemSecurity $state -ControlViews $views|ForEach-Object{$published.Add($_)}}catch{$caught=$true}
        Assert-WinSecRowSession ($caught -and $published.Count -eq 0)
    }
}
foreach($kind in @('MissingSession','ForeignRecord','WrongSelectedScope')) {
    Test-WinSecRowSession ('CLI rejects inconsistent scope references: '+$kind) {
        switch($kind) {
            MissingSession {$ctx.PublicScans=@{}}
            ForeignRecord {foreach($p in $ctx.PublicScans.Values){$p.ControlResults[0].DeviceId='local:other'}}
            WrongSelectedScope {foreach($p in $ctx.PublicScans.Values){$p.ScopeKey='WSA-SYS-002'}}
        }
        $caught=$false;try{$null=Get-WinSecCLIControlViews $state $ctx}catch{$caught=$true}
        Assert-WinSecRowSession $caught
    }
}
Write-Host ('Control row sessions: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Control row session tests failed.'}
