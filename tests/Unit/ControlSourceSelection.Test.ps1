# Historical source selection only: no provider calls, application startup or storage writes.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/CLI/FrameworkWorkflow.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','tests/Fixtures/FrameworkWorkflowMemory.ps1')){. (Join-Path $root $file)}
function Get-CimInstance {throw 'Native collection prohibited.'}
function Get-WinSecSourceHardware {'local:hw1-'+('b'*64)}
Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecSourceHardware -Scope Script
$passed=0;$failed=0
function Assert-SourceSelection {param([bool]$Value);if(-not $Value){throw 'Source selection assertion failed.'}}
function Test-SourceSelection {param($Name,[scriptblock]$Action);try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
function New-SourceContext {
    $coordinator=New-WinSecScanCoordinator $root;$id='local:hw1-'+('b'*64)
    [pscustomobject]@{ProjectRoot=$root;ScanCoordinator=$coordinator;PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};
        LocalDeviceId=$id;Devices=@([pscustomobject]@{DeviceId=$id;Hostname='SYNTHETIC';DisplayName='SYNTHETIC'})}
}
function Add-SourceFixture {
    param($Context,[string]$Id,[int]$Minute,[string]$Type='CONTROL',[switch]$Partial,[string]$Check='WSA-SYS-002')
    $fixture=New-WinSecFrameworkWorkflowFixture $Check $Id
    $control=$fixture.Session.ControlResults[0]
    $start=('2026-10-28T10:{0:00}:00Z' -f $Minute);$end=('2026-10-28T10:{0:00}:30Z' -f $Minute)
    $control.TimestampUTC=$end;$control.Evidence.CollectedAtUTC=$end
    if($Partial){$control.ObservedStatus='UNKNOWN';$control.Evidence.CollectionComplete=$false}
    $scopeKey=switch($Type){CONTROL {$Check};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
    $status=if($Partial){'COMPLETED_WITH_ERRORS'}else{'COMPLETED'}
    $s=New-WinSecResultSession -DeviceId $fixture.Session.DeviceId -ScanId $Id -ExpectedCheckIds @($Check) -ControlResults @($control) `
        -CatalogVersion '1.0.0' -StartedAtUTC $start -CompletedAtUTC $end -ExecutionStatus $status -ScopeType $Type -ScopeKey $scopeKey
    $public=ConvertTo-WinSecPublicScanResult $s;$d=$s.DeviceId
    $Context.PublicScans[('{0}:{1}{2}:{3}' -f $d.Length,$d,$Id.Length,$Id)]=$public
    $Context.ScanCoordinator.Sessions[(Get-WinSecScanSessionKey $d $Id)]=[pscustomobject]@{DeviceId=$d;ScanId=$Id;Session=$s;HistoryOrigin='LIVE'}
    if($Type -ceq 'DEVICE'){$Context.ActiveScanByDevice[$d]=$Id}else{$Context.ActiveScanByScope[(Get-WinSecCLIScopeKey $d $Type $scopeKey)]=$Id}
}
function Get-SourceState {param($Context);[pscustomobject]@{Screen='Section';SelectedDeviceId=$Context.LocalDeviceId;SectionIndex=0;ControlIndex=1}}
foreach($type in @('CONTROL','SECTION','DEVICE')){
    Test-SourceSelection ('Latest partial and previous complete remain independently selectable: '+$type) {
        $ctx=New-SourceContext;Add-SourceFixture $ctx old 1 -Type $type;Add-SourceFixture $ctx recent 2 -Type $type -Partial
        $state=Get-SourceState $ctx
        $latest=Get-WinSecCLIActiveAssessment $state $ctx
        $complete=Get-WinSecCLIActiveAssessment $state $ctx -SourcePreference PREFER_COMPLETE
        Assert-SourceSelection ($latest.ScanId -ceq 'recent' -and $complete.ScanId -ceq 'old' -and $latest.SourceScopeType -ceq $type)
        $rows=@(Get-WinSecWorkflowControlRows $state $ctx)
        Assert-SourceSelection ($rows[1].Status -ceq 'PARTIAL' -and $rows[0].Status -ceq 'PENDING')
    }
}
Test-SourceSelection 'A control without a complete predecessor keeps its saved partial source' {
    $ctx=New-SourceContext;Add-SourceFixture $ctx only 1 -Partial
    Assert-SourceSelection ((Get-WinSecCLIActiveAssessment (Get-SourceState $ctx) $ctx -SourcePreference PREFER_COMPLETE).ScanId -ceq 'only')
}
Test-SourceSelection 'An absent observed status cannot become a complete reading' {
    $ctx=New-SourceContext;Add-SourceFixture $ctx old 1;Add-SourceFixture $ctx recent 2
    $key='{0}:{1}{2}:{3}' -f $ctx.LocalDeviceId.Length,$ctx.LocalDeviceId,6,'recent'
    $ctx.PublicScans[$key].ControlResults[0].ObservedStatus=$null
    $source=[pscustomobject]@{CheckId='WSA-SYS-002';PublicResult=$ctx.PublicScans[$key]}
    Assert-SourceSelection ((Get-WinSecWorkflowControlState $source $ctx) -ceq 'PARTIAL' -and
        (Get-WinSecCLIActiveAssessment (Get-SourceState $ctx) $ctx -SourcePreference PREFER_COMPLETE).ScanId -ceq 'old')
}
Test-SourceSelection 'A public source that contradicts the stored session is rejected' {
    $ctx=New-SourceContext;Add-SourceFixture $ctx recent 2
    $key='{0}:{1}{2}:{3}' -f $ctx.LocalDeviceId.Length,$ctx.LocalDeviceId,6,'recent'
    $ctx.PublicScans[$key].ControlResults[0].ObservedStatus='UNKNOWN';$rejected=$false
    try{$null=Get-WinSecWorkflowSources (Get-SourceState $ctx) $ctx}catch{$rejected=$true}
    Assert-SourceSelection $rejected
}
Test-SourceSelection 'Operational receipt fields do not invalidate the same immutable public source' {
    $ctx=New-SourceContext;Add-SourceFixture $ctx recent 2
    $key='{0}:{1}{2}:{3}' -f $ctx.LocalDeviceId.Length,$ctx.LocalDeviceId,6,'recent'
    $ctx.PublicScans[$key]|Add-Member EvidenceStorageStatus NOT_REQUESTED
    $ctx.PublicScans[$key]|Add-Member StoredEvidenceCount 0
    $ctx.PublicScans[$key]|Add-Member FailedEvidenceCount 0
    $sources=@(Get-WinSecWorkflowSources (Get-SourceState $ctx) $ctx)
    Assert-SourceSelection ($sources.Count -eq 1 -and $sources[0].ScanId -ceq 'recent' -and $sources[0].Origin -ceq 'LIVE')
}
Test-SourceSelection 'Newer complete SECTION supersedes partial CONTROL without fabricating scope' {
    $ctx=New-SourceContext;Add-SourceFixture $ctx partial 1 -Partial;Add-SourceFixture $ctx section 2 -Type SECTION
    $s=Get-WinSecCLIActiveAssessment (Get-SourceState $ctx) $ctx
    Assert-SourceSelection ($s.ScanId -ceq 'section' -and $s.SourceScopeType -ceq 'SECTION' -and $s.SourceScopeKey -ceq 'SystemSecurity')
}
Test-SourceSelection 'Control selection does not reuse another control or device' {
    $ctx=New-SourceContext;Add-SourceFixture $ctx selected 1;Add-SourceFixture $ctx defender 2 -Check WSA-SYS-001
    $ctx.PublicScans['foreign-device-key']=[pscustomobject]@{DeviceId='local:foreign';Evidence='PRIVATE'}
    Assert-SourceSelection ((Get-WinSecCLIActiveAssessment (Get-SourceState $ctx) $ctx).ScanId -ceq 'selected')
}
foreach($damage in @('index','null-index','nested','time','time-array','scope','scope-array')){
    Test-SourceSelection ('A damaged source is rejected without replacing history: '+$damage) {
        $ctx=New-SourceContext;Add-SourceFixture $ctx old 1;Add-SourceFixture $ctx recent 2 -Partial
        $key='{0}:{1}{2}:{3}' -f $ctx.LocalDeviceId.Length,$ctx.LocalDeviceId,6,'recent'
        switch($damage){
            index {$ctx.ActiveScanByScope[(Get-WinSecCLIScopeKey $ctx.LocalDeviceId CONTROL WSA-SYS-002)]='missing'}
            null-index {$ctx.ActiveScanByScope[(Get-WinSecCLIScopeKey $ctx.LocalDeviceId CONTROL WSA-SYS-002)]=$null}
            nested {$ctx.PublicScans[$key].ControlResults[0].DeviceId='local:foreign'}
            time {$ctx.PublicScans[$key].CompletedAtUTC='2026-10-27T00:00:00Z'}
            time-array {$ctx.PublicScans[$key].CompletedAtUTC=@('2026-10-28T10:02:30Z')}
            scope {$ctx.PublicScans[$key].ScopeKey='WSA-SYS-001'}
            scope-array {$ctx.PublicScans[$key].ScopeKey=@('WSA-SYS-002')}
        }
        $before=Get-WinSecPublicHistoryJson $ctx.PublicScans;$rejected=$false
        try{$null=Get-WinSecCLIActiveAssessment (Get-SourceState $ctx) $ctx}catch{$rejected=$true}
        Assert-SourceSelection ($rejected -and (Get-WinSecPublicHistoryJson $ctx.PublicScans) -ceq $before)
    }
}
Test-SourceSelection 'Calculated historical metadata is rejected without executing its getter' {
    $ctx=New-SourceContext;Add-SourceFixture $ctx old 1;Add-SourceFixture $ctx recent 2
    $key='{0}:{1}{2}:{3}' -f $ctx.LocalDeviceId.Length,$ctx.LocalDeviceId,3,'old';$script:getterCalls=0
    $ctx.PublicScans[$key]|Add-Member -MemberType ScriptProperty -Name ScopeType -Value {$script:getterCalls++;'CONTROL'} -Force
    $rejected=$false;try{$null=Get-WinSecCLIActiveAssessment (Get-SourceState $ctx) $ctx}catch{$rejected=$true}
    Assert-SourceSelection ($rejected -and $script:getterCalls -eq 0)
}
Test-SourceSelection 'Findings indicates saved-source preparation and Esc preserves the old view before file reads' {
    $ctx=New-SourceContext;Add-SourceFixture $ctx recent 2
    $ctx|Add-Member FrameworkFindings ([pscustomobject]@{AnalysisId='previous-view'})
    $script:sourceProgress=New-Object 'Collections.Generic.List[object]'
    function Show-WinSecExportFrameworkSelection {param($Selection,[switch]$ForFindings);[pscustomobject]@{Confirmed=$true;FrameworkId='nist-csf'}}
    function Show-WinSecFrameworkProgress {param($Progress);$script:sourceProgress.Add($Progress)}
    function Read-WinSecPendingKey {[pscustomobject]@{VirtualKeyCode=27;KeyDown=$true;ControlKeyState=0}}
    function Read-WinSecTechnicalReport {throw 'Cancelled Findings must not read a technical file.'}
    $result=Invoke-WinSecCLIFrameworkFindings (Get-SourceState $ctx) $ctx -ShowProgress
    Assert-SourceSelection (-not $result -and $ctx.FrameworkFindings.AnalysisId -ceq 'previous-view' -and
        $sourceProgress[0].Phase -ceq 'Selecting saved source history' -and $sourceProgress[0].Completed -eq 0 -and $sourceProgress[0].Total -eq 1)
}
Write-Host ("Source selection: $passed passed; $failed failed.");if($failed){exit 1}
