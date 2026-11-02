[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$device='local:hw1-'+('a'*64)
$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $base ('wru-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-RU {param([bool]$Value);if(-not $Value){throw 'Technical restoration unit assertion failed.'}}
function Reject-RU {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-RU $caught}
function New-RUContext {
    [pscustomobject]@{ProjectRoot=$sandbox;Devices=@([pscustomobject]@{DeviceId=$device;Hostname='SYNTHETIC'});
        ScanCoordinator=[pscustomobject]@{Sessions=@{};TechnicalLocations=@{}};
        PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{}}
}
function Test-RU {param([string]$Case,[scriptblock]$Action)
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try{
    Test-RU 'Preparation stamps existing empty caches without adding technical properties or readiness' {
        $c=New-RUContext;$s=New-WinSecTechnicalRestoreStamp $c;Assert-WinSecTechnicalRestoreStamp $c $s
        Assert-RU ([object]::ReferenceEquals($s.Publics,$c.PublicScans) -and $s.Devices[0].DeviceId -ceq $device -and
            $null -eq $c.PSObject.Properties['TechnicalSourceIndexes'] -and $null -eq $c.PSObject.Properties['HistoryReady'])
    }
    foreach($damage in @('Technical','TechnicalType','Ready','ReadyType','HistoryReady','Locations','Publics','Active','Sessions')){
        Test-RU ('Stale or malformed caches reject preparation: '+$damage) {
            $c=New-RUContext
            switch($damage){
                Technical {$c|Add-Member NoteProperty TechnicalSourceIndexes @{$device='STALE'}}
                TechnicalType {$c|Add-Member NoteProperty TechnicalSourceIndexes @()}
                Ready {$c|Add-Member NoteProperty TechnicalSourcesReady $true}
                ReadyType {$c|Add-Member NoteProperty TechnicalSourcesReady 'false'}
                HistoryReady {$c|Add-Member NoteProperty HistoryReady $true}
                Locations {$c.ScanCoordinator.TechnicalLocations['stale']='STALE'}
                Publics {$c.PublicScans['stale']='STALE'}
                Active {$c.ActiveScanByScope['stale']='STALE'}
                Sessions {$c.ScanCoordinator.Sessions['stale']='STALE'}
            }
            Reject-RU {New-WinSecTechnicalRestoreStamp $c}
        }
    }
    foreach($change in @('Root','Device','Coordinator','EmptyMapReplacement','PopulatedMap','Ready')){
        Test-RU ('Mutation during preparation cannot overwrite a changed context: '+$change) {
            $c=New-RUContext;$s=New-WinSecTechnicalRestoreStamp $c
            switch($change){
                Root {$c.ProjectRoot=Join-Path $sandbox 'other'}
                Device {$c.Devices[0].DeviceId='local:hw1-'+('b'*64)}
                Coordinator {$c.ScanCoordinator=$c.ScanCoordinator.PSObject.Copy()}
                EmptyMapReplacement {$c.PublicScans=@{}}
                PopulatedMap {$c.ActiveScanByDevice['external']='EXTERNAL'}
                Ready {$c|Add-Member NoteProperty TechnicalSourcesReady $true}
            }
            Reject-RU {Assert-WinSecTechnicalRestoreStamp $c $s}
        }
    }
    Test-RU 'Duplicate or foreign device identities cannot enter a restoration manifest' {
        Reject-RU {Get-WinSecTechnicalRestoreDevices @([pscustomobject]@{DeviceId=$device},[pscustomobject]@{DeviceId=$device})}
        Reject-RU {Get-WinSecTechnicalRestoreDevices @([pscustomobject]@{DeviceId='../foreign'})}
    }
    Test-RU 'A context getter is rejected before its private value is executed' {
        $c=New-RUContext;$c.PSObject.Properties.Remove('PublicScans');$script:getterRan=$false
        $c|Add-Member ScriptProperty PublicScans {$script:getterRan=$true;throw 'Getter executed.'}
        Reject-RU {New-WinSecTechnicalRestoreStamp $c};Assert-RU (-not $script:getterRan)
    }
    Test-RU 'Display-name changes do not change frozen device identities' {
        $c=New-RUContext;$s=New-WinSecTechnicalRestoreStamp $c;$c.Devices[0].Hostname='RENAMED'
        Assert-WinSecTechnicalRestoreStamp $c $s
    }
    Test-RU 'Cancellation is honored even when no devices need restoration' {
        $cancelled=$false;try{$null=Read-WinSecTechnicalRestoreIndexes $sandbox @() {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-RU ($cancelled -and -not [IO.Directory]::Exists((Join-Path $sandbox 'data')))
    }
    Test-RU 'Non-Boolean cancellation is not accepted for empty restoration' {
        Reject-RU {Read-WinSecTechnicalRestoreIndexes $sandbox @() {'yes'}}
    }
    Test-RU 'Unready restored caches cannot invoke selection or public-history fallback' {
        function Select-WinSecTechnicalSource {throw 'Selection must not be called.'}
        $c=New-RUContext;$c.PublicScans['legacy']='LEGACY'
        Reject-RU {Select-WinSecRestoredTechnicalSource $c $device REVIEWED_PROJECTION CONTROL WSA-SYS-001}
        Assert-RU ($c.PublicScans['legacy'] -ceq 'LEGACY')
    }
    Test-RU 'The restored-cache consumer delegates policy and family explicitly without consulting public maps' {
        function Select-WinSecTechnicalSource {param($ProjectRoot,$Index,$DeviceId,$Family,$ScopeType,$ScopeKey,$CheckId,$SourcePreference,$PolicyVersion,$CancellationAction)
            [pscustomobject]@{DeviceId=$DeviceId;Family=$Family;Preference=$SourcePreference;Index=$Index;Origin='RECORDS'}
        }
        $c=New-RUContext;$c|Add-Member NoteProperty HistoryReady $true;$c|Add-Member NoteProperty TechnicalSourcesReady $true
        $c|Add-Member NoteProperty TechnicalSourceIndexes @{$device=[pscustomobject]@{Marker='INDEX'}}
        $s=Select-WinSecRestoredTechnicalSource $c $device DEFENDER_CANDIDATE CONTROL WSA-SYS-001 -SourcePreference LATEST_ATTEMPT
        Assert-RU ($s.Preference -ceq 'LATEST_ATTEMPT' -and $s.Family -ceq 'DEFENDER_CANDIDATE' -and $s.Index.Marker -ceq 'INDEX' -and $c.PublicScans.Count -eq 0)
    }
    Test-RU 'Readiness flags must be Boolean rather than coerced strings or arrays' {
        function Select-WinSecTechnicalSource {$script:selectionCalled=$true;'UNEXPECTED'}
        foreach($flag in @('True',@($true))){
            $c=New-RUContext;$script:selectionCalled=$false
            $c|Add-Member NoteProperty HistoryReady $flag;$c|Add-Member NoteProperty TechnicalSourcesReady $true
            $c|Add-Member NoteProperty TechnicalSourceIndexes @{$device='INDEX'}
            Reject-RU {Select-WinSecRestoredTechnicalSource $c $device DEFENDER_CANDIDATE CONTROL WSA-SYS-001}
            Assert-RU (-not $script:selectionCalled)
        }
    }
    Test-RU 'Missing and incompatible restored indexes reject rather than using legacy results' {
        $c=New-RUContext;$c|Add-Member NoteProperty HistoryReady $true;$c|Add-Member NoteProperty TechnicalSourcesReady $true
        $c|Add-Member NoteProperty TechnicalSourceIndexes @{};$c.PublicScans['legacy']='LEGACY'
        Reject-RU {Select-WinSecRestoredTechnicalSource $c $device REVIEWED_PROJECTION CONTROL WSA-SYS-001}
        $c.TechnicalSourceIndexes[$device]=[pscustomobject]@{ArtifactType='WinSec.StoredSession';SchemaVersion='1.0.0'}
        Reject-RU {Select-WinSecRestoredTechnicalSource $c $device REVIEWED_PROJECTION CONTROL WSA-SYS-001}
        Assert-RU ($c.PublicScans['legacy'] -ceq 'LEGACY')
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awru-[a-f0-9]{8}\z'){throw 'Unsafe restoration unit cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical source restoration unit: $passed passed; $failed failed.");if($failed){exit 1}
