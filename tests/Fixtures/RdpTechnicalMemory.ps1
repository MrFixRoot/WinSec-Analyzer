# Synthetic local configuration receipts only; no Windows or application-history reads.
function New-WinSecRdpCandidateFixture {
    param([int]$ListenerCount=2)
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-rdp';SnapshotId=('b'*32);
        CheckId='WSA-NET-003';SectionKey='NetworkSecurity';ScopeType='CONTROL';ScopeKey='WSA-NET-003'}
    $fields=@(Get-WinSecRdpCandidateFields)
    $sources=@(foreach($a in Get-WinSecRdpCandidateAreas){
        $n=if($a.Id -ceq 'Services'){3}elseif($a.Host -and $a.Id -cne 'Global'){$ListenerCount}else{1}
        $rows=@(for($i=0;$i -lt $n;$i++){
            $data=[ordered]@{}
            foreach($d in $fields|Where-Object Inventory -CEQ $a.Id){
                $v=switch($d.Kind){Version {'10.0.26100'};Build {'26100'};UInt32 {[uint32]0};Boolean {$false}
                    Listener {'Listener-'+$i};Protocol {'Microsoft RDP 8.0'};Transport {'TCP'}
                    ServiceName {@('TermService','UmRdpService','SessionEnv')[$i]};ServiceState {'Stopped'};StartMode {'Manual'};ErrorControl {'Normal'}
                    RegistryDWord {[pscustomobject]@{State='OBSERVED';Kind='DWord';Value=[int]0}}
                };$data[$d.Property]=$v
            }
            if($a.Id -ceq 'Platform'){$data.OperatingSystemSKU=[uint32]48;$data.ProductType=[uint32]1}
            if($a.Id -ceq 'General'){$data.MinEncryptionLevel=[uint32]3;$data.UserAuthenticationRequired=[uint32]1}
            if($a.Id -ceq 'Redirection'){$data.AllowDwm=$null;$data.PolicySourceAllowDwm=$null}
            if($a.Id -ceq 'Registry'){$data.ListenerPort.Value=[int]3389}
            [pscustomobject]$data
        })
        [pscustomobject]@{SourceId=$a.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';
            Location=$a.Location;State='OBSERVED';Data=$(if($a.Id -cin @('Platform','Global','Registry')){$rows[0]}else{,$rows})}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}

function New-WinSecRdpFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecRdpCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Get-WinSecRdpFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
