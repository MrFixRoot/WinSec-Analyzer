# Prepared synthetic receipts only; never queries Windows, shares or application history.
function New-WinSecSmbCandidateFixture {
    param()
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-smb';SnapshotId=('b'*32);
        CheckId='WSA-NET-002';SectionKey='NetworkSecurity';ScopeType='CONTROL';ScopeKey='WSA-NET-002'}
    $definitions=@(Get-WinSecSmbCandidateFields)
    $sources=@(foreach($area in Get-WinSecSmbCandidateAreas){
        $names=switch($area.Id){Features {@('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server','SMB1Protocol-Deprecation')};Services {@('LanmanServer','LanmanWorkstation')};default {@('Singleton')}}
        $rows=@(foreach($name in $names){
            $data=[ordered]@{}
            foreach($d in $definitions|Where-Object Inventory -CEQ $area.Id){
                if($d.Kind -cin @('Installation','DependencyCount')){continue}
                $v=switch($d.Kind){
                    Version {'10.0.26100'};Build {'26100'};UInt32 {[uint32]0};Boolean {$false};UInt64Text {[uint64]::MaxValue}
                    Ciphers {'AES_128_GCM, AES_256_GCM'};Dialect {'SMB311'};FeatureName {$name};ServiceName {$name}
                    ServiceState {'Stopped'};StartMode {'Manual'};Status {'OK'};ErrorControl {'Normal'};Utc {'2026-10-28T01:02:04.0000000Z'}
                    RegistryDWord {[pscustomobject]@{State='OBSERVED';Kind='DWord';Value=[int]0}}
                    Dependencies {[pscustomobject]@{State='OBSERVED';Kind='MultiString';Value=[string[]]@('Bowser','MRxSMB10','MRxSMB20','NSI')}}
                };$data[$d.Property]=$v
            }
            if($area.Id -ceq 'Platform'){$data.OperatingSystemSKU=[uint32]48;$data.ProductType=[uint32]1}
            if($area.Id -ceq 'Features'){$data.InstallState=[uint32]2}
            [pscustomobject]$data
        })
        [pscustomobject]@{SourceId=$area.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';
            Location=$area.Location;State='OBSERVED';Data=$(if($area.Id -cin @('Features','Services')){,$rows}else{$rows[0]})}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}

function New-WinSecSmbFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecSmbCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Get-WinSecSmbFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
