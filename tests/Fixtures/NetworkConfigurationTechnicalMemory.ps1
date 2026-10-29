# Explicit synthetic receipts only; never reads Windows or existing histories.
function New-WinSecNetworkCandidateFixture {
    param([int]$RecordCount=2)
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-network';SnapshotId=('b'*32);
        CheckId='WSA-NET-005';SectionKey='NetworkSecurity';ScopeType='CONTROL';ScopeKey='WSA-NET-005'}
    $fields=@(Get-WinSecNetworkCandidateFields)
    $sources=@(foreach($a in Get-WinSecNetworkCandidateAreas){
        $n=if($a.Id -cin @('Platform','DNSGlobal','Registry')){1}else{$RecordCount}
        $rows=@(for($i=0;$i -lt $n;$i++){
            $data=[ordered]@{}
            foreach($d in $fields|Where-Object Inventory -CEQ $a.Id){
                if($d.Derived){continue}
                $v=switch($d.Kind){
                    Version {'10.0.26100'};Build {'26100'};Boolean {$false};UInt64Text {[uint64]::MaxValue};Guid {'01234567-89AB-CDEF-0123-456789abcdef'}
                    Family {[uint16]2};Address {'192.0.2.10'};Prefix {'192.0.2.0/24'};Addresses {,@('192.0.2.53','192.0.2.54','192.0.2.53')}
                    RegistryDWord {[pscustomobject]@{State='OBSERVED';Kind='DWord';Value=[int]0}};default {[uint32]0}
                };if($d.Property -cin @('InterfaceIndex','Index')){$v=[uint32]($i+1)};$data[$d.Property]=$v
            }
            if($a.Id -ceq 'Platform'){$data.OperatingSystemSKU=[uint32]48;$data.ProductType=[uint32]1}
            [pscustomobject]$data
        })
        [pscustomobject]@{SourceId=$a.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';
            Location=$a.Location;State='OBSERVED';Data=$(if($a.Id -cin @('Platform','DNSGlobal','Registry')){$rows[0]}else{,$rows})}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}
function New-WinSecNetworkFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecNetworkCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}
function Get-WinSecNetworkFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
