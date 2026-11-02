# Prepared synthetic endpoint receipts; never reads Windows, DNS, processes or history.
function New-WinSecOpenPortsCandidateFixture {
    param([int]$EndpointCount=2)
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-ports';SnapshotId=('b'*32);
        CheckId='WSA-NET-004';SectionKey='NetworkSecurity';ScopeType='CONTROL';ScopeKey='WSA-NET-004'}
    $fields=@(Get-WinSecOpenPortsCandidateFields)
    $sources=@(foreach($a in Get-WinSecOpenPortsCandidateAreas){
        $n=if($a.Id -ceq 'Platform'){1}else{$EndpointCount}
        $rows=@(for($i=0;$i -lt $n;$i++){
            $data=[ordered]@{}
            foreach($d in $fields|Where-Object Inventory -CEQ $a.Id){
                if($d.Derived){continue}
                $v=switch($d.Kind){Version {'10.0.26100'};Build {'26100'};{$_ -cin @('UInt8','UInt16','UInt32')} {[uint32]0}
                    Address {if(($i % 2) -eq 0){'192.0.2.10'}else{'FE80:0:0:0:0:0:0:1%5'}}
                    NativeTime {if($d.Property -ceq 'TimeOfLastStateChange'){[timespan]::Zero}else{'2026-10-29T01:02:01.0000000Z'}}
                };$data[$d.Property]=$v
            }
            if($a.Id -ceq 'Platform'){$data.OperatingSystemSKU=[uint32]48;$data.ProductType=[uint32]1}
            else{$data.LocalPort=[uint32](1024+($i % 60000));$data.OwningProcess=[uint32]1234;if($a.Id -ceq 'TCP'){$data.State=[uint32]2}}
            [pscustomobject]$data
        })
        [pscustomobject]@{SourceId=$a.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';
            Location=$a.Location;State='OBSERVED';Data=$(if($a.Id -ceq 'Platform'){$rows[0]}else{,$rows})}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}

function New-WinSecOpenPortsFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecOpenPortsCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Get-WinSecOpenPortsFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
