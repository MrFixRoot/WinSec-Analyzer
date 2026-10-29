# Prepared captures only; no Firewall, network or application-data access.
function New-WinSecFirewallCandidateFixture {
    param([int]$RuleCount=1)
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-firewall';SnapshotId=('b'*32);
        CheckId='WSA-NET-001';SectionKey='NetworkSecurity';ScopeType='CONTROL';ScopeKey='WSA-NET-001'}
    $fields=@(Get-WinSecFirewallCandidateFields);$sources=@(foreach($area in Get-WinSecFirewallCandidateAreas){
        $n=if($area.Role -ceq 'Platform'){1}elseif($area.Role -ceq 'Profiles'){3}else{$RuleCount}
        $rows=@(for($i=0;$i -lt $n;$i++){
            $data=[ordered]@{}
            foreach($d in $fields|Where-Object Inventory -CEQ $area.Id){
                if($d.Kind -ceq 'ListCount'){continue}
                $v=switch($d.Kind){
                    Version {'10.0.26100'};Build {'26100'};UInt32 {[uint32]0};UInt64Text {[uint64]::MaxValue}
                    Profile {@('Domain','Private','Public')[$i]};Protocol {'TCP'}
                    LocalPorts {,@('80','443','1000-1002')};RemotePorts {,@('Any')};Icmp {,@('Any')}
                    Identifier {if($d.Property -ceq 'RuleInstanceID' -or $area.Role -ceq 'Rules'){'Rule-'+$i}else{'Filter-'+$i}}
                };$data[$d.Property]=$v
            }
            if($area.Role -ceq 'Platform'){$data.OperatingSystemSKU=[uint32]48;$data.ProductType=[uint32]1}
            [pscustomobject]$data
        })
        [pscustomobject]@{SourceId=$area.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';
            PolicyStore=$area.Store;State='OBSERVED';Data=$(if($area.Role -ceq 'Platform'){$rows[0]}else{,$rows})}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}

function New-WinSecFirewallFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecFirewallCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Get-WinSecFirewallFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
