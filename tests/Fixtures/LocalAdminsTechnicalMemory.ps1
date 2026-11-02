# Synthetic direct-membership receipts only; no native API, SAM, account or domain queries.
function New-WinSecLocalAdminsCandidateFixture {
    param([int]$MemberCount=2,[int]$PageSize=128)
    if($MemberCount -lt 0 -or $PageSize -lt 1){throw 'Invalid synthetic membership size.'}
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-local-admins';SnapshotId=('b'*32);
        CheckId='WSA-IAM-001';SectionKey='IdentityAccess';ScopeType='CONTROL';ScopeKey='WSA-IAM-001'}
    $pages=New-Object 'Collections.Generic.List[object]'
    for($offset=0;($offset -lt $MemberCount) -or ($offset -eq 0 -and $MemberCount -eq 0);$offset+=$PageSize){
        $count=[Math]::Min($PageSize,$MemberCount-$offset);$more=($offset+$count -lt $MemberCount)
        $rows=@(for($i=0;$i -lt $count;$i++){[pscustomobject]@{SID=('S-1-5-21-11-22-33-'+(1000+$offset+$i))}})
        $pages.Add([pscustomobject]@{Status=[uint32]$(if($more){234}else{0});EntriesRead=[uint32]$count;TotalEntries=[uint32]($MemberCount-$offset);ResumePending=[bool]$more;Records=$rows})
    }
    $sources=@(foreach($a in Get-WinSecLocalAdminsCandidateAreas){
        $data=switch($a.Id){
            Platform {[pscustomobject]@{Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}}
            Group {[pscustomobject]@{SID='S-1-5-32-544';Name='Administrators - Synthetic';LocalAccount=$true;SIDType=[byte]4}}
            Members {[pscustomobject]@{GroupSID='S-1-5-32-544';Level=[uint32]0;Pages=$pages.ToArray()}}
        }
        [pscustomobject]@{SourceId=$a.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';Location=$a.Location;State='OBSERVED';Data=$data}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}
function New-WinSecLocalAdminsFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecLocalAdminsCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}
function Get-WinSecLocalAdminsFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
