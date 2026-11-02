# Configuration-only synthetic audit receipts. No audit API, event, activity or account query.
function New-WinSecAuditPolicyCandidateFixture {
    param([int]$SubcategoryCount=2)
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-audit-policy';SnapshotId=('b'*32);
        CheckId='WSA-LOG-002';SectionKey='LoggingAuditing';ScopeType='CONTROL';ScopeKey='WSA-LOG-002'}
    $category='11111111-1111-4111-8111-111111111111'
    $subcategories=@(for($i=1;$i -le $SubcategoryCount;$i++){[pscustomobject]@{AuditSubCategoryGuid=('22222222-2222-4222-8222-'+('{0:x12}' -f $i))}})
    $sources=@(foreach($a in Get-WinSecAuditPolicyCandidateAreas){
        $data=switch($a.Id){
            Platform {[pscustomobject]@{Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}}
            Categories {,@([pscustomobject]@{AuditCategoryGuid=$category})}
            Subcategories {,$subcategories}
            Requests {,@($subcategories|ForEach-Object {[pscustomobject]@{AuditSubCategoryGuid=$_.AuditSubCategoryGuid}})}
            SystemPolicy {,@($subcategories|ForEach-Object {[pscustomobject]@{AuditSubCategoryGuid=$_.AuditSubCategoryGuid;AuditingInformation=[uint32]3;AuditCategoryGuid=$category}})}
            Options {[pscustomobject]@{SCENoApplyLegacyAuditPolicy=[pscustomobject]@{State='OBSERVED';Kind='DWord';Value=[uint32]1}}}
        }
        [pscustomobject]@{SourceId=$a.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';Location=$a.Location;State='OBSERVED';Data=$data}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}
function New-WinSecAuditPolicyFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecAuditPolicyCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}
function Get-WinSecAuditPolicyFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
