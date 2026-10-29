# Prepared synthetic local Guest receipts. Never enumerates accounts or tries authentication.
function New-WinSecGuestCandidateFixture {
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-guest';SnapshotId=('b'*32);
        CheckId='WSA-IAM-002';SectionKey='IdentityAccess';ScopeType='CONTROL';ScopeKey='WSA-IAM-002'}
    $guest=[pscustomobject]@{SID='S-1-5-21-11-22-33-501';Name='Guest - Synthetic';Domain='SYNTHETIC-PC';Disabled=$true;LocalAccount=$true;Lockout=$false;
        PasswordRequired=$false;PasswordChangeable=$true;PasswordExpires=$false;AccountType=[uint32]512;SIDType=[byte]1;Status='OK'}
    $sources=@(foreach($a in Get-WinSecGuestCandidateAreas){
        $data=if($a.Id -ceq 'Platform'){[pscustomobject]@{Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}}else{,@($guest)}
        [pscustomobject]@{SourceId=$a.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';Location=$a.Location;State='OBSERVED';Data=$data}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}
function New-WinSecGuestFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecGuestCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}
function Get-WinSecGuestFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
