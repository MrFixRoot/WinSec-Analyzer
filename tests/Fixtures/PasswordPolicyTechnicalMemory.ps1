# Prepared synthetic policy receipts only; never queries the security database.
function New-WinSecPasswordPolicyCandidateFixture {
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-policy';SnapshotId=('b'*32);
        CheckId='WSA-IAM-003';SectionKey='IdentityAccess';ScopeType='CONTROL';ScopeKey='WSA-IAM-003'}
    $sources=@(foreach($a in Get-WinSecPasswordPolicyCandidateAreas){
        $data=switch -CaseSensitive ($a.Id){
            Platform {[pscustomobject]@{Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}}
            Policy {[pscustomobject]@{Level=[uint32]0;ServerName=$null;ReturnValue=[uint32]0;Settings=[pscustomobject]@{MinimumLength=[uint32]14;MaximumAgeSeconds=[uint32]4294967295;MinimumAgeSeconds=[uint32]0;ForceLogoffSeconds=[uint32]4294967295;HistoryLength=[uint32]24}}}
            Lockout {[pscustomobject]@{Level=[uint32]3;ServerName=$null;ReturnValue=[uint32]0;Settings=[pscustomobject]@{DurationSeconds=[uint32]900;ObservationWindowSeconds=[uint32]900;Threshold=[uint32]10}}}
            Template {[pscustomobject]@{Section='System Access';MergedPolicy=$false;ReturnValue=[uint32]0;Settings=[pscustomobject]@{PasswordComplexity=[uint32]1;ClearTextPassword=[uint32]0}}}
        }
        [pscustomobject]@{SourceId=$a.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';Location=$a.Location;State='OBSERVED';Data=$data}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}
function New-WinSecPasswordPolicyFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecPasswordPolicyCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}
function Get-WinSecPasswordPolicyFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
