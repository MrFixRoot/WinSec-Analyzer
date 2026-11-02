# Prepared synthetic policy flags only. No logs, events, profiles or user data.
function New-WinSecPowerShellLoggingCandidateFixture {
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-logging';SnapshotId=('b'*32);
        CheckId='WSA-LOG-001';SectionKey='LoggingAuditing';ScopeType='CONTROL';ScopeKey='WSA-LOG-001'}
    $sources=@(foreach($a in Get-WinSecPowerShellLoggingCandidateAreas){
        $data=if($a.Id -ceq 'Platform'){[pscustomobject]@{Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}}
        else{
            $settings=[ordered]@{};foreach($d in Get-WinSecPowerShellLoggingCandidateFields|Where-Object Inventory -CEQ $a.Id){
                $settings[$d.Property]=[pscustomobject]@{State='OBSERVED';Kind='DWord';Value=[uint32]1}
            };[pscustomobject]$settings
        }
        [pscustomobject]@{SourceId=$a.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';Location=$a.Location;State='OBSERVED';Data=$data}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}
function New-WinSecPowerShellLoggingFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecPowerShellLoggingCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}
function Get-WinSecPowerShellLoggingFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
