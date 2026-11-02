# Prepared synthetic service configuration. No service APIs, accounts or process queries.
function New-WinSecWindowsServicesCandidateFixture {
    param([int]$ServiceCount=2)
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-services';SnapshotId=('b'*32);
        CheckId='WSA-HRD-001';SectionKey='ServicesHardening';ScopeType='CONTROL';ScopeKey='WSA-HRD-001'}
    $services=@(for($i=1;$i -le $ServiceCount;$i++){
        [pscustomobject]@{Name=('SyntheticService'+$i);State='Stopped';StartMode='Manual';Started=$false;DelayedAutoStart=$false;ServiceType='Own Process';ErrorControl='Normal';
            AcceptPause=$false;AcceptStop=$false;DesktopInteract=$false;ExitCode=[uint32]0;ServiceSpecificExitCode=[uint32]0;ProcessId=[uint32]0;CheckPoint=[uint32]0;WaitHint=[uint32]0;TagId=[uint32]0;Status='OK'}
    })
    $sources=@(foreach($a in Get-WinSecWindowsServicesCandidateAreas){
        $data=if($a.Id -ceq 'Platform'){[pscustomobject]@{Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}}else{,$services}
        [pscustomobject]@{SourceId=$a.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-29T01:02:04.0000000Z';Location=$a.Location;State='OBSERVED';Data=$data}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-29T01:02:03.0000000Z';CompletedAtUTC='2026-10-29T01:02:05.0000000Z';GeneratedAtUTC='2026-10-29T01:02:06.0000000Z'}
}
function New-WinSecWindowsServicesFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecWindowsServicesCandidateSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}
function Get-WinSecWindowsServicesFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
