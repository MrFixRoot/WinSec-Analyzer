# Prepared data fixtures only. No Windows providers or application-data writes.
function New-WinSecWindowsUpdateTechnicalFixture {
    param([int]$UpdateCount=2)
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-windows-update';SnapshotId=('b'*32);
        CheckId='WSA-SYS-003';SectionKey='SystemSecurity';ScopeType='CONTROL';ScopeKey='WSA-SYS-003'}
    $data=@{
        Platform=[pscustomobject]@{Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}
        Revision=[pscustomobject]@{CurrentBuildNumber=[pscustomobject]@{State='OBSERVED';Kind='String';Value='26100'};UBR=[pscustomobject]@{State='OBSERVED';Kind='DWord';Value=[uint32]100}}
        Services=@(foreach($name in Get-WinSecWindowsUpdateTechnicalServices){[pscustomobject]@{Name=$name;State='Stopped';StartMode='Manual';Started=$false;ExitCode=[uint32]0;ServiceSpecificExitCode=[uint32]0}})
        GPOAU=[pscustomobject]@{};GPOUpdate=[pscustomobject]@{};Reboot=[pscustomobject]@{RebootRequired=$false}
        InstalledCBSUpdates=@(for($i=0;$i -lt $UpdateCount;$i++){[pscustomobject]@{HotFixID=('KB'+(5000000+$i));InstalledOn='10/28/2026';InstallDate=[datetimeoffset]'2026-10-28T00:00:00Z';Status='OK'}})
    }
    foreach($definition in Get-WinSecWindowsUpdateTechnicalFields|Where-Object Inventory -CIN @('GPOAU','GPOUpdate')){
        $data[$definition.Inventory]|Add-Member NoteProperty $definition.Property ([pscustomobject]@{State='NOT_CONFIGURED';Kind=$null;Value=$null})
    }
    $sources=@(foreach($area in Get-WinSecWindowsUpdateTechnicalAreas){[pscustomobject]@{SourceId=$area.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;
        CollectedAtUTC='2026-10-28T01:02:04.0000000Z';State='OBSERVED';Data=$data[$area.Id]}})
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-28T01:02:03.0000000Z';CompletedAtUTC='2026-10-28T01:02:05.0000000Z';GeneratedAtUTC='2026-10-28T01:02:06.0000000Z'}
}

function New-WinSecWindowsUpdateFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecWindowsUpdateTechnicalSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Get-WinSecWindowsUpdateFixtureReadings {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)
}
