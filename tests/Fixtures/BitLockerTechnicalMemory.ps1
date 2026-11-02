# Prepared receipts only; no native provider, Windows or application-data access.
function New-WinSecBitLockerTechnicalFixture {
    param()
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-bitlocker';SnapshotId=('b'*32);
        CheckId='WSA-SYS-002';SectionKey='SystemSecurity';ScopeType='CONTROL';ScopeKey='WSA-SYS-002'}
    $volume='\\?\Volume{12345678-1234-4567-89ab-123456789abc}\'
    $data=@{
        Platform=[pscustomobject]@{Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1;SystemDrive='D:'}
        Volume=[pscustomobject]@{DeviceID=$volume;DriveLetter='D:';VolumeType=[uint32]0;IsVolumeInitializedForProtection=$false}
        Protection=[pscustomobject]@{ReturnValue=[uint32]0;ProtectionStatus=[uint32]0}
        Conversion=[pscustomobject]@{ReturnValue=[uint32]0;ConversionStatus=[uint32]0;EncryptionPercentage=[uint32]0;EncryptionFlags=[uint32]1;WipingStatus=[uint32]0;WipingPercentage=[uint32]0}
        Algorithm=[pscustomobject]@{ReturnValue=[uint32]0;EncryptionMethod=[uint32]0}
        Lock=[pscustomobject]@{ReturnValue=[uint32]0;LockStatus=[uint32]0}
        Metadata=[pscustomobject]@{ReturnValue=[uint32]0;Version=[uint32]2}
        HardwareTest=[pscustomobject]@{ReturnValue=[uint32]0;TestStatus=[uint32]0;TestError=[uint32]0}
    }
    $sources=@(foreach($area in Get-WinSecBitLockerTechnicalAreas){
        [pscustomobject]@{SourceId=$area.Id;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-28T01:02:04.0000000Z';
            VolumeDeviceId=$(if($area.Id -ceq 'Platform'){$null}else{$volume});State='OBSERVED';Data=$data[$area.Id]}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-28T01:02:03.0000000Z';CompletedAtUTC='2026-10-28T01:02:05.0000000Z';GeneratedAtUTC='2026-10-28T01:02:06.0000000Z'}
}

function New-WinSecBitLockerFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecBitLockerTechnicalSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Get-WinSecBitLockerFixtureReading {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)[0]
}
