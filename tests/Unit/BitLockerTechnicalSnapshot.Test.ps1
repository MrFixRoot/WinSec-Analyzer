# Synthetic prepared data only; native provider functions fail if accidentally invoked.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/BitLocker/BitLockerTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/BitLockerTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Invoke-CimMethod {throw 'Native audit forbidden.'}
function Get-BitLockerVolume {throw 'Native audit forbidden.'}
$passed=0;$failed=0
function Assert-BitLockerCandidate {param([bool]$Value);if(-not $Value){throw 'BitLocker candidate assertion failed.'}}
function Reject-BitLockerCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-BitLockerCandidate $caught}
function Test-BitLockerCandidate {param($Name,[scriptblock]$Action);$f=New-WinSecBitLockerTechnicalFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
Test-BitLockerCandidate 'A versioned candidate reviews forty fields and eight singleton inventories' {
    $c=Get-WinSecBitLockerTechnicalCatalog;Assert-WinSecSnapshotCatalog $c
    Assert-BitLockerCandidate ($c.CatalogId -ceq 'WinSec.BitLocker.Candidate' -and $c.CheckId -ceq 'WSA-SYS-002' -and $c.Fields.Count -eq 40 -and $c.Inventories.Count -eq 8 -and
        @($c.Inventories|Where-Object {-not $_.Singleton}).Count -eq 0 -and ($c.Fields.Id -join '|') -notmatch 'KeyProtector|RecoveryKey|Password|Secret')
}
Test-BitLockerCandidate 'Complete collection preserves false and zero without a score or security judgment' {
    $s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'COMPLETE' -and $s.Collection.Observed -eq 40 -and
        (Get-WinSecBitLockerFixtureReading $s Volume.IsVolumeInitializedForProtection).Value -ceq $false -and
        (Get-WinSecBitLockerFixtureReading $s Protection.ProtectionStatus).Value -eq 0 -and -not $s.PSObject.Properties['Score'])
}
Test-BitLockerCandidate 'Conversion flags wiping metadata and native hardware diagnostics remain available' {
    $f.Sources[3].Data.EncryptionFlags=[uint32]65537;$f.Sources[7].Data.TestError=[uint32]2150694975
    $s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ((Get-WinSecBitLockerFixtureReading $s Conversion.EncryptionFlags).Value -eq 65537 -and
        (Get-WinSecBitLockerFixtureReading $s Conversion.WipingPercentage).Value -eq 0 -and
        (Get-WinSecBitLockerFixtureReading $s Metadata.Version).Value -eq 2 -and
        (Get-WinSecBitLockerFixtureReading $s HardwareTest.TestError).Value -eq 2150694975)
}
Test-BitLockerCandidate 'One hundred percent does not rewrite an in-progress conversion code' {
    $f.Sources[3].Data.ConversionStatus=[uint32]2;$f.Sources[3].Data.EncryptionPercentage=[uint32]100
    $s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ((Get-WinSecBitLockerFixtureReading $s Conversion.ConversionStatus).Value -eq 2 -and
        (Get-WinSecBitLockerFixtureReading $s Conversion.EncryptionPercentage).Value -eq 100)
}
Test-BitLockerCandidate 'Optional missing telemetry limits coverage while required missing telemetry remains partial' {
    $f.Sources[3].Data.PSObject.Properties.Remove('WipingStatus');$s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED')
    $f.Sources[3].Data.PSObject.Properties.Remove('EncryptionPercentage');$s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ($s.Collection.Status -ceq 'PARTIAL')
}
Test-BitLockerCandidate 'A numeric Boolean or out-of-range percentage is not a verified reading' {
    $f.Sources[1].Data.IsVolumeInitializedForProtection=0;$f.Sources[3].Data.EncryptionPercentage=[uint32]101
    $s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ((Get-WinSecBitLockerFixtureReading $s Volume.IsVolumeInitializedForProtection).State -ceq 'UNKNOWN' -and
        (Get-WinSecBitLockerFixtureReading $s Conversion.EncryptionPercentage).Reason -ceq 'INVALID_VALUE' -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($area in @(Get-WinSecBitLockerTechnicalAreas|Where-Object Method)){Test-BitLockerCandidate ('A failed native return code suppresses output: '+$area.Id) {
    $source=@($f.Sources|Where-Object SourceId -CEQ $area.Id)[0];$source.Data.ReturnValue=[uint32]2150694912
    $s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    $outputs=@($s.Batches|Where-Object InventoryId -CEQ $area.Id|ForEach-Object Records|ForEach-Object Readings|Where-Object {$_.FieldId -cnotin @(($area.Id+'.ReturnValue'),($area.Id+'.CollectedAtUTC'),($area.Id+'.TargetVolumeId'))})
    Assert-BitLockerCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecBitLockerFixtureReading $s ($area.Id+'.ReturnValue')).Value -eq 2150694912 -and
        @($outputs|Where-Object {$_.State -cne 'ERROR' -or $null -ne $_.Value}).Count -eq 0)
}}
foreach($value in @($null,'0',$false)){Test-BitLockerCandidate 'Malformed method return values cannot authorize output telemetry' {
    $f.Sources[2].Data.ReturnValue=$value;$s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecBitLockerFixtureReading $s Protection.ProtectionStatus).State -ceq 'UNKNOWN')
}}
foreach($state in @('ERROR','NOT_COLLECTED')){Test-BitLockerCandidate ('Unavailable method data is explicit: '+$state) {
    $f.Sources[6].State=$state;$f.Sources[6].Data=$null;$s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecBitLockerFixtureReading $s Metadata.Version).State -ceq $state)
}}
Test-BitLockerCandidate 'No volume identity is fabricated when the provider is unavailable' {
    foreach($source in $f.Sources|Where-Object SourceId -CNE Platform){$source.State='NOT_COLLECTED';$source.Data=$null;$source.VolumeDeviceId=$null}
    $s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecBitLockerFixtureReading $s Volume.DeviceID).State -ceq 'NOT_COLLECTED')
}
foreach($damage in @('owner','scan','duplicate','extra','time','scope','other-control','other-volume','drive','type','unbound','raw-error','platform','version')){Test-BitLockerCandidate ('Foreign or inconsistent capture is rejected: '+$damage) {
    switch($damage){
        owner {$f.Sources[2].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[2].ScanId='another'}
        duplicate {$f.Sources[2].SourceId='Volume'};extra {$f.Sources[2]|Add-Member NoteProperty RawError 'PRIVATE-SECRET'}
        time {$f.Sources[2].CollectedAtUTC='2026-10-29T01:02:04.0000000Z'};scope {$f.Identity.ScopeKey='WSA-SYS-001'}
        other-control {$f.Identity.CheckId='WSA-SYS-001';$f.Identity.ScopeKey='WSA-SYS-001'}
        other-volume {$f.Sources[2].VolumeDeviceId='\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\'}
        drive {$f.Sources[1].Data.DriveLetter='C:'};type {$f.Sources[1].Data.VolumeType=[uint32]1}
        unbound {$f.Sources[1].Data.DeviceID='PRIVATE-SECRET'};raw-error {$f.Sources[6].State='ERROR'}
        platform {$f.Sources[0].Data.BuildNumber='19045';$f.Sources[0].Data.Version='10.0.19045'}
        version {$f.Sources[0].Data.Version='10.0.22631'}
    }
    Reject-BitLockerCandidate {New-WinSecBitLockerFixturePackage $f}
}}
Test-BitLockerCandidate 'Source timestamps and volume bindings persist per method without profile-derived metadata' {
    $f.Sources[7].CollectedAtUTC='2026-10-28T01:02:05.0000000Z';$s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ($s.CollectedAtUTC -ceq $f.Sources[7].CollectedAtUTC -and
        (Get-WinSecBitLockerFixtureReading $s HardwareTest.CollectedAtUTC).Value -ceq $f.Sources[7].CollectedAtUTC -and
        (Get-WinSecBitLockerFixtureReading $s HardwareTest.TargetVolumeId).Value -ceq $f.Sources[1].Data.DeviceID -and
        $null -eq $s.Platform.Edition -and $null -eq $s.Platform.OSRelease -and $null -eq $s.Platform.UBR)
}
Test-BitLockerCandidate 'Future numeric enums and unknown-algorithm sentinel remain raw codes without guessed interpretations' {
    $f.Sources[2].Data.ProtectionStatus=[uint32]2;$f.Sources[4].Data.EncryptionMethod=[uint32]::MaxValue
    $s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ((Get-WinSecBitLockerFixtureReading $s Protection.ProtectionStatus).Value -eq 2 -and
        (Get-WinSecBitLockerFixtureReading $s Algorithm.EncryptionMethod).Value -eq [uint32]::MaxValue)
}
Test-BitLockerCandidate 'Unreviewed secrets and calculated properties never execute or enter the snapshot' {
    $script:getters=0;$f.Sources[2].Data|Add-Member ScriptProperty RecoveryKey {$script:getters++;'PRIVATE-SECRET'}
    $f.Sources[2].Data|Add-Member ScriptProperty ProtectionStatus {$script:getters++;'PRIVATE-SECRET'} -Force
    $f.Sources[4].Data|Add-Member NoteProperty SelfEncryptionDriveEncryptionMethod 'PRIVATE-SECRET'
    $s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    Assert-BitLockerCandidate ($script:getters -eq 0 -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|RecoveryKey|SelfEncryptionDriveEncryptionMethod' -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-BitLockerCandidate 'Ordinary dictionaries work but arrays of volumes are rejected without silently selecting one' {
    $f.Sources[2].Data=@{ReturnValue=[uint32]0;ProtectionStatus=[uint32]0};$null=New-WinSecBitLockerFixturePackage $f
    $f.Sources[1].Data=@($f.Sources[1].Data,$f.Sources[1].Data);Reject-BitLockerCandidate {New-WinSecBitLockerFixturePackage $f}
}
Test-BitLockerCandidate 'Real normalization progress can be cancelled without input mutation' {
    $script:done=0;$before=ConvertTo-Json $f -Depth 10 -Compress;$cancelled=$false
    try{$null=New-WinSecBitLockerFixturePackage $f -ProgressCallback {param($event);$script:done=$event.CompletedInventories} -CancellationAction {$script:done -ge 3}}
    catch [OperationCanceledException]{$cancelled=$true}
    Assert-BitLockerCandidate ($cancelled -and $script:done -eq 3 -and (ConvertTo-Json $f -Depth 10 -Compress) -ceq $before)
}
foreach($damage in @('volume','time','method','collector')){Test-BitLockerCandidate ('Semantic revalidation rejects a forged saved value: '+$damage) {
    $s=(New-WinSecBitLockerFixturePackage $f).Snapshot
    switch($damage){
        volume {(Get-WinSecBitLockerFixtureReading $s Lock.TargetVolumeId).Value='\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\'}
        time {(Get-WinSecBitLockerFixtureReading $s Lock.CollectedAtUTC).Value='2026-10-29T01:02:04.0000000Z'}
        method {(Get-WinSecBitLockerFixtureReading $s Lock.ReturnValue).Value=[uint32]5}
        collector {$s.CollectorVersion='9.0.0'}
    }
    Reject-BitLockerCandidate {Assert-WinSecBitLockerTechnicalSnapshot $s $f.Identity}
}}
Write-Host ("BitLocker technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
