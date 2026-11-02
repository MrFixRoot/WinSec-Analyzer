[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Defender/DefenderStatusCapture.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderTechnicalMemory.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderStatusMemory.ps1')
function Get-MpComputerStatus {[CmdletBinding()]param();Get-WinSecDefenderStatusFixtureData}
function Get-MpPreference {throw 'Preference acquisition forbidden.'}
function Get-CimInstance {throw 'Native CIM query forbidden.'}
function Get-CimClass {throw 'Native CIM schema forbidden.'}
$script:jobsStarted=0
function Start-Job {[CmdletBinding()]param($ScriptBlock,$ArgumentList);$script:jobsStarted++;throw 'Unexpected job in a pure unit test.'}
$passed=0;$failed=0
function Assert-StatusCapture {param([bool]$Value);if(-not $Value){throw 'Status capture assertion failed.'}}
function Reject-StatusCapture {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-StatusCapture $caught}
function New-StatusFrame {
    $script:DefenderStatusFixtureQueries=0
    & (Get-WinSecDefenderStatusQueryWorker) (Join-Path $root 'src/Checks/Defender/DefenderTechnicalSnapshot.ps1') $f.Identity.DeviceId $f.Identity.ScanId
}
function Read-StatusFrame {param([object]$Frame);ConvertFrom-WinSecDefenderStatusQueryFrame $Frame $f.Identity '2020-01-01T00:00:00.0000000Z' '2099-01-01T00:00:00.0000000Z'}
function Test-StatusCapture {
    param([string]$Name,[scriptblock]$Action)
    $f=New-WinSecDefenderTechnicalFixture;$script:DefenderStatusFixtureMode='Success'
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-StatusCapture 'One local status query conserves exactly all 42 reviewed readings' {
    $capture=Read-StatusFrame (New-StatusFrame)
    Assert-StatusCapture ($script:DefenderStatusFixtureQueries -eq 1 -and $capture.Source.State -ceq 'OBSERVED' -and
        $capture.Coverage.Expected -eq 42 -and $capture.Coverage.Observed -eq 42 -and $capture.Coverage.Complete -and
        $capture.Provenance.Command -ceq 'Get-MpComputerStatus' -and -not $capture.Provenance.RemoteRequested -and -not $capture.Provenance.FallbackUsed)
}
Test-StatusCapture 'All 18 additional properties are included in the status capture' {
    $payload=(Read-StatusFrame (New-StatusFrame)).Source.Data
    foreach($property in @('AntispywareEnabled','IsVirtualMachine','FullScanOverdue','FullScanRequired','QuickScanOverdue','AntispywareSignatureAge',
        'LastFullScanSource','LastQuickScanSource','RealTimeScanDirection','ProductStatus','AMServiceVersion','AntispywareSignatureVersion',
        'NISEngineVersion','FullScanSignatureVersion','QuickScanSignatureVersion','AntispywareSignatureLastUpdated','QuickScanStartTime','FullScanStartTime')){
        $definition=@(Get-WinSecDefenderTechnicalFields|Where-Object { $_.Inventory -ceq 'Status' -and $_.Property -ceq $property})[0]
        Assert-StatusCapture (@($payload.Readings|Where-Object FieldId -CEQ $definition.Id).Count -eq 1)
    }
}
Test-StatusCapture 'Raw and normalized captures produce exactly the same snapshot when values are valid' {
    $raw=ConvertTo-WinSecDefenderCimFixture $f
    try{
        $before=New-WinSecDefenderFixturePackage $raw;$payload=New-WinSecDefenderStatusReadings $raw.Sources[1].Data
        $raw.Sources[1].Data.Dispose();$raw.Sources[1].Data=$payload;$after=New-WinSecDefenderFixturePackage $raw
        Assert-StatusCapture ((ConvertTo-Json -InputObject $before -Depth 20 -Compress) -ceq (ConvertTo-Json -InputObject $after -Depth 20 -Compress))
    }finally{Close-WinSecDefenderCimFixture $raw}
}
Test-StatusCapture 'Private metadata, detection details and invalid strings never cross the boundary' {
    foreach($fixtureMode in @('Success','InvalidVersion','UnknownMode')){
        $script:DefenderStatusFixtureMode=$fixtureMode;$capture=Read-StatusFrame (New-StatusFrame)
        Assert-StatusCapture ((ConvertTo-Json -InputObject $capture -Depth 12 -Compress) -notmatch 'PRIVATE-|ComputerID|ThreatResources|CimInstanceProperties|PSComputerName')
    }
}
foreach($fixtureMode in @('ProviderError','Empty','Duplicate','WrongClass','WrongNamespace','PlainCarrier')){
    Test-StatusCapture ('Provider failure remains explicit without invented readings: '+$fixtureMode) {
        $script:DefenderStatusFixtureMode=$fixtureMode;$capture=Read-StatusFrame (New-StatusFrame)
        Assert-StatusCapture ($capture.Source.State -ceq 'ERROR' -and $null -eq $capture.Source.Data -and $capture.Coverage.Errors -eq 42 -and
            $capture.Coverage.RequiredUnresolved -eq 3 -and -not $capture.Coverage.Complete -and $capture.Diagnostic -cne 'NONE')
    }
}
foreach($fixtureMode in @('MissingOptional','MissingRequired','NullRequired','InvalidBoolean','InvalidVersion','UnknownMode')){
    Test-StatusCapture ('Unknown values and their exact reasons survive snapshot normalization: '+$fixtureMode) {
        $script:DefenderStatusFixtureMode=$fixtureMode;$capture=Read-StatusFrame (New-StatusFrame)
        $source=$capture.Source;$source.CollectedAtUTC=$f.Sources[1].CollectedAtUTC;$f.Sources[1]=$source
        $s=(New-WinSecDefenderFixturePackage $f).Snapshot
        $id=switch($fixtureMode){MissingOptional {'Status.AntispywareSignatureAgeDays'};{$_ -in @('MissingRequired','NullRequired','InvalidBoolean')} {'Status.AntivirusEnabled'};InvalidVersion {'Status.FullScanSignatureVersion'};UnknownMode {'Status.AMRunningMode'}}
        $r=Get-WinSecDefenderFixtureReading $s $id
        $why=if($fixtureMode -in @('InvalidBoolean','InvalidVersion','UnknownMode')){'INVALID_VALUE'}else{'PROVIDER_UNAVAILABLE'}
        Assert-StatusCapture ($capture.Source.State -ceq 'OBSERVED' -and $r.State -ceq 'UNKNOWN' -and $r.Reason -ceq $why -and $null -eq $r.Value -and $s.Collection.Coverage -ceq 'LIMITED')
        $required=$fixtureMode -in @('MissingRequired','NullRequired','InvalidBoolean')
        Assert-StatusCapture ($s.Collection.Status -ceq $(if($required){'PARTIAL'}else{'COMPLETE'}))
    }
}
Test-StatusCapture 'A valid but empty status carrier is unknown, not a secure or complete configuration' {
    $script:DefenderStatusFixtureMode='EmptyCarrier';$capture=Read-StatusFrame (New-StatusFrame)
    Assert-StatusCapture ($capture.Source.State -ceq 'OBSERVED' -and $capture.Coverage.Unknown -eq 42 -and $capture.Coverage.RequiredUnresolved -eq 3 -and -not $capture.Coverage.Complete)
}
Test-StatusCapture 'False, zero and native maximum age are preserved without evaluation' {
    $rows=(Read-StatusFrame (New-StatusFrame)).Source.Data.Readings
    Assert-StatusCapture (@($rows|Where-Object FieldId -CEQ Status.AntivirusEnabled)[0].Value -ceq $false -and
        @($rows|Where-Object FieldId -CEQ Status.ComputerState)[0].Value -eq 0 -and
        @($rows|Where-Object FieldId -CEQ Status.AntivirusSignatureAgeDays)[0].Value -eq [uint32]::MaxValue)
}
Test-StatusCapture 'A passive running mode is retained as configuration, not a provider error' {
    $script:DefenderStatusFixtureMode='Passive';$capture=Read-StatusFrame (New-StatusFrame)
    Assert-StatusCapture (@($capture.Source.Data.Readings|Where-Object FieldId -CEQ Status.AMRunningMode)[0].Value -ceq 'Passive Mode')
}
Test-StatusCapture 'Native UInt8 scan-source codes widen without dropping unrecognized values' {
    $raw=ConvertTo-WinSecDefenderCimFixture $f
    try{
        Set-WinSecDefenderCimFixtureProperty $raw.Sources[1] LastFullScanSource ([byte]99) UInt8
        $payload=New-WinSecDefenderStatusReadings $raw.Sources[1].Data
        $r=@($payload.Readings|Where-Object FieldId -CEQ Status.LastFullScanSource)[0]
        Assert-StatusCapture ($r.State -ceq 'OBSERVED' -and $r.Value -is [uint32] -and $r.Value -eq 99)
    }finally{Close-WinSecDefenderCimFixture $raw}
}
Test-StatusCapture 'Noisy non-output streams are discarded' {
    $script:DefenderStatusFixtureMode='Noisy';$output=@(New-StatusFrame *>&1)
    Assert-StatusCapture ($output.Count -eq 1 -and $output[0].State -ceq 'OBSERVED')
}
Test-StatusCapture 'CLIXML ArrayList transport is canonicalized without relaxing payload validation' {
    $frame=New-StatusFrame
    $copy=[Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($frame,16))
    Assert-StatusCapture ($copy.Data.Readings -is [Collections.ArrayList])
    $capture=Read-StatusFrame $copy
    Assert-StatusCapture ($capture.Source.Data.Readings -is [array] -and $capture.Coverage.Observed -eq 42)
    $copy.Data.Readings[0].FieldId='Status.ComputerID';Reject-StatusCapture {Read-StatusFrame $copy}
}
Test-StatusCapture 'Bootstrap failure is diagnosed without attributing an error to Defender or querying it' {
    $script:DefenderStatusFixtureQueries=0
    $frame=& (Get-WinSecDefenderStatusQueryWorker) (Join-Path $root '__missing_status_fixture__.ps1') $f.Identity.DeviceId $f.Identity.ScanId
    $capture=Read-StatusFrame $frame
    Assert-StatusCapture ($capture.Diagnostic -ceq 'BOOTSTRAP_FAILED' -and -not $capture.Provenance.QueryAttempted -and $script:DefenderStatusFixtureQueries -eq 0)
}
foreach($damage in @('Marker','Version','Missing','Extra','Order','Duplicate','Field','State','Reason','UnknownValue','ValueType','UnsafeString','Getter')){
    Test-StatusCapture ('Malformed status payload is rejected: '+$damage) {
        $frame=New-StatusFrame;$data=$frame.Data
        switch($damage){Marker {$data.ArtifactType='foreign'};Version {$data.SchemaVersion='9.0.0'};Missing {$data.Readings=@($data.Readings|Select-Object -Skip 1)}
            Extra {$data.Readings+=,$data.Readings[0]};Order {$a=$data.Readings[0];$data.Readings[0]=$data.Readings[1];$data.Readings[1]=$a}
            Duplicate {$data.Readings[1]=$data.Readings[0]};Field {$data.Readings[0].FieldId='Status.ComputerID'}
            State {$data.Readings[0].State='NOT_APPLICABLE'};Reason {$data.Readings[0].Reason='INVALID_VALUE'}
            UnknownValue {$data.Readings[0].State='UNKNOWN';$data.Readings[0].Reason='INVALID_VALUE'}
            ValueType {$data.Readings[0].Value=[uint32]0};UnsafeString {$data.Readings[-1].Value='PRIVATE-SECRET'}
            Getter {$script:executed=0;$data.Readings[0]|Add-Member -MemberType ScriptProperty -Name Value -Value {$script:executed++;throw 'PRIVATE-SECRET'} -Force}}
        Reject-StatusCapture {Read-StatusFrame $frame}
        if($damage -ceq 'Getter'){Assert-StatusCapture ($script:executed -eq 0)}
    }
}
foreach($headerName in @('SchemaVersion','SourceId','DeviceId','ScanId','CollectedAtUTC','State','Reason')){
    Test-StatusCapture ('Array headers are rejected before coercion: '+$headerName) {
        $frame=New-StatusFrame;$frame.$headerName=@($frame.$headerName);Reject-StatusCapture {Read-StatusFrame $frame}
    }
}
Test-StatusCapture 'Foreign identity and timeline cannot be attached to the current snapshot' {
    $frame=New-StatusFrame;$frame.ScanId='foreign';Reject-StatusCapture {Read-StatusFrame $frame}
    $frame=New-StatusFrame;$frame.CollectedAtUTC='2100-01-01T00:00:00.0000000Z';Reject-StatusCapture {Read-StatusFrame $frame}
}
Test-StatusCapture 'Capture and snapshot detach typed rows from later caller mutation' {
    $frame=New-StatusFrame;$capture=Read-StatusFrame $frame;$frame.Data.Readings[0].Value=$true
    Assert-StatusCapture ($capture.Source.Data.Readings[0].Value -ceq $false)
    $capture.Source.CollectedAtUTC=$f.Sources[1].CollectedAtUTC;$f.Sources[1]=$capture.Source
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$capture.Source.Data.Readings[0].Value=$true
    Assert-StatusCapture ((Get-WinSecDefenderFixtureReading $s Status.AMServiceEnabled).Value -ceq $false)
}
Test-StatusCapture 'Cancellation interrupts normalized status validation' {
    $payload=(New-StatusFrame).Data;$cancelled=$false
    try{Assert-WinSecDefenderStatusReadings $payload -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Assert-StatusCapture $cancelled
}
Test-StatusCapture 'Normalized timestamps must already be canonical UTC, not merely parseable' {
    $frame=New-StatusFrame;$r=@($frame.Data.Readings|Where-Object FieldId -CEQ Status.QuickScanStartTime)[0]
    $r.Value='2026-10-28T00:00:00Z';Reject-StatusCapture {Read-StatusFrame $frame}
}
Test-StatusCapture 'Progress callbacks cannot change already validated status values during snapshot construction' {
    $raw=ConvertTo-WinSecDefenderCimFixture $f
    try{
        $payload=New-WinSecDefenderStatusReadings $raw.Sources[1].Data;$raw.Sources[1].Data.Dispose();$raw.Sources[1].Data=$payload
        $script:statusPayload=$payload
        $s=(New-WinSecDefenderFixturePackage $raw -ProgressCallback {param($event);if($event.InventoryId -ceq 'Platform'){$script:statusPayload.Readings[0].Value=$true}}).Snapshot
        Assert-StatusCapture ((Get-WinSecDefenderFixtureReading $s Status.AMServiceEnabled).Value -ceq $false)
    }finally{Close-WinSecDefenderCimFixture $raw}
}
Test-StatusCapture 'Foreign controls and pre-start cancellation perform no acquisition' {
    $other=$f.Identity.PSObject.Copy();$other.CheckId='WSA-SYS-002';$other.ScopeKey='WSA-SYS-002'
    Reject-StatusCapture {Invoke-WinSecDefenderStatusCapture $other}
    $cancelled=$false;try{$null=Invoke-WinSecDefenderStatusCapture $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Assert-StatusCapture ($cancelled -and $script:jobsStarted -eq 0)
}
Test-StatusCapture 'Non-Boolean cancellation fails before worker startup' {
    Reject-StatusCapture {Invoke-WinSecDefenderStatusCapture $f.Identity -CancellationAction {'yes'}}
    Assert-StatusCapture ($script:jobsStarted -eq 0)
}
Write-Host ("Defender status capture: $passed passed; $failed failed.");if($failed){exit 1}
