[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Defender/DefenderPreferenceCapture.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderTechnicalMemory.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderPreferenceMemory.ps1')
function Get-CimClass {[CmdletBinding()]param([string]$Namespace,[string]$ClassName,[uint32]$OperationTimeoutSec);Get-WinSecDefenderPreferenceFixtureSchema @PSBoundParameters}
function Get-CimInstance {[CmdletBinding()]param([string]$Namespace,[string]$ClassName,[uint32]$OperationTimeoutSec,[string[]]$Property);Get-WinSecDefenderPreferenceFixtureData @PSBoundParameters}
function Get-MpComputerStatus {throw 'Native status forbidden.'}
function Get-MpPreference {throw 'Whole preference objects forbidden.'}
function Start-Job {$script:jobsStarted++;throw 'No jobs in unit tests.'}
$passed=0;$failed=0;$script:jobsStarted=0
function Assert-PreferenceCapture {param([bool]$Value);if(-not $Value){throw 'Preference capture assertion failed.'}}
function Reject-PreferenceCapture {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PreferenceCapture $caught}
function Test-PreferenceCapture {
    param([string]$Name,[scriptblock]$Action)
    $f=New-WinSecDefenderTechnicalFixture;$script:DefenderPreferenceFixtureMode='Success'
    $script:DefenderPreferenceFixtureQueries=0;$script:DefenderPreferenceFixtureSchemaQueries=0
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function New-PreferenceFrame {& (Get-WinSecDefenderPreferenceQueryWorker) (Join-Path $root 'src/Checks/Defender/DefenderTechnicalSnapshot.ps1') $f.Identity.DeviceId $f.Identity.ScanId}
function Read-PreferenceFrame {param([object]$Frame);ConvertFrom-WinSecDefenderPreferenceQueryFrame $Frame $f.Identity '2020-01-01T00:00:00.0000000Z' '2100-01-01T00:00:00.0000000Z'}
Test-PreferenceCapture 'Exactly 68 scalars are projected, including 45 Boolean, 22 UInt32 and one percent' {
    $capture=Read-PreferenceFrame (New-PreferenceFrame);$fields=@(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Preferences)
    Assert-PreferenceCapture ($capture.Coverage.Observed -eq 68 -and $capture.Coverage.Complete -and $capture.Source.Scope -ceq 'SCALARS_ONLY' -and
        @($fields|Where-Object Kind -CEQ Boolean).Count -eq 45 -and @($fields|Where-Object Kind -CEQ UInt32).Count -eq 22 -and
        @($fields|Where-Object Kind -CEQ Percent).Count -eq 1 -and $script:DefenderPreferenceFixtureQueries -eq 1 -and $script:DefenderPreferenceFixtureSchemaQueries -eq 1)
    Assert-PreferenceCapture ($capture.Provenance.Provider -ceq 'CIM' -and $capture.Provenance.Properties.Count -eq 68 -and -not $capture.Provenance.RemoteRequested -and -not $capture.Provenance.FallbackUsed)
    Assert-PreferenceCapture ((ConvertTo-Json $capture -Depth 12 -Compress) -notmatch 'PRIVATE-|ExclusionPath|ProxyServer|AttackSurfaceReductionRules|RunspaceId')
}
Test-PreferenceCapture 'All catalog scalar values survive normalization without interpreting false or zero as missing' {
    $capture=Read-PreferenceFrame (New-PreferenceFrame)
    foreach($field in @(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Preferences)){
        $r=@($capture.Source.Data.Readings|Where-Object FieldId -CEQ $field.Id)[0]
        $expected=$f.Sources[2].Data.($field.Property)
        Assert-PreferenceCapture ($r.State -ceq 'OBSERVED' -and $r.Value -ceq $expected)
    }
}
foreach($mode in @('MissingOptional','MissingRequired','NullRequired','MissingSchemaOptional','MissingSchemaRequired','IncompatibleSchema','InvalidBoolean','InvalidPercent','EmptyCarrier')){
    Test-PreferenceCapture ('Unknown values remain explicit and do not become defaults: '+$mode) {
        $script:DefenderPreferenceFixtureMode=$mode;$capture=Read-PreferenceFrame (New-PreferenceFrame)
        $id=if($mode -cin @('MissingOptional','MissingSchemaOptional')){'Preferences.EnableDnsSinkhole'}elseif($mode -ceq 'InvalidPercent'){'Preferences.ScanAvgCPULoadFactor'}else{'Preferences.DisableRealtimeMonitoring'}
        $r=@($capture.Source.Data.Readings|Where-Object FieldId -CEQ $id)[0]
        $why=if($mode -cin @('InvalidBoolean','InvalidPercent')){'INVALID_VALUE'}else{'PROVIDER_UNAVAILABLE'}
        Assert-PreferenceCapture ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq $why -and $null -eq $r.Value -and -not $capture.Coverage.Complete)
        if($mode -cin @('MissingSchemaOptional','MissingSchemaRequired','IncompatibleSchema')){Assert-PreferenceCapture ($capture.Provenance.Properties.Count -eq 67)}
    }
}
foreach($case in @(@('SchemaError','SCHEMA_UNAVAILABLE'),@('SchemaEmpty','UNEXPECTED_CARDINALITY'),@('SchemaDuplicate','UNEXPECTED_CARDINALITY'),
    @('SchemaPlain','INVALID_SCHEMA'),@('WrongSchemaClass','INVALID_SCHEMA'),@('WrongSchemaNamespace','INVALID_SCHEMA'),@('NoProperties','NO_REVIEWED_PROPERTIES'),
    @('ProviderError','PROVIDER_UNAVAILABLE'),@('Empty','UNEXPECTED_CARDINALITY'),@('Duplicate','UNEXPECTED_CARDINALITY'),
    @('PlainCarrier','INVALID_SOURCE'),@('WrongClass','INVALID_SOURCE'),@('WrongNamespace','INVALID_SOURCE'))){
    Test-PreferenceCapture ('Safe source diagnostics without exception disclosure: '+$case[0]) {
        $script:DefenderPreferenceFixtureMode=$case[0];$capture=Read-PreferenceFrame (New-PreferenceFrame)
        Assert-PreferenceCapture ($capture.Diagnostic -ceq $case[1] -and $capture.Source.State -ceq 'ERROR' -and $null -eq $capture.Source.Data -and
            $capture.Coverage.Errors -eq 68 -and (ConvertTo-Json $capture -Depth 12 -Compress) -notmatch 'PRIVATE-')
        if($case[0] -cin @('SchemaError','SchemaEmpty','SchemaDuplicate','SchemaPlain','WrongSchemaClass','WrongSchemaNamespace','NoProperties')){
            Assert-PreferenceCapture ($script:DefenderPreferenceFixtureQueries -eq 0)
        }
    }
}
foreach($mode in @('UIntMax','ByteCode')){Test-PreferenceCapture ('Unrecognized numeric codes remain technical evidence: '+$mode) {
    $script:DefenderPreferenceFixtureMode=$mode;$capture=Read-PreferenceFrame (New-PreferenceFrame)
    $id=if($mode -ceq 'UIntMax'){'Preferences.IntelTDTEnabled'}else{'Preferences.RealTimeScanDirection'}
    $expected=if($mode -ceq 'UIntMax'){[uint32]::MaxValue}else{[uint32]99}
    $r=@($capture.Source.Data.Readings|Where-Object FieldId -CEQ $id)[0]
    Assert-PreferenceCapture ($r.State -ceq 'OBSERVED' -and $r.Value -is [uint32] -and $r.Value -eq $expected)
}}
foreach($value in @([uint32]0,[uint32]100)){Test-PreferenceCapture ('Percent boundary retained: '+$value) {
    $source=New-WinSecDefenderPreferenceFixtureCarrier
    try{$source.Data.CimInstanceProperties['ScanAvgCPULoadFactor'].Value=$value
        $p=New-WinSecDefenderPreferenceReadings $source.Data -RequestedProperties @('ScanAvgCPULoadFactor')
        Assert-PreferenceCapture ($p.Readings[-1].Value -eq $value -and @($p.Readings|Where-Object State -CEQ OBSERVED).Count -eq 1)
    }finally{$source.Data.Dispose()}
}}
Test-PreferenceCapture 'Noisy non-output streams are discarded' {
    $script:DefenderPreferenceFixtureMode='Noisy';$output=@(New-PreferenceFrame *>&1)
    Assert-PreferenceCapture ($output.Count -eq 1 -and $output[0].State -ceq 'OBSERVED')
}
Test-PreferenceCapture 'Known CLIXML lists are canonicalized and then strictly validated' {
    $copy=[Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize((New-PreferenceFrame),16))
    Assert-PreferenceCapture ($copy.RequestedProperties -is [Collections.ArrayList] -and $copy.Data.Readings -is [Collections.ArrayList])
    Assert-PreferenceCapture ((Read-PreferenceFrame $copy).Coverage.Observed -eq 68)
    $copy.RequestedProperties[0]='ExclusionPath';Reject-PreferenceCapture {Read-PreferenceFrame $copy}
}
foreach($damage in @('Marker','Version','Missing','Extra','Order','Duplicate','Field','State','Reason','UnknownValue','ValueType','Getter')){
    Test-PreferenceCapture ('Malformed scalar payload is rejected: '+$damage) {
        $frame=New-PreferenceFrame;$data=$frame.Data
        switch($damage){Marker {$data.ArtifactType='foreign'};Version {$data.SchemaVersion='9.0.0'};Missing {$data.Readings=@($data.Readings|Select-Object -Skip 1)}
            Extra {$data.Readings+=,$data.Readings[0]};Order {$a=$data.Readings[0];$data.Readings[0]=$data.Readings[1];$data.Readings[1]=$a}
            Duplicate {$data.Readings[1]=$data.Readings[0]};Field {$data.Readings[0].FieldId='Preferences.ExclusionPath'}
            State {$data.Readings[0].State='NOT_APPLICABLE'};Reason {$data.Readings[0].Reason='INVALID_VALUE'}
            UnknownValue {$data.Readings[0].State='UNKNOWN';$data.Readings[0].Reason='INVALID_VALUE'}
            ValueType {$data.Readings[0].Value=[uint32]0}
            Getter {$script:executed=0;$data.Readings[0]|Add-Member -MemberType ScriptProperty -Name Value -Value {$script:executed++;throw 'PRIVATE-SECRET'} -Force}}
        Reject-PreferenceCapture {Read-PreferenceFrame $frame}
        if($damage -ceq 'Getter'){Assert-PreferenceCapture ($script:executed -eq 0)}
    }
}
foreach($header in @('SchemaVersion','SourceId','DeviceId','ScanId','CollectedAtUTC','State','Reason')){
    Test-PreferenceCapture ('Array headers reject before coercion: '+$header) {$frame=New-PreferenceFrame;$frame.$header=@($frame.$header);Reject-PreferenceCapture {Read-PreferenceFrame $frame}}
}
foreach($damage in @('Duplicate','Empty','Unreviewed','UnrequestedObserved','Timeline')){Test-PreferenceCapture ('Projection and source bindings reject tampering: '+$damage) {
    $frame=New-PreferenceFrame
    switch($damage){Duplicate {$frame.RequestedProperties+=,$frame.RequestedProperties[0]};Empty {$frame.RequestedProperties=@()}
        Unreviewed {$frame.RequestedProperties[0]='ExclusionPath'};UnrequestedObserved {$frame.RequestedProperties=@($frame.RequestedProperties|Select-Object -Skip 1)}
        Timeline {$frame.CollectedAtUTC='2200-01-01T00:00:00.0000000Z'}}
    Reject-PreferenceCapture {Read-PreferenceFrame $frame}
}}
Test-PreferenceCapture 'Only the reviewed immutable schema metadata is read through CLR accessors' {
    $source=New-WinSecDefenderPreferenceFixtureCarrier;$schema=$source.Data.CimClass;$source.Data.Dispose();$script:executed=0
    try{
        $schema|Add-Member -MemberType ScriptProperty -Name CimSystemProperties -Value {$script:executed++;throw 'PRIVATE-SECRET'} -Force
        $schema|Add-Member -MemberType ScriptProperty -Name CimClassProperties -Value {$script:executed++;throw 'PRIVATE-SECRET'} -Force
        Assert-PreferenceCapture (@(Get-WinSecDefenderPreferenceProjection $schema).Count -eq 68 -and $script:executed -eq 0)
    }finally{$schema.Dispose()}
}
Test-PreferenceCapture 'Historical catalog digest is unchanged and the CIM source has a distinct reviewed version' {
    $old=Get-WinSecDefenderTechnicalCatalog;$new=Get-WinSecDefenderTechnicalCatalog 1.1.0
    Assert-PreferenceCapture ((Get-WinSecSnapshotCatalogHash $old) -ceq '75423BCC66B40648658364385765246B08D72D7DD0B6A3C9B328BC93DDD34127' -and
        (Get-WinSecSnapshotCatalogHash $new) -cne (Get-WinSecSnapshotCatalogHash $old) -and $old.Fields.Count -eq $new.Fields.Count -and
        @($old.Sources|Where-Object Id -CEQ Preferences)[0].Provider -ceq 'CMDLET' -and @($new.Sources|Where-Object Id -CEQ Preferences)[0].Provider -ceq 'CIM')
}
foreach($receiptHeader in @('SchemaVersion','Scope')){Test-PreferenceCapture ('Scoped receipt headers reject arrays: '+$receiptHeader) {
    $capture=Read-PreferenceFrame (New-PreferenceFrame);$capture.Source.CollectedAtUTC=$f.Sources[2].CollectedAtUTC;$f.Sources[2]=$capture.Source
    $capture.Source.$receiptHeader=@($capture.Source.$receiptHeader);Reject-PreferenceCapture {New-WinSecDefenderFixturePackage $f}
}}
Test-PreferenceCapture 'Snapshot progress cannot mutate already validated preference rows' {
    $capture=Read-PreferenceFrame (New-PreferenceFrame);$capture.Source.CollectedAtUTC=$f.Sources[2].CollectedAtUTC;$f.Sources[2]=$capture.Source
    $script:preferencePayload=$capture.Source.Data
    $s=(New-WinSecDefenderFixturePackage $f -ProgressCallback {param($event);if($event.InventoryId -ceq 'Platform'){$script:preferencePayload.Readings[0].Value=$true}}).Snapshot
    Assert-PreferenceCapture ((Get-WinSecDefenderFixtureReading $s Preferences.CheckForSignaturesBeforeRunningScan).Value -ceq $false)
}
Test-PreferenceCapture 'A typed payload without scalar source version cannot be mistaken for complete preferences' {
    $frame=New-PreferenceFrame;$f.Sources[2].Data=$frame.Data;Reject-PreferenceCapture {New-WinSecDefenderFixturePackage $f}
}
Test-PreferenceCapture 'Scalar-only source cannot be broadened by adding raw ASR or exclusions' {
    $capture=Read-PreferenceFrame (New-PreferenceFrame);$capture.Source.CollectedAtUTC=$f.Sources[2].CollectedAtUTC
    $capture.Source.Data|Add-Member ExclusionPath @('PRIVATE-SECRET');$f.Sources[2]=$capture.Source
    Reject-PreferenceCapture {New-WinSecDefenderFixturePackage $f}
}
Test-PreferenceCapture 'Capture and snapshot detach values from later caller mutation' {
    $frame=New-PreferenceFrame;$capture=Read-PreferenceFrame $frame;$frame.Data.Readings[0].Value=$true
    Assert-PreferenceCapture ($capture.Source.Data.Readings[0].Value -ceq $false)
    $capture.Source.CollectedAtUTC=$f.Sources[2].CollectedAtUTC;$f.Sources[2]=$capture.Source
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$capture.Source.Data.Readings[0].Value=$true
    Assert-PreferenceCapture ((Get-WinSecDefenderFixtureReading $s Preferences.CheckForSignaturesBeforeRunningScan).Value -ceq $false)
}
Test-PreferenceCapture 'Source scope and version are strict and validated without getters' {
    $capture=Read-PreferenceFrame (New-PreferenceFrame);$capture.Source.CollectedAtUTC=$f.Sources[2].CollectedAtUTC;$f.Sources[2]=$capture.Source
    $capture.Source.Scope='ALL';Reject-PreferenceCapture {New-WinSecDefenderFixturePackage $f}
    $capture.Source.Scope='SCALARS_ONLY';$script:executed=0
    $capture.Source|Add-Member -MemberType ScriptProperty -Name SchemaVersion -Value {$script:executed++;throw 'PRIVATE-SECRET'} -Force
    Reject-PreferenceCapture {New-WinSecDefenderFixturePackage $f};Assert-PreferenceCapture ($script:executed -eq 0)
}
Test-PreferenceCapture 'Cancellation interrupts payload validation' {
    $p=(New-PreferenceFrame).Data;$cancelled=$false
    try{Assert-WinSecDefenderPreferenceReadings $p -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Assert-PreferenceCapture $cancelled
}
Test-PreferenceCapture 'Foreign controls and cancellation perform no acquisition' {
    $other=$f.Identity.PSObject.Copy();$other.CheckId='WSA-SYS-002';$other.ScopeKey='WSA-SYS-002'
    Reject-PreferenceCapture {Invoke-WinSecDefenderPreferenceCapture $other}
    $cancelled=$false;try{$null=Invoke-WinSecDefenderPreferenceCapture $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Reject-PreferenceCapture {Invoke-WinSecDefenderPreferenceCapture $f.Identity -CancellationAction {'yes'}}
    Assert-PreferenceCapture ($cancelled -and $script:jobsStarted -eq 0)
}
Write-Host ("Defender preference capture: $passed passed; $failed failed.");if($failed){exit 1}
