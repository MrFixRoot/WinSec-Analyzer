[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Network/OpenPortsTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/OpenPortsTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native query forbidden.'}
function Get-CimClass {throw 'Native query forbidden.'}
function Get-NetTCPConnection {throw 'Native query forbidden.'}
function Get-NetUDPEndpoint {throw 'Native query forbidden.'}
$passed=0;$failed=0
function Assert-PortsCandidate {param([bool]$Value);if(-not $Value){throw 'Open Ports technical candidate assertion failed.'}}
function Reject-PortsCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PortsCandidate $caught}
function Get-PortsCandidateSummary {param($Snapshot,$Id);@($Snapshot.Inventories|Where-Object Id -CEQ $Id)[0]}
function Test-PortsCandidate {param($Name,[scriptblock]$Action);$f=New-WinSecOpenPortsCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}

Test-PortsCandidate 'The isolated catalog declares four inventories and forty five definitions' {
    $p=New-WinSecOpenPortsFixturePackage $f
    Assert-PortsCandidate ($p.Catalog.Fields.Count -eq 45 -and $p.Catalog.Inventories.Count -eq 4 -and $p.Snapshot.Collection.RetainedRecords -eq 6 -and
        $p.Snapshot.Collection.Observed -eq 76 -and $p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'COMPLETE')
}
Test-PortsCandidate 'Raw scoped IPv6 and IPv4 addresses remain identifiable with independent canonical values' {
    $s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ((Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddress)[1].Value -ceq 'FE80:0:0:0:0:0:0:1%5' -and
        (Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddressCanonical)[1].Value -ceq 'fe80::1%5' -and
        (Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddressFamily)[1].Value -ceq 'IPv6' -and
        (Get-WinSecOpenPortsFixtureReadings $s UDP.LocalAddress)[0].Value -ceq '192.0.2.10' -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'sha256:|Score|NOT_SCORED|/100')
}
foreach($address in @('0.0.0.0','::','127.0.0.1','::1','192.0.2.10','fe80::1%9')){Test-PortsCandidate ('Binding labels describe only the parsed local address: '+$address) {
    $f.Sources[1].Data[0].LocalAddress=$address;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    $expected=if($address -cin @('0.0.0.0','::')){'ANY'}elseif($address -cin @('127.0.0.1','::1')){'LOOPBACK'}else{'SPECIFIC'}
    Assert-PortsCandidate ((Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddressScope)[0].Value -ceq $expected -and $s.Collection.Status -ceq 'COMPLETE')
}}
foreach($address in @('127.1','010.0.0.1','0x7f000001','example.invalid','fe80::1%adapter','fe80::1%4294967296','C:\PRIVATE-SECRET')){Test-PortsCandidate ('Unreviewed address forms stay unknown without resolution: '+$address) {
    $f.Sources[1].Data[0].LocalAddress=$address;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ((Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddress)[0].State -ceq 'UNKNOWN' -and
        (Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddressCanonical)[0].State -ceq 'UNKNOWN' -and $s.Collection.Status -ceq 'PARTIAL' -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|example.invalid')
}}
Test-PortsCandidate 'PID zero native enum codes and maximum ports remain concrete values without process lookup' {
    $f.Sources[1].Data[0].OwningProcess=[uint32]0;$f.Sources[1].Data[0].AppliedSetting=[byte]255;$f.Sources[1].Data[0].HealthState=[uint16]65535
    $f.Sources[2].Data[0].LocalPort=[uint16]65535;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ((Get-WinSecOpenPortsFixtureReadings $s TCP.OwningProcess)[0].Value -eq 0 -and
        (Get-WinSecOpenPortsFixtureReadings $s TCP.AppliedSetting)[0].Value -eq 255 -and
        (Get-WinSecOpenPortsFixtureReadings $s TCP.HealthState)[0].Value -eq 65535 -and (Get-WinSecOpenPortsFixtureReadings $s UDP.LocalPort)[0].Value -eq 65535)
}
Test-PortsCandidate 'Port zero is preserved but cannot claim resolved endpoint identification' {
    $f.Sources[1].Data[0].LocalPort=[uint16]0;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ((Get-WinSecOpenPortsFixtureReadings $s TCP.LocalPort)[0].Value -eq 0 -and
        (Get-PortsCandidateSummary $s TCP).Reason -ceq 'INVALID_VALUE' -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($kind in @('UTC','OFFSET','LOCAL','UNSPECIFIED')){Test-PortsCandidate ('Creation timestamps retain their actual time basis: '+$kind) {
    $wall=[datetime]::SpecifyKind([datetime]'2026-10-29T01:00:00',[DateTimeKind]::Unspecified)
    $value=switch($kind){UTC {[datetime]::SpecifyKind($wall,[DateTimeKind]::Utc)};OFFSET {[datetimeoffset]::new($wall,[timespan]::FromHours(-6))};LOCAL {[datetime]::SpecifyKind($wall,[DateTimeKind]::Local)};default {$wall}}
    $f.Sources[1].Data[0].CreationTime=$value;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    $r=(Get-WinSecOpenPortsFixtureReadings $s TCP.CreationTime)[0];$basis=(Get-WinSecOpenPortsFixtureReadings $s TCP.CreationTimeBasis)[0]
    Assert-PortsCandidate ($basis.Value -ceq $kind -and $r.State -ceq 'OBSERVED')
    if($kind -cin @('LOCAL','UNSPECIFIED')){Assert-PortsCandidate ($r.Value -ceq '2026-10-29T01:00:00.0000000')}
    if($kind -ceq 'OFFSET'){Assert-PortsCandidate ($r.Value -ceq '2026-10-29T01:00:00.0000000-06:00')}
}}
Test-PortsCandidate 'The documented last-enabled-state zero interval is not invented as an event date' {
    $s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ((Get-WinSecOpenPortsFixtureReadings $s TCP.TimeOfLastStateChange)[0].Value -ceq '00:00:00' -and
        (Get-WinSecOpenPortsFixtureReadings $s TCP.TimeOfLastStateChangeBasis)[0].Value -ceq 'INTERVAL')
    $f.Sources[1].Data[0].CreationTime=[timespan]::Zero;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ((Get-WinSecOpenPortsFixtureReadings $s TCP.CreationTime)[0].State -ceq 'UNKNOWN' -and
        (Get-WinSecOpenPortsFixtureReadings $s TCP.CreationTimeBasis)[0].State -ceq 'UNKNOWN')
}
Test-PortsCandidate 'Optional nulls preserve successful collection with limited coverage while required nulls stay partial' {
    $f.Sources[2].Data[0].CreationTime=$null;$f.Sources[2].Data[0].HealthState=$null;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED')
    $f.Sources[2].Data[0].LocalPort=$null;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ($s.Collection.Status -ceq 'PARTIAL')
}
Test-PortsCandidate 'Duplicate endpoint tuples and separate protocol inventories are preserved in provider order' {
    $f.Sources[1].Data=@($f.Sources[1].Data[0],$f.Sources[1].Data[0]);$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ((Get-PortsCandidateSummary $s TCP).RetainedRecords -eq 2 -and
        (Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddress)[0].Value -ceq (Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddress)[1].Value -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-PortsCandidate 'Observed empty TCP and UDP lists are valid empty snapshots without security verdicts' {
    $f=New-WinSecOpenPortsCandidateFixture 0;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-PortsCandidateSummary $s TCP).ReportedRecords -eq 0 -and
        (Get-PortsCandidateSummary $s UDP).RetainedRecords -eq 0 -and (Get-WinSecOpenPortsFixtureReadings $s Capture.TCPSourceState)[0].Value -ceq 'OBSERVED')
}
Test-PortsCandidate 'Five hundred thirteen TCP endpoints cross the old provider limit without losing a record' {
    $large=New-WinSecOpenPortsCandidateFixture 513;$f.Sources[1].Data=$large.Sources[1].Data;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ((Get-PortsCandidateSummary $s TCP).RetainedRecords -eq 513 -and (Get-PortsCandidateSummary $s TCP).ReportedRecords -eq 513 -and
        @($s.Batches|Where-Object InventoryId -CEQ TCP).Count -eq 5 -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-PortsCandidate 'Exhausted bytes keep the full supplied count and an explicit partial prefix' {
    $f.Sources[1].Data=@($f.Sources[1].Data[0])*10001;function Get-WinSecOpenPortsCandidatePayloadBudget {return 0}
    $s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ((Get-PortsCandidateSummary $s TCP).ReportedRecords -eq 10001 -and (Get-PortsCandidateSummary $s TCP).RetainedRecords -eq 0 -and
        (Get-PortsCandidateSummary $s TCP).Reason -ceq 'RESOURCE_LIMIT' -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($state in @('ERROR','NOT_COLLECTED')){Test-PortsCandidate ('Unavailable providers cannot manufacture zero endpoint counts: '+$state) {
    $f.Sources[1].State=$state;$f.Sources[1].Data=$null;$s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $null -eq (Get-PortsCandidateSummary $s TCP).ReportedRecords -and
        (Get-WinSecOpenPortsFixtureReadings $s Capture.TCPSourceState)[0].Value -ceq $state -and (Get-PortsCandidateSummary $s UDP).Complete)
}}
foreach($damage in @('owner','scan','location','remote','time','duplicate','scope','control','raw-error','platform','version','established','tcp-unknown')){Test-PortsCandidate ('Foreign contradictory or non-listening data is rejected: '+$damage) {
    switch($damage){owner {$f.Sources[0].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[0].ScanId='other'}
        location {$f.Sources[1].Location='CIMV2'};remote {$f.Sources[1]|Add-Member NoteProperty CimSession 'remote'}
        time {$f.Sources[1].CollectedAtUTC='2026-10-30T01:02:04.0000000Z'};duplicate {$f.Sources[2].SourceId='TCP'}
        scope {$f.Identity.ScopeKey='WSA-NET-003'};control {$f.Identity.CheckId='WSA-NET-003';$f.Identity.ScopeKey='WSA-NET-003'}
        raw-error {$f.Sources[1].State='ERROR'};platform {$f.Sources[0].Data.ProductType=[uint32]3};version {$f.Sources[0].Data.Version='10.0.22631'}
        established {$f.Sources[1].Data[0].State=[byte]5};tcp-unknown {$f.Sources[1].Data[0].State=$null}
    };Reject-PortsCandidate {New-WinSecOpenPortsFixturePackage $f}
}}
Test-PortsCandidate 'Unreviewed process paths peer addresses descriptions and getters never enter the snapshot' {
    $script:getters=0;$f.Sources[1].Data[0]|Add-Member ScriptProperty LocalAddress {$script:getters++;'PRIVATE-SECRET'} -Force
    foreach($name in @('RemoteAddress','RemotePort','CommandLine','ExecutablePath','UserName','InstanceID','Description')){$f.Sources[1].Data[0]|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
    $s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    Assert-PortsCandidate ($script:getters -eq 0 -and $s.Collection.Status -ceq 'PARTIAL' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|RemoteAddress|CommandLine|ExecutablePath')
}
Test-PortsCandidate 'Real progress and cancellation follow retained rows without mutating supplied data' {
    $f=New-WinSecOpenPortsCandidateFixture 20;$before=ConvertTo-Json $f -Depth 10 -Compress;$script:rows=0;$cancelled=$false
    try{$null=New-WinSecOpenPortsFixturePackage $f -ProgressCallback {param($e);if($e.InventoryId -ceq 'TCP'){$script:rows=$e.RetainedRecords}} -CancellationAction {$script:rows -ge 7}}
    catch [OperationCanceledException]{$cancelled=$true}
    Assert-PortsCandidate ($cancelled -and $script:rows -eq 7 -and (ConvertTo-Json $f -Depth 10 -Compress) -ceq $before)
}
foreach($damage in @('location','time','scope','collector','address','family','binding','protocol','tcp-state','time-basis')){Test-PortsCandidate ('Specific validation rejects forged data: '+$damage) {
    $s=(New-WinSecOpenPortsFixturePackage $f).Snapshot
    switch($damage){location {(Get-WinSecOpenPortsFixtureReadings $s Capture.TCPLocation)[0].Value='CIMV2'}
        time {(Get-WinSecOpenPortsFixtureReadings $s Capture.TCPTime)[0].Value='2026-10-30T01:02:04.0000000Z'}
        scope {(Get-WinSecOpenPortsFixtureReadings $s Capture.Scope)[0].Value='OTHER'};collector {$s.CollectorVersion='9.0.0'}
        address {(Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddressCanonical)[0].Value='192.0.2.11'}
        family {(Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddressFamily)[0].Value='IPv6'}
        binding {(Get-WinSecOpenPortsFixtureReadings $s TCP.LocalAddressScope)[0].Value='ANY'}
        protocol {(Get-WinSecOpenPortsFixtureReadings $s TCP.Protocol)[0].Value='UDP'};tcp-state {(Get-WinSecOpenPortsFixtureReadings $s TCP.State)[0].Value=[byte]5}
        time-basis {(Get-WinSecOpenPortsFixtureReadings $s TCP.CreationTimeBasis)[0].Value='LOCAL'}
    };Reject-PortsCandidate {Assert-WinSecOpenPortsCandidateSnapshot $s $f.Identity}
}}
Test-PortsCandidate 'Invented absence states fail even with consistent generic coverage counters' {
    $s=(New-WinSecOpenPortsFixturePackage $f).Snapshot;$r=(Get-WinSecOpenPortsFixtureReadings $s UDP.OwningProcess)[0]
    $r.State='NOT_CONFIGURED';$r.Reason='ABSENT';$r.Value=$null;$s.Collection.Observed--;$s.Collection.NotConfigured++
    Assert-WinSecTechnicalSnapshot $s (Get-WinSecOpenPortsCandidateCatalog) $s.CatalogSha256 $f.Identity
    Reject-PortsCandidate {Assert-WinSecOpenPortsCandidateSnapshot $s $f.Identity}
}
Write-Host ("Open Ports technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
