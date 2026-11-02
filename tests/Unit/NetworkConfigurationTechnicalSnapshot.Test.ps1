[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Network/NetworkConfigurationTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/NetworkConfigurationTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native query forbidden.'}
function Get-CimClass {throw 'Native query forbidden.'}
function Resolve-DnsName {throw 'DNS resolution forbidden.'}
$passed=0;$failed=0
function Assert-NetworkCandidate {param([bool]$Value);if(-not $Value){throw 'Network technical candidate assertion failed.'}}
function Reject-NetworkCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-NetworkCandidate $caught}
function Get-NetworkCandidateSource {param($Fixture,$Id);@($Fixture.Sources|Where-Object SourceId -CEQ $Id)[0]}
function Get-NetworkCandidateSummary {param($Snapshot,$Id);@($Snapshot.Inventories|Where-Object Id -CEQ $Id)[0]}
function Test-NetworkCandidate {param($Name,[scriptblock]$Action);$f=New-WinSecNetworkCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}

Test-NetworkCandidate 'The isolated catalog represents all nine reviewed inventories plus platform registry and receipts' {
    $p=New-WinSecNetworkFixturePackage $f;$d=@(Get-WinSecNetworkCandidateFields)
    Assert-NetworkCandidate ($p.Catalog.Fields.Count -eq 132 -and $p.Catalog.Inventories.Count -eq 12 -and @($d|Where-Object Derived -EQ $false).Count -eq 92 -and
        $p.Snapshot.Collection.RetainedRecords -eq 20 -and $p.Snapshot.Collection.Observed -eq 221 -and $p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'COMPLETE')
}
Test-NetworkCandidate 'All 79 earlier CIM properties remain declared without importing production' {
    $module=Get-Content (Join-Path $root 'src/Core/NetworkConfigurationTelemetry.ps1') -Raw
    # Execute only the pure catalog in an isolated scope, not any provider or production audit.
    $old=& {. (Join-Path $root 'src/Core/NetworkConfigurationTelemetry.ps1');@(foreach($a in Get-WinSecNetworkConfigurationProviders){foreach($d in $a.Fields){$a.Role+'.'+$d.Name}})}
    $new=@((Get-WinSecNetworkCandidateFields).Id);Assert-NetworkCandidate ($old.Count -eq 79)
    foreach($id in $old){Assert-NetworkCandidate ($id -cin $new)}
}
Test-NetworkCandidate 'Real IP prefixes DNS order duplicates and GUIDs are retained without hashes or scores' {
    $s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s Route.DestinationPrefix)[0].Value -ceq '192.0.2.0/24' -and
        (Get-WinSecNetworkFixtureReadings $s DNSServer.ServerAddresses)[0].Value[2] -ceq '192.0.2.53' -and
        (Get-WinSecNetworkFixtureReadings $s Adapter.InterfaceGuid)[0].Value -ceq '01234567-89AB-CDEF-0123-456789abcdef' -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'sha256:|Score')
}
Test-NetworkCandidate 'Scoped IPv6 retains original spelling and validates matching family' {
    $source=Get-NetworkCandidateSource $f IPAddress;$source.Data[0].AddressFamily=[uint16]23;$source.Data[0].IPAddress='FE80:0:0:0:0:0:0:1%5';$source.Data[0].PrefixLength=[byte]64
    $s=(New-WinSecNetworkFixturePackage $f).Snapshot;Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s IPAddress.IPAddress)[0].Value -ceq $source.Data[0].IPAddress -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-NetworkCandidate 'Full native UInt64 speeds survive exactly without Int64 or floating point loss' {
    $s=(New-WinSecNetworkFixturePackage $f).Snapshot;Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s Adapter.TransmitLinkSpeed)[0].Value -ceq '18446744073709551615')
}
foreach($value in @('18446744073709551616','01','-1','1e3')){Test-NetworkCandidate ('Unreviewed speed representation remains unknown: '+$value) {
    (Get-NetworkCandidateSource $f Adapter).Data[0].TransmitLinkSpeed=$value;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s Adapter.TransmitLinkSpeed)[0].State -ceq 'UNKNOWN' -and $s.Collection.Coverage -ceq 'LIMITED')
}}
Test-NetworkCandidate 'Boolean false and numeric zero are observed rather than missing' {
    $s=(New-WinSecNetworkFixturePackage $f).Snapshot;Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s IPInterface.Forwarding)[0].Value -eq 0 -and
        (Get-WinSecNetworkFixtureReadings $s Adapter.Virtual)[0].Value -ceq $false)
}
Test-NetworkCandidate 'Informational null limits coverage without inventing a failed scan or security failure' {
    (Get-NetworkCandidateSource $f Adapter).Data[0].MtuSize=$null;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED')
}
Test-NetworkCandidate 'Missing required interface retains the row and partial status' {
    (Get-NetworkCandidateSource $f Adapter).Data[0].InterfaceIndex=$null;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-NetworkCandidateSummary $s Adapter).RetainedRecords -eq 2)
}
Test-NetworkCandidate 'Non IP legacy records may lack a network interface without losing their Index key' {
    (Get-NetworkCandidateSource $f Legacy).Data[0].InterfaceIndex=$null;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED' -and (Get-WinSecNetworkFixtureReadings $s Legacy.Index)[0].Value -eq 1)
}
Test-NetworkCandidate 'IP enabled legacy rows require the interface link' {
    $source=Get-NetworkCandidateSource $f Legacy;$source.Data[0].IPEnabled=$true;$source.Data[0].InterfaceIndex=$null;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-NetworkCandidateSummary $s Legacy).Reason -ceq 'INVALID_VALUE')
}
Test-NetworkCandidate 'Duplicate legacy keys are preserved and explicitly partial without deduplication' {
    (Get-NetworkCandidateSource $f Legacy).Data[1].Index=[uint32]1;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ((Get-NetworkCandidateSummary $s Legacy).RetainedRecords -eq 2 -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($damage in @('family','prefix','category','netbios','registry')){Test-NetworkCandidate ('Concrete contradictory codes are retained as partial rather than security verdicts: '+$damage) {
    switch($damage){family {(Get-NetworkCandidateSource $f IPAddress).Data[0].AddressFamily=[uint16]23}
        prefix {(Get-NetworkCandidateSource $f IPAddress).Data[0].PrefixLength=[byte]33}
        category {(Get-NetworkCandidateSource $f Profile).Data[0].NetworkCategory=[uint32]99}
        netbios {(Get-NetworkCandidateSource $f Legacy).Data[0].TcpipNetbiosOptions=[uint32]99}
        registry {(Get-NetworkCandidateSource $f Registry).Data.EnableMulticast.Value=[int]-1}}
    $s=(New-WinSecNetworkFixturePackage $f).Snapshot;Assert-NetworkCandidate ($s.Collection.Status -ceq 'PARTIAL')
    if($damage -ceq 'registry'){Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s Registry.EnableMulticast)[0].Value -eq 4294967295)}
}}
Test-NetworkCandidate 'IPv6 DNS family contradictions remain visible and partial' {
    (Get-NetworkCandidateSource $f DNSServer).Data[0].ServerAddresses=@('2001:db8::53');$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecNetworkFixtureReadings $s DNSServer.ServerAddresses)[0].Value[0] -ceq '2001:db8::53')
}
Test-NetworkCandidate 'Nine DNS addresses are retained in order without the old eight address cutoff' {
    (Get-NetworkCandidateSource $f DNSServer).Data[0].ServerAddresses=@('192.0.2.53')*9;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s DNSServer.ServerAddresses)[0].Value.Length -eq 9 -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-NetworkCandidate 'An oversized address list reports the whole omission and never a misleading prefix' {
    (Get-NetworkCandidateSource $f DNSServer).Data[0].ServerAddresses=@('192.0.2.53')*12
    $old=(Get-Command Get-WinSecNetworkCandidateListBudget).ScriptBlock
    try{function script:Get-WinSecNetworkCandidateListBudget {return 16};$s=(New-WinSecNetworkFixturePackage $f).Snapshot}
    finally{Set-Item Function:script:Get-WinSecNetworkCandidateListBudget $old}
    Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s DNSServer.ServerAddresses)[0].State -ceq 'NOT_COLLECTED' -and
        (Get-WinSecNetworkFixtureReadings $s DNSServer.ServerAddressesReportedCount)[0].Value -eq 12 -and
        (Get-WinSecNetworkFixtureReadings $s DNSServer.ServerAddressesRetainedCount)[0].Value -eq 0 -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-NetworkCandidate 'Empty observed lists differ from null and invalid lists' {
    $source=Get-NetworkCandidateSource $f DNSServer;$source.Data[0].ServerAddresses=@();$source.Data[1].ServerAddresses=$null;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s DNSServer.ServerAddresses)[0].State -ceq 'OBSERVED' -and
        (Get-WinSecNetworkFixtureReadings $s DNSServer.ServerAddressesReportedCount)[0].Value -eq 0 -and
        (Get-WinSecNetworkFixtureReadings $s DNSServer.ServerAddressesReportedCount)[1].State -ceq 'UNKNOWN')
}
foreach($value in @('localhost','127.1','010.0.0.1','192.0.2.300','fe80::1%Ethernet','192.0.2.1/24')){Test-NetworkCandidate ('Invalid address never becomes a raw free text field: '+$value) {
    (Get-NetworkCandidateSource $f IPAddress).Data[0].IPAddress=$value;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s IPAddress.IPAddress)[0].State -ceq 'UNKNOWN' -and $s.Collection.Status -ceq 'PARTIAL')
}}
Test-NetworkCandidate 'Native registry absence stays explicit without asserting default or effective policy' {
    (Get-NetworkCandidateSource $f Registry).Data.EnableMulticast=[pscustomobject]@{State='NOT_CONFIGURED';Kind=$null;Value=$null};$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s Registry.EnableMulticast)[0].State -ceq 'NOT_CONFIGURED' -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-NetworkCandidate 'A wrong native registry type is unknown rather than coerced' {
    (Get-NetworkCandidateSource $f Registry).Data.DoHPolicy.Kind='String';$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ((Get-WinSecNetworkFixtureReadings $s Registry.DoHPolicy)[0].State -ceq 'UNKNOWN' -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($state in @('ERROR','NOT_COLLECTED')){Test-NetworkCandidate ('Unavailable source preserves its receipt and unknown count: '+$state) {
    $source=Get-NetworkCandidateSource $f Legacy;$source.State=$state;$source.Data=$null;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ($null -eq (Get-NetworkCandidateSummary $s Legacy).ReportedRecords -and $s.Collection.Status -ceq 'PARTIAL' -and
        (Get-WinSecNetworkFixtureReadings $s Capture.LegacySourceState)[0].Value -ceq $state)
}}
Test-NetworkCandidate 'Empty observed inventories have zero rather than an unavailable provider count' {
    $f=New-WinSecNetworkCandidateFixture 0;$s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-NetworkCandidateSummary $s Route).ReportedRecords -eq 0)
}
Test-NetworkCandidate 'A complete 129 row route inventory crosses the old cutoff and batch boundary' {
    $large=New-WinSecNetworkCandidateFixture 129;(Get-NetworkCandidateSource $f Route).Data=(Get-NetworkCandidateSource $large Route).Data
    $s=(New-WinSecNetworkFixturePackage $f).Snapshot
    Assert-NetworkCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-NetworkCandidateSummary $s Route).RetainedRecords -eq 129 -and @($s.Batches|Where-Object InventoryId -CEQ Route).Count -eq 2)
}
Test-NetworkCandidate 'A forced byte budget reports all omitted rows instead of claiming complete retention' {
    $large=New-WinSecNetworkCandidateFixture 65;(Get-NetworkCandidateSource $f Route).Data=(Get-NetworkCandidateSource $large Route).Data
    $old=(Get-Command Get-WinSecNetworkCandidatePayloadBudget).ScriptBlock
    try{function script:Get-WinSecNetworkCandidatePayloadBudget {return 0};$s=(New-WinSecNetworkFixturePackage $f).Snapshot}
    finally{Set-Item Function:script:Get-WinSecNetworkCandidatePayloadBudget $old}
    $r=Get-NetworkCandidateSummary $s Route;Assert-NetworkCandidate ($r.ReportedRecords -eq 65 -and $r.RetainedRecords -eq 0 -and $r.Reason -ceq 'RESOURCE_LIMIT' -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-NetworkCandidate 'Cooperative cancellation during normalization preserves caller data' {
    $before=ConvertTo-Json $f -Depth 10 -Compress;$script:cancelNetwork=$false;$caught=$false
    try{$null=New-WinSecNetworkFixturePackage $f -CancellationAction {$script:cancelNetwork} -ProgressCallback {param($e);if($e.InventoryId -ceq 'Route'){$script:cancelNetwork=$true}}}catch [OperationCanceledException]{$caught=$true}
    Assert-NetworkCandidate ($caught -and (ConvertTo-Json $f -Depth 10 -Compress) -ceq $before)
}
Test-NetworkCandidate 'Script getters are never executed and private extras never reach the projection' {
    $data=(Get-NetworkCandidateSource $f Adapter).Data[0];$data.PSObject.Properties.Remove('MtuSize');$data|Add-Member ScriptProperty MtuSize {throw 'GETTER EXECUTED'}
    foreach($name in @('SSID','MACAddress','Name','Credential','DNSDomain','RemoteAddress')){$data|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
    $s=(New-WinSecNetworkFixturePackage $f).Snapshot;Assert-NetworkCandidate ((ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|GETTER EXECUTED|MACAddress|SSID')
}
foreach($damage in @('device','scan','scope','control','source','location','time','duplicate','remote','absence')){Test-NetworkCandidate ('Foreign or inconsistent receipt rejected: '+$damage) {
    switch($damage){device {$f.Sources[1].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[1].ScanId='other'};scope {$f.Identity.ScopeKey='WSA-NET-004'}
        control {$f.Identity.CheckId='WSA-NET-004';$f.Identity.ScopeKey='WSA-NET-004'};source {$f.Sources[1].SourceId='OTHER'};location {$f.Sources[1].Location='CIMV2'}
        time {$f.Sources[1].CollectedAtUTC='2026-10-29T00:00:00.0000000Z'};duplicate {$f.Sources[1]=$f.Sources[0]};remote {$f.Sources[1]|Add-Member NoteProperty ComputerName 'REMOTE'}
        absence {$f.Sources[1].State='NOT_APPLICABLE';$f.Sources[1].Data=$null}}
    Reject-NetworkCandidate {New-WinSecNetworkFixturePackage $f}
}}
foreach($damage in @('count','platform','source','location','scope','collector','absence')){Test-NetworkCandidate ('Stored semantic forgery rejected: '+$damage) {
    $s=(New-WinSecNetworkFixturePackage $f).Snapshot
    switch($damage){count {(Get-WinSecNetworkFixtureReadings $s DNSServer.ServerAddressesReportedCount)[0].Value=[uint32]99}
        platform {$s.Platform.BuildNumber=[uint32]22631};source {(Get-WinSecNetworkFixtureReadings $s Capture.AdapterSourceState)[0].Value='ERROR'}
        location {(Get-WinSecNetworkFixtureReadings $s Capture.AdapterLocation)[0].Value='CIMV2'};scope {(Get-WinSecNetworkFixtureReadings $s Capture.Scope)[0].Value='OTHER'}
        collector {$s.CollectorVersion='9.0.0'};absence {$r=(Get-WinSecNetworkFixtureReadings $s Adapter.MtuSize)[0];$r.State='NOT_CONFIGURED';$r.Reason='ABSENT';$r.Value=$null;$s.Collection.Observed--;$s.Collection.NotConfigured++}}
    Reject-NetworkCandidate {Assert-WinSecNetworkCandidateSnapshot $s $f.Identity}
}}
Write-Host ("Network technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
