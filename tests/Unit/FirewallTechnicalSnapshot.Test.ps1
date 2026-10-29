# Synthetic captures only. No Firewall provider or application-data access.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Firewall/FirewallTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/FirewallTechnicalMemory.ps1')
function Get-NetFirewallRule {throw 'Native audit forbidden.'}
function Get-NetFirewallPortFilter {throw 'Native audit forbidden.'}
function Get-CimInstance {throw 'Native audit forbidden.'}
$passed=0;$failed=0
function Assert-FirewallCandidate {param([bool]$Value);if(-not $Value){throw 'Firewall candidate assertion failed.'}}
function Reject-FirewallCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-FirewallCandidate $caught}
function Test-FirewallCandidate {param($Name,[scriptblock]$Action);$f=New-WinSecFirewallCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
function Get-FirewallSummary {param($Snapshot,$Id);@($Snapshot.Inventories|Where-Object Id -CEQ $Id)[0]}
Test-FirewallCandidate 'The isolated catalog declares ten inventories and one hundred two reviewed definitions' {
    $c=Get-WinSecFirewallCandidateCatalog;Assert-WinSecSnapshotCatalog $c
    Assert-FirewallCandidate ($c.CheckId -ceq 'WSA-NET-001' -and $c.Fields.Count -eq 102 -and $c.Inventories.Count -eq 10)
}
Test-FirewallCandidate 'A complete subset preserves numeric zero and UInt64 maximum without a score or hash substitution' {
    $s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'COMPLETE' -and
        (Get-WinSecFirewallFixtureReadings $s ActiveRules.Enabled)[0].Value -eq 0 -and
        (Get-WinSecFirewallFixtureReadings $s ActiveProfiles.LogMaxSizeKilobytes)[0].Value -ceq '18446744073709551615' -and
        (Get-WinSecFirewallFixtureReadings $s ActiveRules.InstanceID)[0].Value -ceq 'Rule-0' -and -not $s.PSObject.Properties['Score'])
}
Test-FirewallCandidate 'Distinct rule and filter identities associate only through explicit provider endpoints' {
    $s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ((Get-WinSecFirewallFixtureReadings $s ActiveRules.InstanceID)[0].Value -cne
        (Get-WinSecFirewallFixtureReadings $s ActivePorts.InstanceID)[0].Value -and (Get-FirewallSummary $s ActiveLinks).Complete)
}
Test-FirewallCandidate 'Equal identifiers without an association do not fabricate a relationship' {
    $f.Sources[3].Data[0].InstanceID='Rule-0';$f.Sources[4].Data=@();$s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate (-not (Get-FirewallSummary $s ActiveLinks).Complete -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($damage in @('rule-duplicate','filter-duplicate','link-duplicate','orphan','case','cross-store')){Test-FirewallCandidate ('Ambiguities remain explicit without dropping records: '+$damage) {
    $f=New-WinSecFirewallCandidateFixture 2
    switch($damage){rule-duplicate {$f.Sources[2].Data[1].InstanceID='Rule-0'};filter-duplicate {$f.Sources[3].Data[1].InstanceID='Filter-0'}
        link-duplicate {$f.Sources[4].Data[1].RuleInstanceID='Rule-0'};orphan {$f.Sources[4].Data[1].FilterInstanceID='Missing'}
        case {$f.Sources[4].Data[1].RuleInstanceID='RULE-1'};cross-store {$f.Sources[2].Data=@()}
    }
    $s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate (-not (Get-FirewallSummary $s ActiveLinks).Complete -and (Get-FirewallSummary $s ActiveLinks).RetainedRecords -eq 2 -and
        (Get-FirewallSummary $s PersistentLinks).Complete -and $s.Collection.Status -ceq 'PARTIAL')
}}
Test-FirewallCandidate 'The two stores may independently reuse identities without cross-store deduplication' {
    $s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ((Get-FirewallSummary $s ActiveRules).RetainedRecords -eq 1 -and (Get-FirewallSummary $s PersistentRules).RetainedRecords -eq 1 -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-FirewallCandidate 'A missing profile stays partial without inventing Domain Private or Public' {
    $f.Sources[1].Data=@($f.Sources[1].Data|Select-Object -First 2);$s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate (-not (Get-FirewallSummary $s ActiveProfiles).Complete -and (Get-FirewallSummary $s ActiveProfiles).RetainedRecords -eq 2)
}
Test-FirewallCandidate 'Optional missing fields limit coverage and required missing fields keep collection partial' {
    $f.Sources[2].Data[0].PSObject.Properties.Remove('StatusCode');$s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED')
    $f.Sources[2].Data[0].PSObject.Properties.Remove('Enabled');$s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ($s.Collection.Status -ceq 'PARTIAL')
}
Test-FirewallCandidate 'Native numeric enums never coerce Boolean values into a valid code' {
    $f.Sources[2].Data[0].Enabled=$true;$s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ((Get-WinSecFirewallFixtureReadings $s ActiveRules.Enabled)[0].State -ceq 'UNKNOWN')
}
Test-FirewallCandidate 'Port lists preserve every range keyword and ICMP form with separate counts' {
    $f.Sources[3].Data[0].LocalPort=@('0','65535','1000-2000','RPC','RPC-EPMap','IPHTTPSIn','PlayToDiscovery')
    $f.Sources[3].Data[0].RemotePort=@('Any','IPHTTPSOut');$f.Sources[3].Data[0].IcmpType=@('Any','8','3.4','3:4')
    $s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ((Get-WinSecFirewallFixtureReadings $s ActivePorts.LocalPort)[0].Value.Length -eq 7 -and
        (Get-WinSecFirewallFixtureReadings $s ActivePorts.LocalPortReportedCount)[0].Value -eq 7 -and
        (Get-WinSecFirewallFixtureReadings $s ActivePorts.IcmpType)[0].Value.Length -eq 4)
}
foreach($bad in @('65536','200-100','PRIVATE-SECRET')){Test-FirewallCandidate ('Unreviewed port entries remain unknown rather than silently removed: '+$bad) {
    $f.Sources[3].Data[0].LocalPort=@('80',$bad);$s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ((Get-WinSecFirewallFixtureReadings $s ActivePorts.LocalPort)[0].State -ceq 'UNKNOWN' -and
        (Get-WinSecFirewallFixtureReadings $s ActivePorts.LocalPortReportedCount)[0].Value -eq 2 -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET')
}}
Test-FirewallCandidate 'An oversized port list is explicitly withheld with its full reported element count' {
    $f.Sources[3].Data[0].LocalPort=@('80')*50000;$s=(New-WinSecFirewallFixturePackage $f).Snapshot
    $r=(Get-WinSecFirewallFixtureReadings $s ActivePorts.LocalPort)[0]
    Assert-FirewallCandidate ($r.State -ceq 'NOT_COLLECTED' -and $r.Reason -ceq 'RESOURCE_LIMIT' -and
        (Get-WinSecFirewallFixtureReadings $s ActivePorts.LocalPortReportedCount)[0].Value -eq 50000 -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-FirewallCandidate 'Rules and filters above the legacy batch boundary retain all records in separate batches' {
    $f=New-WinSecFirewallCandidateFixture 129;$s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ((Get-FirewallSummary $s ActiveRules).RetainedRecords -eq 129 -and
        (Get-FirewallSummary $s ActivePorts).RetainedRecords -eq 129 -and (Get-FirewallSummary $s ActiveLinks).RetainedRecords -eq 129 -and
        @($s.Batches|Where-Object InventoryId -CEQ ActiveRules).Count -eq 2 -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-FirewallCandidate 'A capture above ten thousand rows is not silently cut at the old query count' {
    $f.Sources[2].Data=@($f.Sources[2].Data[0])*10001
    function Get-WinSecFirewallCandidatePayloadBudget {return 0}
    $s=(New-WinSecFirewallFixturePackage $f).Snapshot;$i=Get-FirewallSummary $s ActiveRules
    Assert-FirewallCandidate ($i.ReportedRecords -eq 10001 -and $i.RetainedRecords -eq 0 -and $i.Reason -ceq 'RESOURCE_LIMIT' -and
        -not $i.Complete -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($state in @('ERROR','NOT_COLLECTED')){Test-FirewallCandidate ('Unavailable provider metadata and links remain explicit: '+$state) {
    $f.Sources[3].State=$state;$f.Sources[3].Data=$null;$s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ((Get-FirewallSummary $s ActivePorts).State -ceq $state -and -not (Get-FirewallSummary $s ActiveLinks).Complete -and
        (Get-WinSecFirewallFixtureReadings $s Capture.ActivePortsState)[0].Value -ceq $state)
}}
foreach($damage in @('owner','scan','store','remote','time','duplicate','scope','control','raw-error','platform','version')){Test-FirewallCandidate ('Foreign or contradictory capture is rejected: '+$damage) {
    switch($damage){owner {$f.Sources[0].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[0].ScanId='other'}
        store {$f.Sources[2].PolicyStore='PersistentStore'};remote {$f.Sources[2]|Add-Member NoteProperty CimSession 'remote'}
        time {$f.Sources[2].CollectedAtUTC='2026-10-30T01:02:04.0000000Z'};duplicate {$f.Sources[3].SourceId='ActiveRules'}
        scope {$f.Identity.ScopeKey='WSA-NET-002'};control {$f.Identity.CheckId='WSA-NET-002';$f.Identity.ScopeKey='WSA-NET-002'}
        raw-error {$f.Sources[2].State='ERROR'};platform {$f.Sources[0].Data.ProductType=[uint32]3};version {$f.Sources[0].Data.Version='10.0.22631'}
    };Reject-FirewallCandidate {New-WinSecFirewallFixturePackage $f}
}}
Test-FirewallCandidate 'Private paths descriptions owner identities and getters never enter the candidate' {
    $script:getters=0;$f.Sources[2].Data[0]|Add-Member ScriptProperty Description {$script:getters++;'PRIVATE-SECRET'}
    $f.Sources[2].Data[0]|Add-Member ScriptProperty Enabled {$script:getters++;'PRIVATE-SECRET'} -Force
    $f.Sources[1].Data[0]|Add-Member NoteProperty LogFileName 'C:\PRIVATE-SECRET'
    $s=(New-WinSecFirewallFixturePackage $f).Snapshot
    Assert-FirewallCandidate ($script:getters -eq 0 -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|LogFileName|"Description"' -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-FirewallCandidate 'Cancellation follows actual retained rows and preserves prepared data' {
    $f=New-WinSecFirewallCandidateFixture 20;$script:rows=0;$before=ConvertTo-Json $f -Depth 10 -Compress;$cancelled=$false
    try{$null=New-WinSecFirewallFixturePackage $f -ProgressCallback {param($e);if($e.InventoryId -ceq 'ActiveRules'){$script:rows=$e.RetainedRecords}} -CancellationAction {$script:rows -ge 7}}
    catch [OperationCanceledException]{$cancelled=$true}
    Assert-FirewallCandidate ($cancelled -and $script:rows -eq 7 -and (ConvertTo-Json $f -Depth 10 -Compress) -ceq $before)
}
foreach($damage in @('store','time','scope','collector','link','list-count')){Test-FirewallCandidate ('Semantic validation rejects forged stored data: '+$damage) {
    $s=(New-WinSecFirewallFixturePackage $f).Snapshot
    switch($damage){store {(Get-WinSecFirewallFixtureReadings $s Capture.ActiveRulesStore)[0].Value='PersistentStore'}
        time {(Get-WinSecFirewallFixtureReadings $s Capture.ActiveRulesTime)[0].Value='2026-10-30T01:02:04.0000000Z'}
        scope {(Get-WinSecFirewallFixtureReadings $s Capture.Scope)[0].Value='ALL_FIREWALL'};collector {$s.CollectorVersion='9.0.0'}
        link {(Get-WinSecFirewallFixtureReadings $s ActiveLinks.FilterInstanceID)[0].Value='Missing'}
        list-count {(Get-WinSecFirewallFixtureReadings $s ActivePorts.LocalPortReportedCount)[0].Value=[uint32]999}
    };Reject-FirewallCandidate {Assert-WinSecFirewallCandidateSnapshot $s $f.Identity}
}}
Write-Host ("Firewall technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
