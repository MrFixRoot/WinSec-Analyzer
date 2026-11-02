[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Network/RdpTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/RdpTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native query forbidden.'}
function Get-CimClass {throw 'Native query forbidden.'}
function Get-ItemProperty {throw 'Native registry query forbidden.'}
$passed=0;$failed=0
function Assert-RdpCandidate {param([bool]$Value);if(-not $Value){throw 'RDP technical candidate assertion failed.'}}
function Reject-RdpCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-RdpCandidate $caught}
function Get-RdpCandidateSummary {param($Snapshot,$Id);@($Snapshot.Inventories|Where-Object Id -CEQ $Id)[0]}
function Test-RdpCandidate {param($Name,[scriptblock]$Action);$f=New-WinSecRdpCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}

Test-RdpCandidate 'The isolated catalog has eleven inventories and one hundred fifty eight definitions' {
    $p=New-WinSecRdpFixturePackage $f
    Assert-RdpCandidate ($p.Catalog.Fields.Count -eq 158 -and $p.Catalog.Inventories.Count -eq 11 -and
        $p.Snapshot.Collection.RetainedRecords -eq 19 -and $p.Snapshot.Collection.Observed -eq 261 -and $p.Snapshot.Collection.Unknown -eq 4 -and
        $p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'LIMITED')
}
Test-RdpCandidate 'New safe properties and raw zero values survive without scores or security conclusions' {
    $f.Sources[2].Data.TimeZoneRedirection=[uint32]1;$f.Sources[4].Data[0].PolicySourceUserName=[uint32]2
    $f.Sources[5].Data[0].IdleSessionLimit=[uint32]::MaxValue;$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ((Get-WinSecRdpFixtureReadings $s Global.AllowTSConnections)[0].Value -eq 0 -and
        (Get-WinSecRdpFixtureReadings $s Global.TimeZoneRedirection)[0].Value -eq 1 -and
        (Get-WinSecRdpFixtureReadings $s General.TerminalProtocol)[0].Value -ceq 'Microsoft RDP 8.0' -and
        (Get-WinSecRdpFixtureReadings $s Session.IdleSessionLimit)[0].Value -eq [uint32]::MaxValue -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'Score|NOT_SCORED|/100|Finding|HostEnabled')
}
Test-RdpCandidate 'NLA disabled and Stopped Manual services are observed configuration without automatic verdicts' {
    $f.Sources[3].Data[0].UserAuthenticationRequired=[uint32]0;$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-WinSecRdpFixtureReadings $s General.UserAuthenticationRequired)[0].Value -eq 0 -and
        (Get-WinSecRdpFixtureReadings $s Services.State)[0].Value -ceq 'Stopped' -and (Get-WinSecRdpFixtureReadings $s Services.Started)[0].Value -ceq $false)
}
Test-RdpCandidate 'Listener identities preserve real Unicode spelling and remain separate by provider family' {
    $f.Sources[3].Data[0].TerminalName='Terminal-'+[char]0x00F1;$f.Sources[5].Data[0].TerminalName='Different-session-listener'
    $s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ((Get-WinSecRdpFixtureReadings $s General.TerminalName)[0].Value -ceq $f.Sources[3].Data[0].TerminalName -and
        (Get-WinSecRdpFixtureReadings $s Session.TerminalName)[0].Value -ceq 'Different-session-listener' -and $s.Collection.Status -ceq 'COMPLETE')
}
foreach($case in @('duplicate','case')){Test-RdpCandidate ('Ambiguous listener identities are retained without merging rows: '+$case) {
    $f.Sources[3].Data[1].TerminalName=if($case -ceq 'case'){'LISTENER-0'}else{'Listener-0'};$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ((Get-RdpCandidateSummary $s General).RetainedRecords -eq 2 -and (Get-RdpCandidateSummary $s General).Reason -ceq 'INVALID_VALUE' -and $s.Collection.Status -ceq 'PARTIAL')
}}
Test-RdpCandidate 'Missing listener and service inventories stay partial without asserting absence of exposure' {
    $f.Sources[3].Data=@();$f.Sources[1].Data=@();$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-RdpCandidateSummary $s General).ReportedRecords -eq 0 -and
        (Get-RdpCandidateSummary $s Services).ReportedRecords -eq 0 -and (Get-RdpCandidateSummary $s Session).RetainedRecords -eq 2)
}
Test-RdpCandidate 'One hundred twenty nine General records cross legacy count limits without truncation' {
    $large=New-WinSecRdpCandidateFixture 129;$f.Sources[3].Data=$large.Sources[3].Data;$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ((Get-RdpCandidateSummary $s General).ReportedRecords -eq 129 -and (Get-RdpCandidateSummary $s General).RetainedRecords -eq 129 -and
        @($s.Batches|Where-Object InventoryId -CEQ General).Count -eq 2 -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-RdpCandidate 'A depleted byte budget reports all supplied records and retains an explicit partial result' {
    $f.Sources[3].Data=@($f.Sources[3].Data[0])*10001;function Get-WinSecRdpCandidatePayloadBudget {return 0}
    $s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ((Get-RdpCandidateSummary $s General).ReportedRecords -eq 10001 -and (Get-RdpCandidateSummary $s General).RetainedRecords -eq 0 -and
        (Get-RdpCandidateSummary $s General).Reason -ceq 'RESOURCE_LIMIT' -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-RdpCandidate 'Informational nulls and principal nulls have distinct completion consequences' {
    $f.Sources[8].Data[0].DenyAdminPermissionForCustomization=$null;$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED')
    $f.Sources[3].Data[0].UserAuthenticationRequired=$null;$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecRdpFixtureReadings $s General.UserAuthenticationRequired)[0].State -ceq 'UNKNOWN')
}
foreach($property in @('UserAuthenticationRequired','SecurityLayer','MinEncryptionLevel')){Test-RdpCandidate ('Unknown principal enum codes are retained but not accepted as resolved: '+$property) {
    $f.Sources[3].Data[0].$property=[uint32]99;$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ((Get-WinSecRdpFixtureReadings $s ('General.'+$property))[0].Value -eq 99 -and
        (Get-RdpCandidateSummary $s General).Reason -ceq 'INVALID_VALUE' -and $s.Collection.Status -ceq 'PARTIAL')
}}
Test-RdpCandidate 'Native numeric flags do not coerce Boolean or string values' {
    $f.Sources[2].Data.AllowTSConnections=$false;$f.Sources[3].Data[0].SecurityLayer='0';$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ((Get-WinSecRdpFixtureReadings $s Global.AllowTSConnections)[0].State -ceq 'UNKNOWN' -and
        (Get-WinSecRdpFixtureReadings $s General.SecurityLayer)[0].State -ceq 'UNKNOWN' -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($sku in @(98,99,100,101)){Test-RdpCandidate ('Home excludes only explicitly skipped host providers with observed platform proof: '+$sku) {
    $f.Sources[0].Data.OperatingSystemSKU=[uint32]$sku;foreach($source in $f.Sources){if($source.Location -ceq 'TERMINALSERVICES'){$source.State='NOT_APPLICABLE';$source.Data=$null}}
    $s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate (@($s.Inventories|Where-Object State -CEQ NOT_APPLICABLE).Count -eq 7 -and $s.Collection.Status -ceq 'COMPLETE' -and
        (Get-RdpCandidateSummary $s Services).RetainedRecords -eq 3 -and (Get-WinSecRdpFixtureReadings $s Registry.ListenerPort)[0].Value -eq 3389 -and
        (Get-WinSecRdpFixtureReadings $s Capture.GeneralSourceState)[0].Value -ceq 'NOT_APPLICABLE')
}}
Test-RdpCandidate 'Unknown editions preserve received values but cannot claim resolved host applicability' {
    $f.Sources[0].Data.OperatingSystemSKU=[uint32]999;$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-RdpCandidateSummary $s General).RetainedRecords -eq 2 -and
        (Get-WinSecRdpFixtureReadings $s General.UserAuthenticationRequired)[0].Value -eq 1 -and @($s.Inventories|Where-Object State -CEQ NOT_APPLICABLE).Count -eq 0)
}
Test-RdpCandidate 'Retired fields stay visible as unknown until a reviewed contract can express their retirement' {
    $s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ((Get-WinSecRdpFixtureReadings $s Redirection.AllowDwm)[0].State -ceq 'UNKNOWN' -and $s.Collection.NotApplicable -eq 0)
    $f.Sources[6].Data[0].AllowDwm=[uint32]0;$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ((Get-WinSecRdpFixtureReadings $s Redirection.AllowDwm)[0].Value -eq 0)
}
Test-RdpCandidate 'All permitted observed fields can have complete coverage without changing their meaning' {
    foreach($row in $f.Sources[6].Data){$row.AllowDwm=[uint32]0;$row.PolicySourceAllowDwm=[uint32]0};$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'COMPLETE' -and $s.Collection.Unknown -eq 0)
}
Test-RdpCandidate 'Absent Registry64 entries are not effective policy defaults' {
    foreach($d in Get-WinSecRdpCandidateRegistry){$f.Sources[9].Data.($d.Id)=[pscustomobject]@{State='NOT_CONFIGURED';Kind=$null;Value=$null}}
    $s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.NotConfigured -eq 6 -and
        (Get-WinSecRdpFixtureReadings $s Global.AllowTSConnections)[0].Value -eq 0)
}
Test-RdpCandidate 'Physical DWORD bit patterns and invalid port ranges remain visible and partial' {
    $f.Sources[9].Data.ListenerPort.Value=[int]-1;$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ((Get-WinSecRdpFixtureReadings $s Registry.ListenerPort)[0].Value -eq [uint32]::MaxValue -and
        (Get-RdpCandidateSummary $s Registry).Reason -ceq 'INVALID_VALUE' -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($state in @('ERROR','NOT_COLLECTED')){Test-RdpCandidate ('Unavailable source metadata survives without apparent successful values: '+$state) {
    $f.Sources[2].State=$state;$f.Sources[2].Data=$null;$f.Sources[3].State=$state;$f.Sources[3].Data=$null
    $s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecRdpFixtureReadings $s Global.AllowTSConnections)[0].State -ceq $state -and
        (Get-RdpCandidateSummary $s General).RetainedRecords -eq 0 -and (Get-WinSecRdpFixtureReadings $s Capture.GeneralSourceState)[0].Value -ceq $state)
}}
foreach($damage in @('owner','scan','location','remote','time','duplicate','scope','control','raw-error','platform','version','service','listener','registry-absence','home','unknown-home','non-host-home')){Test-RdpCandidate ('Foreign or contradictory receipts are rejected: '+$damage) {
    switch($damage){owner {$f.Sources[0].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[0].ScanId='other'}
        location {$f.Sources[3].Location='CIMV2'};remote {$f.Sources[3]|Add-Member NoteProperty CimSession 'remote'}
        time {$f.Sources[3].CollectedAtUTC='2026-10-30T01:02:04.0000000Z'};duplicate {$f.Sources[3].SourceId='Global'}
        scope {$f.Identity.ScopeKey='WSA-NET-002'};control {$f.Identity.CheckId='WSA-NET-002';$f.Identity.ScopeKey='WSA-NET-002'}
        raw-error {$f.Sources[3].State='ERROR'};platform {$f.Sources[0].Data.ProductType=[uint32]3};version {$f.Sources[0].Data.Version='10.0.22631'}
        service {$f.Sources[1].Data[0].Name='UnreviewedService'};listener {$f.Sources[3].Data[0].TerminalName='../unsafe'}
        registry-absence {$f.Sources[9].Data.ListenerPort.State='NOT_CONFIGURED'}
        home {$f.Sources[3].State='NOT_APPLICABLE';$f.Sources[3].Data=$null}
        unknown-home {$f.Sources[0].Data.OperatingSystemSKU=[uint32]999;$f.Sources[3].State='NOT_APPLICABLE';$f.Sources[3].Data=$null}
        non-host-home {$f.Sources[0].Data.OperatingSystemSKU=[uint32]101;$f.Sources[9].State='NOT_APPLICABLE';$f.Sources[9].Data=$null}
    };Reject-RdpCandidate {New-WinSecRdpFixturePackage $f}
}}
Test-RdpCandidate 'Secrets certificates user identities descriptors and getters never enter the candidate' {
    $script:getters=0;$f.Sources[3].Data[0]|Add-Member ScriptProperty CertificateName {$script:getters++;'PRIVATE-SECRET'}
    $f.Sources[3].Data[0]|Add-Member ScriptProperty SecurityLayer {$script:getters++;'PRIVATE-SECRET'} -Force
    foreach($name in @('Password','UserName','Domain')){$f.Sources[4].Data[0]|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
    $f.Sources[8].Data[0]|Add-Member NoteProperty StringSecurityDescriptor 'PRIVATE-SECRET';$s=(New-WinSecRdpFixturePackage $f).Snapshot
    Assert-RdpCandidate ($script:getters -eq 0 -and $s.Collection.Status -ceq 'PARTIAL' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|CertificateName|StringSecurityDescriptor|"Password"|"Domain"|"UserName"')
}
Test-RdpCandidate 'Cancellation follows actual records and preserves the supplied captures' {
    $f=New-WinSecRdpCandidateFixture 20;$before=ConvertTo-Json $f -Depth 10 -Compress;$script:rows=0;$cancelled=$false
    try{$null=New-WinSecRdpFixturePackage $f -ProgressCallback {param($e);if($e.InventoryId -ceq 'General'){$script:rows=$e.RetainedRecords}} -CancellationAction {$script:rows -ge 3}}
    catch [OperationCanceledException]{$cancelled=$true}
    Assert-RdpCandidate ($cancelled -and $script:rows -eq 3 -and (ConvertTo-Json $f -Depth 10 -Compress) -ceq $before)
}
foreach($damage in @('location','time','scope','collector','duplicate','principal')){Test-RdpCandidate ('Specific validation rejects forged snapshots: '+$damage) {
    $s=(New-WinSecRdpFixturePackage $f).Snapshot
    switch($damage){location {(Get-WinSecRdpFixtureReadings $s Capture.GeneralLocation)[0].Value='CIMV2'}
        time {(Get-WinSecRdpFixtureReadings $s Capture.GlobalTime)[0].Value='2026-10-30T01:02:04.0000000Z'}
        scope {(Get-WinSecRdpFixtureReadings $s Capture.Scope)[0].Value='OTHER'};collector {$s.CollectorVersion='9.0.0'}
        duplicate {(Get-WinSecRdpFixtureReadings $s General.TerminalName)[1].Value='Listener-0'}
        principal {(Get-WinSecRdpFixtureReadings $s General.UserAuthenticationRequired)[0].Value=[uint32]99}
    };Reject-RdpCandidate {Assert-WinSecRdpCandidateSnapshot $s $f.Identity}
}}
Test-RdpCandidate 'A CIM absence is rejected even after generic counts have been made consistent' {
    $s=(New-WinSecRdpFixturePackage $f).Snapshot;$r=(Get-WinSecRdpFixtureReadings $s General.Transport)[0]
    $r.State='NOT_CONFIGURED';$r.Reason='ABSENT';$r.Value=$null;$s.Collection.Observed--;$s.Collection.NotConfigured++
    Assert-WinSecTechnicalSnapshot $s (Get-WinSecRdpCandidateCatalog) $s.CatalogSha256 $f.Identity
    Reject-RdpCandidate {Assert-WinSecRdpCandidateSnapshot $s $f.Identity}
}
Write-Host ("RDP technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
