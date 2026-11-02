[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Services/WindowsServicesTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/WindowsServicesTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native enumeration forbidden.'}
function Get-Service {throw 'Native enumeration forbidden.'}
function Start-Service {throw 'Service action forbidden.'}
function Stop-Service {throw 'Service action forbidden.'}
function Set-Service {throw 'Service action forbidden.'}
$passed=0;$failed=0
function Assert-ServicesCandidate {param([bool]$Value);if(-not $Value){throw 'Windows Services candidate assertion failed.'}}
function Reject-ServicesCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-ServicesCandidate $caught}
function Test-ServicesCandidate {param($CaseName,[scriptblock]$Action);$f=New-WinSecWindowsServicesCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}

Test-ServicesCandidate 'Versioned catalog keeps twenty-one native definitions and explicit limits' {
    $p=New-WinSecWindowsServicesFixturePackage $f;$d=@(Get-WinSecWindowsServicesCandidateFields)
    Assert-ServicesCandidate ($p.Catalog.Fields.Count -eq 38 -and $p.Catalog.Inventories.Count -eq 3 -and @($d|Where-Object Derived -EQ $false).Count -eq 21 -and
        $p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'LIMITED' -and $p.Snapshot.Collection.Observed -eq 50 -and $p.Snapshot.Collection.NotCollected -eq 5)
}
Test-ServicesCandidate 'Concrete service identifiers and PID survive without hashing or identity resolution' {
    $f.Sources[1].Data[0].Name='Service '+[char]0xE9+' | <tag> $literal';$f.Sources[1].Data[0].ProcessId=[uint32]4294967295
    $s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ((Get-WinSecWindowsServicesFixtureReadings $s Services.Name)[0].Value -ceq $f.Sources[1].Data[0].Name -and
        (Get-WinSecWindowsServicesFixtureReadings $s Services.ProcessId)[0].Value -eq 4294967295 -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'sha256:|Score')
}
foreach($state in @('Stopped','Start Pending','Stop Pending','Running','Continue Pending','Pause Pending','Paused','Unknown')){Test-ServicesCandidate ('Documented current state is data rather than a security verdict: '+$state) {
    $f.Sources[1].Data[0].State=$state;$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-WinSecWindowsServicesFixtureReadings $s Services.State)[0].Value -ceq $state)
}}
foreach($mode in @('Boot','System','Auto','Manual','Disabled')){Test-ServicesCandidate ('Observed start mode never creates an automatic vulnerability: '+$mode) {
    $f.Sources[1].Data[0].StartMode=$mode;$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-WinSecWindowsServicesFixtureReadings $s Services.StartMode)[0].Value -ceq $mode)
}}
foreach($name in @('Started','DelayedAutoStart','AcceptPause','AcceptStop','DesktopInteract')){Test-ServicesCandidate ('Boolean false and true remain exact observations: '+$name) {
    $f.Sources[1].Data[0].($name)=$true;$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    $r=@(Get-WinSecWindowsServicesFixtureReadings $s ('Services.'+$name))
    Assert-ServicesCandidate ($r[0].Value -ceq $true -and $r[1].Value -ceq $false)
}}
Test-ServicesCandidate 'Diagnostics preserve zero maximum DWORD and explicit millisecond field name' {
    foreach($name in @('ExitCode','ServiceSpecificExitCode','ProcessId','CheckPoint','WaitHint','TagId')){$f.Sources[1].Data[0].($name)=[uint32]4294967295}
    $s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ((Get-WinSecWindowsServicesFixtureReadings $s Services.WaitHintMilliseconds)[0].Value -eq 4294967295 -and
        (Get-WinSecWindowsServicesFixtureReadings $s Services.ExitCode)[1].Value -eq 0 -and $s.Collection.Status -ceq 'COMPLETE')
}
foreach($name in @('DelayedAutoStart','ServiceType','ErrorControl','AcceptPause','AcceptStop','DesktopInteract','ExitCode','ServiceSpecificExitCode','ProcessId','CheckPoint','WaitHint','TagId','Status')){Test-ServicesCandidate ('Optional unavailable field remains visible and limits coverage: '+$name) {
    $f.Sources[1].Data[0].($name)=$null;$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    $id=if($name -ceq 'WaitHint'){'Services.WaitHintMilliseconds'}else{'Services.'+$name}
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-WinSecWindowsServicesFixtureReadings $s $id)[0].State -ceq 'UNKNOWN' -and $s.Collection.Coverage -ceq 'LIMITED')
}}
foreach($name in @('Name','State','StartMode','Started')){Test-ServicesCandidate ('Required unknown field stays partial without invented values: '+$name) {
    $f.Sources[1].Data[0].($name)=$null;$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecWindowsServicesFixtureReadings $s ('Services.'+$name))[0].State -ceq 'UNKNOWN')
}}
foreach($damage in @('name','state','mode','bool','number','status')){Test-ServicesCandidate ('Unreviewed values never become configuration defaults: '+$damage) {
    switch($damage){name {$f.Sources[1].Data[0].Name='bad/name'};state {$f.Sources[1].Data[0].State='PRIVATE-SECRET'};mode {$f.Sources[1].Data[0].StartMode='PRIVATE-SECRET'}
        bool {$f.Sources[1].Data[0].Started='false'};number {$f.Sources[1].Data[0].ProcessId=1.5};status {$f.Sources[1].Data[0].Status='PRIVATE-SECRET'}}
    $s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ($s.Collection.Coverage -ceq 'LIMITED' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|bad/name')
}}
Test-ServicesCandidate 'Native literal Unknown is distinct from a missing property' {
    $f.Sources[1].Data[0].Status='Unknown';$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ((Get-WinSecWindowsServicesFixtureReadings $s Services.Status)[0].State -ceq 'OBSERVED' -and
        (Get-WinSecWindowsServicesFixtureReadings $s Services.Status)[0].Value -ceq 'Unknown')
}
Test-ServicesCandidate 'Case-ambiguous duplicate names are retained and diagnosed without deduplication' {
    $f.Sources[1].Data[1].Name=$f.Sources[1].Data[0].Name.ToUpperInvariant();$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'PARTIAL' -and ($s.Inventories|Where-Object Id -CEQ Services).RetainedRecords -eq 2 -and
        ($s.Inventories|Where-Object Id -CEQ Services).Reason -ceq 'INVALID_VALUE')
}
Test-ServicesCandidate 'Different per-user-shaped identifiers stay distinct without inferring users' {
    $f.Sources[1].Data[0].Name='SyntheticSvc_abc123';$f.Sources[1].Data[1].Name='SyntheticSvc_def456';$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'COMPLETE' -and @(Get-WinSecWindowsServicesFixtureReadings $s Services.Name).Count -eq 2)
}
foreach($idx in @(0,1)){foreach($state in @('ERROR','NOT_COLLECTED')){Test-ServicesCandidate ('Unavailable source keeps unknown totals rather than zero services: '+$idx+'/'+$state) {
    $f.Sources[$idx].State=$state;$f.Sources[$idx].Data=$null;$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot;$id=$f.Sources[$idx].SourceId
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $null -eq ($s.Inventories|Where-Object Id -CEQ $id).ReportedRecords)
}}}
Test-ServicesCandidate 'Observed empty inventory is partial without a safe absence claim' {
    $f.Sources[1].Data=@();$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'PARTIAL' -and ($s.Inventories|Where-Object Id -CEQ Services).ReportedRecords -eq 0 -and $s.Collection.NotApplicable -eq 0)
}
Test-ServicesCandidate 'More than one batch retains the entire reviewed inventory' {
    $f=New-WinSecWindowsServicesCandidateFixture -ServiceCount 129;$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'COMPLETE' -and ($s.Inventories|Where-Object Id -CEQ Services).RetainedRecords -eq 129 -and @($s.Batches|Where-Object InventoryId -CEQ Services).Count -eq 2)
}
Test-ServicesCandidate 'A document budget can retain one service and explicitly report the remainder' {
    $full=(New-WinSecWindowsServicesFixturePackage $f).Snapshot;$first=$full.Batches[0].Records[0];$row=($full.Batches|Where-Object InventoryId -CEQ Services).Records[0]
    $script:servicesTestBudget=1024+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $first -Depth 8 -Compress))+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $row -Depth 8 -Compress))
    $old=(Get-Command Get-WinSecWindowsServicesCandidatePayloadBudget).ScriptBlock
    try{function script:Get-WinSecWindowsServicesCandidatePayloadBudget {return $script:servicesTestBudget};$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot}
    finally{Set-Item Function:script:Get-WinSecWindowsServicesCandidatePayloadBudget $old}
    $summary=$s.Inventories|Where-Object Id -CEQ Services
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $summary.ReportedRecords -eq 2 -and $summary.RetainedRecords -eq 1 -and $summary.Reason -ceq 'RESOURCE_LIMIT')
}
Test-ServicesCandidate 'Cancellation on service progress preserves caller input and returns no snapshot' {
    $before=ConvertTo-Json $f -Depth 12 -Compress;$script:cancelServices=$false;$caught=$false
    try{$null=New-WinSecWindowsServicesFixturePackage $f -CancellationAction {$script:cancelServices} -ProgressCallback {param($e);if($e.InventoryId -ceq 'Services'){$script:cancelServices=$true}}}catch [OperationCanceledException]{$caught=$true}
    Assert-ServicesCandidate ($caught -and (ConvertTo-Json $f -Depth 12 -Compress) -ceq $before)
}
Test-ServicesCandidate 'Resource omission remains explicit even when a retained service has an unknown required field' {
    $f.Sources[1].Data[0].Started=$null;$full=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    $first=$full.Batches[0].Records[0];$row=($full.Batches|Where-Object InventoryId -CEQ Services).Records[0]
    $script:servicesTestBudget=1024+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $first -Depth 8 -Compress))+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $row -Depth 8 -Compress))
    $old=(Get-Command Get-WinSecWindowsServicesCandidatePayloadBudget).ScriptBlock
    try{function script:Get-WinSecWindowsServicesCandidatePayloadBudget {return $script:servicesTestBudget};$s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot}
    finally{Set-Item Function:script:Get-WinSecWindowsServicesCandidatePayloadBudget $old}
    $summary=$s.Inventories|Where-Object Id -CEQ Services
    Assert-ServicesCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $summary.ReportedRecords -eq 2 -and $summary.RetainedRecords -eq 1 -and
        $summary.Reason -ceq 'RESOURCE_LIMIT' -and (Get-WinSecWindowsServicesFixtureReadings $s Services.Started)[0].State -ceq 'UNKNOWN')
}
Test-ServicesCandidate 'Getters paths arguments accounts descriptions and secrets are never serialized' {
    $d=$f.Sources[1].Data[0];$d.PSObject.Properties.Remove('StartMode');$d|Add-Member ScriptProperty StartMode {throw 'GETTER EXECUTED'}
    foreach($key in @('PathName','StartName','DisplayName','Description','Caption','SystemName','Password','Token','SecurityDescriptor')){$d|Add-Member NoteProperty $key 'PRIVATE-SECRET'}
    $s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    Assert-ServicesCandidate ((Get-WinSecWindowsServicesFixtureReadings $s Services.StartMode)[0].State -ceq 'UNKNOWN' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|GETTER EXECUTED|PathName|StartName')
}
foreach($damage in @('device','scan','scope','control','source','location','time','duplicate','remote','array','absence')){Test-ServicesCandidate ('Foreign unsafe or unreviewed source rejected: '+$damage) {
    switch($damage){device {$f.Sources[1].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[1].ScanId='other'};scope {$f.Identity.ScopeKey='WSA-LOG-002'}
        control {$f.Identity.CheckId='WSA-LOG-002';$f.Identity.SectionKey='LoggingAuditing';$f.Identity.ScopeKey='WSA-LOG-002'};source {$f.Sources[1].SourceId='OTHER'};location {$f.Sources[1].Location='REMOTE'}
        time {$f.Sources[1].CollectedAtUTC='2026-10-29T00:00:00.0000000Z'};duplicate {$f.Sources[1]=$f.Sources[0]};remote {$f.Sources[1]|Add-Member NoteProperty ComputerName 'REMOTE'}
        array {$f.Sources[1].Data=$f.Sources[1].Data[0]};absence {$f.Sources[1].State='NOT_APPLICABLE';$f.Sources[1].Data=$null}}
    Reject-ServicesCandidate {New-WinSecWindowsServicesFixturePackage $f}
}}
foreach($damage in @('platform','source','scope','authority','collector','location','date','value','absence','details')){Test-ServicesCandidate ('Stored semantic forgery rejected: '+$damage) {
    $s=(New-WinSecWindowsServicesFixturePackage $f).Snapshot
    switch($damage){platform {$s.Platform.BuildNumber=[uint32]22631};source {(Get-WinSecWindowsServicesFixtureReadings $s Capture.ServicesSourceState)[0].Value='ERROR'}
        scope {(Get-WinSecWindowsServicesFixtureReadings $s Capture.Scope)[0].Value='DRIVERS_ONLY'};authority {(Get-WinSecWindowsServicesFixtureReadings $s Capture.PolicyAuthority)[0].Value='DOMAIN'}
        collector {$s.CollectorVersion='9.0.0'};location {(Get-WinSecWindowsServicesFixtureReadings $s Capture.ServicesLocation)[0].Value='CIMV2'}
        date {(Get-WinSecWindowsServicesFixtureReadings $s Capture.ServicesTime)[0].Value='2026-10-28T01:02:04.0000000Z'};value {(Get-WinSecWindowsServicesFixtureReadings $s Services.Started)[0].Value=[uint32]0}
        absence {$r=(Get-WinSecWindowsServicesFixtureReadings $s Services.Name)[0];$r.State='NOT_CONFIGURED';$r.Reason='ABSENT';$r.Value=$null;$s.Collection.Observed--;$s.Collection.NotConfigured++}
        details {$r=(Get-WinSecWindowsServicesFixtureReadings $s Capture.ServiceAccounts)[0];$r.State='OBSERVED';$r.Reason='NONE';$r.Value='PRIVATE-SECRET';$s.Collection.NotCollected--;$s.Collection.Observed++}}
    Reject-ServicesCandidate {Assert-WinSecWindowsServicesCandidateSnapshot $s $f.Identity}
}}
Write-Host ("Windows Services technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
