[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Accounts/LocalAdminsTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/LocalAdminsTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native queries forbidden.'}
function Get-CimClass {throw 'Native queries forbidden.'}
function Get-LocalGroupMember {throw 'Native account lookup forbidden.'}
$passed=0;$failed=0
function Assert-LocalAdminsCandidate {param([bool]$Value);if(-not $Value){throw 'Local Administrators candidate assertion failed.'}}
function Reject-LocalAdminsCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-LocalAdminsCandidate $caught}
function Get-LocalAdminsCandidateSummary {param($Snapshot,$Id);@($Snapshot.Inventories|Where-Object Id -CEQ $Id)[0]}
function Test-LocalAdminsCandidate {param($CaseName,[scriptblock]$Action);$f=New-WinSecLocalAdminsCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}

Test-LocalAdminsCandidate 'Catalog and basic capture declare only reviewed membership and page data' {
    $p=New-WinSecLocalAdminsFixturePackage $f;$d=@(Get-WinSecLocalAdminsCandidateFields)
    Assert-LocalAdminsCandidate ($p.Catalog.Fields.Count -eq 32 -and $p.Catalog.Inventories.Count -eq 5 -and @($d|Where-Object Derived -EQ $false).Count -eq 12 -and
        $p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'COMPLETE' -and $p.Snapshot.Collection.Observed -eq 34 -and $p.Snapshot.Collection.RetainedRecords -eq 6)
}
Test-LocalAdminsCandidate 'Concrete member SID and local group identity survive without hashes notes or member names' {
    $s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ((Get-WinSecLocalAdminsFixtureReadings $s Members.SID)[0].Value -ceq 'S-1-5-21-11-22-33-1000' -and
        (Get-WinSecLocalAdminsFixtureReadings $s Group.SID)[0].Value -ceq 'S-1-5-32-544' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'sha256:|Score|PrincipalSource|AccountName')
}
Test-LocalAdminsCandidate 'A renamed localized group is identified by SID rather than a language-specific name' {
    $name=([string][char]0xC9)+'quipe d'+[char]0x2019+'administration';$f.Sources[1].Data.Name=$name;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ((Get-WinSecLocalAdminsFixtureReadings $s Group.Name)[0].Value -ceq $name -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-LocalAdminsCandidate 'Domain and cloud shaped SIDs remain direct unidentified principals without origin inference' {
    $f.Sources[2].Data.Pages[0].Records[1].SID='S-1-12-1-11-22-33-44';$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ((Get-WinSecLocalAdminsFixtureReadings $s Members.SID)[1].Value -ceq 'S-1-12-1-11-22-33-44' -and
        (Get-WinSecLocalAdminsFixtureReadings $s Capture.DomainExpansion)[0].Value -ceq 'NOT_PERFORMED' -and
        (Get-WinSecLocalAdminsFixtureReadings $s Capture.CloudResolution)[0].Value -ceq 'NOT_PERFORMED' -and
        (Get-WinSecLocalAdminsFixtureReadings $s Capture.PolicyAuthority)[0].Value -ceq 'NOT_OBSERVED')
}
Test-LocalAdminsCandidate 'Native zero codes and false resume flags remain observed' {
    $s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ((Get-WinSecLocalAdminsFixtureReadings $s Pages.Status)[0].State -ceq 'OBSERVED' -and
        (Get-WinSecLocalAdminsFixtureReadings $s Pages.Status)[0].Value -eq 0 -and (Get-WinSecLocalAdminsFixtureReadings $s Pages.ResumePending)[0].Value -ceq $false)
}
Test-LocalAdminsCandidate 'Optional SID type null limits coverage without fabricating an execution failure' {
    $f.Sources[1].Data.SIDType=$null;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED')
}
Test-LocalAdminsCandidate 'Required missing group name remains unknown and collection partial' {
    $f.Sources[1].Data.Name=$null;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecLocalAdminsFixtureReadings $s Group.Name)[0].State -ceq 'UNKNOWN')
}
Test-LocalAdminsCandidate 'Unexpected group SID type is retained as a code with partial status' {
    $f.Sources[1].Data.SIDType=[byte]99;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecLocalAdminsFixtureReadings $s Group.SIDType)[0].Value -eq 99)
}
foreach($value in @('S-1-5-21-11-22-33-01000','S-1-5-21-11-22-33-4294967296','S-1-5-21-1;PASSWORD','s-1-5-32-544','BUILTIN\Administrators')){Test-LocalAdminsCandidate ('Unreviewed member identifier remains unknown without resolving it: '+$value) {
    $f.Sources[2].Data.Pages[0].Records[0].SID=$value;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecLocalAdminsFixtureReadings $s Members.SID)[0].State -ceq 'UNKNOWN')
}}
foreach($name in @('Admins|Other','Admins\Remote',('Admins'+[char]0x0A+'Other'),('A'*257))){Test-LocalAdminsCandidate 'Unsafe or oversized names never become a raw free-text field' {
    $f.Sources[1].Data.Name=$name;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecLocalAdminsFixtureReadings $s Group.Name)[0].State -ceq 'UNKNOWN')
}}
Test-LocalAdminsCandidate 'Two pages retain order and explicit parent membership without duplicate removal' {
    $f=New-WinSecLocalAdminsCandidateFixture 3 2;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ((Get-WinSecLocalAdminsFixtureReadings $s Members.PageSequence)[2].Value -eq 2 -and
        (Get-WinSecLocalAdminsFixtureReadings $s Members.SID)[2].Value -ceq 'S-1-5-21-11-22-33-1002' -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-LocalAdminsCandidate 'The last per-call TotalEntries hint is not assumed to equal the entire enumeration' {
    $f=New-WinSecLocalAdminsCandidateFixture 3 2;$f.Sources[2].Data.Pages[0].TotalEntries=[uint32]4294967295;$f.Sources[2].Data.Pages[1].TotalEntries=[uint32]1
    $s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot;Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'COMPLETE' -and
        (Get-WinSecLocalAdminsFixtureReadings $s Pages.TotalEntries)[0].Value -eq 4294967295 -and (Get-LocalAdminsCandidateSummary $s Members).ReportedRecords -eq 3)
}
Test-LocalAdminsCandidate 'Unknown total hint is informational rather than an invented member count' {
    $f.Sources[2].Data.Pages[0].TotalEntries=$null;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED')
}
Test-LocalAdminsCandidate 'An incomplete final native page never becomes a complete enumeration' {
    $f.Sources[2].Data.Pages[0].Status=[uint32]234;$f.Sources[2].Data.Pages[0].ResumePending=$true;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-LocalAdminsCandidateSummary $s Members).RetainedRecords -eq 2)
}
Test-LocalAdminsCandidate 'A native access error retains the code and already captured entries as partial' {
    $f.Sources[2].Data.Pages[0].Status=[uint32]5;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecLocalAdminsFixtureReadings $s Pages.Status)[0].Value -eq 5)
}
foreach($damage in @('entries','resume','continuation','progress')){Test-LocalAdminsCandidate ('Contradictory native page metadata cannot yield complete: '+$damage) {
    $f=New-WinSecLocalAdminsCandidateFixture 3 2
    switch($damage){entries {$f.Sources[2].Data.Pages[0].EntriesRead=[uint32]99};resume {$f.Sources[2].Data.Pages[1].ResumePending=$true}
        continuation {$f.Sources[2].Data.Pages[0].Status=[uint32]0};progress {$f.Sources[2].Data.Pages[0].Records=@();$f.Sources[2].Data.Pages[0].EntriesRead=[uint32]0}}
    $s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot;Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL')
}}
Test-LocalAdminsCandidate 'Duplicate SID across pages remains visible and partial' {
    $f=New-WinSecLocalAdminsCandidateFixture 3 2;$f.Sources[2].Data.Pages[1].Records[0].SID=$f.Sources[2].Data.Pages[0].Records[0].SID
    $s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot;Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-LocalAdminsCandidateSummary $s Members).RetainedRecords -eq 3)
}
Test-LocalAdminsCandidate 'A successful empty final page differs from no enumeration page' {
    $f=New-WinSecLocalAdminsCandidateFixture 0;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-LocalAdminsCandidateSummary $s Members).ReportedRecords -eq 0)
    $f.Sources[2].Data.Pages=@();$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot;Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL')
}
Test-LocalAdminsCandidate 'All 257 members and seventeen pages cross the old count and page cutoffs' {
    $f=New-WinSecLocalAdminsCandidateFixture 257 16;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-LocalAdminsCandidateSummary $s Members).RetainedRecords -eq 257 -and
        (Get-LocalAdminsCandidateSummary $s Pages).RetainedRecords -eq 17 -and @($s.Batches|Where-Object InventoryId -CEQ Members).Count -eq 3)
}
Test-LocalAdminsCandidate 'A forced resource budget keeps reported counts and no orphan members' {
    $old=(Get-Command Get-WinSecLocalAdminsCandidatePayloadBudget).ScriptBlock
    try{function script:Get-WinSecLocalAdminsCandidatePayloadBudget {return 0};$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot}
    finally{Set-Item Function:script:Get-WinSecLocalAdminsCandidatePayloadBudget $old}
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-LocalAdminsCandidateSummary $s Members).ReportedRecords -eq 2 -and
        (Get-LocalAdminsCandidateSummary $s Members).RetainedRecords -eq 0 -and (Get-LocalAdminsCandidateSummary $s Members).Reason -ceq 'RESOURCE_LIMIT')
}
Test-LocalAdminsCandidate 'A byte budget can retain a valid member prefix only with explicit partial counts and parent pages' {
    $s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot;$script:localAdminsByteBudget=0
    foreach($batch in $s.Batches|Where-Object {$_.InventoryId -cin @('Platform','Group','Pages')}){foreach($row in $batch.Records){$script:localAdminsByteBudget+=512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $row -Depth 8 -Compress))}}
    $row=@($s.Batches|Where-Object InventoryId -CEQ Members)[0].Records[0]
    $script:localAdminsByteBudget+=512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $row -Depth 8 -Compress))
    $old=(Get-Command Get-WinSecLocalAdminsCandidatePayloadBudget).ScriptBlock
    try{function script:Get-WinSecLocalAdminsCandidatePayloadBudget {return $script:localAdminsByteBudget};$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot}
    finally{Set-Item Function:script:Get-WinSecLocalAdminsCandidatePayloadBudget $old}
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-LocalAdminsCandidateSummary $s Pages).RetainedRecords -eq 1 -and
        (Get-LocalAdminsCandidateSummary $s Members).ReportedRecords -eq 2 -and (Get-LocalAdminsCandidateSummary $s Members).RetainedRecords -eq 1 -and
        (Get-LocalAdminsCandidateSummary $s Members).Reason -ceq 'RESOURCE_LIMIT')
}
foreach($state in @('ERROR','NOT_COLLECTED')){Test-LocalAdminsCandidate ('Failed or omitted member source preserves an unknown count: '+$state) {
    $f.Sources[2].State=$state;$f.Sources[2].Data=$null;$s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $null -eq (Get-LocalAdminsCandidateSummary $s Members).ReportedRecords -and
        (Get-WinSecLocalAdminsFixtureReadings $s Capture.MembersSourceState)[0].Value -ceq $state)
}}
Test-LocalAdminsCandidate 'A failed group lookup leaves membership unrequested rather than inventing a local group' {
    $f.Sources[1].State='ERROR';$f.Sources[1].Data=$null;$f.Sources[2].State='NOT_COLLECTED';$f.Sources[2].Data=$null
    $s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot;Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL')
}
Test-LocalAdminsCandidate 'Cancellation after retained member progress preserves all caller receipts' {
    $before=ConvertTo-Json $f -Depth 12 -Compress;$script:cancelLocalAdmins=$false;$caught=$false
    try{$null=New-WinSecLocalAdminsFixturePackage $f -CancellationAction {$script:cancelLocalAdmins} -ProgressCallback {param($e);if($e.InventoryId -ceq 'Members'){$script:cancelLocalAdmins=$true}}}catch [OperationCanceledException]{$caught=$true}
    Assert-LocalAdminsCandidate ($caught -and (ConvertTo-Json $f -Depth 12 -Compress) -ceq $before)
}
Test-LocalAdminsCandidate 'Script getters never run and secrets and member names are never projected' {
    $raw=$f.Sources[2].Data.Pages[0].Records[0];$raw.PSObject.Properties.Remove('SID');$raw|Add-Member ScriptProperty SID {throw 'GETTER EXECUTED'}
    foreach($name in @('Name','Domain','Password','Token','Credential')){$raw|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
    $s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot;Assert-LocalAdminsCandidate ($s.Collection.Status -ceq 'PARTIAL' -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|GETTER EXECUTED|Members.Name|Members.Domain')
}
foreach($damage in @('device','scan','scope','control','source','location','time','duplicate','remote','group','local','member-group','level','early','unbound','page-extra')){Test-LocalAdminsCandidate ('Foreign or inconsistent capture rejected: '+$damage) {
    switch($damage){device {$f.Sources[2].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[2].ScanId='other'};scope {$f.Identity.ScopeKey='WSA-IAM-002'}
        control {$f.Identity.CheckId='WSA-IAM-002';$f.Identity.ScopeKey='WSA-IAM-002'};source {$f.Sources[2].SourceId='OTHER'};location {$f.Sources[2].Location='REMOTE_NETAPI'}
        time {$f.Sources[2].CollectedAtUTC='2026-10-29T00:00:00.0000000Z'};duplicate {$f.Sources[2]=$f.Sources[1]};remote {$f.Sources[2]|Add-Member NoteProperty ComputerName 'REMOTE'}
        group {$f.Sources[1].Data.SID='S-1-5-32-545'};local {$f.Sources[1].Data.LocalAccount=$false};member-group {$f.Sources[2].Data.GroupSID='S-1-5-32-545'}
        level {$f.Sources[2].Data.Level=[uint32]2};early {$f.Sources[1].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'}
        unbound {$f.Sources[1].State='ERROR';$f.Sources[1].Data=$null};page-extra {$f.Sources[2].Data.Pages[0]|Add-Member NoteProperty Server 'REMOTE'}}
    Reject-LocalAdminsCandidate {New-WinSecLocalAdminsFixturePackage $f}
}}
foreach($damage in @('page','sequence','provided','platform','source','location','policy','domain','level','collector','absence')){Test-LocalAdminsCandidate ('Stored semantic forgery rejected: '+$damage) {
    $s=(New-WinSecLocalAdminsFixturePackage $f).Snapshot
    switch($damage){page {(Get-WinSecLocalAdminsFixtureReadings $s Members.PageSequence)[0].Value=[uint32]99};sequence {(Get-WinSecLocalAdminsFixtureReadings $s Pages.Sequence)[0].Value=[uint32]0}
        provided {(Get-WinSecLocalAdminsFixtureReadings $s Pages.ProvidedMemberCount)[0].Value=[uint32]0};platform {$s.Platform.BuildNumber=[uint32]22631}
        source {(Get-WinSecLocalAdminsFixtureReadings $s Capture.MembersSourceState)[0].Value='ERROR'};location {(Get-WinSecLocalAdminsFixtureReadings $s Capture.GroupLocation)[0].Value='LOCAL_NETAPI_LEVEL0'}
        policy {(Get-WinSecLocalAdminsFixtureReadings $s Capture.PolicyAuthority)[0].Value='DOMAIN'};domain {(Get-WinSecLocalAdminsFixtureReadings $s Capture.DomainExpansion)[0].Value='PERFORMED'}
        level {(Get-WinSecLocalAdminsFixtureReadings $s Capture.RequestedAPILevel)[0].Value=[uint32]2};collector {$s.CollectorVersion='9.0.0'}
        absence {$r=(Get-WinSecLocalAdminsFixtureReadings $s Group.Name)[0];$r.State='NOT_CONFIGURED';$r.Reason='ABSENT';$r.Value=$null;$s.Collection.Observed--;$s.Collection.NotConfigured++}}
    Reject-LocalAdminsCandidate {Assert-WinSecLocalAdminsCandidateSnapshot $s $f.Identity}
}}
Write-Host ("Local Administrators technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
