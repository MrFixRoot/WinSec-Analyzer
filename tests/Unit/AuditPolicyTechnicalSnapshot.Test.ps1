[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Policies/AuditPolicyTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/AuditPolicyTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native query forbidden.'}
function Get-ItemProperty {throw 'Native Registry query forbidden.'}
function Get-WinEvent {throw 'Event content forbidden.'}
function auditpol {throw 'Native audit query forbidden.'}
$passed=0;$failed=0
function Assert-AuditCandidate {param([bool]$Value);if(-not $Value){throw 'Audit Policy candidate assertion failed.'}}
function Reject-AuditCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-AuditCandidate $caught}
function Test-AuditCandidate {param($CaseName,[scriptblock]$Action);$f=New-WinSecAuditPolicyCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}

Test-AuditCandidate 'Seven inventories forty-two definitions and explicit limited coverage' {
    $p=New-WinSecAuditPolicyFixturePackage $f;$d=@(Get-WinSecAuditPolicyCandidateFields)
    Assert-AuditCandidate ($p.Catalog.Fields.Count -eq 42 -and $p.Catalog.Inventories.Count -eq 7 -and @($d|Where-Object Derived -EQ $false).Count -eq 10 -and
        $p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'LIMITED' -and $p.Snapshot.Collection.Observed -eq 46 -and $p.Snapshot.Collection.NotCollected -eq 4)
}
foreach($code in @(0,1,2,3,4)){Test-AuditCandidate ('Query masks retain exact semantics without a security verdict: '+$code) {
    $f.Sources[4].Data[0].AuditingInformation=[uint32]$code;$s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot
    $mode=(Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.Mode)[0];$success=(Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.Success)[0];$failure=(Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.Failure)[0]
    $expected=@('UNCHANGED','SUCCESS','FAILURE','SUCCESS_AND_FAILURE','NONE')[$code]
    Assert-AuditCandidate ($mode.Value -ceq $expected -and $s.Collection.Status -ceq 'COMPLETE')
    if($code -eq 0){Assert-AuditCandidate ($success.State -ceq 'UNKNOWN' -and $failure.State -ceq 'UNKNOWN' -and $null -eq $success.Value)}
    else{Assert-AuditCandidate ($success.Value -ceq [bool]($code -band 1) -and $failure.Value -ceq [bool]($code -band 2))}
}}
foreach($code in @(5,6,7,8,[uint32]4294967295)){Test-AuditCandidate ('Future or contradictory mask preserved with unknown flags and PARTIAL: '+$code) {
    $f.Sources[4].Data[0].AuditingInformation=$code;$s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot
    Assert-AuditCandidate ((Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.AuditingInformation)[0].Value -eq $code -and
        (Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.Mode)[0].Value -ceq 'UNRECOGNIZED' -and
        (Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.Success)[0].State -ceq 'UNKNOWN' -and $s.Collection.Status -ceq 'PARTIAL')
}}
foreach($value in @($null,'3',$false,-1,1.5)){Test-AuditCandidate 'Unknown or invalid mask is not NONE or a failed framework check' {
    $f.Sources[4].Data[0].AuditingInformation=$value;$s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot
    Assert-AuditCandidate ((Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.AuditingInformation)[0].State -ceq 'UNKNOWN' -and
        (Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.Mode)[0].State -ceq 'UNKNOWN' -and $s.Collection.Status -ceq 'PARTIAL')
}}
Test-AuditCandidate 'Physical option absence is not a default or resolved legacy policy' {
    $f.Sources[5].Data.SCENoApplyLegacyAuditPolicy=[pscustomobject]@{State='NOT_CONFIGURED';Kind=$null;Value=$null};$s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot
    Assert-AuditCandidate ((Get-WinSecAuditPolicyFixtureReadings $s Options.SCENoApplyLegacyAuditPolicy)[0].State -ceq 'NOT_CONFIGURED' -and $s.Collection.Status -ceq 'COMPLETE')
}
foreach($damage in @('bool','string','qword','future')){Test-AuditCandidate ('Invalid option does not become enabled or disabled: '+$damage) {
    switch($damage){bool {$f.Sources[5].Data.SCENoApplyLegacyAuditPolicy.Value=$false};string {$f.Sources[5].Data.SCENoApplyLegacyAuditPolicy.Value='1'};qword {$f.Sources[5].Data.SCENoApplyLegacyAuditPolicy.Kind='QWord'};future {$f.Sources[5].Data.SCENoApplyLegacyAuditPolicy.Value=[uint32]2}}
    $s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot;Assert-AuditCandidate ($s.Collection.Status -ceq 'PARTIAL')
}}
foreach($idx in @(0,1,2,3,4,5)){foreach($state in @('ERROR','NOT_COLLECTED')){Test-AuditCandidate ('Unavailable source retains unknown count and no fake empty inventory: '+$idx+'/'+$state) {
    $f.Sources[$idx].State=$state;$f.Sources[$idx].Data=$null
    if($idx -eq 2){$f.Sources[3].State='NOT_COLLECTED';$f.Sources[3].Data=$null}
    if($idx -in @(2,3)){$f.Sources[4].State='NOT_COLLECTED';$f.Sources[4].Data=$null}
    $s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot;$id=$f.Sources[$idx].SourceId
    Assert-AuditCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $null -eq ($s.Inventories|Where-Object Id -CEQ $id).ReportedRecords -and
        (Get-WinSecAuditPolicyFixtureReadings $s ('Capture.'+$id+'SourceState'))[0].Value -ceq $state)
}}}
foreach($idx in @(1,2,3,4)){Test-AuditCandidate ('Empty observed inventory is not a complete scan: '+$idx) {
    $f.Sources[$idx].Data=@()
    if($idx -eq 1){$f.Sources[4].Data=@()};if($idx -eq 2){$f.Sources[3].Data=@();$f.Sources[4].Data=@()};if($idx -eq 3){$f.Sources[4].Data=@()}
    $s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot;Assert-AuditCandidate ($s.Collection.Status -ceq 'PARTIAL')
}}
Test-AuditCandidate 'Incomplete query selection and missing responses remain explicit partial data' {
    $f.Sources[3].Data=@($f.Sources[3].Data[0]);$f.Sources[4].Data=@($f.Sources[4].Data[0]);$s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot
    Assert-AuditCandidate ($s.Collection.Status -ceq 'PARTIAL' -and ($s.Inventories|Where-Object Id -CEQ Requests).Reason -ceq 'PROVIDER_UNAVAILABLE')
}
Test-AuditCandidate 'Policy response omission is visible without inventing NONE for the missing subcategory' {
    $f.Sources[4].Data=@($f.Sources[4].Data[0]);$s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot
    Assert-AuditCandidate ($s.Collection.Status -ceq 'PARTIAL' -and @(Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.Mode).Count -eq 1)
}
foreach($idx in @(1,2,3,4)){Test-AuditCandidate ('Duplicate configuration identities are retained and diagnosed rather than deduplicated: '+$idx) {
    $f.Sources[$idx].Data+=,$f.Sources[$idx].Data[0];$s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot
    Assert-AuditCandidate ($s.Collection.Status -ceq 'PARTIAL' -and ($s.Inventories|Where-Object Id -CEQ $f.Sources[$idx].SourceId).RetainedRecords -eq $f.Sources[$idx].Data.Length)
}}
Test-AuditCandidate 'More than one batch retains all available requested and returned subcategories' {
    $f=New-WinSecAuditPolicyCandidateFixture -SubcategoryCount 129;$s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot
    Assert-AuditCandidate ($s.Collection.Status -ceq 'COMPLETE' -and ($s.Inventories|Where-Object Id -CEQ SystemPolicy).RetainedRecords -eq 129 -and
        @($s.Batches|Where-Object InventoryId -CEQ SystemPolicy).Count -eq 2 -and ($s.Inventories|Where-Object Id -CEQ Requests).RetainedRecords -eq 129)
}
Test-AuditCandidate 'Resource exhaustion does not leave policy rows with omitted request parents' {
    $old=(Get-Command Get-WinSecAuditPolicyCandidatePayloadBudget).ScriptBlock
    try{function script:Get-WinSecAuditPolicyCandidatePayloadBudget {return 0};$s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot}
    finally{Set-Item Function:script:Get-WinSecAuditPolicyCandidatePayloadBudget $old}
    Assert-AuditCandidate ($s.Collection.Status -ceq 'PARTIAL' -and ($s.Inventories|Where-Object Id -CEQ SystemPolicy).ReportedRecords -eq 2 -and
        ($s.Inventories|Where-Object Id -CEQ SystemPolicy).RetainedRecords -eq 0 -and ($s.Inventories|Where-Object Id -CEQ Requests).RetainedRecords -eq 0)
}
Test-AuditCandidate 'A byte budget can preserve one policy row with validated parents and explicit missing count' {
    $full=(New-WinSecAuditPolicyFixturePackage $f).Snapshot;$prefix=0
    foreach($b in $full.Batches|Where-Object {$_.InventoryId -cin @('Platform','Categories','Subcategories','Requests')}){foreach($record in $b.Records){$prefix+=512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $record -Depth 8 -Compress))}}
    $row=@($full.Batches|Where-Object InventoryId -CEQ SystemPolicy)[0].Records[0]
    $script:auditTestBudget=$prefix+512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $row -Depth 8 -Compress))
    $old=(Get-Command Get-WinSecAuditPolicyCandidatePayloadBudget).ScriptBlock
    try{function script:Get-WinSecAuditPolicyCandidatePayloadBudget {return $script:auditTestBudget};$s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot}
    finally{Set-Item Function:script:Get-WinSecAuditPolicyCandidatePayloadBudget $old}
    $summary=$s.Inventories|Where-Object Id -CEQ SystemPolicy
    Assert-AuditCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $summary.ReportedRecords -eq 2 -and $summary.RetainedRecords -eq 1 -and
        $summary.Reason -ceq 'RESOURCE_LIMIT' -and ($s.Inventories|Where-Object Id -CEQ Requests).RetainedRecords -eq 2)
}
Test-AuditCandidate 'Cancellation after real row progress preserves supplied configuration' {
    $before=ConvertTo-Json $f -Depth 12 -Compress;$script:cancelAudit=$false;$caught=$false
    try{$null=New-WinSecAuditPolicyFixturePackage $f -CancellationAction {$script:cancelAudit} -ProgressCallback {param($e);if($e.InventoryId -ceq 'SystemPolicy'){$script:cancelAudit=$true}}}catch [OperationCanceledException]{$caught=$true}
    Assert-AuditCandidate ($caught -and (ConvertTo-Json $f -Depth 12 -Compress) -ceq $before)
}
Test-AuditCandidate 'Provider extras and getters never expose activity events accounts or secrets' {
    $d=$f.Sources[4].Data[0];$d.PSObject.Properties.Remove('AuditingInformation');$d|Add-Member ScriptProperty AuditingInformation {throw 'GETTER EXECUTED'}
    foreach($key in @('EventContents','UserName','SID','Activity','CommandLine','Password','Token')){$d|Add-Member NoteProperty $key 'PRIVATE-SECRET'}
    $s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot
    Assert-AuditCandidate ((Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.AuditingInformation)[0].State -ceq 'UNKNOWN' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|GETTER EXECUTED|UserName|CommandLine')
}
foreach($damage in @('device','scan','scope','control','source','location','time','duplicate-source','remote','array','guid','empty-guid','unrequested','unknown-category','requests-before','response-before','absence-kind')){Test-AuditCandidate ('Foreign unsafe or unverifiable capture rejected: '+$damage) {
    switch($damage){device {$f.Sources[1].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[1].ScanId='other'};scope {$f.Identity.ScopeKey='WSA-LOG-001'}
        control {$f.Identity.CheckId='WSA-LOG-001';$f.Identity.ScopeKey='WSA-LOG-001'};source {$f.Sources[1].SourceId='OTHER'};location {$f.Sources[1].Location='REMOTE'}
        time {$f.Sources[1].CollectedAtUTC='2026-10-29T00:00:00.0000000Z'};duplicate-source {$f.Sources[1]=$f.Sources[0]};remote {$f.Sources[1]|Add-Member NoteProperty ComputerName 'REMOTE'}
        array {$f.Sources[1].Data=$f.Sources[1].Data[0]};guid {$f.Sources[2].Data[0].AuditSubCategoryGuid='PRIVATE-SECRET'};empty-guid {$f.Sources[1].Data[0].AuditCategoryGuid=[guid]::Empty.ToString('D')}
        unrequested {$f.Sources[4].Data[0].AuditSubCategoryGuid='33333333-3333-4333-8333-333333333333'};unknown-category {$f.Sources[4].Data[0].AuditCategoryGuid='33333333-3333-4333-8333-333333333333'}
        requests-before {$f.Sources[3].CollectedAtUTC=$f.StartedAtUTC};response-before {$f.Sources[4].CollectedAtUTC=$f.StartedAtUTC}
        absence-kind {$f.Sources[5].Data.SCENoApplyLegacyAuditPolicy.State='NOT_CONFIGURED';$f.Sources[5].Data.SCENoApplyLegacyAuditPolicy.Value=$null}}
    Reject-AuditCandidate {New-WinSecAuditPolicyFixturePackage $f}
}}
foreach($damage in @('platform','source','scope','authority','collector','location','date','success','mode','parent','details')){Test-AuditCandidate ('Stored semantic forgery rejected: '+$damage) {
    $s=(New-WinSecAuditPolicyFixturePackage $f).Snapshot
    switch($damage){platform {$s.Platform.BuildNumber=[uint32]22631};source {(Get-WinSecAuditPolicyFixtureReadings $s Capture.CategoriesSourceState)[0].Value='ERROR'}
        scope {(Get-WinSecAuditPolicyFixtureReadings $s Capture.Scope)[0].Value='PER_USER'};authority {(Get-WinSecAuditPolicyFixtureReadings $s Capture.PolicyAuthority)[0].Value='DOMAIN'}
        collector {$s.CollectorVersion='9.0.0'};location {(Get-WinSecAuditPolicyFixtureReadings $s Capture.SystemPolicyLocation)[0].Value='LOCAL_AUDIT_QUERY_REQUEST'}
        date {(Get-WinSecAuditPolicyFixtureReadings $s Capture.RequestsTime)[0].Value=$f.StartedAtUTC};success {(Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.Success)[0].Value=$false}
        mode {(Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.Mode)[0].Value='NONE'};parent {(Get-WinSecAuditPolicyFixtureReadings $s SystemPolicy.AuditCategoryGuid)[0].Value='33333333-3333-4333-8333-333333333333'}
        details {$r=(Get-WinSecAuditPolicyFixtureReadings $s Capture.PerUserPolicy)[0];$r.State='OBSERVED';$r.Reason='NONE';$r.Value='PRIVATE-SECRET';$s.Collection.NotCollected--;$s.Collection.Observed++}}
    Reject-AuditCandidate {Assert-WinSecAuditPolicyCandidateSnapshot $s $f.Identity}
}}
Write-Host ("Audit Policy technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
