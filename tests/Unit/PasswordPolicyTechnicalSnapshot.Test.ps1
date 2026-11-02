[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Policies/PasswordPolicyTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/PasswordPolicyTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native policy query forbidden.'}
function Get-LocalUser {throw 'Native account query forbidden.'}
function secedit {throw 'Native policy export forbidden.'}
$passed=0;$failed=0
function Assert-PolicyCandidate {param([bool]$Value);if(-not $Value){throw 'Password Policy candidate assertion failed.'}}
function Reject-PolicyCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PolicyCandidate $caught}
function Test-PolicyCandidate {param($CaseName,[scriptblock]$Action);$f=New-WinSecPasswordPolicyCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}

Test-PolicyCandidate 'Versioned configuration catalog has five singletons and thirty-seven definitions' {
    $p=New-WinSecPasswordPolicyFixturePackage $f;$d=@(Get-WinSecPasswordPolicyCandidateFields)
    Assert-PolicyCandidate ($p.Catalog.Fields.Count -eq 37 -and $p.Catalog.Inventories.Count -eq 5 -and @($d|Where-Object Derived -EQ $false).Count -eq 17 -and
        $p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'COMPLETE' -and $p.Snapshot.Collection.Observed -eq 37)
}
Test-PolicyCandidate 'All eight previous parameters remain represented with original seconds and counts' {
    $s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    foreach($name in @('MinimumLength','MaximumAgeSeconds','MinimumAgeSeconds','ForceLogoffSeconds','HistoryLength')){Assert-PolicyCandidate ((Get-WinSecPasswordPolicyFixtureReadings $s ('Policy.'+$name))[0].Value -eq $f.Sources[1].Data.Settings.$name)}
    foreach($name in @('DurationSeconds','ObservationWindowSeconds','Threshold')){Assert-PolicyCandidate ((Get-WinSecPasswordPolicyFixtureReadings $s ('Lockout.'+$name))[0].Value -eq $f.Sources[2].Data.Settings.$name)}
    $c=Get-WinSecPasswordPolicyCandidateCatalog;Assert-PolicyCandidate (($c.Fields|Where-Object Id -CEQ Policy.MaximumAgeSeconds).Unit -ceq 'seconds')
}
Test-PolicyCandidate 'Zero and TIMEQ_FOREVER remain exact observed values without logon or expiry claims' {
    $f.Sources[1].Data.Settings.MinimumLength=[uint32]0;$f.Sources[2].Data.Settings.Threshold=[uint32]0
    $s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    Assert-PolicyCandidate ((Get-WinSecPasswordPolicyFixtureReadings $s Policy.MaximumAgeSeconds)[0].Value -eq 4294967295 -and
        (Get-WinSecPasswordPolicyFixtureReadings $s Policy.ForceLogoffSeconds)[0].Value -eq 4294967295 -and
        (Get-WinSecPasswordPolicyFixtureReadings $s Lockout.Threshold)[0].Value -eq 0 -and $s.Collection.Status -ceq 'COMPLETE' -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'Score|LogonSucceeded|PasswordValue')
}
foreach($flag in @('PasswordComplexity','ClearTextPassword')){foreach($value in @(0,1,2,65536)){Test-PolicyCandidate ('Reviewed template integer flags retain native values: '+$flag+'/'+$value) {
    $f.Sources[3].Data.Settings.$flag=[uint32]$value;$s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    Assert-PolicyCandidate ((Get-WinSecPasswordPolicyFixtureReadings $s ('Template.'+$flag))[0].Value -eq $value -and $s.Collection.Coverage -ceq 'COMPLETE')
}}}
foreach($flag in @('PasswordComplexity','ClearTextPassword')){Test-PolicyCandidate ('Missing optional policy is visible UNKNOWN without invented default: '+$flag) {
    $f.Sources[3].Data.Settings.PSObject.Properties.Remove($flag);$s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    Assert-PolicyCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED' -and
        (Get-WinSecPasswordPolicyFixtureReadings $s ('Template.'+$flag))[0].State -ceq 'UNKNOWN')
}}
foreach($value in @($false,'0',-1,65537)){Test-PolicyCandidate 'Unreviewed template representations stay unknown instead of disabled' {
    $f.Sources[3].Data.Settings.ClearTextPassword=$value;$s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    Assert-PolicyCandidate ((Get-WinSecPasswordPolicyFixtureReadings $s Template.ClearTextPassword)[0].State -ceq 'UNKNOWN' -and
        $null -eq (Get-WinSecPasswordPolicyFixtureReadings $s Template.ClearTextPassword)[0].Value -and $s.Collection.Coverage -ceq 'LIMITED')
}}
foreach($value in @($null,'14',$false,-1,1.5,[uint64]4294967296)){Test-PolicyCandidate 'Invalid or unknown required values never become zero or COMPLETE' {
    $f.Sources[1].Data.Settings.MinimumLength=$value;$s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    Assert-PolicyCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecPasswordPolicyFixtureReadings $s Policy.MinimumLength)[0].State -ceq 'UNKNOWN')
}}
Test-PolicyCandidate 'Contradictory native ages remain visible with a partial collection diagnostic' {
    $f.Sources[1].Data.Settings.MaximumAgeSeconds=[uint32]86400;$f.Sources[1].Data.Settings.MinimumAgeSeconds=[uint32]86401
    $s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    Assert-PolicyCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecPasswordPolicyFixtureReadings $s Policy.MinimumAgeSeconds)[0].Value -eq 86401 -and
        ($s.Inventories|Where-Object Id -CEQ Policy).Reason -ceq 'INVALID_VALUE')
}
foreach($idx in @(0,1,2,3)){foreach($state in @('ERROR','NOT_COLLECTED')){Test-PolicyCandidate ('Unavailable sources preserve unknown totals and explicit states: '+$idx+'/'+$state) {
    $f.Sources[$idx].State=$state;$f.Sources[$idx].Data=$null;$s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot;$id=$f.Sources[$idx].SourceId
    Assert-PolicyCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $null -eq ($s.Inventories|Where-Object Id -CEQ $id).ReportedRecords -and
        (Get-WinSecPasswordPolicyFixtureReadings $s ('Capture.'+$id+'SourceState'))[0].Value -ceq $state)
}}}
foreach($idx in @(1,2,3)){Test-PolicyCandidate ('Nonzero native status retained with no output trusted: '+$idx) {
    $f.Sources[$idx].Data.ReturnValue=[uint32]5;$f.Sources[$idx].Data.Settings=$null;$s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot;$id=$f.Sources[$idx].SourceId
    Assert-PolicyCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecPasswordPolicyFixtureReadings $s ($id+'.ReturnValue'))[0].Value -eq 5 -and $s.Collection.Errors -gt 0)
}}
Test-PolicyCandidate 'Future UInt32 return codes remain exact without publishing usable outputs' {
    $f.Sources[1].Data.ReturnValue=[uint32]4294967295;$f.Sources[1].Data.Settings=$null;$s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    Assert-PolicyCandidate ((Get-WinSecPasswordPolicyFixtureReadings $s Policy.ReturnValue)[0].Value -eq 4294967295 -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-PolicyCandidate 'Scope states do not assert domain MDM cloud or effective policy applicability' {
    $s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    foreach($id in @('DomainPolicy','MDMPolicy','CloudPolicy')){Assert-PolicyCandidate ((Get-WinSecPasswordPolicyFixtureReadings $s ('Capture.'+$id))[0].Value -ceq 'NOT_COLLECTED')}
    Assert-PolicyCandidate ((Get-WinSecPasswordPolicyFixtureReadings $s Capture.EffectivePolicy)[0].Value -ceq 'NOT_RESOLVED' -and
        (Get-WinSecPasswordPolicyFixtureReadings $s Capture.PolicyAuthority)[0].Value -ceq 'NOT_OBSERVED')
}
Test-PolicyCandidate 'Property getters are not executed and secrets never leave supplied data' {
    $d=$f.Sources[1].Data.Settings;$d.PSObject.Properties.Remove('MinimumLength');$d|Add-Member ScriptProperty MinimumLength {throw 'GETTER EXECUTED'}
    foreach($key in @('Password','PasswordHash','Credential','Token','Description')){$d|Add-Member NoteProperty $key 'PRIVATE-SECRET'}
    $s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    Assert-PolicyCandidate ((Get-WinSecPasswordPolicyFixtureReadings $s Policy.MinimumLength)[0].State -ceq 'UNKNOWN' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|GETTER EXECUTED')
}
Test-PolicyCandidate 'Ambiguous property casing cannot silently select a setting' {
    $d=New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal);$d.Add('MinimumLength',[uint32]14);$d.Add('minimumlength',[uint32]0)
    $f.Sources[1].Data.Settings=$d;$s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    Assert-PolicyCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecPasswordPolicyFixtureReadings $s Policy.MinimumLength)[0].Reason -ceq 'INVALID_VALUE')
}
Test-PolicyCandidate 'Cancellation after progress returns no snapshot and preserves all caller receipts' {
    $before=ConvertTo-Json $f -Depth 12 -Compress;$script:cancelPolicy=$false;$caught=$false
    try{$null=New-WinSecPasswordPolicyFixturePackage $f -CancellationAction {$script:cancelPolicy} -ProgressCallback {param($e);if($e.InventoryId -ceq 'Policy'){$script:cancelPolicy=$true}}}catch [OperationCanceledException]{$caught=$true}
    Assert-PolicyCandidate ($caught -and (ConvertTo-Json $f -Depth 12 -Compress) -ceq $before)
}
foreach($damage in @('device','scan','scope','control','source','location','time','duplicate','remote','server','level','section','merged','nonzero-output','status','array','empty','absence')){Test-PolicyCandidate ('Untrusted or foreign policy receipt rejected: '+$damage) {
    switch($damage){device {$f.Sources[1].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[1].ScanId='other'};scope {$f.Identity.ScopeKey='WSA-IAM-001'}
        control {$f.Identity.CheckId='WSA-IAM-001';$f.Identity.ScopeKey='WSA-IAM-001'};source {$f.Sources[1].SourceId='OTHER'};location {$f.Sources[1].Location='CIMV2'}
        time {$f.Sources[1].CollectedAtUTC='2026-10-29T00:00:00.0000000Z'};duplicate {$f.Sources[1]=$f.Sources[0]};remote {$f.Sources[1]|Add-Member NoteProperty ComputerName 'REMOTE'}
        server {$f.Sources[1].Data.ServerName='REMOTE'};level {$f.Sources[1].Data.Level=[uint32]1};section {$f.Sources[3].Data.Section='Registry Values'};merged {$f.Sources[3].Data.MergedPolicy=$true}
        nonzero-output {$f.Sources[1].Data.ReturnValue=[uint32]5};status {$f.Sources[1].Data.ReturnValue='0'};array {$f.Sources[1].Data.Settings=@($f.Sources[1].Data.Settings)}
        empty {$f.Sources[1].Data.Settings=$null};absence {$f.Sources[1].State='NOT_APPLICABLE';$f.Sources[1].Data=$null}}
    Reject-PolicyCandidate {New-WinSecPasswordPolicyFixturePackage $f}
}}
foreach($damage in @('platform','source','scope','domain','cloud','mdm','effective','template','collector','absence','status-output','location','date','flag')){Test-PolicyCandidate ('Stored semantic policy forgery rejected: '+$damage) {
    $s=(New-WinSecPasswordPolicyFixturePackage $f).Snapshot
    switch($damage){platform {$s.Platform.BuildNumber=[uint32]22631};source {(Get-WinSecPasswordPolicyFixtureReadings $s Capture.PolicySourceState)[0].Value='ERROR'}
        scope {(Get-WinSecPasswordPolicyFixtureReadings $s Capture.Scope)[0].Value='DOMAIN'};domain {(Get-WinSecPasswordPolicyFixtureReadings $s Capture.PolicyAuthority)[0].Value='DOMAIN'}
        cloud {(Get-WinSecPasswordPolicyFixtureReadings $s Capture.CloudPolicy)[0].Value='NOT_OBSERVED'};mdm {(Get-WinSecPasswordPolicyFixtureReadings $s Capture.MDMPolicy)[0].Value='NOT_RESOLVED'}
        effective {(Get-WinSecPasswordPolicyFixtureReadings $s Capture.EffectivePolicy)[0].Value='NOT_COLLECTED'};template {(Get-WinSecPasswordPolicyFixtureReadings $s Capture.TemplateMode)[0].Value='MERGED'}
        collector {$s.CollectorVersion='9.0.0'};absence {$r=(Get-WinSecPasswordPolicyFixtureReadings $s Policy.MinimumLength)[0];$r.State='NOT_CONFIGURED';$r.Reason='ABSENT';$r.Value=$null;$s.Collection.Observed--;$s.Collection.NotConfigured++}
        status-output {(Get-WinSecPasswordPolicyFixtureReadings $s Policy.ReturnValue)[0].Value=[uint32]5};location {(Get-WinSecPasswordPolicyFixtureReadings $s Capture.PolicyLocation)[0].Value='LOCAL_NETAPI_LEVEL3'}
        date {(Get-WinSecPasswordPolicyFixtureReadings $s Capture.TemplateTime)[0].Value='2026-10-28T01:02:04.0000000Z'};flag {(Get-WinSecPasswordPolicyFixtureReadings $s Template.ClearTextPassword)[0].Value=[uint32]65537}}
    Reject-PolicyCandidate {Assert-WinSecPasswordPolicyCandidateSnapshot $s $f.Identity}
}}
Write-Host ("Password Policy technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
