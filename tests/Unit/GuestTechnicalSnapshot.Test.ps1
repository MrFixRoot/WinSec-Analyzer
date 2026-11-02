[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Accounts/GuestTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/GuestTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native account query forbidden.'}
function Get-CimClass {throw 'Native account query forbidden.'}
function Get-LocalUser {throw 'Native account query forbidden.'}
$passed=0;$failed=0
function Assert-GuestCandidate {param([bool]$Value);if(-not $Value){throw 'Guest technical candidate assertion failed.'}}
function Reject-GuestCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-GuestCandidate $caught}
function Get-GuestCandidateSummary {param($Snapshot,$Id);@($Snapshot.Inventories|Where-Object Id -CEQ $Id)[0]}
function Test-GuestCandidate {param($CaseName,[scriptblock]$Action);$f=New-WinSecGuestCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}

Test-GuestCandidate 'The catalog has three inventories thirty fields and no production dependency' {
    $p=New-WinSecGuestFixturePackage $f;$d=@(Get-WinSecGuestCandidateFields)
    Assert-GuestCandidate ($p.Catalog.Fields.Count -eq 30 -and $p.Catalog.Inventories.Count -eq 3 -and @($d|Where-Object Derived -EQ $false).Count -eq 16 -and
        $p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'COMPLETE' -and $p.Snapshot.Collection.RetainedRecords -eq 3 -and $p.Snapshot.Collection.Observed -eq 30)
}
Test-GuestCandidate 'All prior Guest readings remain represented with identity and derived presence' {
    $ids=@((Get-WinSecGuestCandidateFields).Id)
    foreach($name in @('Present','Disabled','LocalAccount','Lockout','PasswordRequired','PasswordChangeable','PasswordExpires','AccountType','SIDType')){Assert-GuestCandidate (('Guest.'+$name) -cin $ids)}
    $s=(New-WinSecGuestFixturePackage $f).Snapshot;Assert-GuestCandidate ((Get-WinSecGuestFixtureReadings $s Guest.SID)[0].Value -ceq 'S-1-5-21-11-22-33-501' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'sha256:|Score')
}
Test-GuestCandidate 'Renamed localized Guest is selected by RID and local evidence rather than its display name' {
    $name='Invit'+[char]0xE9;$f.Sources[1].Data[0].Name=$name;$s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-WinSecGuestFixtureReadings $s Guest.Name)[0].Value -ceq $name)
}
Test-GuestCandidate 'A derived domain SID is explicit context and never machine or AD authority attestation' {
    $s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ((Get-WinSecGuestFixtureReadings $s Guest.AccountDomainSID)[0].Value -ceq 'S-1-5-21-11-22-33' -and
        (Get-WinSecGuestFixtureReadings $s Capture.AccountDomainSIDBasis)[0].Value -ceq 'DERIVED_FROM_GUEST_SID_NOT_MACHINE_ATTESTATION' -and
        (Get-WinSecGuestFixtureReadings $s Capture.PolicyAuthority)[0].Value -ceq 'NOT_OBSERVED' -and
        (Get-WinSecGuestFixtureReadings $s Capture.CloudResolution)[0].Value -ceq 'NOT_PERFORMED')
}
foreach($disabled in @($true,$false)){Test-GuestCandidate ('Disabled is preserved exactly without creating security verdicts: '+$disabled) {
    $f.Sources[1].Data[0].Disabled=$disabled;$s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ((Get-WinSecGuestFixtureReadings $s Guest.Disabled)[0].Value -ceq $disabled -and $s.Collection.Status -ceq 'COMPLETE' -and
        (Get-WinSecGuestFixtureReadings $s Guest.Present)[0].Value -ceq $true)
}}
Test-GuestCandidate 'Password flags do not become blank password or successful logon claims' {
    $s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ((Get-WinSecGuestFixtureReadings $s Guest.PasswordRequired)[0].State -ceq 'OBSERVED' -and
        (Get-WinSecGuestFixtureReadings $s Guest.PasswordRequired)[0].Value -ceq $false -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'BlankPassword|PasswordValue|LogonSucceeded')
}
foreach($name in @('Name','Domain','Status','Lockout','PasswordRequired','PasswordChangeable','PasswordExpires','AccountType','SIDType')){Test-GuestCandidate ('Optional null stays visible with limited coverage: '+$name) {
    $f.Sources[1].Data[0].($name)=$null;$s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED' -and
        (Get-WinSecGuestFixtureReadings $s ('Guest.'+$name))[0].State -ceq 'UNKNOWN')
}}
foreach($value in @($null,'false',[int]0)){Test-GuestCandidate 'Unknown or invalid Disabled never becomes false or a complete collection' {
    $f.Sources[1].Data[0].Disabled=$value;$s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecGuestFixtureReadings $s Guest.Disabled)[0].State -ceq 'UNKNOWN')
}}
Test-GuestCandidate 'All account type bits survive without inferring authentication policy' {
    $f.Sources[1].Data[0].AccountType=[uint32]4294967295;$s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ((Get-WinSecGuestFixtureReadings $s Guest.AccountType)[0].Value -eq 4294967295 -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-GuestCandidate 'Unexpected SID type retains the observed code and partial diagnostic' {
    $f.Sources[1].Data[0].SIDType=[byte]99;$s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ((Get-WinSecGuestFixtureReadings $s Guest.SIDType)[0].Value -eq 99 -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-GuestCandidate 'The literal native status Unknown differs from an unavailable property' {
    $f.Sources[1].Data[0].Status='Unknown';$s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ((Get-WinSecGuestFixtureReadings $s Guest.Status)[0].State -ceq 'OBSERVED' -and (Get-WinSecGuestFixtureReadings $s Guest.Status)[0].Value -ceq 'Unknown')
}
foreach($damage in @('name','domain','status')){Test-GuestCandidate ('Unreviewed free text is not retained: '+$damage) {
    switch($damage){name {$f.Sources[1].Data[0].Name='Guest|PRIVATE-SECRET'};domain {$f.Sources[1].Data[0].Domain='https://PRIVATE-SECRET'};status {$f.Sources[1].Data[0].Status='PRIVATE-SECRET'}}
    $s=(New-WinSecGuestFixturePackage $f).Snapshot;Assert-GuestCandidate ($s.Collection.Coverage -ceq 'LIMITED' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET')
}}
Test-GuestCandidate 'An observed empty selection is partial and never invents absent or disabled Guest values' {
    $f.Sources[1].Data=@();$s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-GuestCandidateSummary $s Guest).ReportedRecords -eq 0 -and
        @(Get-WinSecGuestFixtureReadings $s Guest.Present).Count -eq 0 -and $s.Collection.NotApplicable -eq 0)
}
foreach($state in @('ERROR','NOT_COLLECTED')){Test-GuestCandidate ('Unavailable Guest source keeps a receipt but no false inventory count: '+$state) {
    $f.Sources[1].State=$state;$f.Sources[1].Data=$null;$s=(New-WinSecGuestFixturePackage $f).Snapshot
    Assert-GuestCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $null -eq (Get-GuestCandidateSummary $s Guest).ReportedRecords -and
        (Get-WinSecGuestFixtureReadings $s Capture.GuestSourceState)[0].Value -ceq $state)
}}
Test-GuestCandidate 'A forced document budget reports the omitted account without an unsafe publication claim' {
    $old=(Get-Command Get-WinSecGuestCandidatePayloadBudget).ScriptBlock
    try{function script:Get-WinSecGuestCandidatePayloadBudget {return 0};$s=(New-WinSecGuestFixturePackage $f).Snapshot}
    finally{Set-Item Function:script:Get-WinSecGuestCandidatePayloadBudget $old}
    Assert-GuestCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-GuestCandidateSummary $s Guest).ReportedRecords -eq 1 -and
        (Get-GuestCandidateSummary $s Guest).RetainedRecords -eq 0 -and (Get-GuestCandidateSummary $s Guest).Reason -ceq 'RESOURCE_LIMIT')
}
Test-GuestCandidate 'Cancellation after account progress preserves caller receipts and returns no snapshot' {
    $before=ConvertTo-Json $f -Depth 10 -Compress;$script:cancelGuest=$false;$caught=$false
    try{$null=New-WinSecGuestFixturePackage $f -CancellationAction {$script:cancelGuest} -ProgressCallback {param($e);if($e.InventoryId -ceq 'Guest'){$script:cancelGuest=$true}}}catch [OperationCanceledException]{$caught=$true}
    Assert-GuestCandidate ($caught -and (ConvertTo-Json $f -Depth 10 -Compress) -ceq $before)
}
Test-GuestCandidate 'Getters are not executed and credential or personal metadata extras are excluded' {
    $raw=$f.Sources[1].Data[0];$raw.PSObject.Properties.Remove('Name');$raw|Add-Member ScriptProperty Name {throw 'GETTER EXECUTED'}
    foreach($name in @('Password','PasswordHash','Token','Credential','FullName','Caption','Description')){$raw|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
    $s=(New-WinSecGuestFixturePackage $f).Snapshot;Assert-GuestCandidate ((Get-WinSecGuestFixtureReadings $s Guest.Name)[0].State -ceq 'UNKNOWN' -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'GETTER EXECUTED|PRIVATE-SECRET|FullName|PasswordHash')
}
foreach($damage in @('device','scan','scope','control','source','location','time','duplicate','remote','rid','cloud','sid-format','local','missing-local','ambiguous','not-array','absence')){Test-GuestCandidate ('Foreign or ambiguous account capture rejected: '+$damage) {
    switch($damage){device {$f.Sources[1].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[1].ScanId='other'};scope {$f.Identity.ScopeKey='WSA-IAM-001'}
        control {$f.Identity.CheckId='WSA-IAM-001';$f.Identity.ScopeKey='WSA-IAM-001'};source {$f.Sources[1].SourceId='OTHER'};location {$f.Sources[1].Location='REMOTE'}
        time {$f.Sources[1].CollectedAtUTC='2026-10-29T00:00:00.0000000Z'};duplicate {$f.Sources[1]=$f.Sources[0]};remote {$f.Sources[1]|Add-Member NoteProperty ComputerName 'REMOTE'}
        rid {$f.Sources[1].Data[0].SID='S-1-5-21-11-22-33-1000';$f.Sources[1].Data[0].Name='Guest'};cloud {$f.Sources[1].Data[0].SID='S-1-12-1-11-22-33-501'}
        sid-format {$f.Sources[1].Data[0].SID='S-1-5-21-011-22-33-501'};local {$f.Sources[1].Data[0].LocalAccount=$false};missing-local {$f.Sources[1].Data[0].LocalAccount=$null}
        ambiguous {$f.Sources[1].Data=@($f.Sources[1].Data[0],$f.Sources[1].Data[0])};not-array {$f.Sources[1].Data=$f.Sources[1].Data[0]};absence {$f.Sources[1].State='NOT_APPLICABLE';$f.Sources[1].Data=$null}}
    Reject-GuestCandidate {New-WinSecGuestFixturePackage $f}
}}
foreach($damage in @('present','domain-sid','local','platform','source','scope','rid','domain','cloud','basis','collector','absence')){Test-GuestCandidate ('Stored Guest semantic forgery rejected: '+$damage) {
    $s=(New-WinSecGuestFixturePackage $f).Snapshot
    switch($damage){present {(Get-WinSecGuestFixtureReadings $s Guest.Present)[0].Value=$false};domain-sid {(Get-WinSecGuestFixtureReadings $s Guest.AccountDomainSID)[0].Value='S-1-5-21-44-55-66'}
        local {(Get-WinSecGuestFixtureReadings $s Guest.LocalAccount)[0].Value=$false};platform {$s.Platform.BuildNumber=[uint32]22631}
        source {(Get-WinSecGuestFixtureReadings $s Capture.GuestSourceState)[0].Value='ERROR'};scope {(Get-WinSecGuestFixtureReadings $s Capture.Scope)[0].Value='DOMAIN_GUEST'}
        rid {(Get-WinSecGuestFixtureReadings $s Capture.RequestedRID)[0].Value=[uint32]500};domain {(Get-WinSecGuestFixtureReadings $s Capture.PolicyAuthority)[0].Value='DOMAIN'}
        cloud {(Get-WinSecGuestFixtureReadings $s Capture.CloudResolution)[0].Value='PERFORMED'};basis {(Get-WinSecGuestFixtureReadings $s Capture.AccountDomainSIDBasis)[0].Value='MACHINE_ATTESTED'}
        collector {$s.CollectorVersion='9.0.0'};absence {$r=(Get-WinSecGuestFixtureReadings $s Guest.Name)[0];$r.State='NOT_CONFIGURED';$r.Reason='ABSENT';$r.Value=$null;$s.Collection.Observed--;$s.Collection.NotConfigured++}}
    Reject-GuestCandidate {Assert-WinSecGuestCandidateSnapshot $s $f.Identity}
}}
Write-Host ("Guest technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
