[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/TechnicalSnapshotContract.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSnapshotMemory.ps1')
function Get-CimInstance {throw 'Native queries prohibited.'}
function Get-MpPreference {throw 'Native queries prohibited.'}
$passed=0;$failed=0
function Assert-Snapshot {param([bool]$Condition);if(-not $Condition){throw 'Snapshot assertion failed.'}}
function Reject-Snapshot {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-Snapshot $caught}
function Check-Snapshot {param($CaseLabel,[scriptblock]$Action);$f=New-WinSecSnapshotFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseLabel)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseLabel+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
function Validate-Snapshot {Assert-WinSecTechnicalSnapshot $f.Snapshot $f.Catalog $f.Hash $f.Identity}

Check-Snapshot 'Typed roundtrip preserves false, zero, UTC text and detached objects' {
    Validate-Snapshot
    $json=ConvertTo-Json -InputObject $f.Snapshot -Depth 16
    $copy=ConvertFrom-WinSecTechnicalSnapshotJson $json $f.Catalog $f.Hash $f.Identity
    Assert-Snapshot ($copy.CollectedAtUTC -is [string] -and $copy.Batches[0].Records[0].Readings[0].Value -ceq $false -and $copy.Batches[0].Records[0].Readings[1].Value -ceq 0)
    $copy.Batches[0].Records[0].Readings[2].Value='CHANGED'
    Assert-Snapshot ($f.Snapshot.Batches[0].Records[0].Readings[2].Value -ceq 'SYNTHETIC ACCOUNT')
}
Check-Snapshot 'All fourteen storage identities match the existing catalog without granting execution' {
    $catalog=Get-Content -Raw -LiteralPath (Join-Path $root 'config/checks.json') | ConvertFrom-Json
    Assert-Snapshot ($catalog.checks.Count -eq 14 -and -not (Get-WinSecSnapshotSpecification).ProductionEnabled)
    foreach($check in $catalog.checks){$c=Get-WinSecSnapshotControl $check.checkId;Assert-Snapshot ($c.SectionKey -ceq $check.sectionKey -and $c.ControlName -ceq $check.controlKey)}
}
foreach($name in @('DeviceId','ScanId','SnapshotId','CheckId','SectionKey','ScopeType','ScopeKey')){Check-Snapshot ('Reject mixed owner: '+$name) {
    $f.Snapshot.Identity.$name='FOREIGN';Reject-Snapshot {Validate-Snapshot}
}}
foreach($name in @('DeviceId','ScanId','SnapshotId','CheckId')){Check-Snapshot ('Reject mixed batch: '+$name) {
    $f.Snapshot.Batches[0].$name='FOREIGN';Reject-Snapshot {Validate-Snapshot}
}}
Check-Snapshot 'Control, section and device scopes preserve the original identity' {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){$key=switch($scope){CONTROL {'WSA-IAM-002'} SECTION {'IdentityAccess'} DEVICE {'ALL'}}
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=$key;$f.Snapshot.Identity.ScopeType=$scope;$f.Snapshot.Identity.ScopeKey=$key;Validate-Snapshot}
}
Check-Snapshot 'Reject stale catalog fingerprint and altered definitions' {
    $f.Catalog.Fields[0].Required=$false;Reject-Snapshot {Validate-Snapshot}
}
Check-Snapshot 'Reject missing, unknown and duplicate fields' {
    $r=$f.Snapshot.Batches[0].Records[0];$r.Readings[1].FieldId=$r.Readings[0].FieldId;Reject-Snapshot {Validate-Snapshot}
    $r.Readings[1].FieldId='Invented';Reject-Snapshot {Validate-Snapshot}
    $r.Readings=@($r.Readings[0]);Reject-Snapshot {Validate-Snapshot}
}
Check-Snapshot 'Reject forged totals, ordering and chronology' {
    $f.Snapshot.Collection.Observed=2;Reject-Snapshot {Validate-Snapshot};$f.Snapshot.Collection.Observed=3
    $f.Snapshot.Batches[0].Sequence=2;Reject-Snapshot {Validate-Snapshot};$f.Snapshot.Batches[0].Sequence=1
    $f.Snapshot.CompletedAtUTC='2026-10-28T00:00:00.0000000Z';Reject-Snapshot {Validate-Snapshot}
}
foreach($name in @('ArtifactType','SchemaVersion','CatalogId','CatalogVersion')){Check-Snapshot ('Reject array masquerading as scalar: '+$name) {
    $f.Snapshot.$name=@($f.Snapshot.$name);Reject-Snapshot {Validate-Snapshot}
}}
Check-Snapshot 'Reject values with unexpected types or terminal controls' {
    $r=$f.Snapshot.Batches[0].Records[0].Readings
    $r[0].Value='false';Reject-Snapshot {Validate-Snapshot};$r[0].Value=$false
    $r[1].Value=-1;Reject-Snapshot {Validate-Snapshot};$r[1].Value=0
    $r[2].Value=('unsafe'+[char]27+'[0m');Reject-Snapshot {Validate-Snapshot}
}
Check-Snapshot 'Optional UNKNOWN limits coverage without fabricating failure' {
    $r=$f.Snapshot.Batches[0].Records[0].Readings[2];$r.State='UNKNOWN';$r.Reason='PROVIDER_UNAVAILABLE';$r.Value=$null
    $f.Snapshot.Collection.Observed=2;$f.Snapshot.Collection.Unknown=1;$f.Snapshot.Collection.Coverage='LIMITED';Validate-Snapshot
}
Check-Snapshot 'Required UNKNOWN forces partial execution' {
    $r=$f.Snapshot.Batches[0].Records[0].Readings[0];$r.State='UNKNOWN';$r.Reason='PROVIDER_UNAVAILABLE';$r.Value=$null
    $f.Snapshot.Collection.Observed=2;$f.Snapshot.Collection.Unknown=1;$f.Snapshot.Collection.Coverage='LIMITED'
    Reject-Snapshot {Validate-Snapshot};$f.Snapshot.Collection.Status='PARTIAL';Validate-Snapshot
}
Check-Snapshot 'Exclusion requires observed platform evidence rather than a selected profile' {
    $r=$f.Snapshot.Batches[0].Records[0].Readings[2];$r.State='NOT_APPLICABLE';$r.Reason='PLATFORM_EXCLUDED';$r.Value=$null
    $f.Snapshot.Collection.Observed=2;$f.Snapshot.Collection.NotApplicable=1;Reject-Snapshot {Validate-Snapshot}
    $f.Catalog.Fields[2].Applicability=[pscustomobject]@{MinBuild=26100;MaxBuild=$null;Skus=@()}
    $f.Hash=Get-WinSecSnapshotCatalogHash $f.Catalog;$f.Snapshot.CatalogSha256=$f.Hash;Validate-Snapshot
    $f.Snapshot.Platform.BuildNumber=$null;$f.Snapshot.Platform.Version=$null;Reject-Snapshot {Validate-Snapshot}
}
Check-Snapshot 'Resource-limited inventory is partial and retains explicit counts' {
    $i=$f.Snapshot.Inventories[0];$i.Complete=$false;$i.Reason='RESOURCE_LIMIT';$i.ReportedRecords=10
    Reject-Snapshot {Validate-Snapshot};$f.Snapshot.Collection.Status='PARTIAL';$f.Snapshot.Collection.Coverage='LIMITED';Validate-Snapshot
}
Check-Snapshot 'Catalog prohibits secrets and score fields while allowing password-policy configuration' {
    foreach($id in @('Guest.Password','Guest.Secret','Guest.PasswordHash','Guest.RecoveryKey','Guest.Score')){
        $f.Catalog.Fields[0].Id=$id;Reject-Snapshot {Assert-WinSecSnapshotCatalog $f.Catalog}
    }
    $f.Catalog.Fields[0].Id='Policy.PasswordComplexity';Assert-WinSecSnapshotCatalog $f.Catalog
}
Check-Snapshot 'More than 256 records survive ordered batches; duplicates and oversized batches fail' {
    $f.Catalog.Inventories[0].Singleton=$false;$f.Hash=Get-WinSecSnapshotCatalogHash $f.Catalog;$f.Snapshot.CatalogSha256=$f.Hash
    $template=$f.Snapshot.Batches[0];$batches=@();$records=@()
    for($n=0;$n -lt 300;$n++){$records += [pscustomobject]@{Id=('Row'+$n);Readings=$template.Records[0].Readings}}
    for($n=0;$n -lt 300;$n+=128){$b=$template.PSObject.Copy();$b.Sequence=$batches.Count+1;$b.Records=@($records[$n..([Math]::Min($n+127,299))]);$batches+= $b}
    $f.Snapshot.Batches=$batches;$f.Snapshot.Inventories[0].ReportedRecords=300;$f.Snapshot.Inventories[0].RetainedRecords=300
    $f.Snapshot.Collection.RetainedRecords=300;$f.Snapshot.Collection.Observed=900;Validate-Snapshot
    $f.Snapshot.Batches[2].Records[0].Id='Row0';Reject-Snapshot {Validate-Snapshot}
    $f.Snapshot.Batches[0].Records=$records;Reject-Snapshot {Validate-Snapshot}
}
Check-Snapshot 'Strict JSON rejects duplicate, escaped duplicate, reserved, comment and trailing syntax' {
    $json=ConvertTo-Json -InputObject $f.Snapshot -Depth 16 -Compress
    foreach($bad in @($json.Replace('"SchemaVersion":"2.0.0"','"SchemaVersion":"2.0.0","SchemaVersion":"2.0.0"'),
        $json.Replace('"SchemaVersion":"2.0.0"','"SchemaVersion":"2.0.0","\u0053chemaVersion":"2.0.0"'),
        ('{"psobject":0,'+$json.Substring(1)),('/*comment*/'+$json),($json+' trailing'))){
        Reject-Snapshot {ConvertFrom-WinSecTechnicalSnapshotJson $bad $f.Catalog $f.Hash $f.Identity}
    }
}
Check-Snapshot 'JSON depth and byte budgets reject overflow before parsing' {
    Reject-Snapshot {Assert-WinSecSnapshotJsonBudget (('['*17)+'0'+(']'*17))}
    Reject-Snapshot {Assert-WinSecSnapshotJsonBudget ('"'+('a'*16777216)+'"')}
    Assert-WinSecSnapshotJsonBudget '{"quoted":"[{}]","escaped":"\""}'
}
Check-Snapshot 'Cancellation rejects validation without modifying the original snapshot' {
    Reject-Snapshot {Assert-WinSecTechnicalSnapshot $f.Snapshot $f.Catalog $f.Hash $f.Identity -CancellationAction {$true}}
    $json=ConvertTo-Json -InputObject $f.Snapshot -Depth 16
    Reject-Snapshot {ConvertFrom-WinSecTechnicalSnapshotJson $json $f.Catalog $f.Hash $f.Identity -CancellationAction {$true}}
    Reject-Snapshot {Assert-WinSecTechnicalSnapshot $f.Snapshot $f.Catalog $f.Hash $f.Identity -CancellationAction {'invalid'}}
    Validate-Snapshot
}
Check-Snapshot 'Expired validation budget fails without waiting or calling a provider' {
    $clock=New-Object Diagnostics.Stopwatch
    $expired=Get-WinSecSnapshotSpecification;$expired.ValidationTimeoutMilliseconds=0
    # Local test override changes only the returned fixture budget, never production configuration.
    function Get-WinSecSnapshotSpecification {return $expired}
    Reject-Snapshot {Assert-WinSecSnapshotValidationBudget $clock}
}
Check-Snapshot 'Property casing, extra members and executable properties are rejected' {
    $f.Snapshot | Add-Member -NotePropertyName Evidence -NotePropertyValue 'UNREVIEWED';Reject-Snapshot {Validate-Snapshot}
    $f=New-WinSecSnapshotFixture;$f.Snapshot.PSObject.Properties.Remove('ArtifactType')
    $f.Snapshot | Add-Member -NotePropertyName artifactType -NotePropertyValue 'WinSec.TechnicalSnapshot';Reject-Snapshot {Validate-Snapshot}
    $f=New-WinSecSnapshotFixture;$f.Snapshot.PSObject.Properties.Remove('ArtifactType')
    $script:SnapshotGetterInvoked=$false
    $f.Snapshot | Add-Member -MemberType ScriptProperty -Name ArtifactType -Value {$script:SnapshotGetterInvoked=$true;return 'WinSec.TechnicalSnapshot'}
    Reject-Snapshot {Validate-Snapshot};Assert-Snapshot (-not $script:SnapshotGetterInvoked)
}
Check-Snapshot 'Catalog metadata rejects array enums, unknown providers, sources and invalid units' {
    $f.Catalog.Sources[0].Provider=@('NETAPI');Reject-Snapshot {Assert-WinSecSnapshotCatalog $f.Catalog}
    $f.Catalog.Sources[0].Provider='NETAPI';$f.Catalog.Fields[0].Unit='seconds';Reject-Snapshot {Assert-WinSecSnapshotCatalog $f.Catalog}
    $f.Catalog.Fields[0].Unit='none';$f.Catalog.Inventories[0].SourceId='UNREVIEWED';Reject-Snapshot {Assert-WinSecSnapshotCatalog $f.Catalog}
}
Check-Snapshot 'Batch byte overflow is rejected rather than dropping records' {
    $f.Catalog.Inventories[0].Singleton=$false;$f.Catalog.Fields[2].Type='StringArray'
    $f.Hash=Get-WinSecSnapshotCatalogHash $f.Catalog;$f.Snapshot.CatalogSha256=$f.Hash
    $f.Snapshot.Batches[0].Records[0].Readings[2].Value=@(('x'*4096))*256
    Reject-Snapshot {Validate-Snapshot}
}
Check-Snapshot 'Unavailable provider is partial with zero retained records and explicit inventory state' {
    $i=$f.Snapshot.Inventories[0];$i.State='ERROR';$i.Complete=$false;$i.ReportedRecords=$null;$i.RetainedRecords=0;$i.Reason='PROVIDER_UNAVAILABLE'
    $f.Snapshot.Batches=@();$f.Snapshot.Collection.RetainedRecords=0;$f.Snapshot.Collection.Observed=0
    $f.Snapshot.Collection.Coverage='LIMITED';Reject-Snapshot {Validate-Snapshot};$f.Snapshot.Collection.Status='PARTIAL';Validate-Snapshot
}
Check-Snapshot 'Explicit absence states preserve null and distinguish missing data from configuration' {
    foreach($state in @('ERROR','NOT_COLLECTED','NOT_CONFIGURED')){
        $f=New-WinSecSnapshotFixture;$r=$f.Snapshot.Batches[0].Records[0].Readings[2];$r.State=$state;$r.Value=$null
        $r.Reason=switch($state){ERROR {'INVALID_VALUE'} NOT_COLLECTED {'NOT_REQUESTED'} NOT_CONFIGURED {'ABSENT'}}
        $counter=switch($state){ERROR {'Errors'} NOT_COLLECTED {'NotCollected'} NOT_CONFIGURED {'NotConfigured'}}
        $f.Snapshot.Collection.Observed=2;$f.Snapshot.Collection.$counter=1
        if($state -cne 'NOT_CONFIGURED'){$f.Snapshot.Collection.Coverage='LIMITED'}
        Validate-Snapshot;$r.Value=$false;Reject-Snapshot {Validate-Snapshot}
    }
}
Check-Snapshot 'Whole-inventory exclusion is verified against the observed build' {
    $f.Catalog.Inventories[0].Applicability=[pscustomobject]@{MinBuild=26100;MaxBuild=$null;Skus=@()}
    $f.Hash=Get-WinSecSnapshotCatalogHash $f.Catalog;$f.Snapshot.CatalogSha256=$f.Hash
    $i=$f.Snapshot.Inventories[0];$i.State='NOT_APPLICABLE';$i.RetainedRecords=0;$i.ReportedRecords=$null;$i.Reason='PLATFORM_EXCLUDED'
    $f.Snapshot.Batches=@();$f.Snapshot.Collection.RetainedRecords=0;$f.Snapshot.Collection.Observed=0;Validate-Snapshot
    $f.Snapshot.Platform.BuildNumber=26100;$f.Snapshot.Platform.Version='10.0.26100';Reject-Snapshot {Validate-Snapshot}
}
Check-Snapshot 'Platform and timestamps reject numeric text, mismatches and noncanonical dates' {
    $f.Snapshot.Platform.Edition=48;Reject-Snapshot {Validate-Snapshot};$f.Snapshot.Platform.Edition='Pro'
    $f.Snapshot.Platform.Version='10.0.26100';Reject-Snapshot {Validate-Snapshot};$f.Snapshot.Platform.Version='10.0.22631'
    foreach($date in @('2026-10-28T01:02:04Z','2026-10-28T01:02:04.0000000+00:00','2026-02-30T01:02:04.0000000Z')){
        $f.Snapshot.CollectedAtUTC=$date;Reject-Snapshot {Validate-Snapshot}
    }
}
Check-Snapshot 'Measured quantities preserve units but reject negative counts and percentages over 100' {
    $f.Catalog.Fields[1].Type='Int64';$f.Hash=Get-WinSecSnapshotCatalogHash $f.Catalog;$f.Snapshot.CatalogSha256=$f.Hash
    $f.Snapshot.Batches[0].Records[0].Readings[1].Value=[long]-1;Reject-Snapshot {Validate-Snapshot}
    $f.Catalog.Fields[1].Unit='percent';$f.Hash=Get-WinSecSnapshotCatalogHash $f.Catalog;$f.Snapshot.CatalogSha256=$f.Hash
    $f.Snapshot.Batches[0].Records[0].Readings[1].Value=[long]101;Reject-Snapshot {Validate-Snapshot}
    $f.Snapshot.Batches[0].Records[0].Readings[1].Value=[long]0;Validate-Snapshot
}
Write-Host ("Snapshot contract: $passed passed; $failed failed.")
if($failed){exit 1}
