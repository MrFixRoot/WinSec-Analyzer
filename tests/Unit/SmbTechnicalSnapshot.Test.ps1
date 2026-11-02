[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Network/SmbTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/SmbTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-SmbServerConfiguration {throw 'Native audit forbidden.'}
function Get-SmbClientConfiguration {throw 'Native audit forbidden.'}
$passed=0;$failed=0
function Assert-SmbCandidate {param([bool]$Value);if(-not $Value){throw 'SMB technical candidate assertion failed.'}}
function Reject-SmbCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SmbCandidate $caught}
function Get-SmbCandidateSummary {param($Snapshot,$Id);@($Snapshot.Inventories|Where-Object Id -CEQ $Id)[0]}
function Test-SmbCandidate {param($Name,[scriptblock]$Action);$f=New-WinSecSmbCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}

Test-SmbCandidate 'Versioned catalog has seven inventories and one hundred forty six reviewed definitions' {
    $p=New-WinSecSmbFixturePackage $f
    Assert-SmbCandidate ($p.Catalog.Fields.Count -eq 146 -and $p.Catalog.Inventories.Count -eq 7 -and
        $p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'COMPLETE' -and
        $p.Snapshot.Collection.RetainedRecords -eq 11 -and $p.Snapshot.Collection.Observed -eq 171)
}
Test-SmbCandidate 'False zero maximum native integers and configuration context survive without scoring' {
    $f.Sources[1].Data.AsynchronousCredits=[uint32]::MaxValue;$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ((Get-WinSecSmbFixtureReadings $s Server.EnableSMB1Protocol)[0].Value -ceq $false -and
        (Get-WinSecSmbFixtureReadings $s Registry.ServerSMB1)[0].Value -eq 0 -and
        (Get-WinSecSmbFixtureReadings $s Server.AsynchronousCredits)[0].Value -eq [uint32]::MaxValue -and
        (Get-WinSecSmbFixtureReadings $s Client.CompressibilitySamplingSize)[0].Value -ceq '18446744073709551615' -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'Score|NOT_SCORED|/100')
}
foreach($code in @(1,2,3,4,99)){Test-SmbCandidate ('Feature native states preserve installation distinctions: '+$code) {
    $f.Sources[3].Data[0].InstallState=[uint32]$code;$s=(New-WinSecSmbFixturePackage $f).Snapshot
    $expected=switch($code){1 {'ENABLED'};2 {'DISABLED'};3 {'ABSENT'};default {'UNKNOWN'}}
    Assert-SmbCandidate ((Get-WinSecSmbFixtureReadings $s Features.InstallState)[0].Value -eq $code -and
        (Get-WinSecSmbFixtureReadings $s Features.InstallationState)[0].Value -ceq $expected -and
        ($s.Collection.Status -ceq 'COMPLETE') -eq ($code -le 3))
}}
foreach($id in @('Features','Services')){Test-SmbCandidate ('Missing or empty inventories never imply disabled SMB: '+$id) {
    $source=@($f.Sources|Where-Object SourceId -CEQ $id)[0];$source.Data=@();$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ($s.Collection.Status -ceq 'PARTIAL' -and -not (Get-SmbCandidateSummary $s $id).Complete -and
        (Get-SmbCandidateSummary $s $id).ReportedRecords -eq 0 -and (Get-WinSecSmbFixtureReadings $s ('Capture.'+$id+'SourceState'))[0].Value -ceq 'OBSERVED')
}}
Test-SmbCandidate 'Stopped Manual and Disabled services are observed context rather than security findings' {
    $f.Sources[4].Data[0].StartMode='Disabled';$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-WinSecSmbFixtureReadings $s Services.State)[0].Value -ceq 'Stopped' -and
        (Get-WinSecSmbFixtureReadings $s Services.StartMode)[0].Value -ceq 'Disabled' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'FAIL|Finding')
}
Test-SmbCandidate 'Modern security compression and native cipher order remain technical context' {
    $f.Sources[1].Data.EncryptionCiphers='AES_256_GCM,AES_128_CCM,AES_256_GCM,AES_128_GCM,AES_256_CCM';$f.Sources[2].Data.BlockNTLM=$true
    $f.Sources[2].Data.Smb2DialectMin=[uint32]999;$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ((Get-WinSecSmbFixtureReadings $s Server.EncryptionCiphers)[0].Value -ceq $f.Sources[1].Data.EncryptionCiphers -and
        (Get-WinSecSmbFixtureReadings $s Client.BlockNTLM)[0].Value -ceq $true -and (Get-WinSecSmbFixtureReadings $s Client.Smb2DialectMin)[0].Value -ceq '999')
}
Test-SmbCandidate 'Only explicitly absent registry values become not configured without effective defaults' {
    foreach($name in @('ServerSMB1','ClientDependencies')){$f.Sources[5].Data.$name=[pscustomobject]@{State='NOT_CONFIGURED';Kind=$null;Value=$null}}
    $s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ($s.Collection.Status -ceq 'COMPLETE' -and (Get-WinSecSmbFixtureReadings $s Registry.ServerSMB1)[0].State -ceq 'NOT_CONFIGURED' -and
        (Get-WinSecSmbFixtureReadings $s Registry.ClientDependenciesReportedCount)[0].State -ceq 'NOT_CONFIGURED')
}
Test-SmbCandidate 'Signed Registry64 DWORD bit patterns survive without extending normal numeric coercion' {
    $f.Sources[5].Data.ServerSMB1.Value=[int]-1;$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ((Get-WinSecSmbFixtureReadings $s Registry.ServerSMB1)[0].Value -eq [uint32]::MaxValue -and
        -not (ConvertTo-WinSecSmbCandidateValue ([int]-1) UInt32).Valid -and -not (ConvertTo-WinSecSmbCandidateValue $true RegistryDWord).Valid)
}
Test-SmbCandidate 'Dependency names ordering duplicates and a known empty list remain exact' {
    $f.Sources[5].Data.ClientDependencies.Value=[string[]]@('MRxSMB20','NSI','MRxSMB20');$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate (((Get-WinSecSmbFixtureReadings $s Registry.ClientDependencies)[0].Value -join '|') -ceq 'MRxSMB20|NSI|MRxSMB20' -and
        (Get-WinSecSmbFixtureReadings $s Registry.ClientDependenciesReportedCount)[0].Value -eq 3)
    $f.Sources[5].Data.ClientDependencies.Value=[string[]]@();$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ((Get-WinSecSmbFixtureReadings $s Registry.ClientDependencies)[0].State -ceq 'OBSERVED' -and
        (Get-WinSecSmbFixtureReadings $s Registry.ClientDependenciesReportedCount)[0].Value -eq 0)
}
Test-SmbCandidate 'Dependencies above both old count cutoffs retain every permitted entry within bytes' {
    $f.Sources[5].Data.ClientDependencies.Value=@('NSI')*10001;$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ((Get-WinSecSmbFixtureReadings $s Registry.ClientDependencies)[0].Value.Count -eq 10001 -and
        (Get-WinSecSmbFixtureReadings $s Registry.ClientDependenciesReportedCount)[0].Value -eq 10001 -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-SmbCandidate 'Oversized dependencies retain total count and withhold the whole field explicitly' {
    $f.Sources[5].Data.ClientDependencies.Value=@('MRxSMB10')*50000;$s=(New-WinSecSmbFixturePackage $f).Snapshot
    $r=(Get-WinSecSmbFixtureReadings $s Registry.ClientDependencies)[0]
    Assert-SmbCandidate ($r.State -ceq 'NOT_COLLECTED' -and $r.Reason -ceq 'RESOURCE_LIMIT' -and
        (Get-WinSecSmbFixtureReadings $s Registry.ClientDependenciesReportedCount)[0].Value -eq 50000 -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-SmbCandidate 'Duplicate provider rows above one batch are preserved and cannot claim complete identities' {
    $f.Sources[4].Data=@($f.Sources[4].Data[0])*129;$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ((Get-SmbCandidateSummary $s Services).RetainedRecords -eq 129 -and
        (Get-SmbCandidateSummary $s Services).Reason -ceq 'INVALID_VALUE' -and @($s.Batches|Where-Object InventoryId -CEQ Services).Count -eq 2 -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-SmbCandidate 'Exhausted payload budget reports supplied records without pretending full retention' {
    function Get-WinSecSmbCandidatePayloadBudget {return 0}
    $s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ((Get-SmbCandidateSummary $s Features).ReportedRecords -eq 4 -and (Get-SmbCandidateSummary $s Features).RetainedRecords -eq 0 -and
        (Get-SmbCandidateSummary $s Features).Reason -ceq 'RESOURCE_LIMIT' -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-SmbCandidate 'Optional unknowns limit coverage while required unknowns keep collection partial' {
    $f.Sources[2].Data.RequestCompression=$null;$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED')
    $f.Sources[1].Data.EnableSMB1Protocol=$null;$s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecSmbFixtureReadings $s Server.EnableSMB1Protocol)[0].State -ceq 'UNKNOWN')
}
Test-SmbCandidate 'Missing modern fields are never excluded using an older selected profile' {
    foreach($build in @(22000,22621,22631,26100,26200,28000)){
        $f.Sources[0].Data.BuildNumber=[string]$build;$f.Sources[0].Data.Version='10.0.'+$build;$f.Sources[0].Data.OperatingSystemSKU=[uint32]101
        $f.Sources[1].Data.AuditClientDoesNotSupportSigning=$null;$s=(New-WinSecSmbFixturePackage $f).Snapshot
        Assert-SmbCandidate ((Get-WinSecSmbFixtureReadings $s Server.AuditClientDoesNotSupportSigning)[0].State -ceq 'UNKNOWN' -and
            $s.Collection.Coverage -ceq 'LIMITED' -and $null -eq $s.Platform.Edition -and $s.Platform.BuildNumber -eq $build)
    }
}
Test-SmbCandidate 'Local or ambiguous feature dates remain unknown rather than fabricated UTC' {
    $f.Sources[3].Data[0].InstallDate=[datetime]::SpecifyKind([datetime]'2026-10-28',[DateTimeKind]::Unspecified)
    $s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ((Get-WinSecSmbFixtureReadings $s Features.InstallDate)[0].State -ceq 'UNKNOWN' -and $s.Collection.Coverage -ceq 'LIMITED')
}
foreach($state in @('ERROR','NOT_COLLECTED')){Test-SmbCandidate ('Unavailable sources preserve metadata without apparent readings: '+$state) {
    $f.Sources[1].State=$state;$f.Sources[1].Data=$null;$f.Sources[3].State=$state;$f.Sources[3].Data=$null
    $s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecSmbFixtureReadings $s Server.EnableSMB1Protocol)[0].State -ceq $state -and
        (Get-SmbCandidateSummary $s Features).RetainedRecords -eq 0 -and (Get-WinSecSmbFixtureReadings $s Capture.FeaturesSourceState)[0].Value -ceq $state)
}}
foreach($damage in @('bool','number','cipher','dependency','registry-kind','registry-null')){Test-SmbCandidate ('Invalid field types never become security defaults: '+$damage) {
    switch($damage){bool {$f.Sources[1].Data.EnableSMB1Protocol=0};number {$f.Sources[1].Data.AsynchronousCredits='0'}
        cipher {$f.Sources[2].Data.EncryptionCiphers='PRIVATE-SECRET'};dependency {$f.Sources[5].Data.ClientDependencies.Value=@('NSI','C:\PRIVATE-SECRET')}
        registry-kind {$f.Sources[5].Data.ServerSMB1.Kind='String'};registry-null {$f.Sources[5].Data.ServerSMB1=$null}}
    $s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ($s.Collection.Coverage -ceq 'LIMITED' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET')
}}
foreach($damage in @('owner','scan','location','remote','time','duplicate','scope','control','raw-error','platform','version','service','feature','registry-absence')){Test-SmbCandidate ('Foreign or contradictory captured data is rejected: '+$damage) {
    switch($damage){owner {$f.Sources[0].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[0].ScanId='other'}
        location {$f.Sources[5].Location='LOCAL'};remote {$f.Sources[1]|Add-Member NoteProperty CimSession 'remote'}
        time {$f.Sources[2].CollectedAtUTC='2026-10-30T01:02:04.0000000Z'};duplicate {$f.Sources[2].SourceId='Server'}
        scope {$f.Identity.ScopeKey='WSA-NET-001'};control {$f.Identity.CheckId='WSA-NET-001';$f.Identity.ScopeKey='WSA-NET-001'}
        raw-error {$f.Sources[1].State='ERROR'};platform {$f.Sources[0].Data.ProductType=[uint32]3};version {$f.Sources[0].Data.Version='10.0.22631'}
        service {$f.Sources[4].Data[0].Name='UnreviewedService'};feature {$f.Sources[3].Data[0].Name='UnreviewedFeature'}
        registry-absence {$f.Sources[5].Data.ServerSMB1.State='NOT_CONFIGURED'}
    };Reject-SmbCandidate {New-WinSecSmbFixturePackage $f}
}}
Test-SmbCandidate 'Private fields and script getters are neither invoked nor persisted' {
    $script:getters=0;$f.Sources[1].Data|Add-Member ScriptProperty EnableSMB1Protocol {$script:getters++;'PRIVATE-SECRET'} -Force
    $f.Sources[1].Data|Add-Member ScriptProperty AnnounceComment {$script:getters++;'PRIVATE-SECRET'}
    $f.Sources[4].Data[0]|Add-Member NoteProperty PathName 'C:\PRIVATE-SECRET';$f.Sources[1].Data|Add-Member NoteProperty NullSessionShares 'PRIVATE-SECRET'
    $s=(New-WinSecSmbFixturePackage $f).Snapshot
    Assert-SmbCandidate ($script:getters -eq 0 -and $s.Collection.Status -ceq 'PARTIAL' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|AnnounceComment|PathName|NullSessionShares')
}
Test-SmbCandidate 'Progress counts retained records and cancellation preserves the prepared capture' {
    $before=ConvertTo-Json $f -Depth 10 -Compress;$script:rows=0;$cancelled=$false
    try{$null=New-WinSecSmbFixturePackage $f -ProgressCallback {param($e);if($e.InventoryId -ceq 'Features'){$script:rows=$e.RetainedRecords}} -CancellationAction {$script:rows -ge 2}}
    catch [OperationCanceledException]{$cancelled=$true}
    Assert-SmbCandidate ($cancelled -and $script:rows -eq 2 -and (ConvertTo-Json $f -Depth 10 -Compress) -ceq $before)
}
foreach($damage in @('location','time','scope','collector','feature-state','dependency-count')){Test-SmbCandidate ('Semantic validation rejects forged snapshots: '+$damage) {
    $s=(New-WinSecSmbFixturePackage $f).Snapshot
    switch($damage){location {(Get-WinSecSmbFixtureReadings $s Capture.RegistryLocation)[0].Value='LOCAL'}
        time {(Get-WinSecSmbFixtureReadings $s Capture.ServerTime)[0].Value='2026-10-30T01:02:04.0000000Z'}
        scope {(Get-WinSecSmbFixtureReadings $s Capture.Scope)[0].Value='OTHER'};collector {$s.CollectorVersion='9.0.0'}
        feature-state {(Get-WinSecSmbFixtureReadings $s Features.InstallationState)[0].Value='ENABLED'}
        dependency-count {(Get-WinSecSmbFixtureReadings $s Registry.ClientDependenciesReportedCount)[0].Value=[uint32]999}
    };Reject-SmbCandidate {Assert-WinSecSmbCandidateSnapshot $s $f.Identity}
}}
Test-SmbCandidate 'A forged CIM absence fails even when shared counts and completion are consistent' {
    $s=(New-WinSecSmbFixturePackage $f).Snapshot;$r=(Get-WinSecSmbFixtureReadings $s Client.RequestCompression)[0]
    $r.State='NOT_CONFIGURED';$r.Reason='ABSENT';$r.Value=$null;$s.Collection.Observed--;$s.Collection.NotConfigured++
    Assert-WinSecTechnicalSnapshot $s (Get-WinSecSmbCandidateCatalog) $s.CatalogSha256 $f.Identity
    Reject-SmbCandidate {Assert-WinSecSmbCandidateSnapshot $s $f.Identity}
}
Test-SmbCandidate 'A failed dependency source cannot acquire an observed count after serialization' {
    $f.Sources[5].Data.ClientDependencies=[pscustomobject]@{State='ERROR';Kind=$null;Value=$null};$s=(New-WinSecSmbFixturePackage $f).Snapshot
    $r=(Get-WinSecSmbFixtureReadings $s Registry.ClientDependenciesReportedCount)[0];$r.State='OBSERVED';$r.Reason='NONE';$r.Value=[uint32]0
    $s.Collection.Errors--;$s.Collection.Observed++
    Assert-WinSecTechnicalSnapshot $s (Get-WinSecSmbCandidateCatalog) $s.CatalogSha256 $f.Identity
    Reject-SmbCandidate {Assert-WinSecSmbCandidateSnapshot $s $f.Identity}
}
Write-Host ("SMB technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
