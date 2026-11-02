[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceReader.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
function Get-CimInstance {throw 'Native provider forbidden.'}
function Get-CimClass {throw 'Native schema forbidden.'}
function Get-MpComputerStatus {throw 'Native Defender forbidden.'}
function Get-MpPreference {throw 'Native preferences forbidden.'}
function Start-Job {throw 'Acquisition forbidden.'}
$passed=0;$failed=0;$base=New-WinSecTechnicalSourceFixture
function Assert-SourceResolution {param([bool]$Value);if(-not $Value){throw 'Source resolution assertion failed.'}}
function Reject-SourceResolution {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SourceResolution $caught}
function Test-SourceResolution {
    param([string]$Case,[scriptblock]$Action)
    $ref=Copy-WinSecResultData $base.Reference;$owner=$base.Identity.PSObject.Copy()
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
foreach($collector in @('1.0.0','1.1.0','1.2.0','1.3.0')){
    Test-SourceResolution ('Historical candidate collector resolves without changing schema: '+$collector) {
        $ref.CatalogVersion='1.0.0';$ref.CatalogSha256=Get-WinSecSnapshotCatalogHash (Get-WinSecDefenderTechnicalCatalog);$ref.CollectorVersion=$collector
        $r=Resolve-WinSecTechnicalSourceVersion $ref $owner
        Assert-SourceResolution ($r.Family -ceq 'DEFENDER_CANDIDATE' -and $r.SnapshotSchemaVersion -ceq '2.0.0' -and $r.CollectorVersion -ceq $collector)
    }
}
Test-SourceResolution 'CIM preference catalog 1.1 binds only to candidate collector 1.3' {
    $r=Resolve-WinSecTechnicalSourceVersion $ref $owner
    Assert-SourceResolution ($r.CatalogVersion -ceq '1.1.0' -and $r.CollectorVersion -ceq '1.3.0' -and $r.ReferenceKind -ceq 'VERSIONED_1_0')
}
Test-SourceResolution 'Reviewed projection 2.1 has its own catalog schema and collector versions' {
    $f=New-WinSecTechnicalSourceFixture -Family PROJECTION;$r=Resolve-WinSecTechnicalSourceVersion $f.Reference $f.Identity
    Assert-SourceResolution ($r.Family -ceq 'REVIEWED_PROJECTION' -and $r.SnapshotSchemaVersion -ceq '2.1.0' -and $r.CatalogSchemaVersion -ceq '1.1.0' -and $r.CatalogVersion -ceq '1.0.0' -and $r.CollectorVersion -ceq '0.9.0')
}
Test-SourceResolution 'A historical three-field index reference retains its prescribed projection meaning' {
    $f=New-WinSecTechnicalSourceFixture -Family PROJECTION;$old=Get-WinSecLegacySourceFixtureReference $f
    $before=ConvertTo-Json $old -Depth 8 -Compress;$r=Resolve-WinSecTechnicalSourceVersion $old $f.Identity
    Assert-SourceResolution ($r.ReferenceKind -ceq 'TRANSITION_1_0' -and $r.Family -ceq 'REVIEWED_PROJECTION' -and (ConvertTo-Json $old -Depth 8 -Compress) -ceq $before)
}
foreach($field in @('ArtifactType','SchemaVersion','SnapshotSchemaVersion','CatalogId','CatalogSchemaVersion','CatalogVersion','CollectorVersion')){
    Test-SourceResolution ('Unknown version or artifact family rejects: '+$field) {$ref.$field='99.0.0';Reject-SourceResolution {Resolve-WinSecTechnicalSourceVersion $ref $owner}}
}
foreach($field in @('ArtifactType','SchemaVersion','SnapshotSchemaVersion','CatalogId','CatalogSchemaVersion','CatalogVersion','CollectorVersion','CollectedAtUTC','CatalogSha256')){
    Test-SourceResolution ('Version headers reject arrays before coercion: '+$field) {$ref.$field=@($ref.$field);Reject-SourceResolution {Resolve-WinSecTechnicalSourceVersion $ref $owner}}
    Test-SourceResolution ('Version headers reject getters without executing them: '+$field) {
        $script:executed=0;$ref|Add-Member -MemberType ScriptProperty -Name $field -Value {$script:executed++;throw 'PRIVATE-SOURCE-SECRET'} -Force
        Reject-SourceResolution {Resolve-WinSecTechnicalSourceVersion $ref $owner};Assert-SourceResolution ($script:executed -eq 0)
    }
}
foreach($collector in @('1.0.0','1.1.0','1.2.0')){Test-SourceResolution ('Known but incompatible collector with catalog 1.1 rejects: '+$collector) {
    $ref.CollectorVersion=$collector;Reject-SourceResolution {Resolve-WinSecTechnicalSourceVersion $ref $owner}
}}
foreach($damage in @('ProjectionSchema','ProjectionCatalog','ProjectionCatalogSchema','ProjectionCollector','CandidateCatalogSchema')){
    Test-SourceResolution ('Cross-family version combinations reject: '+$damage) {
        switch($damage){ProjectionSchema {$ref.SnapshotSchemaVersion='2.1.0'};ProjectionCatalog {$ref.CatalogId='WinSec.Reviewed.WSA-SYS-001'}
            ProjectionCatalogSchema {$ref.CatalogSchemaVersion='1.1.0'};ProjectionCollector {$ref.CollectorVersion='0.9.0'}
            CandidateCatalogSchema {$ref.CatalogSchemaVersion='2.0.0'}}
        Reject-SourceResolution {Resolve-WinSecTechnicalSourceVersion $ref $owner}
    }
}
foreach($damage in @('Extra','Missing','PlainHash','LowerHash','LocalDate','DateObject','OldExtra','OldWrongField')){
    Test-SourceResolution ('Malformed reference rejects: '+$damage) {
        switch($damage){Extra {$ref|Add-Member Path '../PRIVATE-SOURCE-SECRET'};Missing {$ref.PSObject.Properties.Remove('CatalogVersion')}
            PlainHash {$ref.CatalogSha256='not-a-digest'};LowerHash {$ref.CatalogSha256=$ref.CatalogSha256.ToLowerInvariant()}
            LocalDate {$ref.CollectedAtUTC='2026-11-01T00:00:00'};DateObject {$ref.CollectedAtUTC=[datetime]::UtcNow}
            OldExtra {$ref=Get-WinSecLegacySourceFixtureReference $base;$ref|Add-Member CollectorVersion '1.3.0'}
            OldWrongField {$ref=[pscustomobject]@{Identity=$owner;CollectedAtUTC=$ref.CollectedAtUTC;Path='untrusted'}}}
        Reject-SourceResolution {Resolve-WinSecTechnicalSourceVersion $ref $owner}
    }
}
foreach($binding in @('DeviceId','ScanId','SnapshotId','ScopeType')){
    Test-SourceResolution ('References must match the complete expected identity: '+$binding) {
        switch($binding){DeviceId {$ref.Identity.DeviceId='local:hw1-'+('c'*64)};ScanId {$ref.Identity.ScanId='foreign-scan'}
            SnapshotId {$ref.Identity.SnapshotId='d'*32};ScopeType {$ref.Identity.ScopeType='SECTION';$ref.Identity.ScopeKey='SystemSecurity'}}
        Reject-SourceResolution {Resolve-WinSecTechnicalSourceVersion $ref $owner}
    }
}
Test-SourceResolution 'Other controls are not implicitly connected by this pilot' {
    $owner.CheckId='WSA-SYS-002';$owner.ScopeKey='WSA-SYS-002';Reject-SourceResolution {Resolve-WinSecTechnicalSourceVersion $ref $owner}
}
Test-SourceResolution 'Resolution detaches its identity and scalar metadata from caller mutation' {
    $r=Resolve-WinSecTechnicalSourceVersion $ref $owner;$ref.Identity.ScanId='mutated';$ref.CollectorVersion='99.0.0';$owner.DeviceId='local:hw1-'+('c'*64)
    Assert-SourceResolution ($r.Identity.ScanId -ceq $base.Identity.ScanId -and $r.Identity.DeviceId -ceq $base.Identity.DeviceId -and $r.CollectorVersion -ceq '1.3.0')
}
Test-SourceResolution 'Invalid versions and catalog digests fail before any storage reader is invoked' {
    $ref.SnapshotSchemaVersion='99.0.0';$message=$null
    try{Read-WinSecVersionedTechnicalSource 'Z:\nonexistent-source-fixture' $ref $owner}catch{$message=$_.Exception.Message}
    Assert-SourceResolution ($message -ceq 'Unknown or incompatible technical source versions.')
    $ref.SnapshotSchemaVersion='2.0.0';$ref.CatalogSha256='A'*64;$message=$null
    try{Read-WinSecVersionedTechnicalSource 'Z:\nonexistent-source-fixture' $ref $owner}catch{$message=$_.Exception.Message}
    Assert-SourceResolution ($message -ceq 'Technical source catalog does not match the reviewed version.')
}
Test-SourceResolution 'Cancellation is checked before filesystem or candidate loading' {
    $cancelled=$false;try{Read-WinSecVersionedTechnicalSource 'Z:\nonexistent-source-fixture' $ref $owner -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Assert-SourceResolution $cancelled
    Reject-SourceResolution {Read-WinSecVersionedTechnicalSource 'Z:\nonexistent-source-fixture' $ref $owner -CancellationAction {'yes'}}
}
Write-Host ("Technical source resolution: $passed passed; $failed failed.");if($failed){exit 1}
