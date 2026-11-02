[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceEmitter.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$base=New-WinSecTechnicalSourceFixture
function Assert-Emission {param([bool]$Value);if(-not $Value){throw 'Source emission assertion failed.'}}
function Reject-Emission {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-Emission $caught}
function Test-Emission {
    param([string]$Case,[scriptblock]$Action)
    $p=Copy-WinSecResultData $base.Package;$owner=$base.Identity.PSObject.Copy()
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
foreach($collector in @('1.0.0','1.1.0','1.2.0','1.3.0')){Test-Emission ('Prepared historical collector produces an original-version stamp: '+$collector) {
    $f=New-WinSecTechnicalSourceFixture -CatalogVersion 1.0.0 -CollectorVersion $collector
    $stamp=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
    $r=Resolve-WinSecTechnicalSourceVersion $stamp.Reference $f.Identity
    Assert-Emission ($r.SnapshotSchemaVersion -ceq '2.0.0' -and $r.CatalogVersion -ceq '1.0.0' -and $r.CollectorVersion -ceq $collector -and $stamp.SnapshotSha256 -cmatch '\A[A-F0-9]{64}\z')
}}
Test-Emission 'Prepared CIM preference catalog 1.1 retains partial coverage without a publication claim' {
    $stamp=Get-WinSecTechnicalSourcePackageStamp $p $owner
    Assert-Emission ($stamp.Reference.CatalogVersion -ceq '1.1.0' -and $stamp.Reference.CollectorVersion -ceq '1.3.0' -and
        $p.Snapshot.Collection.Status -ceq 'PARTIAL' -and $null -eq $stamp.PSObject.Properties['PublicationStatus'])
}
Test-Emission 'Reviewed projection uses its distinct snapshot, catalog schema and collector versions' {
    $f=New-WinSecTechnicalSourceFixture -Family PROJECTION;$stamp=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
    $r=Resolve-WinSecTechnicalSourceVersion $stamp.Reference $f.Identity
    Assert-Emission ($r.Family -ceq 'REVIEWED_PROJECTION' -and $r.SnapshotSchemaVersion -ceq '2.1.0' -and $r.CatalogSchemaVersion -ceq '1.1.0' -and $r.CollectorVersion -ceq '0.9.0')
}
foreach($damage in @('Extra','Missing','ForeignPackageIdentity','ForeignSnapshotIdentity','CatalogHash','CatalogContent','Schema','CatalogVersion','Collector','UnsafeValue','Inventory','Collection')){
    Test-Emission ('Invalid package rejects before emission: '+$damage) {
        switch($damage){Extra {$p|Add-Member Evidence 'PRIVATE-EMISSION-SECRET'};Missing {$p.PSObject.Properties.Remove('Identity')}
            ForeignPackageIdentity {$p.Identity.ScanId='foreign'};ForeignSnapshotIdentity {$p.Snapshot.Identity.SnapshotId='c'*32}
            CatalogHash {$p.CatalogSha256='A'*64};CatalogContent {$p.Catalog.Sources[0].ReferenceUrl='https://example.com/unreviewed'}
            Schema {$p.Snapshot.SchemaVersion='2.1.0'};CatalogVersion {$p.Snapshot.CatalogVersion='99.0.0'};Collector {$p.Snapshot.CollectorVersion='1.2.0'}
            UnsafeValue {$p.Snapshot.Batches[0].Records[0].Readings[0].Value='PRIVATE-EMISSION-SECRET'}
            Inventory {$p.Snapshot.Inventories[0].RetainedRecords=999};Collection {$p.Snapshot.Collection.Status='COMPLETE'}}
        Reject-Emission {Get-WinSecTechnicalSourcePackageStamp $p $owner}
    }
}
foreach($property in @('Snapshot','Catalog','CatalogSha256','Identity')){Test-Emission ('Package getters never execute: '+$property) {
    $script:executed=0;$p|Add-Member -MemberType ScriptProperty -Name $property -Value {$script:executed++;throw 'PRIVATE-EMISSION-SECRET'} -Force
    Reject-Emission {Get-WinSecTechnicalSourcePackageStamp $p $owner};Assert-Emission ($script:executed -eq 0)
}}
foreach($property in @('SchemaVersion','CollectorVersion','CatalogSha256','Batches')){Test-Emission ('Snapshot getters never execute: '+$property) {
    $script:executed=0;$p.Snapshot|Add-Member -MemberType ScriptProperty -Name $property -Value {$script:executed++;throw 'PRIVATE-EMISSION-SECRET'} -Force
    Reject-Emission {Get-WinSecTechnicalSourcePackageStamp $p $owner};Assert-Emission ($script:executed -eq 0)
}}
Test-Emission 'Nested reading getters reject without exposing their values' {
    $script:executed=0;$p.Snapshot.Batches[0].Records[0].Readings[0]|Add-Member -MemberType ScriptProperty -Name Value -Value {$script:executed++;throw 'PRIVATE-EMISSION-SECRET'} -Force
    Reject-Emission {Get-WinSecTechnicalSourcePackageStamp $p $owner};Assert-Emission ($script:executed -eq 0)
}
foreach($property in @('SchemaVersion','CatalogVersion','CollectorVersion','CollectedAtUTC')){Test-Emission ('Version or timestamp arrays do not coerce into a reference: '+$property) {
    $p.Snapshot.$property=@($p.Snapshot.$property);Reject-Emission {Get-WinSecTechnicalSourcePackageStamp $p $owner}
}}
Test-Emission 'Artifact private fields cannot be included in a validated stamp' {
    $p.Snapshot|Add-Member RawExclusions @('PRIVATE-EMISSION-SECRET');Reject-Emission {Get-WinSecTechnicalSourcePackageStamp $p $owner}
}
Test-Emission 'Canonical property ordering keeps values equal without reordering inventory arrays' {
    $stamp=Get-WinSecTechnicalSourcePackageStamp $p $owner;$reversed=[ordered]@{}
    foreach($property in @($p.Snapshot.PSObject.Properties|Sort-Object Name -Descending)){$reversed[$property.Name]=$property.Value}
    $p.Snapshot=[pscustomobject]$reversed;$other=Get-WinSecTechnicalSourcePackageStamp $p $owner
    Assert-Emission ($stamp.SnapshotSha256 -ceq $other.SnapshotSha256)
}
Test-Emission 'A changed valid reading changes the full snapshot stamp but keeps its version metadata' {
    $before=Get-WinSecTechnicalSourcePackageStamp $p $owner
    $r=@($p.Snapshot.Batches|Where-Object InventoryId -CEQ Preferences)[0].Records[0].Readings[0];$r.Value=-not $r.Value
    $after=Get-WinSecTechnicalSourcePackageStamp $p $owner
    Assert-Emission ($before.SnapshotSha256 -cne $after.SnapshotSha256 -and
        (ConvertTo-Json $before.Reference -Depth 8 -Compress) -ceq (ConvertTo-Json $after.Reference -Depth 8 -Compress))
}
Test-Emission 'Stamp references detach identity and scalar metadata from their package' {
    $stamp=Get-WinSecTechnicalSourcePackageStamp $p $owner;$p.Identity.ScanId='mutated';$p.Snapshot.Identity.ScanId='mutated';$p.Snapshot.CatalogVersion='99.0.0'
    Assert-Emission ($stamp.Reference.Identity.ScanId -ceq $base.Identity.ScanId -and $stamp.Reference.CatalogVersion -ceq '1.1.0')
}
Test-Emission 'A valid prepared package alone cannot issue a reference to a nonexistent pair' {
    Reject-Emission {New-WinSecTechnicalSourceReference 'Z:\nonexistent-emission-fixture' $p $owner}
}
Test-Emission 'Cancellation before validation or non-Boolean responses issue no reference' {
    $cancelled=$false;try{New-WinSecTechnicalSourceReference 'Z:\nonexistent-emission-fixture' $p $owner -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Assert-Emission $cancelled
    Reject-Emission {New-WinSecTechnicalSourceReference 'Z:\nonexistent-emission-fixture' $p $owner -CancellationAction {'yes'}}
}
Test-Emission 'Other controls do not acquire emission support through this pilot' {
    $owner.CheckId='WSA-SYS-002';$owner.ScopeKey='WSA-SYS-002';Reject-Emission {Get-WinSecTechnicalSourcePackageStamp $p $owner}
}
Write-Host ("Technical source emission: $passed passed; $failed failed.");if($failed){exit 1}
