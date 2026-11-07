# Stage 3 pilot only. No publication, index mutation, collection or production import.
. (Join-Path $PSScriptRoot 'TechnicalSourceReader.ps1')

function Get-WinSecTechnicalSourcePackageStamp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Package,[Parameter(Mandatory)][object]$ExpectedIdentity)
    # Offline preparation, not proof that a corresponding pair has been committed.
    $clock=[Diagnostics.Stopwatch]::StartNew()
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    $null=Get-WinSecProductiveTechnicalSourceSpecification $ExpectedIdentity.CheckId
    $owner=$ExpectedIdentity.PSObject.Copy()
    Assert-WinSecSnapshotFields $Package @('Snapshot','Catalog','CatalogSha256','Identity')
    Assert-WinSecSnapshotIdentity $Package.Identity
    foreach($field in @('DeviceId','ScanId','SnapshotId','CheckId','SectionKey','ScopeType','ScopeKey')){
        if($Package.Identity.$field -cne $owner.$field){throw 'Foreign technical source package identity.'}
    }
    Assert-WinSecSnapshotCatalog $Package.Catalog
    Assert-WinSecSnapshotFields $Package.Snapshot @('ArtifactType','SchemaVersion','Identity','CatalogId','CatalogVersion','CatalogSha256',
        'CollectorVersion','StartedAtUTC','CollectedAtUTC','CompletedAtUTC','GeneratedAtUTC','Platform','SelectedProfile','Collection','Inventories','Batches')
    $s=$Package.Snapshot
    $reference=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceReference';SchemaVersion='1.0.0';Identity=$owner.PSObject.Copy();
        CollectedAtUTC=$s.CollectedAtUTC;SnapshotSchemaVersion=$s.SchemaVersion;CatalogId=$s.CatalogId;CatalogSchemaVersion=$Package.Catalog.SchemaVersion;
        CatalogVersion=$s.CatalogVersion;CatalogSha256=$s.CatalogSha256;CollectorVersion=$s.CollectorVersion}
    $resolved=Resolve-WinSecTechnicalSourceVersion $reference $owner
    if($resolved.Family -ceq 'DEFENDER_CANDIDATE'){
        . (Join-Path $PSScriptRoot '../Checks/Defender/DefenderTechnicalStorage.ps1')
        $catalog=Get-WinSecDefenderTechnicalCatalog -CatalogVersion $resolved.CatalogVersion
    }else{$catalog=Get-WinSecProjectionCatalog $owner.CheckId}
    $hash=Get-WinSecSnapshotCatalogHash $catalog
    if($Package.CatalogSha256 -isnot [string] -or $Package.CatalogSha256 -cne $hash -or
        (Get-WinSecSnapshotCatalogHash $Package.Catalog) -cne $hash -or $resolved.CatalogSha256 -cne $hash){throw 'Unreviewed technical source package catalog.'}
    if($resolved.Family -ceq 'DEFENDER_CANDIDATE'){Assert-WinSecDefenderTechnicalSnapshot $s $owner}
    else{Assert-WinSecTechnicalSnapshot $s $catalog $hash $owner;$null=ConvertFrom-WinSecProjectionSnapshot $s}
    Assert-WinSecSnapshotValidationBudget $clock $null
    # Freeze the full validated value before any caller callback or disk access.
    # Canonical property ordering preserves array order and avoids representation-only mismatches.
    $bytes=[Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $s))
    if($bytes.Length -gt (Get-WinSecSnapshotSpecification).MaxDocumentBytes){throw 'Technical source package exceeds its byte budget.'}
    $snapshotHash=Get-WinSecSnapshotByteHash $bytes
    Assert-WinSecSnapshotValidationBudget $clock $null
    [pscustomobject]@{Reference=$reference;SnapshotSha256=$snapshotHash}
}

function New-WinSecTechnicalSourceReference {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Package,
        [Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    $owner=$ExpectedIdentity.PSObject.Copy();$clock=[Diagnostics.Stopwatch]::StartNew()
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    # Validation/freezing deliberately has no caller callbacks between checking and copying values.
    $stamp=Get-WinSecTechnicalSourcePackageStamp $Package $owner
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    $held=$null;$streams=New-Object 'Collections.Generic.List[object]'
    try{
        $layout=Get-WinSecSnapshotPairLayout $ProjectRoot $owner $stamp.Reference.CollectedAtUTC
        $held=Open-WinSecSnapshotDirectories $ProjectRoot $layout
        # Existing secure relative opens deny writes/deletion and reject links; never create a lock file.
        foreach($name in @('Intent','Commit','Json','Markdown')){
            $streams.Add([WinSec.SnapshotIO3]::Read($layout.$name))
        }
        $saved=Read-WinSecVersionedTechnicalSource -ProjectRoot $ProjectRoot -Reference $stamp.Reference -ExpectedIdentity $owner -CancellationAction $CancellationAction
        $bytes=[Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $saved.Snapshot))
        if($bytes.Length -gt (Get-WinSecSnapshotSpecification).MaxDocumentBytes -or (Get-WinSecSnapshotByteHash $bytes) -cne $stamp.SnapshotSha256){
            throw 'Validated package differs from its committed technical source.'
        }
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        return $stamp.Reference
    }catch{
        if($_.Exception -is [OperationCanceledException]){throw}
        throw 'Cannot emit a reference from an unsafe or inconsistent technical pair.'
    }finally{
        foreach($stream in $streams){$stream.Dispose()}
        if($held){foreach($handle in $held){$handle.Dispose()}}
    }
}
