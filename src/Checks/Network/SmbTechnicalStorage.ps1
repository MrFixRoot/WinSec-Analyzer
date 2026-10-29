# Explicit candidate pair I/O only. No production imports, index registration or SMB queries.
. (Join-Path $PSScriptRoot 'SmbTechnicalSnapshot.ps1')
. (Join-Path $PSScriptRoot '../../Services/TechnicalSnapshotStore.ps1')

function Write-WinSecSmbCandidatePair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Package,
        [Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;Assert-WinSecSnapshotFields $Package @('Snapshot','Catalog','CatalogSha256','Identity')
    $catalog=Get-WinSecSmbCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    if($Package.CatalogSha256 -cne $hash -or (Get-WinSecSnapshotCatalogHash $Package.Catalog) -cne $hash){throw 'Unreviewed SMB candidate catalog.'}
    Assert-WinSecSnapshotIdentity $Package.Identity
    foreach($p in $ExpectedIdentity.PSObject.Properties){if($Package.Identity.($p.Name) -cne $p.Value){throw 'Foreign SMB package identity.'}}
    Assert-WinSecSmbCandidateSnapshot $Package.Snapshot $ExpectedIdentity -CancellationAction $CancellationAction
    Write-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -Snapshot $Package.Snapshot -Catalog $catalog -CatalogSha256 $hash -ExpectedIdentity $ExpectedIdentity `
        -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Read-WinSecSmbCandidatePair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$ExpectedIdentity,
        [Parameter(Mandatory)][string]$CollectedAtUTC,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-NET-002'){throw 'Foreign SMB candidate control.'}
    $catalog=Get-WinSecSmbCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    $result=Read-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -ExpectedIdentity $ExpectedIdentity -CollectedAtUTC $CollectedAtUTC `
        -Catalog $catalog -CatalogSha256 $hash -CancellationAction $CancellationAction
    if($result.PublicationStatus -ceq 'COMMITTED'){Assert-WinSecSmbCandidateSnapshot $result.Snapshot $ExpectedIdentity -CancellationAction $CancellationAction}
    return $result
}
