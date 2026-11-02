# Explicit candidate pair I/O only. No production import, index, network or process query.
. (Join-Path $PSScriptRoot 'AuditPolicyTechnicalSnapshot.ps1')
. (Join-Path $PSScriptRoot '../../Services/TechnicalSnapshotStore.ps1')

function Write-WinSecAuditPolicyCandidatePair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Package,
        [Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;Assert-WinSecSnapshotFields $Package @('Snapshot','Catalog','CatalogSha256','Identity')
    $catalog=Get-WinSecAuditPolicyCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    if($Package.CatalogSha256 -cne $hash -or (Get-WinSecSnapshotCatalogHash $Package.Catalog) -cne $hash){throw 'Unreviewed AuditPolicy candidate catalog.'}
    Assert-WinSecSnapshotIdentity $Package.Identity
    foreach($p in $ExpectedIdentity.PSObject.Properties){if($Package.Identity.($p.Name) -cne $p.Value){throw 'Foreign AuditPolicy package identity.'}}
    Assert-WinSecAuditPolicyCandidateSnapshot $Package.Snapshot $ExpectedIdentity -CancellationAction $CancellationAction
    Write-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -Snapshot $Package.Snapshot -Catalog $catalog -CatalogSha256 $hash -ExpectedIdentity $ExpectedIdentity `
        -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Read-WinSecAuditPolicyCandidatePair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$ExpectedIdentity,
        [Parameter(Mandatory)][string]$CollectedAtUTC,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-LOG-002'){throw 'Foreign AuditPolicy candidate control.'}
    $catalog=Get-WinSecAuditPolicyCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    $r=Read-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -ExpectedIdentity $ExpectedIdentity -CollectedAtUTC $CollectedAtUTC -Catalog $catalog -CatalogSha256 $hash -CancellationAction $CancellationAction
    if($r.PublicationStatus -ceq 'COMMITTED'){Assert-WinSecAuditPolicyCandidateSnapshot $r.Snapshot $ExpectedIdentity -CancellationAction $CancellationAction}
    return $r
}
