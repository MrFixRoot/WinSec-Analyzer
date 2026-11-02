# Explicit candidate pair I/O only. No production import, index, network or process query.
. (Join-Path $PSScriptRoot 'PasswordPolicyTechnicalSnapshot.ps1')
. (Join-Path $PSScriptRoot '../../Services/TechnicalSnapshotStore.ps1')

function Write-WinSecPasswordPolicyCandidatePair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Package,
        [Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;Assert-WinSecSnapshotFields $Package @('Snapshot','Catalog','CatalogSha256','Identity')
    $catalog=Get-WinSecPasswordPolicyCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    if($Package.CatalogSha256 -cne $hash -or (Get-WinSecSnapshotCatalogHash $Package.Catalog) -cne $hash){throw 'Unreviewed PasswordPolicy candidate catalog.'}
    Assert-WinSecSnapshotIdentity $Package.Identity
    foreach($p in $ExpectedIdentity.PSObject.Properties){if($Package.Identity.($p.Name) -cne $p.Value){throw 'Foreign PasswordPolicy package identity.'}}
    Assert-WinSecPasswordPolicyCandidateSnapshot $Package.Snapshot $ExpectedIdentity -CancellationAction $CancellationAction
    Write-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -Snapshot $Package.Snapshot -Catalog $catalog -CatalogSha256 $hash -ExpectedIdentity $ExpectedIdentity `
        -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Read-WinSecPasswordPolicyCandidatePair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$ExpectedIdentity,
        [Parameter(Mandatory)][string]$CollectedAtUTC,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-IAM-003'){throw 'Foreign PasswordPolicy candidate control.'}
    $catalog=Get-WinSecPasswordPolicyCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    $r=Read-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -ExpectedIdentity $ExpectedIdentity -CollectedAtUTC $CollectedAtUTC -Catalog $catalog -CatalogSha256 $hash -CancellationAction $CancellationAction
    if($r.PublicationStatus -ceq 'COMMITTED'){Assert-WinSecPasswordPolicyCandidateSnapshot $r.Snapshot $ExpectedIdentity -CancellationAction $CancellationAction}
    return $r
}
