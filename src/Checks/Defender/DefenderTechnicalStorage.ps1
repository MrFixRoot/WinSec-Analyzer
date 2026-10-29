# Isolated candidate I/O. No import from production, session-index registration or activation.
. (Join-Path $PSScriptRoot 'DefenderTechnicalSnapshot.ps1')
. (Join-Path $PSScriptRoot '../../Services/TechnicalSnapshotStore.ps1')

function Write-WinSecDefenderTechnicalPair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Package,
        [Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    Assert-WinSecSnapshotFields $Package @('Snapshot','Catalog','CatalogSha256','Identity')
    $catalog=Get-WinSecDefenderTechnicalCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    if($Package.CatalogSha256 -cne $hash -or (Get-WinSecSnapshotCatalogHash $Package.Catalog) -cne $hash){throw 'Unreviewed Defender candidate catalog.'}
    Assert-WinSecSnapshotIdentity $Package.Identity
    foreach($property in $ExpectedIdentity.PSObject.Properties){if($Package.Identity.($property.Name) -cne $property.Value){throw 'Foreign Defender package identity.'}}
    Assert-WinSecDefenderTechnicalSnapshot $Package.Snapshot $ExpectedIdentity -CancellationAction $CancellationAction
    Write-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -Snapshot $Package.Snapshot -Catalog $catalog -CatalogSha256 $hash -ExpectedIdentity $ExpectedIdentity `
        -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Read-WinSecDefenderTechnicalPair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$ExpectedIdentity,
        [Parameter(Mandatory)][string]$CollectedAtUTC,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    if($ExpectedIdentity.CheckId -cne 'WSA-SYS-001'){throw 'Foreign Defender candidate control.'}
    $catalog=Get-WinSecDefenderTechnicalCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    $result=Read-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -ExpectedIdentity $ExpectedIdentity -CollectedAtUTC $CollectedAtUTC `
        -Catalog $catalog -CatalogSha256 $hash -CancellationAction $CancellationAction
    if($result.PublicationStatus -ceq 'COMMITTED'){Assert-WinSecDefenderTechnicalSnapshot $result.Snapshot $ExpectedIdentity -CancellationAction $CancellationAction}
    return $result
}
