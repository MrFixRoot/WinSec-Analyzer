# Isolated candidate I/O. No production session registration or native collection.
. (Join-Path $PSScriptRoot 'WindowsUpdateTechnicalSnapshot.ps1')
. (Join-Path $PSScriptRoot '../../Services/TechnicalSnapshotStore.ps1')

function Write-WinSecWindowsUpdateTechnicalPair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Package,
        [Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    Assert-WinSecSnapshotFields $Package @('Snapshot','Catalog','CatalogSha256','Identity')
    $catalog=Get-WinSecWindowsUpdateTechnicalCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    if($Package.CatalogSha256 -cne $hash -or (Get-WinSecSnapshotCatalogHash $Package.Catalog) -cne $hash){throw 'Unreviewed Windows Update candidate catalog.'}
    Assert-WinSecSnapshotIdentity $Package.Identity
    foreach($p in $ExpectedIdentity.PSObject.Properties){if($Package.Identity.($p.Name) -cne $p.Value){throw 'Foreign Windows Update package identity.'}}
    Assert-WinSecWindowsUpdateTechnicalSnapshot $Package.Snapshot $ExpectedIdentity -CancellationAction $CancellationAction
    Write-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -Snapshot $Package.Snapshot -Catalog $catalog -CatalogSha256 $hash -ExpectedIdentity $ExpectedIdentity `
        -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Read-WinSecWindowsUpdateTechnicalPair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$ExpectedIdentity,
        [Parameter(Mandatory)][string]$CollectedAtUTC,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    if($ExpectedIdentity.CheckId -cne 'WSA-SYS-003'){throw 'Foreign Windows Update candidate control.'}
    $catalog=Get-WinSecWindowsUpdateTechnicalCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    $result=Read-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -ExpectedIdentity $ExpectedIdentity -CollectedAtUTC $CollectedAtUTC `
        -Catalog $catalog -CatalogSha256 $hash -CancellationAction $CancellationAction
    if($result.PublicationStatus -ceq 'COMMITTED'){Assert-WinSecWindowsUpdateTechnicalSnapshot $result.Snapshot $ExpectedIdentity -CancellationAction $CancellationAction}
    return $result
}
