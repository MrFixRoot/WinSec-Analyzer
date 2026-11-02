# Isolated stage 3 source reader. Not imported by production, restoration, F or P.
. (Join-Path $PSScriptRoot '../Core/TechnicalSourceResolution.ps1')
. (Join-Path $PSScriptRoot '../Core/TargetRegistry.ps1')
. (Join-Path $PSScriptRoot '../Core/ResultModel.ps1')
. (Join-Path $PSScriptRoot '../Core/TechnicalReportModel.ps1')
. (Join-Path $PSScriptRoot 'PublicHistoryService.ps1')
. (Join-Path $PSScriptRoot 'TechnicalMarkdownService.ps1')
. (Join-Path $PSScriptRoot 'TechnicalSnapshotStore.ps1')

function Read-WinSecVersionedTechnicalSource {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Reference,
        [Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    $resolution=Resolve-WinSecTechnicalSourceVersion $Reference $ExpectedIdentity
    $clock=[Diagnostics.Stopwatch]::StartNew()
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    if($resolution.Family -ceq 'DEFENDER_CANDIDATE'){
        # Closed local adapter; never use a path, script or command provided by the reference.
        . (Join-Path $PSScriptRoot '../Checks/Defender/DefenderTechnicalStorage.ps1')
        $catalog=Get-WinSecDefenderTechnicalCatalog -CatalogVersion $resolution.CatalogVersion
    }else{$catalog=Get-WinSecProjectionCatalog $resolution.Identity.CheckId}
    $hash=Get-WinSecSnapshotCatalogHash $catalog
    if($catalog.CatalogId -cne $resolution.CatalogId -or $catalog.SchemaVersion -cne $resolution.CatalogSchemaVersion -or
        $catalog.CatalogVersion -cne $resolution.CatalogVersion -or $hash -cne $resolution.CatalogSha256){throw 'Technical source catalog does not match the reviewed version.'}
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    if($resolution.Family -ceq 'DEFENDER_CANDIDATE'){
        $pair=Read-WinSecDefenderTechnicalPair -ProjectRoot $ProjectRoot -ExpectedIdentity $resolution.Identity `
            -CollectedAtUTC $resolution.CollectedAtUTC -CatalogVersion $resolution.CatalogVersion -CancellationAction $CancellationAction
    }else{
        $pair=Read-WinSecTechnicalSnapshotPair -ProjectRoot $ProjectRoot -ExpectedIdentity $resolution.Identity `
            -CollectedAtUTC $resolution.CollectedAtUTC -Catalog $catalog -CatalogSha256 $hash -CancellationAction $CancellationAction
    }
    if($pair.PublicationStatus -cne 'COMMITTED' -or $null -eq $pair.Snapshot){throw 'Technical source requires a committed pair; recovery is separate.'}
    $snapshot=$pair.Snapshot
    foreach($field in @('CatalogId','CatalogVersion','CatalogSha256','CollectorVersion','CollectedAtUTC')){
        if($snapshot.$field -cne $resolution.$field){throw 'Stored technical source contradicts its reference.'}
    }
    if($snapshot.SchemaVersion -cne $resolution.SnapshotSchemaVersion){throw 'Stored technical source schema contradicts its reference.'}
    if($resolution.Family -ceq 'REVIEWED_PROJECTION'){
        # Reuse the historical semantic validator. Its report is not substituted for the snapshot.
        $null=ConvertFrom-WinSecProjectionSnapshot $snapshot
    }
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    [pscustomobject]@{ArtifactType='WinSec.ResolvedTechnicalSource';SchemaVersion='1.0.0';Resolution=$resolution;
        PublicationStatus=$pair.PublicationStatus;Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;
        JsonPath=$pair.JsonPath;MarkdownPath=$pair.MarkdownPath}
}
