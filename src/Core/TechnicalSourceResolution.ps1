# Stage 3 preparation only: explicit metadata, no files, collectors, index mutation or activation.
. (Join-Path $PSScriptRoot 'TechnicalSnapshotContract.ps1')

function Resolve-WinSecTechnicalSourceVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Reference,[Parameter(Mandatory)][object]$ExpectedIdentity)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    if($ExpectedIdentity.CheckId -cne 'WSA-SYS-001'){throw 'Technical source pilot supports Defender only.'}
    # The historical stored-session reference has exactly three fields and means reviewed projection.
    # It is never used to discover or guess a candidate catalog from files or a hash.
    $legacy=($null -ne $Reference -and $Reference.GetType() -eq [Management.Automation.PSCustomObject] -and @($Reference.PSObject.Properties).Count -eq 3)
    if($legacy){
        Assert-WinSecSnapshotFields $Reference @('Identity','CollectedAtUTC','CatalogSha256')
    }else{
        Assert-WinSecSnapshotFields $Reference @('ArtifactType','SchemaVersion','Identity','CollectedAtUTC','SnapshotSchemaVersion','CatalogId','CatalogSchemaVersion','CatalogVersion','CatalogSha256','CollectorVersion')
        foreach($field in @('ArtifactType','SchemaVersion','SnapshotSchemaVersion','CatalogId','CatalogSchemaVersion','CatalogVersion','CollectorVersion')){
            if($Reference.$field -isnot [string]){throw 'Invalid technical source version type.'}
        }
        if($Reference.ArtifactType -cne 'WinSec.TechnicalSourceReference' -or $Reference.SchemaVersion -cne '1.0.0'){throw 'Unknown technical source reference format.'}
    }
    Assert-WinSecSnapshotIdentity $Reference.Identity
    foreach($field in @('DeviceId','ScanId','SnapshotId','CheckId','SectionKey','ScopeType','ScopeKey')){
        if($Reference.Identity.$field -cne $ExpectedIdentity.$field){throw 'Foreign technical source reference identity.'}
    }
    if($Reference.CollectedAtUTC -isnot [string] -or $Reference.CatalogSha256 -isnot [string] -or $Reference.CatalogSha256 -cnotmatch '\A[A-F0-9]{64}\z'){
        throw 'Invalid technical source timestamp or catalog digest.'
    }
    $null=ConvertTo-WinSecSnapshotUtc $Reference.CollectedAtUTC
    $schema=if($legacy){'2.1.0'}else{$Reference.SnapshotSchemaVersion}
    $catalog=if($legacy){'WinSec.Reviewed.WSA-SYS-001'}else{$Reference.CatalogId}
    $catalogSchema=if($legacy){'1.1.0'}else{$Reference.CatalogSchemaVersion}
    $catalogVersion=if($legacy){'1.0.0'}else{$Reference.CatalogVersion}
    $collector=if($legacy){'0.9.0'}else{$Reference.CollectorVersion}
    $family=$null
    if($schema -ceq '2.1.0' -and $catalog -ceq 'WinSec.Reviewed.WSA-SYS-001' -and $catalogSchema -ceq '1.1.0' -and
        $catalogVersion -ceq '1.0.0' -and $collector -ceq '0.9.0'){
        $family='REVIEWED_PROJECTION'
    }elseif($schema -ceq '2.0.0' -and $catalog -ceq 'WinSec.Defender.Candidate' -and $catalogSchema -ceq '1.0.0' -and
        (($catalogVersion -ceq '1.0.0' -and $collector -cin @('1.0.0','1.1.0','1.2.0','1.3.0')) -or
         ($catalogVersion -ceq '1.1.0' -and $collector -ceq '1.3.0'))){
        $family='DEFENDER_CANDIDATE'
    }else{throw 'Unknown or incompatible technical source versions.'}
    # Resolution is a routing decision. It proves neither committed bytes nor native provenance/consent.
    [pscustomobject]@{ArtifactType='WinSec.TechnicalSourceResolution';SchemaVersion='1.0.0';
        ReferenceKind=$(if($legacy){'TRANSITION_1_0'}else{'VERSIONED_1_0'});Family=$family;Identity=$Reference.Identity.PSObject.Copy();
        CollectedAtUTC=$Reference.CollectedAtUTC;SnapshotSchemaVersion=$schema;CatalogId=$catalog;CatalogSchemaVersion=$catalogSchema;
        CatalogVersion=$catalogVersion;CatalogSha256=$Reference.CatalogSha256;CollectorVersion=$collector}
}
