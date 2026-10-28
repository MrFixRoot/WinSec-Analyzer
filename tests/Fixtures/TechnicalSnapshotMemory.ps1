# Synthetic contract only: never calls a collector or reads a managed device.
function New-WinSecSnapshotFixture {
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()}
    $catalog=[pscustomobject]@{
        ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='Synthetic.Guest';CatalogVersion='1.0.0';CheckId='WSA-IAM-002'
        Sources=@([pscustomobject]@{Id='Local';Provider='NETAPI';ReferenceUrl='https://learn.microsoft.com/windows/win32/api/lmaccess/'})
        Inventories=@([pscustomobject]@{Id='Guest';SourceId='Local';Required=$true;Singleton=$true;Applicability=$rule})
        Fields=@(
            [pscustomobject]@{Id='Guest.Disabled';InventoryId='Guest';Type='Boolean';Unit='none';Required=$true;Exposure='CONFIGURATION';Applicability=$rule}
            [pscustomobject]@{Id='Guest.Flags';InventoryId='Guest';Type='UInt32';Unit='count';Required=$false;Exposure='CONFIGURATION';Applicability=$rule}
            [pscustomobject]@{Id='Guest.Name';InventoryId='Guest';Type='String';Unit='none';Required=$false;Exposure='IDENTIFIABLE';Applicability=$rule}
        )
    }
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='synthetic-scan';SnapshotId=('b'*32);CheckId='WSA-IAM-002';SectionKey='IdentityAccess';ScopeType='CONTROL';ScopeKey='WSA-IAM-002'}
    $hash=Get-WinSecSnapshotCatalogHash $catalog
    $snapshot=[pscustomobject]@{
        ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$identity.PSObject.Copy()
        CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$hash;CollectorVersion='2.0.0'
        StartedAtUTC='2026-10-28T01:02:03.0000000Z';CollectedAtUTC='2026-10-28T01:02:04.0000000Z'
        CompletedAtUTC='2026-10-28T01:02:05.0000000Z';GeneratedAtUTC='2026-10-28T01:02:06.0000000Z'
        Platform=[pscustomobject]@{Version='10.0.22631';OSRelease='23H2';Edition='Pro';BuildNumber=22631;UBR=$null;OperatingSystemSKU=48;ProductType=1}
        SelectedProfile='WSA-W11-23H2-PRO-DEF-BASE'
        Collection=[pscustomobject]@{Status='COMPLETE';Coverage='COMPLETE';RetainedRecords=1;Observed=3;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0}
        Inventories=@([pscustomobject]@{Id='Guest';State='OBSERVED';Complete=$true;ReportedRecords=1;RetainedRecords=1;Reason='NONE'})
        Batches=@([pscustomobject]@{
            DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;SnapshotId=$identity.SnapshotId;CheckId=$identity.CheckId;InventoryId='Guest';Sequence=1
            Records=@([pscustomobject]@{Id='Guest501';Readings=@(
                [pscustomobject]@{FieldId='Guest.Disabled';State='OBSERVED';Reason='NONE';Value=$false}
                [pscustomobject]@{FieldId='Guest.Flags';State='OBSERVED';Reason='NONE';Value=0}
                [pscustomobject]@{FieldId='Guest.Name';State='OBSERVED';Reason='NONE';Value='SYNTHETIC ACCOUNT'}
            )})
        })
    }
    [pscustomobject]@{Catalog=$catalog;Hash=$hash;Identity=$identity;Snapshot=$snapshot}
}
