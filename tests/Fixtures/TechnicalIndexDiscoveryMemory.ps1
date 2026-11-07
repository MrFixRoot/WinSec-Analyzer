# Synthetic persisted sessions only; caller supplies its isolated installation and managed inventory.
. (Join-Path $PSScriptRoot 'TechnicalSourceMemory.ps1')

function Save-WinSecStoredDiscoveryFixture {
    param([string]$ProjectRoot,[string]$ScopeType='CONTROL',[string[]]$CheckIds=@('WSA-SYS-001'),[int]$Day=0,[switch]$Partial,[string[]]$PartialCheckIds=@())
    . (Join-Path $ProjectRoot 'src/Core/ScanCoordinator.ps1')
    . (Join-Path $ProjectRoot 'src/Services/TechnicalSourceRestoration.ps1')
    $f=New-WinSecTechnicalSourceFixture -Family PROJECTION -ScopeType $ScopeType
    $report=ConvertFrom-WinSecProjectionSnapshot $f.Package.Snapshot;$scan='combined-'+[guid]::NewGuid().ToString('N');$report.ScanId=$scan
    foreach($field in @('StartedAtUTC','CollectedAtUTC','CompletedAtUTC','GeneratedAtUTC')){
        $report.$field=(ConvertTo-WinSecSnapshotUtc $report.$field).AddDays($Day).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
    }
    if($Partial){$report.CollectorStatus='ERROR'}
    $prototype=New-WinSecProjectionSnapshot $report;$id=$prototype.Identity;$s=$prototype.Snapshot
    $scopeKey=switch($ScopeType){CONTROL {$CheckIds[0]};SECTION {(Get-WinSecSnapshotControl $CheckIds[0]).SectionKey};DEVICE {'ALL'}}
    $controls=@(foreach($check in $CheckIds){
        [pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$scan;CheckId=$check;SectionKey=(Get-WinSecSnapshotControl $check).SectionKey;Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';
            TimestampUTC=$s.CollectedAtUTC;Evidence=[pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$scan;CheckId=$check;CollectedAtUTC=$s.CollectedAtUTC;
                CollectionSuccessful=$true;CollectionComplete=($check -cnotin $PartialCheckIds)}}
    })
    $session=New-WinSecResultSession -DeviceId $id.DeviceId -ScanId $scan -CatalogVersion '1.0.0' -ExpectedCheckIds $CheckIds -ControlResults $controls `
        -StartedAtUTC $s.StartedAtUTC -CompletedAtUTC $s.CompletedAtUTC -ExecutionStatus $(if($Partial -or $PartialCheckIds.Count){'COMPLETED_WITH_ERRORS'}else{'COMPLETED'}) -ScopeType $ScopeType -ScopeKey $scopeKey
    $files=@(foreach($check in $CheckIds){
        $package=if($check -ceq 'WSA-SYS-001'){$prototype}else{
            $other=New-WinSecTechnicalReport $session $check SYNTHETIC SYNTHETIC;New-WinSecProjectionSnapshot $other
        }
        $null=Write-WinSecTechnicalSnapshotPair $ProjectRoot $package.Snapshot $package.Catalog $package.CatalogSha256 $package.Identity
        [pscustomobject]@{Reference=[pscustomobject]@{Identity=$package.Identity;CollectedAtUTC=$package.Snapshot.CollectedAtUTC;CatalogSha256=$package.CatalogSha256}}
    })
    Write-WinSecTransitionSession ([pscustomobject]@{ProjectRoot=$ProjectRoot;TechnicalLocations=@{}}) $session ([pscustomobject]@{Status='SAVED';Files=$files})
    [pscustomobject]@{Identity=[pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$scan;ScopeType=$ScopeType;ScopeKey=$scopeKey};
        Layout=(Get-WinSecTransitionSessionLayout $ProjectRoot $id.DeviceId $scan);Sources=@($files|ForEach-Object Reference);
        Pair=(Get-WinSecSnapshotPairLayout $ProjectRoot $files[0].Reference.Identity $files[0].Reference.CollectedAtUTC)}
}

function Save-WinSecCandidateDiscoveryFixture {
    param([string]$ProjectRoot,[string]$ScopeType='CONTROL')
    . (Join-Path $ProjectRoot 'src/Services/TechnicalSourceRestoration.ps1')
    $f=New-WinSecTechnicalSourceFixture -ScopeType $ScopeType;$scan='candidate-'+[guid]::NewGuid().ToString('N')
    foreach($identity in @($f.Identity,$f.Reference.Identity,$f.Package.Identity,$f.Package.Snapshot.Identity)){$identity.ScanId=$scan}
    foreach($batch in $f.Package.Snapshot.Batches){$batch.ScanId=$scan}
    $null=Save-WinSecTechnicalSourceFixture $ProjectRoot $f
    $owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$scan;ScopeType=$ScopeType;ScopeKey=$f.Identity.ScopeKey}
    $pin=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
    $session=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
        [pscustomobject]@{Reference=$pin.Reference;SnapshotSha256=$pin.SnapshotSha256;Collection=$f.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
    $session.ContentSha256=Get-WinSecTechnicalSessionDigest $session
    $saved=Write-WinSecTechnicalSourceSession $ProjectRoot $session $owner
    [pscustomobject]@{Identity=$owner;Saved=$saved;Pair=(Get-WinSecSnapshotPairLayout $ProjectRoot $f.Identity $f.Reference.CollectedAtUTC)}
}
