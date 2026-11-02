# Offline prepared snapshots and actual model/writer contracts; never calls a Windows provider.
. (Join-Path $PSScriptRoot 'DefenderTechnicalMemory.ps1')
. (Join-Path $PSScriptRoot '../../src/Checks/Defender/DefenderTechnicalStorage.ps1')

function New-WinSecTechnicalSourceFixture {
    [CmdletBinding()]
    param([ValidateSet('CANDIDATE','PROJECTION')][string]$Family='CANDIDATE',
        [ValidateSet('1.0.0','1.1.0')][string]$CatalogVersion='1.1.0',[string]$CollectorVersion='1.3.0',
        [ValidateSet('CONTROL','SECTION','DEVICE')][string]$ScopeType='CONTROL')
    $f=New-WinSecDefenderTechnicalFixture
    $f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');$f.Identity.ScopeType=$ScopeType
    $f.Identity.ScopeKey=switch($ScopeType){CONTROL {'WSA-SYS-001'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
    if($Family -ceq 'CANDIDATE'){
        if($CatalogVersion -ceq '1.1.0'){
            # CIM conversion mutates its input. Keep the prepared Platform/Status sources detached.
            $raw=ConvertTo-WinSecDefenderCimFixture (New-WinSecDefenderTechnicalFixture)
            try{$payload=New-WinSecDefenderPreferenceReadings $raw.Sources[2].Data -RequestedProperties @(
                Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Preferences|ForEach-Object Property)}
            finally{Close-WinSecDefenderCimFixture $raw}
            $f.Sources[2]=[pscustomobject]@{SchemaVersion='WinSec.Defender.PreferenceSource1.0';Scope='SCALARS_ONLY';SourceId='Preferences';
                DeviceId=$f.Identity.DeviceId;ScanId=$f.Identity.ScanId;CollectedAtUTC=$f.Sources[2].CollectedAtUTC;State='OBSERVED';Data=$payload}
        }
        $package=New-WinSecDefenderFixturePackage $f;$package.Snapshot.CollectorVersion=$CollectorVersion
    }else{
        $identity=$f.Identity
        $evidence=[pscustomobject]@{DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CheckId=$identity.CheckId;CollectedAtUTC=$f.Sources[0].CollectedAtUTC;
            CollectionSuccessful=$true;CollectionComplete=$true;Private='PRIVATE-SOURCE-SECRET';
            DefenderStatus=[pscustomobject]@{AntivirusEnabled=$false;AMRunningMode='Normal'};
            DefenderPreferences=[pscustomobject]@{PUAProtection=0};
            AttackSurfaceReduction=[pscustomobject]@{Available=$true;Complete=$true;ConfiguredRuleCount=0;Rules=@()}}
        $control=[pscustomobject]@{DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CheckId=$identity.CheckId;SectionKey='SystemSecurity';
            Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';TimestampUTC=$f.Sources[0].CollectedAtUTC;Evidence=$evidence}
        $session=New-WinSecResultSession -DeviceId $identity.DeviceId -ScanId $identity.ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @($identity.CheckId) `
            -ControlResults @($control) -StartedAtUTC $f.StartedAtUTC -CompletedAtUTC $f.CompletedAtUTC -ExecutionStatus COMPLETED -ScopeType $ScopeType -ScopeKey $identity.ScopeKey
        $report=New-WinSecTechnicalReport $session $identity.CheckId SYNTHETIC SYNTHETIC
        $package=New-WinSecProjectionSnapshot $report
    }
    $s=$package.Snapshot
    $reference=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceReference';SchemaVersion='1.0.0';Identity=$s.Identity.PSObject.Copy();
        CollectedAtUTC=$s.CollectedAtUTC;SnapshotSchemaVersion=$s.SchemaVersion;CatalogId=$s.CatalogId;CatalogSchemaVersion=$package.Catalog.SchemaVersion;
        CatalogVersion=$s.CatalogVersion;CatalogSha256=$s.CatalogSha256;CollectorVersion=$s.CollectorVersion}
    [pscustomobject]@{Package=$package;Reference=$reference;Identity=$s.Identity.PSObject.Copy()}
}

function Get-WinSecLegacySourceFixtureReference {
    param([object]$Fixture)
    [pscustomobject]@{Identity=$Fixture.Identity.PSObject.Copy();CollectedAtUTC=$Fixture.Reference.CollectedAtUTC;CatalogSha256=$Fixture.Reference.CatalogSha256}
}

function Save-WinSecTechnicalSourceFixture {
    param([string]$ProjectRoot,[object]$Fixture)
    $p=$Fixture.Package
    if($Fixture.Reference.SnapshotSchemaVersion -ceq '2.0.0'){Write-WinSecDefenderTechnicalPair $ProjectRoot $p $Fixture.Identity}
    else{Write-WinSecTechnicalSnapshotPair $ProjectRoot $p.Snapshot $p.Catalog $p.CatalogSha256 $Fixture.Identity}
}
