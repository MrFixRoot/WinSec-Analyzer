# Isolated stage 3 container pilot. No StoredSession migration, index publication or restoration import.
. (Join-Path $PSScriptRoot 'TechnicalSourceEmitter.ps1')

function Copy-WinSecTechnicalSessionIdentity {
    param([object]$Identity)
    Assert-WinSecSnapshotFields $Identity @('DeviceId','ScanId','ScopeType','ScopeKey')
    foreach($field in @('DeviceId','ScanId','ScopeType','ScopeKey')){if($Identity.$field -isnot [string]){throw 'Invalid technical session identity type.'}}
    return $Identity.PSObject.Copy()
}

function Copy-WinSecTechnicalSessionReference {
    param([object]$Reference,[object]$Identity)
    # New containers require explicit reference 1.0. Historical three-field references stay historical.
    Assert-WinSecSnapshotFields $Reference @('ArtifactType','SchemaVersion','Identity','CollectedAtUTC','SnapshotSchemaVersion',
        'CatalogId','CatalogSchemaVersion','CatalogVersion','CatalogSha256','CollectorVersion')
    $resolved=Resolve-WinSecTechnicalSourceVersion $Reference $Reference.Identity
    foreach($field in @('DeviceId','ScanId','ScopeType','ScopeKey')){
        if($resolved.Identity.$field -cne $Identity.$field){throw 'Foreign technical session reference.'}
    }
    if($resolved.Family -ceq 'DEFENDER_CANDIDATE'){
        . (Join-Path $PSScriptRoot '../Checks/Defender/DefenderTechnicalStorage.ps1')
        $catalog=Get-WinSecDefenderTechnicalCatalog -CatalogVersion $resolved.CatalogVersion
    }else{$catalog=Get-WinSecProjectionCatalog $resolved.Identity.CheckId}
    if((Get-WinSecSnapshotCatalogHash $catalog) -cne $resolved.CatalogSha256){throw 'Unreviewed technical session catalog.'}
    $copy=$Reference.PSObject.Copy();$copy.Identity=$resolved.Identity.PSObject.Copy();return $copy
}

function Get-WinSecTechnicalSessionDigest {
    param([object]$Session)
    # Metadata only, after structural validation. No snapshot bodies are cloned here.
    $copy=Copy-WinSecResultData $Session;$copy.PSObject.Properties.Remove('ContentSha256')
    return Get-WinSecSnapshotByteHash ([Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $copy)))
}

function Assert-WinSecTechnicalSourceSession {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Session,[Parameter(Mandatory)][object]$ExpectedIdentity)
    $clock=[Diagnostics.Stopwatch]::StartNew();$owner=Copy-WinSecTechnicalSessionIdentity $ExpectedIdentity
    Assert-WinSecSnapshotFields $Session @('ArtifactType','SchemaVersion','Identity','Sources','ContentSha256')
    if($Session.ArtifactType -isnot [string] -or $Session.ArtifactType -cne 'WinSec.TechnicalSourceSession' -or
        $Session.SchemaVersion -isnot [string] -or $Session.SchemaVersion -cne '1.0.0' -or
        $Session.ContentSha256 -isnot [string] -or $Session.ContentSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        $Session.Sources -isnot [array] -or $Session.Sources.Count -lt 1){throw 'Invalid technical source session schema.'}
    $identity=Copy-WinSecTechnicalSessionIdentity $Session.Identity
    foreach($field in @('DeviceId','ScanId','ScopeType','ScopeKey')){if($identity.$field -cne $owner.$field){throw 'Foreign technical source session.'}}
    $checks=@{};$snapshots=@{}
    foreach($entry in $Session.Sources){
        Assert-WinSecSnapshotValidationBudget $clock $null
        Assert-WinSecSnapshotFields $entry @('Reference','SnapshotSha256','Collection')
        $ref=Copy-WinSecTechnicalSessionReference $entry.Reference $owner
        if($checks.ContainsKey($ref.Identity.CheckId) -or $snapshots.ContainsKey($ref.Identity.SnapshotId)){throw 'Duplicate technical session source.'}
        $checks[$ref.Identity.CheckId]=$true;$snapshots[$ref.Identity.SnapshotId]=$true
        if($entry.SnapshotSha256 -isnot [string] -or $entry.SnapshotSha256 -cnotmatch '\A[A-F0-9]{64}\z'){throw 'Invalid technical session snapshot digest.'}
        Assert-WinSecSnapshotFields $entry.Collection @('Status','Coverage','RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')
        foreach($field in @('Status','Coverage')){if($entry.Collection.$field -isnot [string]){throw 'Invalid technical collection state type.'}}
        if($entry.Collection.Status -cnotin @('COMPLETE','PARTIAL') -or $entry.Collection.Coverage -cnotin @('COMPLETE','LIMITED') -or
            ($entry.Collection.Coverage -ceq 'COMPLETE' -and $entry.Collection.Status -cne 'COMPLETE')){throw 'Contradictory technical collection summary.'}
        foreach($field in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){
            if(-not (Test-WinSecSnapshotUInt $entry.Collection.$field)){throw 'Invalid technical collection count.'}
        }
    }
    if((Get-WinSecTechnicalSessionDigest $Session) -cne $Session.ContentSha256){throw 'Technical source session digest mismatch.'}
    # Same 16 KiB metadata budget and bounded JSON parser as pair manifests; not an inventory cap.
    if([Text.Encoding]::UTF8.GetByteCount((Get-WinSecPublicHistoryJson $Session)) -gt 16384){throw 'Technical session metadata budget exceeded.'}
    Assert-WinSecSnapshotValidationBudget $clock $null
}

function ConvertTo-WinSecTechnicalSourceSessionJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Session,[Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    $owner=Copy-WinSecTechnicalSessionIdentity $ExpectedIdentity;$clock=[Diagnostics.Stopwatch]::StartNew()
    Assert-WinSecTechnicalSourceSession $Session $owner
    # Freeze validated metadata before invoking caller code.
    $json=Get-WinSecPublicHistoryJson $Session
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    return $json
}

function ConvertFrom-WinSecTechnicalSourceSessionJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Json,[Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    $owner=Copy-WinSecTechnicalSessionIdentity $ExpectedIdentity;$clock=[Diagnostics.Stopwatch]::StartNew()
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    if($Json -isnot [string]){throw 'Technical session JSON requires text.'}
    try{$session=ConvertFrom-WinSecSnapshotPairJson $Json}catch{throw 'Invalid technical source session JSON.'}
    Assert-WinSecTechnicalSourceSession $session $owner
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    return $session
}

function Get-WinSecVerifiedTechnicalSessionEntry {
    param([string]$ProjectRoot,[object]$Reference,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$held=$null;$streams=New-Object 'Collections.Generic.List[object]'
    try{
        # Same existing secure read leases as the emitter, spanning the single exact source read.
        $layout=Get-WinSecSnapshotPairLayout $ProjectRoot $Reference.Identity $Reference.CollectedAtUTC
        $held=Open-WinSecSnapshotDirectories $ProjectRoot $layout
        foreach($name in @('Intent','Commit','Json','Markdown')){$streams.Add([WinSec.SnapshotIO3]::Read($layout.$name))}
        $source=Read-WinSecVersionedTechnicalSource $ProjectRoot $Reference $Reference.Identity -CancellationAction $CancellationAction
        $package=[pscustomobject]@{Snapshot=$source.Snapshot;Catalog=$source.Catalog;CatalogSha256=$source.CatalogSha256;Identity=$Reference.Identity.PSObject.Copy()}
        # Reuse the emitter's full validated snapshot stamp without reading the same pair again.
        $stamp=Get-WinSecTechnicalSourcePackageStamp $package $Reference.Identity
        if((Get-WinSecPublicHistoryJson $stamp.Reference) -cne (Get-WinSecPublicHistoryJson $Reference)){throw 'Technical session reference contradicts its source.'}
        $entry=[pscustomobject]@{Reference=$stamp.Reference;SnapshotSha256=$stamp.SnapshotSha256;Collection=$source.Snapshot.Collection.PSObject.Copy()}
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        return $entry
    }catch{
        if($_.Exception -is [OperationCanceledException]){throw}
        throw 'Technical session requires an intact committed source within its resource budget.'
    }finally{
        foreach($stream in $streams){$stream.Dispose()};if($held){foreach($handle in $held){$handle.Dispose()}}
    }
}

function New-WinSecTechnicalSourceSession {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$References,
        [Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    $owner=Copy-WinSecTechnicalSessionIdentity $ExpectedIdentity;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($References -isnot [array] -or $References.Count -lt 1){throw 'Technical session requires explicit source references.'}
    $copies=@();$checks=@{};$snapshots=@{}
    # Validate and detach the entire selection before any callback or file access.
    foreach($ref in $References){
        $copy=Copy-WinSecTechnicalSessionReference $ref $owner
        if($checks.ContainsKey($copy.Identity.CheckId) -or $snapshots.ContainsKey($copy.Identity.SnapshotId)){throw 'Duplicate technical session source.'}
        $checks[$copy.Identity.CheckId]=$true;$snapshots[$copy.Identity.SnapshotId]=$true;$copies+=,$copy
        Assert-WinSecSnapshotValidationBudget $clock $null
    }
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    $entries=@(foreach($ref in $copies){Get-WinSecVerifiedTechnicalSessionEntry $ProjectRoot $ref $CancellationAction})
    $session=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=$entries;ContentSha256=''}
    $session.ContentSha256=Get-WinSecTechnicalSessionDigest $session
    Assert-WinSecTechnicalSourceSession $session $owner
    # No caller callbacks after the last held-file verification.
    Assert-WinSecSnapshotValidationBudget $clock $null
    return $session
}

function Resolve-WinSecTechnicalSourceSession {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    $owner=Copy-WinSecTechnicalSessionIdentity $ExpectedIdentity;$clock=[Diagnostics.Stopwatch]::StartNew()
    Assert-WinSecTechnicalSourceSession $Session $owner;$frozen=Copy-WinSecResultData $Session
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    foreach($entry in $frozen.Sources){
        $actual=Get-WinSecVerifiedTechnicalSessionEntry $ProjectRoot $entry.Reference $CancellationAction
        if($actual.SnapshotSha256 -cne $entry.SnapshotSha256 -or
            (Get-WinSecPublicHistoryJson $actual.Collection) -cne (Get-WinSecPublicHistoryJson $entry.Collection)){
            throw 'Technical session content or coverage contradicts its committed source.'
        }
    }
    Assert-WinSecSnapshotValidationBudget $clock $null
    return $frozen
}
