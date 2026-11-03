# Explicit StoredSession 1.0 index adapter. No publication, migration or Windows providers.
. (Join-Path $PSScriptRoot 'TechnicalSourceSessionStore.ps1')
. (Join-Path $PSScriptRoot 'StorageTransitionService.ps1')
. (Join-Path $PSScriptRoot 'ExportService.ps1')
. (Join-Path $PSScriptRoot 'EvidenceService.ps1')
. (Join-Path $PSScriptRoot '../Core/CheckRegistry.ps1')

function Copy-WinSecStoredTechnicalIndexEntry {
    param([string]$ProjectRoot,[object]$Entry,[string]$DeviceId)
    Assert-WinSecSnapshotFields $Entry @('ArtifactType','SchemaVersion','PublicationStatus','Path','FileSha256','Identity','ContentSha256','Sources')
    foreach($field in @('ArtifactType','SchemaVersion','PublicationStatus','Path','FileSha256','ContentSha256')){
        if($Entry.$field -isnot [string]){throw 'Invalid stored index entry type.'}
    }
    if($Entry.ArtifactType -cne 'WinSec.StoredSession' -or $Entry.SchemaVersion -cne '1.0.0' -or $Entry.PublicationStatus -cne 'COMMITTED' -or
        $Entry.FileSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or $Entry.ContentSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        $Entry.Sources -isnot [array] -or $Entry.Sources.Count -ne 1){throw 'Unsupported stored index entry or pilot scope.'}
    $owner=Copy-WinSecTechnicalSessionIdentity $Entry.Identity
    $null=Get-WinSecTechnicalSessionStorageLayout $ProjectRoot $owner # existing strict pilot scope/identity validation
    $path=(Get-WinSecTransitionSessionLayout $ProjectRoot $owner.DeviceId $owner.ScanId).Path
    if($owner.DeviceId -cne $DeviceId -or $Entry.Path -cne $path){throw 'Foreign stored index entry.'}
    $source=$Entry.Sources[0]
    Assert-WinSecSnapshotFields $source @('Reference','SnapshotSha256','Collection')
    Assert-WinSecSnapshotFields $source.Reference @('Identity','CollectedAtUTC','CatalogSha256')
    $resolution=Resolve-WinSecTechnicalSourceVersion $source.Reference $source.Reference.Identity
    if($resolution.Family -cne 'REVIEWED_PROJECTION' -or $source.SnapshotSha256 -isnot [string] -or
        $source.SnapshotSha256 -cnotmatch '\A[A-F0-9]{64}\z'){throw 'Invalid stored projection source.'}
    foreach($field in @('DeviceId','ScanId','ScopeType','ScopeKey')){
        if($resolution.Identity.$field -cne $owner.$field){throw 'Foreign stored projection scope.'}
    }
    $collection=$source.Collection
    Assert-WinSecSnapshotFields $collection @('Status','Coverage','RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')
    if($collection.Status -isnot [string] -or $collection.Coverage -isnot [string] -or
        $collection.Status -cnotin @('COMPLETE','PARTIAL') -or $collection.Coverage -cnotin @('COMPLETE','LIMITED') -or
        ($collection.Coverage -ceq 'COMPLETE' -and $collection.Status -cne 'COMPLETE')){throw 'Invalid stored collection state.'}
    foreach($field in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){
        if(-not (Test-WinSecSnapshotUInt $collection.$field)){throw 'Invalid stored collection count.'}
    }
    return Copy-WinSecResultData $Entry
}

function Open-WinSecStoredTechnicalIndexEntry {
    # Internal reader; caller owns the managed-device inventory lease.
    param([string]$ProjectRoot,[object]$Identity,[object]$ExpectedFileSha256,[object]$ExpectedContentSha256,[scriptblock]$CancellationAction)
    $owner=Copy-WinSecTechnicalSessionIdentity $Identity
    $null=Get-WinSecTechnicalSessionStorageLayout $ProjectRoot $owner
    foreach($pin in @($ExpectedFileSha256,$ExpectedContentSha256)){
        if($null -ne $pin -and ($pin -isnot [string] -or $pin -cnotmatch '\A[A-F0-9]{64}\z')){throw 'Invalid stored source pin.'}
    }
    $layout=Get-WinSecTransitionSessionLayout $ProjectRoot $owner.DeviceId $owner.ScanId
    $directories=$null;$header=$null;$sources=$null
    try{
        $clock=[Diagnostics.Stopwatch]::StartNew();Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $directories=Open-WinSecSnapshotDirectories $ProjectRoot $layout
        if(Test-Path -LiteralPath ($layout.Path+'.tmp')){throw 'Incomplete stored source requires explicit recovery.'}
        $header=[WinSec.SnapshotIO3]::Read($layout.Path)
        $bytes=Read-WinSecSnapshotBytes $layout.Path 2097152 $CancellationAction
        $hash=Get-WinSecSnapshotByteHash $bytes
        if($null -ne $ExpectedFileSha256 -and $hash -cne $ExpectedFileSha256){throw 'Stored source file changed.'}
        $utf8=New-Object Text.UTF8Encoding($false,$true)
        $envelope=ConvertFrom-WinSecTransitionJson ($utf8.GetString($bytes))
        $validated=Assert-WinSecTransitionSession $envelope
        foreach($field in @('DeviceId','ScanId','ScopeType','ScopeKey')){
            if($validated.Record.$field -cne $owner.$field){throw 'Foreign stored session identity.'}
        }
        if($null -ne $ExpectedContentSha256 -and $envelope.ContentSha256 -cne $ExpectedContentSha256){throw 'Stored source content changed.'}
        if($envelope.Sources.Count -ne 1 -or $envelope.Sources[0].Identity.CheckId -cne 'WSA-SYS-001'){throw 'Stored source pilot requires Defender only.'}
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $pins=[pscustomobject]@{Sources=@(foreach($ref in $envelope.Sources){[pscustomobject]@{Reference=$ref}})}
        $sources=Open-WinSecTechnicalSessionSourceLeases $ProjectRoot $pins
        $items=@(foreach($ref in $envelope.Sources){
            $saved=Read-WinSecVersionedTechnicalSource $ProjectRoot $ref $ref.Identity -CancellationAction $CancellationAction
            if($saved.Resolution.Family -cne 'REVIEWED_PROJECTION'){throw 'Wrong stored source family.'}
            $package=[pscustomobject]@{Snapshot=$saved.Snapshot;Catalog=$saved.Catalog;CatalogSha256=$saved.CatalogSha256;Identity=$saved.Snapshot.Identity}
            $stamp=Get-WinSecTechnicalSourcePackageStamp $package $saved.Snapshot.Identity
            # Preserve the actual historical reference; versions and coverage come from verified bytes.
            [pscustomobject]@{Reference=(Copy-WinSecResultData $ref);SnapshotSha256=$stamp.SnapshotSha256;Collection=(Copy-WinSecResultData $saved.Snapshot.Collection)}
        })
        $entry=[pscustomobject]@{ArtifactType=$envelope.ArtifactType;SchemaVersion=$envelope.SchemaVersion;PublicationStatus='COMMITTED';Path=$layout.Path;
            FileSha256=$hash;Identity=$owner;ContentSha256=$envelope.ContentSha256;Sources=$items}
        $copy=Copy-WinSecStoredTechnicalIndexEntry $ProjectRoot $entry $owner.DeviceId
        return [pscustomobject]@{Entry=$copy;Directories=$directories;Header=$header;Sources=$sources}
    }catch{
        if($sources){foreach($h in $sources){$h.Dispose()}};if($header){$header.Dispose()};if($directories){foreach($h in $directories){$h.Dispose()}}
        if($_.Exception -is [OperationCanceledException]){throw};throw 'Stored technical source is unsafe, incomplete or incompatible.'
    }
}

function Close-WinSecStoredTechnicalIndexEntry {
    param([object]$Opened)
    if($Opened){foreach($h in $Opened.Sources){$h.Dispose()};$Opened.Header.Dispose();foreach($h in $Opened.Directories){$h.Dispose()}}
}

function Read-WinSecStoredTechnicalIndexEntry {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$ExpectedIdentity,[object]$ExpectedFileSha256=$null,[object]$ExpectedContentSha256=$null,[scriptblock]$CancellationAction)
    $lease=$null;$opened=$null
    try{
        $owner=Copy-WinSecTechnicalSessionIdentity $ExpectedIdentity
        $lease=Open-WinSecTechnicalSessionOwner $ProjectRoot $owner
        $opened=Open-WinSecStoredTechnicalIndexEntry $ProjectRoot $owner $ExpectedFileSha256 $ExpectedContentSha256 $CancellationAction
        Assert-WinSecTechnicalSessionOwnerUnchanged $lease
        return $opened.Entry
    }finally{Close-WinSecStoredTechnicalIndexEntry $opened;if($lease){$lease.Lock.Dispose()}}
}

function Get-WinSecTechnicalIndexEntries {
    param([object]$Index)
    foreach($entry in $Index.Sessions){$entry}
    if($Index.SchemaVersion -ceq '1.1.0'){foreach($entry in $Index.StoredSessions){$entry}}
}

function Get-WinSecTechnicalIndexEntryView {
    # Metadata view only; does not relabel a StoredSession as a TechnicalSourceSession.
    param([object]$Entry)
    if($null -ne $Entry.PSObject.Properties['ArtifactType']){
        [pscustomobject]@{Identity=$Entry.Identity;ContentSha256=$Entry.ContentSha256;Sources=$Entry.Sources}
    }else{$Entry.Session}
}
