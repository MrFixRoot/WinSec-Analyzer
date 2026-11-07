# Isolated metadata restoration pilot. No production cache, CLI, F/P or collector imports.
. (Join-Path $PSScriptRoot 'TechnicalSourceSessionDiscovery.ps1')
. (Join-Path $PSScriptRoot 'StoredTechnicalIndexEntry.ps1')

function Copy-WinSecTechnicalIndexMetadata {
    param([string]$ProjectRoot,[object]$Value,[string]$ExpectedDeviceId,
        [ValidateSet('DISCOVERY','INDEX')][string]$Kind,[scriptblock]$CancellationAction)
    $null=Get-WinSecSnapshotDeviceKey $ExpectedDeviceId
    if($null -eq $Value -or $Value.GetType() -ne [Management.Automation.PSCustomObject]){throw 'Invalid technical index object.'}
    $versionProperty=$Value.PSObject.Properties['SchemaVersion']
    if($null -eq $versionProperty -or $versionProperty.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){throw 'Unsafe technical index version.'}
    $withStored=($Value.SchemaVersion -is [string] -and $Value.SchemaVersion -ceq '1.1.0')
    $fields=@('ArtifactType','SchemaVersion','DeviceId','Sessions')
    if($withStored){$fields+='StoredSessions'}
    if($Kind -ceq 'INDEX'){$fields+=@('Origin','ContentSha256')}
    Assert-WinSecSnapshotFields $Value $fields
    $type=if($Kind -ceq 'INDEX'){'WinSec.TechnicalSourceIndex'}else{'WinSec.TechnicalSourceDiscovery'}
    if($Value.ArtifactType -isnot [string] -or $Value.ArtifactType -cne $type -or
        $Value.SchemaVersion -isnot [string] -or $Value.SchemaVersion -cnotin @('1.0.0','1.1.0') -or
        $Value.DeviceId -isnot [string] -or $Value.DeviceId -cne $ExpectedDeviceId -or $Value.Sessions -isnot [array]){
        throw 'Unknown or foreign technical index metadata.'
    }
    if($Kind -ceq 'INDEX' -and ($Value.Origin -isnot [string] -or $Value.Origin -cne 'RECORDS' -or
        $Value.ContentSha256 -isnot [string] -or $Value.ContentSha256 -cnotmatch '\A[A-F0-9]{64}\z')){throw 'Invalid technical index header.'}
    if($withStored -and $Value.StoredSessions -isnot [array]){throw 'Invalid stored technical manifest.'}
    $header=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceIndex';SchemaVersion=$Value.SchemaVersion;DeviceId=$ExpectedDeviceId;Origin='RECORDS'}
    $items=New-Object 'Collections.Generic.List[object]';$seen=@{};$bytesTotal=0;$hash=[Security.Cryptography.SHA256]::Create()
    $stored=New-Object 'Collections.Generic.List[object]'
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try{
        # Version 1 digest: canonical header + LF, each entry stamp + LF, then END.
        # Stamp the UTF-8 path separately: Desktop/Core JSON escaping must not change index identity.
        # Hash metadata progressively; never clone the whole history through ResultModel's node limit.
        $bytes=[Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $header)+"`n");$bytesTotal+=$bytes.Length
        $null=$hash.TransformBlock($bytes,0,$bytes.Length,$bytes,0)
        foreach($entry in $Value.Sessions){
            Assert-WinSecSnapshotFields $entry @('PublicationStatus','Path','FileSha256','Session')
            if($entry.PublicationStatus -isnot [string] -or $entry.PublicationStatus -cne 'COMMITTED' -or
                $entry.Path -isnot [string] -or $entry.FileSha256 -isnot [string] -or $entry.FileSha256 -cnotmatch '\A[A-F0-9]{64}\z'){
                throw 'Invalid technical index entry.'
            }
            Assert-WinSecSnapshotFields $entry.Session @('ArtifactType','SchemaVersion','Identity','Sources','ContentSha256')
            $owner=Copy-WinSecTechnicalSessionIdentity $entry.Session.Identity
            if($owner.DeviceId -cne $ExpectedDeviceId){throw 'Foreign indexed session.'}
            $layout=Get-WinSecTechnicalSessionStorageLayout $ProjectRoot $owner
            if(-not [string]::Equals($entry.Path,$layout.Path,[StringComparison]::OrdinalIgnoreCase) -or $seen.ContainsKey($layout.Path)){
                throw 'Duplicate or contradictory indexed session path.'
            }
            Assert-WinSecTechnicalSourceSession $entry.Session $owner
            $copy=[pscustomobject]@{PublicationStatus='COMMITTED';Path=$entry.Path;FileSha256=$entry.FileSha256;Session=(Copy-WinSecResultData $entry.Session)}
            $bytesTotal+=[Text.Encoding]::UTF8.GetByteCount((Get-WinSecPublicHistoryJson $copy)+"`n")
            if($bytesTotal+3 -gt 33554432){throw 'Technical index metadata budget exceeded.'}
            $stamp=[pscustomobject]@{PublicationStatus=$copy.PublicationStatus;PathSha256=(Get-WinSecSnapshotByteHash ([Text.Encoding]::UTF8.GetBytes($copy.Path)));
                FileSha256=$copy.FileSha256;Session=$copy.Session}
            $bytes=[Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $stamp)+"`n")
            $null=$hash.TransformBlock($bytes,0,$bytes.Length,$bytes,0);$seen[$layout.Path]=$true;$items.Add($copy)
            Assert-WinSecSnapshotValidationBudget $clock $null
        }
        if($withStored){foreach($entry in $Value.StoredSessions){
            $copy=Copy-WinSecStoredTechnicalIndexEntry $ProjectRoot $entry $ExpectedDeviceId
            if($seen.ContainsKey($copy.Path)){throw 'Duplicate stored technical path.'}
            $seen[$copy.Path]=$true
            $bytesTotal+=[Text.Encoding]::UTF8.GetByteCount((Get-WinSecPublicHistoryJson $copy)+"`n")
            if($bytesTotal+3 -gt 33554432){throw 'Technical index metadata budget exceeded.'}
            $stamp=Copy-WinSecResultData $copy;$stamp.PSObject.Properties.Remove('Path')
            $stamp|Add-Member NoteProperty PathSha256 (Get-WinSecSnapshotByteHash ([Text.Encoding]::UTF8.GetBytes($copy.Path)))
            $bytes=[Text.Encoding]::UTF8.GetBytes("STORED`n"+(Get-WinSecPublicHistoryJson $stamp)+"`n")
            $null=$hash.TransformBlock($bytes,0,$bytes.Length,$bytes,0);$stored.Add($copy)
            Assert-WinSecSnapshotValidationBudget $clock $null
        }}
        $null=$hash.TransformFinalBlock([Text.Encoding]::UTF8.GetBytes('END'),0,3)
        $digest=([BitConverter]::ToString($hash.Hash)).Replace('-','')
        if($Kind -ceq 'INDEX' -and $digest -cne $Value.ContentSha256){throw 'Technical index digest mismatch.'}
        # No callback can mutate the descriptor while it is being detached or hashed.
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $result=[pscustomobject]@{ArtifactType=$header.ArtifactType;SchemaVersion=$header.SchemaVersion;DeviceId=$ExpectedDeviceId;Origin='RECORDS';
            Sessions=$items.ToArray();ContentSha256=$digest}
        if($withStored){$result|Add-Member NoteProperty StoredSessions $stored.ToArray()}
        return $result
    }finally{$hash.Dispose()}
}

function Assert-WinSecTechnicalSourceIndex {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$Index,[string]$ExpectedDeviceId,[scriptblock]$CancellationAction)
    # Metadata validation is not a fresh physical-source verification.
    $null=Copy-WinSecTechnicalIndexMetadata $ProjectRoot $Index $ExpectedDeviceId INDEX $CancellationAction
}

function Read-WinSecTechnicalIndexEntry {
    param([string]$ProjectRoot,[object]$Entry,[scriptblock]$CancellationAction)
    if($null -ne $Entry.PSObject.Properties['ArtifactType']){
        $copy=Copy-WinSecStoredTechnicalIndexEntry $ProjectRoot $Entry $Entry.Identity.DeviceId;$opened=$null
        try{
            $opened=Open-WinSecStoredTechnicalIndexEntry $ProjectRoot $copy.Identity $copy.FileSha256 $copy.ContentSha256 $CancellationAction
            if((Get-WinSecPublicHistoryJson $opened.Entry) -cne (Get-WinSecPublicHistoryJson $copy)){throw 'Indexed stored projection changed.'}
            return $opened.Entry
        }finally{Close-WinSecStoredTechnicalIndexEntry $opened}
    }
    $layout=Get-WinSecTechnicalSessionStorageLayout $ProjectRoot $Entry.Session.Identity;$held=$null;$opened=$null
    try{
        $held=Open-WinSecTechnicalSessionDirectories $ProjectRoot $layout
        if(Test-Path -LiteralPath $layout.Temporary -ErrorAction Stop){throw 'Indexed session publication is incomplete.'}
        $opened=Open-WinSecStoredTechnicalSession $ProjectRoot $layout.Path $Entry.Session.Identity $Entry.Session.ContentSha256 $CancellationAction
        if($opened.FileSha256 -cne $Entry.FileSha256 -or
            (Get-WinSecPublicHistoryJson $opened.Session) -cne (Get-WinSecPublicHistoryJson $Entry.Session)){
            throw 'Indexed session changed after discovery.'
        }
        return [pscustomobject]@{PublicationStatus='COMMITTED';Path=$Entry.Path;FileSha256=$opened.FileSha256;Session=$opened.Session}
    }finally{Close-WinSecStoredTechnicalSession $opened;if($held){foreach($h in $held){$h.Dispose()}}}
}

function Restore-WinSecTechnicalSourceIndex {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$Discovery,[string]$ExpectedDeviceId,[scriptblock]$CancellationAction,
        [AllowEmptyCollection()][object[]]$StoredSessions)
    $lease=$null
    try{
        $inputMetadata=$Discovery
        if($PSBoundParameters.ContainsKey('StoredSessions')){
            # Validate the historical discovery first; no reinterpretation or mutation of its version.
            $old=Copy-WinSecTechnicalIndexMetadata $ProjectRoot $Discovery $ExpectedDeviceId DISCOVERY $CancellationAction
            if($old.SchemaVersion -cne '1.0.0'){throw 'Stored source adaptation requires historical discovery 1.0.'}
            $inputMetadata=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.1.0';DeviceId=$ExpectedDeviceId;
                Sessions=$old.Sessions;StoredSessions=$StoredSessions}
        }
        $index=Copy-WinSecTechnicalIndexMetadata $ProjectRoot $inputMetadata $ExpectedDeviceId DISCOVERY $CancellationAction
        $lease=Open-WinSecTechnicalSessionOwner $ProjectRoot ([pscustomobject]@{DeviceId=$ExpectedDeviceId})
        foreach($entry in @(Get-WinSecTechnicalIndexEntries $index)){
            # Reuse the physical reader, pins and coverage comparison; no fallback to historical projection.
            $null=Read-WinSecTechnicalIndexEntry $ProjectRoot $entry $CancellationAction
        }
        Assert-WinSecTechnicalSessionOwnerUnchanged $lease
        return $index
    }catch{
        if($_.Exception -is [OperationCanceledException]){throw}
        throw 'Technical index restoration rejected; no index was published.'
    }finally{if($lease){$lease.Lock.Dispose()}}
}

function Read-WinSecIndexedTechnicalSession {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$Index,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    $lease=$null
    try{
        $owner=Copy-WinSecTechnicalSessionIdentity $ExpectedIdentity
        $indexCopy=Copy-WinSecTechnicalIndexMetadata $ProjectRoot $Index $owner.DeviceId INDEX $CancellationAction
        $matches=@(foreach($entry in @(Get-WinSecTechnicalIndexEntries $indexCopy)){
            $view=Get-WinSecTechnicalIndexEntryView $entry;$equal=$true
            foreach($field in @('DeviceId','ScanId','ScopeType','ScopeKey')){if($view.Identity.$field -cne $owner.$field){$equal=$false}}
            if($equal){$entry}
        })
        if($matches.Count -ne 1){throw 'Exact indexed session was not found.'}
        $lease=Open-WinSecTechnicalSessionOwner $ProjectRoot $owner
        $entry=Read-WinSecTechnicalIndexEntry $ProjectRoot $matches[0] $CancellationAction
        Assert-WinSecTechnicalSessionOwnerUnchanged $lease
        return $entry
    }catch{
        if($_.Exception -is [OperationCanceledException]){throw}
        throw 'Indexed technical session rejected; no restored entry was published.'
    }finally{if($lease){$lease.Lock.Dispose()}}
}
