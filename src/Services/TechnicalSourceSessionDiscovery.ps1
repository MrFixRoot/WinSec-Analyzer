# Isolated discovery only. Never imported by production restoration, source selection, F or P.
. (Join-Path $PSScriptRoot 'TechnicalSourceSessionStore.ps1')

function Read-WinSecTechnicalSourceSessions {
    [CmdletBinding()]
    param([string]$ProjectRoot,[string]$DeviceId,[scriptblock]$CancellationAction,
        [object]$ArtifactType='WinSec.TechnicalSourceSession',[object]$SchemaVersion='1.0.0')
    $format=Resolve-WinSecTechnicalSessionStorageFormat $ArtifactType $SchemaVersion
    $key=Get-WinSecSnapshotDeviceKey $DeviceId
    $probe=Assert-WinSecSnapshotStoragePath $ProjectRoot ('scans/'+$key+'/'+$format.Directory+'/probe.json') -AllowExistingArtifact
    $directory=[IO.Path]::GetDirectoryName($probe);$owner=[pscustomobject]@{DeviceId=$DeviceId}
    $entries=New-Object 'Collections.Generic.List[object]';$names=@{};$totalBytes=0;$lease=$null;$held=$null
    $entryClock=[Diagnostics.Stopwatch]::StartNew();Assert-WinSecSnapshotValidationBudget $entryClock $CancellationAction
    try{
        # One real lease serializes discovery with cooperative publication and confirmed device removal.
        $lease=Open-WinSecTechnicalSessionOwner $ProjectRoot $owner
        if(-not [IO.Directory]::Exists($directory)){
            if(Test-Path -LiteralPath $directory -ErrorAction Stop){throw 'Invalid technical discovery namespace.'}
            Assert-WinSecTechnicalSessionOwnerUnchanged $lease
            return [pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.0.0';DeviceId=$DeviceId;Sessions=@()}
        }
        $layout=[pscustomobject]@{DeviceKey=$key;Directory=$format.Directory}
        $held=Open-WinSecTechnicalSessionDirectories $ProjectRoot $layout
        # Stream namespace entries. Never enumerate another device, sessions/ or the snapshot bodies.
        foreach($path in [IO.Directory]::EnumerateFileSystemEntries($directory)){
            $opened=$null;$headerLease=$null;$clock=[Diagnostics.Stopwatch]::StartNew()
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $relative=$path.Substring([IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\').Length+1)
            $null=Assert-WinSecSnapshotStoragePath $ProjectRoot $relative -AllowExistingArtifact
            $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if($item.Name -ceq '.gitkeep' -and -not $item.PSIsContainer){continue}
            if($item.PSIsContainer -or $item.Name -cnotmatch '\A[a-f0-9]{64}\.json\z' -or $names.ContainsKey($item.Name)){
                throw 'Unknown, duplicate or incomplete technical discovery entry.'
            }
            $names[$item.Name]=$true
            try{
                $headerLease=[WinSec.SnapshotIO3]::Read($path)
                $bytes=Read-WinSecSnapshotBytes $path $format.MaxBytes $CancellationAction;$totalBytes+=$bytes.Length
                # Aggregate metadata budget inherited from historical session discovery; no inventory truncation.
                if($totalBytes -gt 33554432){throw 'Technical discovery metadata budget exceeded.'}
                $utf8=New-Object Text.UTF8Encoding($false,$true)
                $metadata=ConvertFrom-WinSecSnapshotPairJson ($utf8.GetString($bytes))
                Assert-WinSecSnapshotFields $metadata @('ArtifactType','SchemaVersion','Identity','Sources','ContentSha256')
                $null=Resolve-WinSecTechnicalSessionStorageFormat $metadata.ArtifactType $metadata.SchemaVersion
                $identity=Copy-WinSecTechnicalSessionIdentity $metadata.Identity
                if($identity.DeviceId -cne $DeviceId){throw 'Foreign technical discovery source.'}
                $expected=Get-WinSecTechnicalSessionStorageLayout $ProjectRoot $identity
                if(-not [string]::Equals($expected.Path,$path,[StringComparison]::OrdinalIgnoreCase) -or [IO.File]::Exists($expected.Temporary)){
                    throw 'Technical discovery filename or publication contradicts its identity.'
                }
                $opened=Open-WinSecStoredTechnicalSession $ProjectRoot $path $identity $null $CancellationAction
                $entries.Add([pscustomobject]@{PublicationStatus='COMMITTED';Path=$expected.Path;FileSha256=$opened.FileSha256;Session=$opened.Session})
                Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            }finally{Close-WinSecStoredTechnicalSession $opened;if($headerLease){$headerLease.Dispose()}}
        }
        # Detect namespace or metadata changes outside the cooperative lease before publishing any result.
        foreach($entry in $entries){
            $clock=[Diagnostics.Stopwatch]::StartNew()
            $bytes=Read-WinSecSnapshotBytes $entry.Path $format.MaxBytes $CancellationAction
            if((Get-WinSecSnapshotByteHash $bytes) -cne $entry.FileSha256){throw 'Technical discovery metadata changed.'}
            Assert-WinSecSnapshotValidationBudget $clock $null
        }
        # No caller callbacks after this final namespace check.
        $seen=@{}
        $clock=[Diagnostics.Stopwatch]::StartNew()
        foreach($path in [IO.Directory]::EnumerateFileSystemEntries($directory)){
            Assert-WinSecSnapshotValidationBudget $clock $null
            $name=[IO.Path]::GetFileName($path)
            if($name -ceq '.gitkeep'){continue}
            if(-not $names.ContainsKey($name) -or $seen.ContainsKey($name)){throw 'Technical discovery namespace changed.'}
            $seen[$name]=$true
        }
        if($seen.Count -ne $names.Count){throw 'Technical discovery entry disappeared.'}
        Assert-WinSecTechnicalSessionOwnerUnchanged $lease
        # Ordering is by opaque path only; this is not latest/complete source selection.
        return [pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.0.0';DeviceId=$DeviceId;
            Sessions=@($entries.ToArray()|Sort-Object Path -CaseSensitive)}
    }catch{
        if($_.Exception -is [OperationCanceledException]){throw}
        throw 'Technical session discovery rejected; no discovery result was published.'
    }finally{if($held){foreach($handle in $held){$handle.Dispose()}};if($lease){$lease.Lock.Dispose()}}
}
