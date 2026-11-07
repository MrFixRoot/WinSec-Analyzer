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

function Assert-WinSecTechnicalDiscoveryNamespace {
    # Internal membership gate; caller holds the managed-device inventory lease and directory handles.
    param([string]$ProjectRoot,[string]$DeviceId,[ValidateSet('sessions','technical-sessions')][string]$Namespace,[object[]]$Entries)
    $key=Get-WinSecSnapshotDeviceKey $DeviceId
    $probe=Assert-WinSecSnapshotStoragePath $ProjectRoot ('scans/'+$key+'/'+$Namespace+'/probe.json') -AllowExistingArtifact
    $directory=[IO.Path]::GetDirectoryName($probe);$known=@{};$seen=@{};$clock=[Diagnostics.Stopwatch]::StartNew()
    foreach($entry in $Entries){
        if($known.ContainsKey($entry.Path)){throw 'Duplicate discovery namespace path.'};$known[$entry.Path]=$true
    }
    if(-not [IO.Directory]::Exists($directory)){
        if($known.Count -or (Test-Path -LiteralPath $directory -ErrorAction Stop)){throw 'Discovery namespace disappeared.'};return
    }
    foreach($path in [IO.Directory]::EnumerateFileSystemEntries($directory)){
        Assert-WinSecSnapshotValidationBudget $clock $null
        $relative=$path.Substring([IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\').Length+1)
        $null=Assert-WinSecSnapshotStoragePath $ProjectRoot $relative -AllowExistingArtifact
        $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if($item.Name -ceq '.gitkeep' -and -not $item.PSIsContainer){continue}
        if($item.PSIsContainer -or $item.Name -cnotmatch '\A[a-f0-9]{64}\.json\z' -or
            -not $known.ContainsKey($path) -or $seen.ContainsKey($path)){throw 'Discovery namespace changed or contains an unrecognized publication.'}
        $seen[$path]=$true
    }
    if($seen.Count -ne $known.Count){throw 'Discovery namespace membership changed.'}
}

function Read-WinSecTechnicalIndexDiscovery {
    [CmdletBinding()]
    param([string]$ProjectRoot,[string]$DeviceId,[scriptblock]$CancellationAction)
    # Explicit pilot only. Reuse historical discovery and physical readers; no cache publication.
    . (Join-Path $PSScriptRoot 'StoredTechnicalIndexEntry.ps1')
    $clock=[Diagnostics.Stopwatch]::StartNew();Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    $technical=Read-WinSecTechnicalSourceSessions $ProjectRoot $DeviceId -CancellationAction $CancellationAction
    $lease=$null;$held=New-Object 'Collections.Generic.List[IDisposable]'
    $stored=New-Object 'Collections.Generic.List[object]';$pinned=New-Object 'Collections.Generic.List[object]';$storedPins=@{};$totalBytes=0
    try{
        $lease=Open-WinSecTechnicalSessionOwner $ProjectRoot ([pscustomobject]@{DeviceId=$DeviceId})
        $key=Get-WinSecSnapshotDeviceKey $DeviceId
        # Reacquiring the owner lease cannot hide a publication between the two phases: final
        # membership checks compare both namespaces with the exact manifest prepared here.
        foreach($namespace in @('technical-sessions','sessions')){
            $probe=Assert-WinSecSnapshotStoragePath $ProjectRoot ('scans/'+$key+'/'+$namespace+'/probe.json') -AllowExistingArtifact
            $directory=[IO.Path]::GetDirectoryName($probe)
            if([IO.Directory]::Exists($directory)){
                foreach($handle in (Open-WinSecTechnicalSessionDirectories $ProjectRoot ([pscustomobject]@{DeviceKey=$key;Directory=$namespace}))){$held.Add($handle)}
            }elseif(Test-Path -LiteralPath $directory -ErrorAction Stop){throw 'Invalid combined discovery namespace.'}
            if($namespace -cne 'sessions' -or -not [IO.Directory]::Exists($directory)){continue}
            foreach($path in [IO.Directory]::EnumerateFileSystemEntries($directory)){
                $header=$null;$opened=$null;$clock=[Diagnostics.Stopwatch]::StartNew()
                Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
                $relative=$path.Substring([IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\').Length+1)
                $null=Assert-WinSecSnapshotStoragePath $ProjectRoot $relative -AllowExistingArtifact
                $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
                if($item.Name -ceq '.gitkeep' -and -not $item.PSIsContainer){continue}
                if($item.PSIsContainer -or $item.Name -cnotmatch '\A[a-f0-9]{64}\.json\z'){throw 'Unknown or incomplete stored discovery artifact.'}
                try{
                    $header=[WinSec.SnapshotIO3]::Read($path)
                    $bytes=Read-WinSecSnapshotBytes $path 2097152 $CancellationAction;$totalBytes+=$bytes.Length
                    if($totalBytes -gt 33554432){throw 'Combined discovery metadata budget exceeded.'}
                    $utf8=New-Object Text.UTF8Encoding($false,$true)
                    $envelope=ConvertFrom-WinSecTransitionJson ($utf8.GetString($bytes))
                    $validated=Assert-WinSecTransitionSession $envelope
                    $record=$validated.Record
                    $owner=Copy-WinSecTechnicalSessionIdentity ([pscustomobject]@{DeviceId=$record.DeviceId;ScanId=$record.ScanId;ScopeType=$record.ScopeType;ScopeKey=$record.ScopeKey})
                    $expected=Get-WinSecTransitionSessionLayout $ProjectRoot $DeviceId $owner.ScanId
                    if($owner.DeviceId -cne $DeviceId -or $expected.Path -cne $path){throw 'Foreign stored discovery artifact.'}
                    # Every original source must have reviewed support; never filter the session.
                    foreach($reference in $envelope.Sources){
                        try{$null=Get-WinSecProductiveTechnicalSourceSpecification $reference.Identity.CheckId}
                        catch{throw [NotSupportedException]::new('STORED_CONTROL_NOT_SUPPORTED')}
                    }
                    # Header work and each source package have independent bounded validation
                    # steps. Do not charge three complete package readers to one header clock.
                    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
                    $opened=Open-WinSecStoredTechnicalIndexEntry $ProjectRoot $owner (Get-WinSecSnapshotByteHash $bytes) $envelope.ContentSha256 $CancellationAction
                    $clock=[Diagnostics.Stopwatch]::StartNew()
                    $stored.Add($opened.Entry)
                    # Keep the verified bodies, rather than closing and parsing every source again.
                    $pin=Get-WinSecSnapshotByteHash ([Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $opened.Entry)))
                    if($storedPins.ContainsKey($opened.Entry.Path)){throw 'Duplicate stored discovery path.'};$storedPins[$opened.Entry.Path]=$pin
                    $pinned.Add([pscustomobject]@{Stored=$true;Opened=$opened});$opened=$null
                    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
                }finally{Close-WinSecStoredTechnicalIndexEntry $opened;if($header){$header.Dispose()}}
            }
        }
        foreach($entry in $technical.Sessions){
            $clock=[Diagnostics.Stopwatch]::StartNew()
            $bytes=Read-WinSecSnapshotBytes $entry.Path 16384 $CancellationAction;$totalBytes+=$bytes.Length
            if($totalBytes -gt 33554432 -or (Get-WinSecSnapshotByteHash $bytes) -cne $entry.FileSha256){throw 'Combined discovery metadata changed or exceeds its budget.'}
            Assert-WinSecSnapshotValidationBudget $clock $null
        }
        # Hold the final source bodies and metadata until both namespace gates finish. Later
        # callbacks cannot alter an earlier source after its physical validation.
        foreach($entry in @($technical.Sessions)+@($stored.ToArray())){
            $opened=$null;$isStored=($null -ne $entry.PSObject.Properties['ArtifactType'])
            try{
                if($isStored){
                    # These handles have remained open since the first validation. Check the
                    # detached descriptor against its frozen pin after all earlier callbacks.
                    if(-not $storedPins.ContainsKey($entry.Path) -or (Get-WinSecSnapshotByteHash ([Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $entry)))) -cne $storedPins[$entry.Path]){throw 'Stored discovery metadata changed.'}
                }else{
                    $opened=Open-WinSecStoredTechnicalSession $ProjectRoot $entry.Path $entry.Session.Identity $entry.Session.ContentSha256 $CancellationAction
                    if($opened.FileSha256 -cne $entry.FileSha256){throw 'Technical discovery publication changed.'}
                    $pinned.Add([pscustomobject]@{Stored=$false;Opened=$opened});$opened=$null
                }
            }finally{if($opened){if($isStored){Close-WinSecStoredTechnicalIndexEntry $opened}else{Close-WinSecStoredTechnicalSession $opened}}}
        }
        # No caller callbacks after this final namespace check.
        Assert-WinSecTechnicalDiscoveryNamespace $ProjectRoot $DeviceId technical-sessions $technical.Sessions
        Assert-WinSecTechnicalDiscoveryNamespace $ProjectRoot $DeviceId sessions $stored.ToArray()
        Assert-WinSecTechnicalSessionOwnerUnchanged $lease
        [pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.1.0';DeviceId=$DeviceId;
            Sessions=$technical.Sessions;StoredSessions=@($stored.ToArray()|Sort-Object Path -CaseSensitive)}
    }catch{
        if($_.Exception -is [OperationCanceledException]){throw}
        if($_.Exception -is [NotSupportedException] -and $_.Exception.Message -cin @('MULTI_CONTROL_SESSION_NOT_SUPPORTED','STORED_CONTROL_NOT_SUPPORTED')){throw}
        throw 'Combined technical discovery rejected; no partial discovery or fallback was published.'
    }finally{
        foreach($pin in $pinned){if($pin.Stored){Close-WinSecStoredTechnicalIndexEntry $pin.Opened}else{Close-WinSecStoredTechnicalSession $pin.Opened}}
        foreach($handle in $held){$handle.Dispose()};if($lease){$lease.Lock.Dispose()}
    }
}
