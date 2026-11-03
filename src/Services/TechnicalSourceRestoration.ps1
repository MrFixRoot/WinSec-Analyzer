# Bridge for explicit public-history restoration. Reuse the technical index and policy; no UI wiring.
. (Join-Path $PSScriptRoot 'TechnicalSourceSelection.ps1')

function Get-WinSecTechnicalRestoreDevices {
    param([object[]]$Devices)
    $seen=@{}
    foreach($device in $Devices){
        $id=Get-WinSecTargetField $device DeviceId;$null=Get-WinSecSnapshotDeviceKey $id
        if($seen.ContainsKey($id)){throw 'Duplicate restoration device.'};$seen[$id]=$true
        [pscustomobject]@{DeviceId=$id}
    }
}

function New-WinSecTechnicalRestoreStamp {
    param([object]$Context)
    if($Context.GetType() -ne [Management.Automation.PSCustomObject]){throw 'Technical restoration requires a plain application context.'}
    foreach($name in @('ProjectRoot','Devices','ScanCoordinator','PublicScans','ActiveScanByDevice','ActiveScanByScope','HistoryReady','TechnicalSourceIndexes','TechnicalSourcesReady')){
        $property=$Context.PSObject.Properties[$name]
        if($null -ne $property -and $property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){throw 'Unsafe restoration context property.'}
    }
    $technical=Get-WinSecTargetField $Context TechnicalSourceIndexes;$ready=Get-WinSecTargetField $Context TechnicalSourcesReady
    $aliasProperty=$Context.ScanCoordinator.PSObject.Properties['TechnicalSourceIndexes']
    if($null -ne $aliasProperty -and $aliasProperty.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){throw 'Unsafe coordinator cache property.'}
    $coordinatorTechnical=Get-WinSecTargetField $Context.ScanCoordinator TechnicalSourceIndexes
    if($null -ne $coordinatorTechnical -and ($coordinatorTechnical -isnot [hashtable] -or $coordinatorTechnical.Count)){throw 'Restoration requires an empty coordinator technical cache.'}
    $historyReady=Get-WinSecTargetField $Context HistoryReady
    if(($null -ne $technical -and ($technical -isnot [hashtable] -or $technical.Count)) -or
        ($null -ne $ready -and ($ready -isnot [bool] -or $ready)) -or
        ($null -ne $historyReady -and ($historyReady -isnot [bool] -or $historyReady))){throw 'Restoration requires fresh caches and readiness flags.'}
    foreach($map in @($Context.ScanCoordinator.Sessions,$Context.ScanCoordinator.TechnicalLocations,$Context.PublicScans,$Context.ActiveScanByDevice,$Context.ActiveScanByScope)){
        if($map -isnot [hashtable] -or $map.Count){throw 'Technical restoration requires empty application caches.'}
    }
    [pscustomobject]@{ProjectRoot=$Context.ProjectRoot;Coordinator=$Context.ScanCoordinator;Devices=@(Get-WinSecTechnicalRestoreDevices @($Context.Devices));
        Sessions=$Context.ScanCoordinator.Sessions;Locations=$Context.ScanCoordinator.TechnicalLocations;Publics=$Context.PublicScans;
        ActiveDevice=$Context.ActiveScanByDevice;ActiveScope=$Context.ActiveScanByScope;Technical=$technical;CoordinatorTechnical=$coordinatorTechnical;TechnicalReady=$ready;HistoryReady=$historyReady}
}

function Assert-WinSecTechnicalRestoreStamp {
    param([object]$Context,[object]$Stamp)
    $current=New-WinSecTechnicalRestoreStamp $Context
    if($current.ProjectRoot -cne $Stamp.ProjectRoot -or (Get-WinSecPublicHistoryJson $current.Devices) -cne (Get-WinSecPublicHistoryJson $Stamp.Devices) -or
        $current.TechnicalReady -cne $Stamp.TechnicalReady -or $current.HistoryReady -cne $Stamp.HistoryReady){throw 'Restoration context changed.'}
    foreach($name in @('Coordinator','Sessions','Locations','Publics','ActiveDevice','ActiveScope','Technical','CoordinatorTechnical')){
        if(-not [object]::ReferenceEquals($current.$name,$Stamp.$name)){throw 'Restoration caches changed.'}
    }
}

function Read-WinSecTechnicalRestoreIndexes {
    param([string]$ProjectRoot,[object[]]$Devices,[scriptblock]$CancellationAction)
    $indexes=@{};$total=0;$clock=[Diagnostics.Stopwatch]::StartNew()
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    foreach($device in @(Get-WinSecTechnicalRestoreDevices $Devices)){
        $discovery=Read-WinSecTechnicalSourceSessions $ProjectRoot $device.DeviceId -CancellationAction $CancellationAction
        $index=Restore-WinSecTechnicalSourceIndex $ProjectRoot $discovery $device.DeviceId -CancellationAction $CancellationAction
        foreach($entry in $index.Sessions){$total+=[Text.Encoding]::UTF8.GetByteCount((Get-WinSecPublicHistoryJson $entry));if($total -gt 33554432){throw 'Restored technical cache budget exceeded.'}}
        $indexes[$device.DeviceId]=$index
    }
    return $indexes
}

function Assert-WinSecTechnicalRestoreIndexes {
    # Internal final gate: Restore-WinSecPublicHistory owns the real inventory lease here.
    param([string]$ProjectRoot,[hashtable]$Indexes,[object[]]$Devices,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    $expected=@(Get-WinSecTechnicalRestoreDevices $Devices)
    if($Indexes.Count -ne $expected.Count){throw 'Technical restore manifest changed.'}
    $fingerprint=Get-WinSecDeviceInventoryFingerprint $ProjectRoot;$inventory=Import-WinSecDeviceInventory $ProjectRoot
    foreach($device in $expected){
        if(@($inventory.targets|Where-Object DeviceId -CEQ $device.DeviceId).Count -ne 1 -or
            (Test-WinSecDeviceInventoryRemoval $inventory $device.DeviceId) -or -not $Indexes.ContainsKey($device.DeviceId)){
            throw 'Technical restore owner or manifest changed.'
        }
        $index=Copy-WinSecTechnicalIndexMetadata $ProjectRoot $Indexes[$device.DeviceId] $device.DeviceId INDEX $CancellationAction
        foreach($entry in $index.Sessions){$null=Read-WinSecTechnicalIndexEntry $ProjectRoot $entry $CancellationAction}
        # Membership check only, not another discovery/parser. Detect added/removed publications since
        # preparation while the public restorer now holds the inventory lease; no callbacks afterwards.
        $key=Get-WinSecSnapshotDeviceKey $device.DeviceId
        $probe=Assert-WinSecSnapshotStoragePath $ProjectRoot ('scans/'+$key+'/technical-sessions/probe.json') -AllowExistingArtifact
        $directory=[IO.Path]::GetDirectoryName($probe);$held=$null
        try{
            if([IO.Directory]::Exists($directory)){
                $held=Open-WinSecTechnicalSessionDirectories $ProjectRoot ([pscustomobject]@{DeviceKey=$key;Directory='technical-sessions'})
                $known=@{};foreach($entry in $index.Sessions){$known[$entry.Path]=$true};$count=0;$clock=[Diagnostics.Stopwatch]::StartNew()
                foreach($path in [IO.Directory]::EnumerateFileSystemEntries($directory)){
                    Assert-WinSecSnapshotValidationBudget $clock $null
                    $relative=$path.Substring([IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\').Length+1)
                    $null=Assert-WinSecSnapshotStoragePath $ProjectRoot $relative -AllowExistingArtifact
                    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    if($item.Name -ceq '.gitkeep' -and -not $item.PSIsContainer){continue}
                    if($item.PSIsContainer -or -not $known.ContainsKey($path)){throw 'Technical history changed during restoration.'};$count++
                }
                if($count -ne $index.Sessions.Count){throw 'Technical session disappeared during restoration.'}
            }elseif($index.Sessions.Count -or (Test-Path -LiteralPath $directory -ErrorAction Stop)){throw 'Technical namespace changed.'}
        }finally{if($held){foreach($h in $held){$h.Dispose()}}}
    }
    if((Get-WinSecDeviceInventoryFingerprint $ProjectRoot) -cne $fingerprint){throw 'Inventory changed during technical restoration.'}
}

function Select-WinSecRestoredTechnicalSource {
    [CmdletBinding()]
    param([object]$Context,[string]$DeviceId,[string]$Family,[string]$ScopeType,[string]$ScopeKey,
        [string]$SourcePreference='PREFER_COMPLETE',[scriptblock]$CancellationAction)
    try{
        $historyReady=Get-WinSecTargetField $Context HistoryReady;$technicalReady=Get-WinSecTargetField $Context TechnicalSourcesReady
        if($historyReady -isnot [bool] -or -not $historyReady -or $technicalReady -isnot [bool] -or -not $technicalReady){throw 'Technical history is not ready.'}
        $indexes=Get-WinSecTargetField $Context TechnicalSourceIndexes
        $coordinator=Get-WinSecTargetField $Context ScanCoordinator
        $bound=Get-WinSecTargetField $coordinator TechnicalSourceIndexes
        if($bound -isnot [hashtable] -or -not [object]::ReferenceEquals($indexes,$bound)){throw 'Restored technical cache binding changed.'}
        if($indexes -isnot [hashtable] -or -not $indexes.ContainsKey($DeviceId) -or
            @((Get-WinSecTechnicalRestoreDevices @($Context.Devices))|Where-Object DeviceId -CEQ $DeviceId).Count -ne 1){throw 'Missing restored technical index.'}
        # D-135 revalidates the physical selected/latest sources on every consumption. No cached view
        # or legacy PublicScans fallback can substitute a missing, altered or obsolete technical index.
        Select-WinSecTechnicalSource $Context.ProjectRoot $indexes[$DeviceId] $DeviceId $Family $ScopeType $ScopeKey `
            -SourcePreference $SourcePreference -CancellationAction $CancellationAction
    }catch{
        if($_.Exception -is [OperationCanceledException]){throw}
        throw 'Restored technical source rejected; no legacy fallback was performed.'
    }
}

function New-WinSecTechnicalPublicationCacheStamp {
    # Explicit writer opt-in only. The coordinator and restored context keep one shared map.
    param([object]$Coordinator,[string]$ProjectRoot,[object]$Identity)
    if($null -eq $Coordinator -or $Coordinator.GetType() -ne [Management.Automation.PSCustomObject]){throw 'Invalid technical cache coordinator.'}
    foreach($name in @('ProjectRoot','TechnicalSourceIndexes')){
        $p=$Coordinator.PSObject.Properties[$name]
        if($null -eq $p -or $p.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){throw 'Missing or unsafe technical cache binding.'}
    }
    $root=Get-WinSecReportInstallation $ProjectRoot
    if(-not [string]::Equals($root,(Get-WinSecReportInstallation $Coordinator.ProjectRoot),[StringComparison]::OrdinalIgnoreCase) -or
        $Coordinator.TechnicalSourceIndexes -isnot [hashtable]){throw 'Foreign technical cache installation.'}
    $owner=Copy-WinSecTechnicalSessionIdentity $Identity;$map=$Coordinator.TechnicalSourceIndexes
    $present=$map.ContainsKey($owner.DeviceId);$previous=$null;$digest=$null
    if($present){
        $previous=$map[$owner.DeviceId]
        $digest=(Copy-WinSecTechnicalIndexMetadata $root $previous $owner.DeviceId INDEX $null).ContentSha256
    }
    [pscustomobject]@{Coordinator=$Coordinator;ProjectRoot=$root;Identity=$owner;Map=$map;HadIndex=$present;Previous=$previous;PreviousSha256=$digest}
}

function Assert-WinSecTechnicalPublicationCacheStamp {
    param([object]$Stamp,[switch]$Invalidated)
    $current=New-WinSecTechnicalPublicationCacheStamp $Stamp.Coordinator $Stamp.ProjectRoot $Stamp.Identity
    if(-not [object]::ReferenceEquals($current.Map,$Stamp.Map)){throw 'Technical publication cache binding changed.'}
    if($Invalidated){if($current.HadIndex){throw 'Technical cache changed during reload.'}}
    elseif($current.HadIndex -ne $Stamp.HadIndex -or -not [object]::ReferenceEquals($current.Previous,$Stamp.Previous) -or
        $current.PreviousSha256 -cne $Stamp.PreviousSha256){throw 'Technical cache changed before publication.'}
}

function Restore-WinSecTechnicalCacheAfterPublication {
    # Called only after the writer verified its exclusive commit and invalidated this DeviceId.
    # A reload failure leaves that entry unavailable; persisted history is never rolled back.
    param([object]$Stamp,[object]$Publication,[scriptblock]$CancellationAction)
    # Reject out-of-order calls before entering cleanup: only the verified writer may
    # invalidate a previously available entry. A malformed notification cannot evict it.
    Assert-WinSecTechnicalPublicationCacheStamp $Stamp -Invalidated
    $lease=$null
    try{
        Assert-WinSecSnapshotFields $Publication @('PublicationStatus','Path','Session','FileSha256')
        $owner=$Stamp.Identity;$root=$Stamp.ProjectRoot;$id=$owner.DeviceId
        $layout=Get-WinSecTechnicalSessionStorageLayout $root $owner
        if($Publication.PublicationStatus -isnot [string] -or $Publication.PublicationStatus -cne 'COMMITTED' -or
            $Publication.Path -isnot [string] -or $Publication.Path -cne $layout.Path -or
            $Publication.FileSha256 -isnot [string] -or $Publication.FileSha256 -cnotmatch '\A[A-F0-9]{64}\z'){
            throw 'Unverified technical cache publication.'
        }
        Assert-WinSecTechnicalSourceSession $Publication.Session $owner
        $devices=@([pscustomobject]@{DeviceId=$id})
        $prepared=Read-WinSecTechnicalRestoreIndexes $root $devices $CancellationAction
        $match=@($prepared[$id].Sessions|Where-Object Path -CEQ $layout.Path)
        if($match.Count -ne 1 -or $match[0].FileSha256 -cne $Publication.FileSha256 -or
            (Get-WinSecPublicHistoryJson $match[0].Session) -cne (Get-WinSecPublicHistoryJson $Publication.Session)){
            throw 'Committed technical source was not restored exactly.'
        }
        # Existing final gate holds one inventory lease, revalidates physical pins and membership,
        # then publishes one entry without callbacks. No nested owner lease or replacement cache.
        $lease=Open-WinSecDeviceInventoryStore $root
        Assert-WinSecTechnicalRestoreIndexes $root $prepared $devices $CancellationAction
        Assert-WinSecTechnicalPublicationCacheStamp $Stamp -Invalidated
        $bytes=0
        foreach($key in @($Stamp.Map.Keys)+@($id)){
            $value=if($key -ceq $id){$prepared[$id]}else{$Stamp.Map[$key]}
            $copy=Copy-WinSecTechnicalIndexMetadata $root $value $key INDEX $null
            foreach($entry in $copy.Sessions){$bytes+=[Text.Encoding]::UTF8.GetByteCount((Get-WinSecPublicHistoryJson $entry))}
            if($bytes -gt 33554432){throw 'Restored technical cache budget exceeded.'}
        }
        $Stamp.Map[$id]=$prepared[$id]
    }catch{
        $Stamp.Map.Remove($Stamp.Identity.DeviceId)
        if($_.Exception -is [OperationCanceledException]){throw}
        throw 'Technical session committed; technical cache reload failed and its device entry was invalidated.'
    }finally{if($lease){$lease.Lock.Dispose()}}
}

function Confirm-WinSecStoredSessionCachePublication {
    # Internal notification from the StoredSession 1.0 writer, under its inventory lease.
    # Do not reload technical-sessions/: that discovery cannot represent StoredSession.
    param([object]$Stamp,[object]$Envelope,[string]$Path,[string]$FileSha256)
    Assert-WinSecTechnicalPublicationCacheStamp $Stamp -Invalidated
    $validated=Assert-WinSecTransitionSession $Envelope
    foreach($field in @('DeviceId','ScanId','ScopeType','ScopeKey')){
        if($validated.Record.$field -cne $Stamp.Identity.$field){throw 'Foreign stored publication notification.'}
    }
    $layout=Get-WinSecTransitionSessionLayout $Stamp.ProjectRoot $Stamp.Identity.DeviceId $Stamp.Identity.ScanId
    if($Path -cne $layout.Path -or $FileSha256 -cnotmatch '\A[A-F0-9]{64}\z'){throw 'Invalid stored publication pin.'}
    $header=$null;$sources=$null
    try{
        $header=[WinSec.SnapshotIO3]::Read($Path)
        $bytes=Read-WinSecSnapshotBytes $Path 2097152
        if((Get-WinSecSnapshotByteHash $bytes) -cne $FileSha256 -or
            (Get-WinSecSnapshotByteHash ([Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $Envelope)))) -cne $FileSha256){
            throw 'Stored publication differs from its verified commit.'
        }
        # Reuse source leases/readers with the original three-field projection references.
        # This local adapter is not a new session, candidate reference or persisted artifact.
        $pins=[pscustomobject]@{Sources=@(foreach($ref in $Envelope.Sources){[pscustomobject]@{Reference=$ref}})}
        $sources=Open-WinSecTechnicalSessionSourceLeases $Stamp.ProjectRoot $pins
        foreach($ref in $Envelope.Sources){
            $source=Read-WinSecVersionedTechnicalSource $Stamp.ProjectRoot $ref $ref.Identity
            if($source.Resolution.Family -cne 'REVIEWED_PROJECTION' -or $source.Resolution.SnapshotSchemaVersion -cne '2.1.0'){
                throw 'Stored publication is not a supported production projection.'
            }
        }
        Assert-WinSecTechnicalPublicationCacheStamp $Stamp -Invalidated
    }finally{if($sources){foreach($handle in $sources){$handle.Dispose()}};if($header){$header.Dispose()}}
}
