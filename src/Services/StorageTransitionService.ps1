# New writes only. Legacy readers remain until the separately confirmed cleanup.
. (Join-Path $PSScriptRoot 'TechnicalSnapshotStore.ps1')
. (Join-Path $PSScriptRoot 'StorageTransitionPlan.ps1')

function Save-WinSecTransitionReports {
    param($Coordinator,$Session,$Target,$Context)
    $files=@();$failed=@();$lease=$null
    try {
        $lease=Open-WinSecDeviceInventoryStore $Coordinator.ProjectRoot
        $inventory=Import-WinSecDeviceInventory $Coordinator.ProjectRoot
        $device=@($inventory.targets|Where-Object DeviceId -CEQ $Session.DeviceId)
        if($device.Count -ne 1){throw 'Missing managed snapshot owner.'}
        $name=$device[0].DisplayName;if(-not $name){$name=$Target.Hostname}
        foreach($control in @($Session.ControlResults|Where-Object Status -CNE NOT_SELECTED)){
            try {
                $report=New-WinSecTechnicalReport $Session $control.CheckId $name $Target.Hostname $Context
                $p=New-WinSecProjectionSnapshot $report
                $saved=Write-WinSecTechnicalSnapshotPair $Coordinator.ProjectRoot $p.Snapshot $p.Catalog $p.CatalogSha256 $p.Identity
                $reference=[pscustomobject]@{Identity=$p.Identity;CollectedAtUTC=$p.Snapshot.CollectedAtUTC;CatalogSha256=$p.CatalogSha256}
                $files+=[pscustomobject]@{DeviceId=$Session.DeviceId;ScanId=$Session.ScanId;CheckId=$control.CheckId;Path=$saved.MarkdownPath;
                    RelativePath=$saved.MarkdownPath.Substring($Coordinator.ProjectRoot.TrimEnd('\').Length+1).Replace('\','/');Reference=$reference}
                $Coordinator.TechnicalSnapshots[(Get-WinSecScanSessionKey $Session.DeviceId $Session.ScanId)+'|'+$control.CheckId]=Copy-WinSecResultData $report
            }catch{$failed+=$control.CheckId}
        }
    }finally{if($lease){$lease.Lock.Dispose()}}
    [pscustomobject]@{DeviceId=$Session.DeviceId;ScanId=$Session.ScanId;Status=$(if($failed.Count){if($files.Count){'PARTIAL'}else{'FAILED'}}else{'SAVED'});Files=$files;FailedCheckIds=$failed}
}

function Assert-WinSecTransitionSession {
    param($Envelope)
    Assert-WinSecSnapshotFields $Envelope @('ArtifactType','SchemaVersion','Record','Sources','ContentSha256')
    if($Envelope.ArtifactType -isnot [string] -or $Envelope.SchemaVersion -isnot [string] -or $Envelope.ArtifactType -cne 'WinSec.StoredSession' -or $Envelope.SchemaVersion -cne '1.0.0' -or $Envelope.Sources -isnot [array] -or $Envelope.ContentSha256 -isnot [string]){throw 'Invalid stored session.'}
    $copy=Copy-WinSecResultData $Envelope;$copy.PSObject.Properties.Remove('ContentSha256')
    if((Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson $copy)) -cne $Envelope.ContentSha256){throw 'Stored session digest mismatch.'}
    $validated=ConvertFrom-WinSecPublicHistoryRecord $Envelope.Record
    $ids=@($validated.Session.ControlResults|Where-Object Status -CNE NOT_SELECTED|ForEach-Object CheckId);$seen=@{}
    if($ids.Count -ne $Envelope.Sources.Count){throw 'Stored session is missing technical sources.'}
    foreach($source in $Envelope.Sources){
        Assert-WinSecSnapshotFields $source @('Identity','CollectedAtUTC','CatalogSha256');Assert-WinSecSnapshotIdentity $source.Identity
        $id=$source.Identity.CheckId
        foreach($name in @('DeviceId','ScanId','ScopeType','ScopeKey')){if($source.Identity.$name -cne $validated.Record.$name){throw 'Foreign stored technical source.'}}
        if($id -cnotin $ids -or $seen.ContainsKey($id) -or $source.CatalogSha256 -isnot [string] -or $source.CatalogSha256 -cne (Get-WinSecSnapshotCatalogHash (Get-WinSecProjectionCatalog $id))){throw 'Invalid stored technical catalog or duplicate.'}
        $null=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;$seen[$id]=$true
    }
    return $validated
}

function Get-WinSecTransitionSessionLayout {
    param([string]$ProjectRoot,[string]$DeviceId,[string]$ScanId)
    $ProjectRoot=Get-WinSecReportInstallation $ProjectRoot
    if(-not(Test-WinSecTargetIdentifier $ScanId)){throw 'Invalid session key.'}
    $key=Get-WinSecSnapshotDeviceKey $DeviceId;$relative='scans/'+$key+'/sessions/'+(Get-WinSecEvidenceHash $ScanId)+'.json'
    [pscustomobject]@{DeviceKey=$key;SectionKey='sessions';Path=(Assert-WinSecSnapshotStoragePath $ProjectRoot $relative -AllowExistingArtifact)}
}

function Write-WinSecTransitionSession {
    param($Coordinator,$Session,$Receipt)
    if($Receipt.Status -cne 'SAVED'){throw 'Technical pairs must commit before the public session.'}
    $record=New-WinSecPublicHistoryRecord $Session
    $envelope=[pscustomobject]@{ArtifactType='WinSec.StoredSession';SchemaVersion='1.0.0';Record=$record;Sources=@($Receipt.Files|ForEach-Object Reference);ContentSha256=''}
    $hashable=Copy-WinSecResultData $envelope;$hashable.PSObject.Properties.Remove('ContentSha256');$envelope.ContentSha256=Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson $hashable)
    $null=Assert-WinSecTransitionSession $envelope
    $layout=Get-WinSecTransitionSessionLayout $Coordinator.ProjectRoot $Session.DeviceId $Session.ScanId
    $held=$null;$lease=$null
    try {
        $lease=Open-WinSecDeviceInventoryStore $Coordinator.ProjectRoot
        $inventory=Import-WinSecDeviceInventory $Coordinator.ProjectRoot
        if(@($inventory.targets|Where-Object DeviceId -CEQ $Session.DeviceId).Count -ne 1){throw 'Stored session device removed.'}
        $held=Open-WinSecSnapshotDirectories $Coordinator.ProjectRoot $layout -Create
        $temporary=$layout.Path+'.tmp';$relative=$temporary.Substring($Coordinator.ProjectRoot.TrimEnd('\').Length+1)
        $null=Assert-WinSecSnapshotStoragePath $Coordinator.ProjectRoot $relative
        $json=Get-WinSecPublicHistoryJson $envelope;$bytes=[Text.Encoding]::UTF8.GetBytes($json)
        if($bytes.Length -gt 2097152){throw 'Stored session index budget exceeded.'}
        Write-WinSecSnapshotBytes $temporary $bytes
        $check=Read-WinSecSnapshotBytes $temporary 2097152
        if((Get-WinSecSnapshotByteHash $check) -cne (Get-WinSecSnapshotByteHash $bytes)){throw 'Session temporary verification failed.'}
        $null=Assert-WinSecTransitionSession (ConvertFrom-WinSecTransitionJson ([Text.Encoding]::UTF8.GetString($check)))
        [WinSec.SnapshotIO3]::MoveExclusive($temporary,$layout.Path)
        $check=Read-WinSecSnapshotBytes $layout.Path 2097152
        if((Get-WinSecSnapshotByteHash $check) -cne (Get-WinSecSnapshotByteHash $bytes)){throw 'Session publication verification failed.'}
    }finally{if($held){foreach($h in $held){$h.Dispose()}};if($lease){$lease.Lock.Dispose()}}
    foreach($ref in $envelope.Sources){$Coordinator.TechnicalLocations[(Get-WinSecScanSessionKey $record.DeviceId $record.ScanId)+'|'+$ref.Identity.CheckId]=$ref}
}

function Read-WinSecTransitionSessions {
    param($ProjectRoot,[object[]]$Devices)
    $records=@();$refs=@{};$bytesTotal=0
    foreach($device in $Devices){
        $layout=Get-WinSecTransitionSessionLayout $ProjectRoot $device.DeviceId 'index-probe'
        $directory=[IO.Path]::GetDirectoryName($layout.Path)
        if(-not [IO.Directory]::Exists($directory)){continue}
        $held=Open-WinSecSnapshotDirectories $ProjectRoot $layout
        try {
            foreach($file in @(Get-ChildItem -LiteralPath $directory -Force -File)){
                if($file.Extension -ceq '.tmp'){throw 'Incomplete session publication requires recovery.'}
                if($file.Extension -cne '.json'){throw 'Unknown session index artifact.'}
                $null=Assert-WinSecSnapshotStoragePath $ProjectRoot $file.FullName.Substring($ProjectRoot.TrimEnd('\').Length+1) -AllowExistingArtifact
                $data=Read-WinSecSnapshotBytes $file.FullName 2097152;$bytesTotal+=$data.Length
                if($bytesTotal -gt 33554432 -or $records.Count -ge 10000){throw 'Session index budget exceeded.'}
                $utf8=New-Object Text.UTF8Encoding($false,$true)
                # The existing bounded parser preserves legacy DateTime-compatible values.
                $envelope=ConvertFrom-WinSecTransitionJson ($utf8.GetString($data))
                $validated=Assert-WinSecTransitionSession $envelope
                $expected=Get-WinSecTransitionSessionLayout $ProjectRoot $device.DeviceId $validated.Record.ScanId
                if($validated.Record.DeviceId -cne $device.DeviceId -or -not [string]::Equals($expected.Path,$file.FullName,[StringComparison]::OrdinalIgnoreCase)){throw 'Foreign stored session path.'}
                foreach($reference in $envelope.Sources){
                    $pair=Get-WinSecSnapshotPairLayout $ProjectRoot $reference.Identity $reference.CollectedAtUTC
                    $pairHandles=Open-WinSecSnapshotDirectories $ProjectRoot $pair
                    try {
                        $prepared=Read-WinSecSnapshotPairManifest $pair.Intent $reference.Identity $reference.CollectedAtUTC $reference.CatalogSha256 PREPARED
                        $committed=Read-WinSecSnapshotPairManifest $pair.Commit $reference.Identity $reference.CollectedAtUTC $reference.CatalogSha256 COMMITTED
                        Assert-WinSecSnapshotPairAgreement $prepared $committed
                        if(-not [IO.File]::Exists($pair.Json) -or -not [IO.File]::Exists($pair.Markdown)){throw 'Stored session has missing technical bodies.'}
                    }finally{foreach($h in $pairHandles){$h.Dispose()}}
                }
                $records+=,$validated.Record
                foreach($reference in $envelope.Sources){$refs[(Get-WinSecScanSessionKey $validated.Record.DeviceId $validated.Record.ScanId)+'|'+$reference.Identity.CheckId]=$reference}
            }
        }finally{foreach($h in $held){$h.Dispose()}}
    }
    [pscustomobject]@{Records=$records;References=$refs}
}

function ConvertFrom-WinSecTransitionJson {
    param([string]$Json)
    $jsonReader=Get-Command Microsoft.PowerShell.Utility\ConvertFrom-Json -CommandType Cmdlet
    if($jsonReader.Parameters.ContainsKey('DateKind')){
        function ConvertFrom-WinSecTransitionString {param($InputObject);& $jsonReader -InputObject $InputObject -DateKind String -ErrorAction Stop}
        Set-Alias ConvertFrom-Json ConvertFrom-WinSecTransitionString -Scope Local
    }
    return ConvertFrom-WinSecBoundedStoredJson $Json -MaxBytes 16777216
}

function Read-WinSecTransitionReport {
    param($Coordinator,[string]$DeviceId,[string]$ScanId,[string]$CheckId)
    $key=(Get-WinSecScanSessionKey $DeviceId $ScanId)+'|'+$CheckId
    if(-not $Coordinator.TechnicalLocations.ContainsKey($key)){return Read-WinSecTechnicalReport $Coordinator.ProjectRoot $DeviceId $ScanId $CheckId}
    $reference=$Coordinator.TechnicalLocations[$key];$catalog=Get-WinSecProjectionCatalog $CheckId
    Assert-WinSecSnapshotFields $reference @('Identity','CollectedAtUTC','CatalogSha256');Assert-WinSecSnapshotIdentity $reference.Identity
    if($reference.Identity.DeviceId -cne $DeviceId -or $reference.Identity.ScanId -cne $ScanId -or $reference.Identity.CheckId -cne $CheckId){throw 'Foreign cached technical reference.'}
    $result=Read-WinSecTechnicalSnapshotPair $Coordinator.ProjectRoot $reference.Identity $reference.CollectedAtUTC $catalog $reference.CatalogSha256
    if($result.PublicationStatus -cne 'COMMITTED'){throw 'Technical source is not committed.'}
    return ConvertFrom-WinSecProjectionSnapshot $result.Snapshot
}

function Repair-WinSecTransitionSessionIndex {
    param([string]$ProjectRoot,[string]$DeviceId,[string]$ScanId)
    $layout=Get-WinSecTransitionSessionLayout $ProjectRoot $DeviceId $ScanId;$held=Open-WinSecSnapshotDirectories $ProjectRoot $layout
    try {
        $temporary=$layout.Path+'.tmp';$path=if([IO.File]::Exists($layout.Path)){$layout.Path}else{$temporary}
        $null=Assert-WinSecSnapshotStoragePath $ProjectRoot $path.Substring($ProjectRoot.TrimEnd('\').Length+1) -AllowExistingArtifact
        $bytes=Read-WinSecSnapshotBytes $path 2097152;$utf8=New-Object Text.UTF8Encoding($false,$true)
        $envelope=ConvertFrom-WinSecTransitionJson ($utf8.GetString($bytes));$validated=Assert-WinSecTransitionSession $envelope
        if($validated.Record.DeviceId -cne $DeviceId -or $validated.Record.ScanId -cne $ScanId){throw 'Foreign pending session.'}
        foreach($reference in $envelope.Sources){
            $catalog=Get-WinSecProjectionCatalog $reference.Identity.CheckId
            $result=Read-WinSecTechnicalSnapshotPair $ProjectRoot $reference.Identity $reference.CollectedAtUTC $catalog $reference.CatalogSha256
            if($result.PublicationStatus -ceq 'RECOVERABLE'){$result=Repair-WinSecTechnicalSnapshotPair $ProjectRoot $reference.Identity $reference.CollectedAtUTC $catalog $reference.CatalogSha256}
            if($result.PublicationStatus -cne 'COMMITTED'){throw 'Pending session lacks complete technical pairs.'}
        }
        if($path -ceq $temporary){[WinSec.SnapshotIO3]::MoveExclusive($temporary,$layout.Path)}
        [pscustomobject]@{Status='COMMITTED';DeviceId=$DeviceId;ScanId=$ScanId}
    }finally{foreach($h in $held){$h.Dispose()}}
}

function Get-WinSecTransitionDeviceFiles {
    param([string]$ProjectRoot,[string]$DeviceId,[object]$Device)
    $pack=Read-WinSecTransitionSessions $ProjectRoot @($Device);$files=New-Object 'Collections.Generic.List[object]';$known=@{}
    foreach($record in $pack.Records){
        $path=(Get-WinSecTransitionSessionLayout $ProjectRoot $DeviceId $record.ScanId).Path
        $files.Add([pscustomobject]@{Path=$path;Hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash});$known[$path]=$true
    }
    foreach($reference in $pack.References.Values){
        $plan=Get-WinSecTechnicalSnapshotRemovalPlan $ProjectRoot $reference.Identity $reference.CollectedAtUTC (Get-WinSecProjectionCatalog $reference.Identity.CheckId) $reference.CatalogSha256
        foreach($file in $plan.Files){if(-not $known.ContainsKey($file.Path)){$files.Add([pscustomobject]@{Path=$file.Path;Hash=$file.Sha256});$known[$file.Path]=$true}}
    }
    $key=Get-WinSecSnapshotDeviceKey $DeviceId;$directories=@()
    foreach($base in @('scans','reports')){
        $path=Join-Path $ProjectRoot ($base+'/'+$key)
        Assert-WinSecDeviceRemovalPath $ProjectRoot $path
        if(-not [IO.Directory]::Exists($path)){continue}
        $pending=New-Object 'Collections.Generic.Stack[string]';$pending.Push($path)
        while($pending.Count){$dir=$pending.Pop();$directories+=$dir
            foreach($item in @(Get-ChildItem -LiteralPath $dir -Force)){
                Assert-WinSecDeviceRemovalPath $ProjectRoot $item.FullName
                if(($files.Count+$directories.Count+$pending.Count) -gt 10000){throw 'Device transition removal budget exceeded.'}
                if($item.PSIsContainer){$pending.Push($item.FullName)}elseif($item.Name -cne '.gitkeep' -and -not $known.ContainsKey($item.FullName)){throw 'Unknown or incomplete new storage blocks device deletion.'}
            }
        }
    }
    [pscustomobject]@{Files=$files.ToArray();Directories=$directories}
}

function Remove-WinSecVerifiedTransitionFile {
    param([string]$ProjectRoot,[string]$Path,[string]$Sha256)
    Assert-WinSecDeviceRemovalPath $ProjectRoot $Path
    $handles=New-Object 'Collections.Generic.List[IDisposable]';$paths=New-Object 'Collections.Generic.List[string]';$cursor=[IO.Path]::GetDirectoryName($Path);$stream=$null
    while($cursor){$paths.Insert(0,$cursor);$cursor=[IO.Path]::GetDirectoryName($cursor)}
    try {
        Initialize-WinSecSnapshotFileIO;foreach($directory in $paths){$handles.Add([WinSec.SnapshotIO3]::HoldDirectory($directory))}
        $stream=[WinSec.SnapshotIO3]::OpenRemoval($Path)
        $sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')}finally{$sha.Dispose()}
        if($hash -cne $Sha256){throw 'Transition artifact changed before removal.'}
        [WinSec.SnapshotIO3]::MarkRemoval($stream)
    }finally{if($stream){$stream.Dispose()};foreach($h in $handles){$h.Dispose()}}
}
