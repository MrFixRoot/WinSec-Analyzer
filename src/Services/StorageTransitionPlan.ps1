# Read-only legacy inventory and immutable cleanup plans. No automatic cleanup.
function Get-WinSecLegacyCleanupPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $root=Get-WinSecReportInstallation $ProjectRoot
    $files=New-Object 'Collections.Generic.List[object]';$excluded=New-Object 'Collections.Generic.List[object]'
    $inventoryHash=Get-WinSecDeviceInventoryFingerprint $root;$readBytes=0
    foreach($relative in @('data/scans','reports')){
        $base=Join-Path $root $relative
        Assert-WinSecDeviceRemovalPath $root $base
        if(-not [IO.Directory]::Exists($base)){continue}
        $pending=New-Object 'Collections.Generic.Stack[string]';$pending.Push($base)
        while($pending.Count){
            $directory=$pending.Pop()
            foreach($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)){
                if(($files.Count+$excluded.Count+$pending.Count) -ge 10000){throw 'Cleanup inventory budget exceeded.'}
                if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){$excluded.Add([pscustomobject]@{Path=$item.FullName;Reason='REPARSE_POINT'});continue}
                Assert-WinSecDeviceRemovalPath $root $item.FullName
                if($item.PSIsContainer){
                    $allowed=if($relative -ceq 'reports' -and $directory -ceq $base){$item.Name -ceq 'exports'}else{$item.Name -cmatch '\A[a-f0-9]{64}\z' -and ($directory -ceq $base -or $directory -ceq (Join-Path $base 'exports'))}
                    if($allowed){$pending.Push($item.FullName)}else{$excluded.Add([pscustomobject]@{Path=$item.FullName;Reason='PRESERVE_OTHER_STORAGE'})};continue
                }
                if($item.Name -ceq '.gitkeep'){$excluded.Add([pscustomobject]@{Path=$item.FullName;Reason='PLACEHOLDER'});continue}
                if($relative -ceq 'reports' -and [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($directory)) -cne 'exports'){$excluded.Add([pscustomobject]@{Path=$item.FullName;Reason='NOT_LEGACY_EXPORT'});continue}
                if($item.PSObject.Properties['LinkType'] -and $item.LinkType -ceq 'HardLink'){$excluded.Add([pscustomobject]@{Path=$item.FullName;Reason='HARD_LINK'});continue}
                if($item.Length -le 16777216){$readBytes+=$item.Length;if($readBytes -gt 67108864){throw 'Cleanup read budget exceeded.'}}
                $kind=$null;$owner=$null;$scanId=$null;$hash=$null
                try {
                    if($item.Length -gt 16777216){throw 'Unrecognized artifact size.'}
                    $hash=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                    $text=Get-Content -LiteralPath $item.FullName -Raw -Encoding UTF8 -ErrorAction Stop
                    if($relative -ceq 'data/scans'){
                        $r=(ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $text)).Record
                        $owner=$r.DeviceId;$scanId=$r.ScanId;$kind='LEGACY_PUBLIC_SESSION'
                        $expected=Join-Path $base ((Get-WinSecEvidenceHash $owner)+'/'+(Get-WinSecEvidenceHash $r.ScanId)+'.json')
                        if(-not [string]::Equals($expected,$item.FullName,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected public history path.'}
                    }elseif($text.StartsWith("<!-- WinSec technical report`n",[StringComparison]::Ordinal) -or $text.StartsWith("WinSec technical scan report`n",[StringComparison]::Ordinal)){
                        $metaText=($text -split "`n",3)[1];$meta=ConvertFrom-WinSecStoredJson $metaText;$owner=$meta.DeviceId
                        $report=ConvertFrom-WinSecTechnicalArtifact $text $owner -IncludeReport;$scanId=$report.ScanId;$kind='LEGACY_TECHNICAL'
                    }elseif($text.StartsWith("<!-- WinSec framework findings`n",[StringComparison]::Ordinal)){
                        $meta=ConvertFrom-WinSecStoredJson (($text -split "`n",3)[1]);$owner=$meta.DeviceId
                        $null=ConvertFrom-WinSecFrameworkMarkdownArtifact $text $owner;$kind='LEGACY_FINDINGS'
                    }else{throw 'Unrecognized legacy artifact.'}
                    if($relative -ceq 'reports'){
                        $expected=Join-Path $base ('exports/'+(Get-WinSecEvidenceHash $owner))
                        if(-not [string]::Equals([IO.Path]::GetDirectoryName($item.FullName),$expected,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected legacy report path.'}
                    }
                    if((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -cne $hash){throw 'Legacy artifact changed.'}
                    $files.Add([pscustomobject]@{Path=$item.FullName;Kind=$kind;Bytes=$item.Length;Sha256=$hash;DeviceId=$owner;ScanId=$scanId})
                }catch{$excluded.Add([pscustomobject]@{Path=$item.FullName;Reason='UNRECOGNIZED_OR_INVALID'})}
            }
        }
    }
    if((Get-WinSecDeviceInventoryFingerprint $root) -cne $inventoryHash){throw 'Device inventory changed during cleanup planning.'}
    $manifest=[pscustomobject]@{SchemaVersion='1.0.0';Operation='REMOVE_VERIFIED_LEGACY_RESULTS';ProjectRoot=$root;InventorySha256=$inventoryHash;
        Files=@($files.ToArray()|Sort-Object Path);Excluded=@($excluded.ToArray()|Sort-Object Path);Preserve=@('data/devices.json','data/.gitkeep','data/scans/.gitkeep','reports/.gitkeep','reports/exports/.gitkeep');RequiresConfirmation=$true}
    $digest=Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson $manifest)
    $manifest|Add-Member -NotePropertyName PlanSha256 -NotePropertyValue $digest
    return $manifest
}

function Remove-WinSecLegacyResults {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][scriptblock]$ConfirmAction,[AllowNull()][object]$Context)
    $verified=Assert-WinSecLegacyCleanupPlan $ProjectRoot $Plan
    $request=[pscustomobject]@{Operation=$verified.Operation;PlanSha256=$verified.PlanSha256;Files=$verified.Files;ReadOnlyWindows=$true;Irreversible=$true}
    $frozen=Get-WinSecPublicHistoryJson $request;$answer=& $ConfirmAction (Copy-WinSecResultData $request)
    if($answer -isnot [bool]){throw 'Invalid cleanup confirmation.'};if(-not $answer){return $null}
    if((Get-WinSecPublicHistoryJson $request) -cne $frozen){throw 'Cleanup confirmation was altered.'}
    $lease=$null;$handles=New-Object 'Collections.Generic.List[IDisposable]';$removed=New-Object 'Collections.Generic.List[string]'
    try {
        $lease=Open-WinSecDeviceInventoryStore $ProjectRoot;$null=Assert-WinSecLegacyCleanupPlan $ProjectRoot $verified
        Initialize-WinSecSnapshotFileIO
        $paths=@{};foreach($file in $verified.Files){$cursor=[IO.Path]::GetDirectoryName($file.Path);while($cursor){$paths[$cursor]=$true;$cursor=[IO.Path]::GetDirectoryName($cursor)}}
        foreach($directory in @($paths.Keys|Sort-Object Length)){$handles.Add([WinSec.SnapshotIO3]::HoldDirectory($directory))}
        foreach($file in $verified.Files){
            Assert-WinSecDeviceRemovalPath $ProjectRoot $file.Path
            $stream=[WinSec.SnapshotIO3]::OpenRemoval($file.Path)
            try {
                $sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')}finally{$sha.Dispose()}
                if($stream.Length -ne $file.Bytes -or $hash -cne $file.Sha256){throw 'Cleanup artifact changed.'}
                [WinSec.SnapshotIO3]::MarkRemoval($stream);$removed.Add($file.Path)
            }finally{$stream.Dispose()}
        }
        if((Get-WinSecDeviceInventoryFingerprint $ProjectRoot) -cne $verified.InventorySha256){throw 'Managed devices changed during cleanup.'}
        return [pscustomobject]@{Status='REMOVED';PlanSha256=$verified.PlanSha256;RemovedCount=$removed.Count}
    }catch{if(-not $removed.Count){throw 'Cleanup rejected before removal.'};return [pscustomobject]@{Status='INCOMPLETE';PlanSha256=$verified.PlanSha256;RemovedCount=$removed.Count}}
    finally{
        if($removed.Count -and $null -ne $Context){
            foreach($file in $verified.Files){
                if(-not $file.ScanId){continue};$key=Get-WinSecScanSessionKey $file.DeviceId $file.ScanId
                $Context.ScanCoordinator.Sessions.Remove($key)
                foreach($id in @(Get-WinSecTechnicalControls|ForEach-Object CheckId)){$Context.ScanCoordinator.TechnicalSnapshots.Remove($key+'|'+$id)}
                $publicKey='{0}:{1}{2}:{3}' -f $file.DeviceId.Length,$file.DeviceId,$file.ScanId.Length,$file.ScanId;$Context.PublicScans.Remove($publicKey)
                if($Context.ActiveScanByDevice[$file.DeviceId] -ceq $file.ScanId){$Context.ActiveScanByDevice.Remove($file.DeviceId)}
                $prefix='{0}:{1}' -f $file.DeviceId.Length,$file.DeviceId
                foreach($index in @($Context.ActiveScanByScope.Keys)){if($index.StartsWith($prefix,[StringComparison]::Ordinal) -and $Context.ActiveScanByScope[$index] -ceq $file.ScanId){$Context.ActiveScanByScope.Remove($index)}}
            }
            $Context|Add-Member FrameworkFindings $null -Force;$Context|Add-Member FrameworkSourcesStamp $null -Force
        }
        foreach($h in $handles){$h.Dispose()};if($lease){$lease.Lock.Dispose()}
    }
}

function Assert-WinSecLegacyCleanupPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Plan)
    $fresh=Get-WinSecLegacyCleanupPlan $ProjectRoot
    if((Get-WinSecPublicHistoryJson $fresh) -cne (Get-WinSecPublicHistoryJson $Plan)){throw 'Cleanup plan is stale or altered.'}
    return $fresh
}
