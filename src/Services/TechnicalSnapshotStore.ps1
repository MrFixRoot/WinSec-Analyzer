# Stage 2, intentionally not connected to ScanCoordinator, startup, F/P or device removal.
. (Join-Path $PSScriptRoot '../Core/TechnicalSnapshotPaths.ps1')
. (Join-Path $PSScriptRoot '../Core/TechnicalSnapshotFileIO.ps1')
. (Join-Path $PSScriptRoot 'TechnicalSnapshotMarkdown.ps1')

function Get-WinSecSnapshotByteHash {
    param([byte[]]$Bytes)
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','')}finally{$sha.Dispose()}
}

function Get-WinSecSnapshotPairLayout {
    param([string]$ProjectRoot,[object]$Identity,[string]$CollectedAtUTC)
    Assert-WinSecSnapshotIdentity $Identity
    $date=ConvertTo-WinSecSnapshotUtc $CollectedAtUTC;$control=Get-WinSecSnapshotControl $Identity.CheckId
    $key=Get-WinSecSnapshotDeviceKey $Identity.DeviceId;$stem=$date.ToString('yyyyMMddTHHmmssfffffffZ',[Globalization.CultureInfo]::InvariantCulture)+$control.ControlName+'_'+$Identity.SnapshotId
    $scan='scans/'+$key+'/'+$Identity.SectionKey+'/';$report='reports/'+$key+'/'+$Identity.SectionKey+'/'
    $result=[ordered]@{DeviceKey=$key;SectionKey=$Identity.SectionKey}
    foreach($entry in @(@('Json',($scan+$stem+'.json')),@('Markdown',($report+$stem+'.md')),@('Intent',($scan+$Identity.SnapshotId+'.pair')),
        @('Commit',($scan+$Identity.SnapshotId+'.commit')),@('Lock',($scan+'.l'+$Identity.SnapshotId+'.tmp')),
        @('JsonTemp',($scan+'.j'+$Identity.SnapshotId+'.tmp')),@('MarkdownTemp',($report+'.m'+$Identity.SnapshotId+'.tmp')),
        @('IntentTemp',($scan+'.p'+$Identity.SnapshotId+'.tmp')),@('CommitTemp',($scan+'.c'+$Identity.SnapshotId+'.tmp')))){
        $result[$entry[0]]=Assert-WinSecSnapshotStoragePath $ProjectRoot $entry[1] -AllowExistingArtifact
    }
    return [pscustomobject]$result
}

function ConvertFrom-WinSecSnapshotPairJson {
    param([string]$Json)
    if([Text.Encoding]::UTF8.GetByteCount($Json) -gt 16384){throw 'Pair manifest budget exceeded.'}
    Assert-WinSecSnapshotJsonBudget $Json
    . (Join-Path $PSScriptRoot '../Core/DeviceInventory.ps1')
    $jsonReader=Get-Command Microsoft.PowerShell.Utility\ConvertFrom-Json -CommandType Cmdlet
    if($jsonReader.Parameters.ContainsKey('DateKind')){
        function ConvertFrom-WinSecPairString {param($InputObject);& $jsonReader -InputObject $InputObject -DateKind String -ErrorAction Stop}
        Set-Alias ConvertFrom-Json ConvertFrom-WinSecPairString -Scope Local
    }
    return ConvertFrom-WinSecBoundedStoredJson $Json
}

function Assert-WinSecSnapshotPairManifest {
    param([object]$Manifest,[object]$Identity,[string]$CollectedAtUTC,[string]$CatalogSha256,[string]$State)
    Assert-WinSecSnapshotFields $Manifest @('ArtifactType','SchemaVersion','State','Identity','CollectedAtUTC','CatalogSha256','JsonSha256','MarkdownSha256','JsonBytes','MarkdownBytes')
    foreach($name in @('ArtifactType','SchemaVersion','State','CollectedAtUTC','CatalogSha256','JsonSha256','MarkdownSha256')){if($Manifest.$name -isnot [string]){throw 'Invalid pair metadata.'}}
    if($Manifest.ArtifactType -cne 'WinSec.TechnicalSnapshotPair' -or $Manifest.SchemaVersion -cne '1.0.0' -or $Manifest.State -cne $State -or
        $Manifest.CollectedAtUTC -cne $CollectedAtUTC -or $Manifest.CatalogSha256 -cne $CatalogSha256 -or
        $Manifest.JsonSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or $Manifest.MarkdownSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        -not (Test-WinSecSnapshotUInt $Manifest.JsonBytes 16777216) -or $Manifest.JsonBytes -lt 1 -or
        -not (Test-WinSecSnapshotUInt $Manifest.MarkdownBytes 33554432) -or $Manifest.MarkdownBytes -lt 1){throw 'Pair manifest mismatch.'}
    Assert-WinSecSnapshotIdentity $Manifest.Identity
    foreach($p in $Identity.PSObject.Properties){if($Manifest.Identity.($p.Name) -cne $p.Value){throw 'Foreign snapshot pair.'}}
}

function Read-WinSecSnapshotPairManifest {
    param([string]$Path,[object]$Identity,[string]$CollectedAtUTC,[string]$CatalogSha256,[string]$State)
    $bytes=Read-WinSecSnapshotBytes $Path 16384
    $utf8=New-Object Text.UTF8Encoding($false,$true)
    $manifest=ConvertFrom-WinSecSnapshotPairJson ($utf8.GetString($bytes))
    Assert-WinSecSnapshotPairManifest $manifest $Identity $CollectedAtUTC $CatalogSha256 $State
    return $manifest
}

function Assert-WinSecSnapshotPairAgreement {
    param([object]$Prepared,[object]$Committed)
    foreach($name in @('JsonSha256','MarkdownSha256','JsonBytes','MarkdownBytes')){if($Prepared.$name -cne $Committed.$name){throw 'Pair markers disagree.'}}
}

function Send-WinSecSnapshotStoreProgress {
    param([string]$Stage,[scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    if($CancellationAction){$c=& $CancellationAction;if($c -isnot [bool]){throw 'Invalid cancellation response.'};if($c){throw [OperationCanceledException]::new('Snapshot persistence cancelled.')}}
    if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage=$Stage})}
}

function Write-WinSecTechnicalSnapshotPair {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$Snapshot,[object]$Catalog,[string]$CatalogSha256,[object]$ExpectedIdentity,
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    $held=$null;$lock=$null
    try {
        Send-WinSecSnapshotStoreProgress 'VALIDATING' $ProgressCallback $CancellationAction
        Assert-WinSecTechnicalSnapshot $Snapshot $Catalog $CatalogSha256 $ExpectedIdentity -CancellationAction $CancellationAction
        # Freeze one normalized source for both artifacts before touching storage.
        $json=ConvertTo-Json -InputObject $Snapshot -Depth 16 -Compress
        $source=ConvertFrom-WinSecTechnicalSnapshotJson $json $Catalog $CatalogSha256 $ExpectedIdentity -CancellationAction $CancellationAction
        $markdown=ConvertTo-WinSecSnapshotMarkdown $source $Catalog $CatalogSha256 $ExpectedIdentity -CancellationAction $CancellationAction
        $utf8=New-Object Text.UTF8Encoding($false,$true);$jb=$utf8.GetBytes($json);$mb=$utf8.GetBytes($markdown)
        $layout=Get-WinSecSnapshotPairLayout $ProjectRoot $ExpectedIdentity $source.CollectedAtUTC
        $drive=New-Object IO.DriveInfo([IO.Path]::GetPathRoot($layout.Json))
        if($drive.AvailableFreeSpace -lt ($jb.Length+$mb.Length+67108864)){throw 'Insufficient snapshot storage space.'}
        $held=Open-WinSecSnapshotDirectories $ProjectRoot $layout -Create
        $lock=[WinSec.SnapshotIO2]::Lock($layout.Lock)
        foreach($name in @('Json','Markdown','Intent','Commit','JsonTemp','MarkdownTemp','IntentTemp','CommitTemp')){
            if([IO.File]::Exists($layout.$name)){throw 'Snapshot publication collision.'}
        }
        $manifest=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshotPair';SchemaVersion='1.0.0';State='PREPARED';Identity=$source.Identity
            CollectedAtUTC=$source.CollectedAtUTC;CatalogSha256=$CatalogSha256;JsonSha256=Get-WinSecSnapshotByteHash $jb;MarkdownSha256=Get-WinSecSnapshotByteHash $mb;JsonBytes=$jb.Length;MarkdownBytes=$mb.Length}
        Write-WinSecSnapshotBytes $layout.IntentTemp ($utf8.GetBytes((ConvertTo-Json -InputObject $manifest -Depth 8 -Compress))) $CancellationAction
        [WinSec.SnapshotIO2]::MoveExclusive($layout.IntentTemp,$layout.Intent)
        Send-WinSecSnapshotStoreProgress 'PREPARED' $ProgressCallback $CancellationAction
        Write-WinSecSnapshotBytes $layout.JsonTemp $jb $CancellationAction
        Send-WinSecSnapshotStoreProgress 'JSON_STAGED' $ProgressCallback $CancellationAction
        Write-WinSecSnapshotBytes $layout.MarkdownTemp $mb $CancellationAction
        Send-WinSecSnapshotStoreProgress 'MARKDOWN_STAGED' $ProgressCallback $CancellationAction
        Complete-WinSecSnapshotPublication $ProjectRoot $layout $manifest $Catalog $CatalogSha256 $ExpectedIdentity $CancellationAction $ProgressCallback
        return [pscustomobject]@{PublicationStatus='COMMITTED';CollectionStatus=$source.Collection.Status;JsonPath=$layout.Json;MarkdownPath=$layout.Markdown;CommitPath=$layout.Commit}
    }catch{if($_.Exception -is [OperationCanceledException]){throw};throw 'Technical snapshot persistence failed; publication requires inspection.'}
    finally{if($lock){$lock.Dispose()};if($held){foreach($h in $held){$h.Dispose()}}}
}

function Get-WinSecSnapshotPublicationData {
    param([object]$Layout,[object]$Manifest,[object]$Catalog,[string]$CatalogSha256,[object]$Identity,[switch]$AllowStaged,[scriptblock]$CancellationAction)
    $data=@{}
    foreach($kind in @('Json','Markdown')){
        $path=$Layout.$kind
        if(-not [IO.File]::Exists($path)){
            if(-not $AllowStaged -or -not [IO.File]::Exists($Layout.($kind+'Temp'))){return $null}
            $path=$Layout.($kind+'Temp')
        }
        $limit=if($kind -ceq 'Json'){16777216}else{33554432}
        $bytes=Read-WinSecSnapshotBytes $path $limit $CancellationAction
        if($bytes.Length -ne $Manifest.($kind+'Bytes') -or (Get-WinSecSnapshotByteHash $bytes) -cne $Manifest.($kind+'Sha256')){throw 'Corrupt snapshot artifact.'}
        $data[$kind]=$bytes
    }
    $utf8=New-Object Text.UTF8Encoding($false,$true)
    $snapshot=ConvertFrom-WinSecTechnicalSnapshotJson ($utf8.GetString($data.Json)) $Catalog $CatalogSha256 $Identity -CancellationAction $CancellationAction
    if($snapshot.CollectedAtUTC -cne $Manifest.CollectedAtUTC){throw 'Snapshot collection timestamp mismatch.'}
    $md=ConvertTo-WinSecSnapshotMarkdown $snapshot $Catalog $CatalogSha256 $Identity -CancellationAction $CancellationAction
    if((Get-WinSecSnapshotByteHash ($utf8.GetBytes($md))) -cne $Manifest.MarkdownSha256){throw 'Technical Markdown does not match snapshot.'}
    return $snapshot
}

function Complete-WinSecSnapshotPublication {
    param([string]$ProjectRoot,[object]$Layout,[object]$Manifest,[object]$Catalog,[string]$CatalogSha256,[object]$Identity,
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    $source=Get-WinSecSnapshotPublicationData $Layout $Manifest $Catalog $CatalogSha256 $Identity -AllowStaged -CancellationAction $CancellationAction
    if($null -eq $source){throw 'Incomplete snapshot publication.'}
    foreach($kind in @('Json','Markdown')){
        Send-WinSecSnapshotStoreProgress ('PUBLISHING_'+$kind.ToUpperInvariant()) $ProgressCallback $CancellationAction
        if(-not [IO.File]::Exists($Layout.$kind)){[WinSec.SnapshotIO2]::MoveExclusive($Layout.($kind+'Temp'),$Layout.$kind)}
        Send-WinSecSnapshotStoreProgress ($kind.ToUpperInvariant()+'_PUBLISHED') $ProgressCallback $CancellationAction
    }
    $null=Get-WinSecSnapshotPublicationData $Layout $Manifest $Catalog $CatalogSha256 $Identity -CancellationAction $CancellationAction
    Send-WinSecSnapshotStoreProgress 'COMMITTING' $ProgressCallback $CancellationAction
    $commit=$Manifest.PSObject.Copy();$commit.State='COMMITTED';$utf8=New-Object Text.UTF8Encoding($false,$true)
    $bytes=$utf8.GetBytes((ConvertTo-Json -InputObject $commit -Depth 8 -Compress))
    if([IO.File]::Exists($Layout.CommitTemp)){
        $old=Read-WinSecSnapshotBytes $Layout.CommitTemp 16384
        if((Get-WinSecSnapshotByteHash $old) -cne (Get-WinSecSnapshotByteHash $bytes)){throw 'Incomplete commit marker.'}
    }else{Write-WinSecSnapshotBytes $Layout.CommitTemp $bytes $CancellationAction}
    Send-WinSecSnapshotStoreProgress 'COMMIT_STAGED' $ProgressCallback $CancellationAction
    [WinSec.SnapshotIO2]::MoveExclusive($Layout.CommitTemp,$Layout.Commit)
    # Commit is the linearization point. Cancellation after this point cannot undo publication.
}

function Read-WinSecTechnicalSnapshotPair {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$ExpectedIdentity,[string]$CollectedAtUTC,[object]$Catalog,[string]$CatalogSha256,[scriptblock]$CancellationAction)
    $held=$null
    try {
        Assert-WinSecSnapshotCatalog $Catalog
        if((Get-WinSecSnapshotCatalogHash $Catalog) -cne $CatalogSha256){throw 'Catalog digest mismatch.'}
        $layout=Get-WinSecSnapshotPairLayout $ProjectRoot $ExpectedIdentity $CollectedAtUTC
        # No directory creation or scan; inspect this exact pair only.
        $held=Open-WinSecSnapshotDirectories $ProjectRoot $layout
        $intent=Read-WinSecSnapshotPairManifest $layout.Intent $ExpectedIdentity $CollectedAtUTC $CatalogSha256 PREPARED
        if(-not [IO.File]::Exists($layout.Commit)){
            $source=Get-WinSecSnapshotPublicationData $layout $intent $Catalog $CatalogSha256 $ExpectedIdentity -AllowStaged -CancellationAction $CancellationAction
            if([IO.File]::Exists($layout.CommitTemp)){
                $pending=Read-WinSecSnapshotPairManifest $layout.CommitTemp $ExpectedIdentity $CollectedAtUTC $CatalogSha256 COMMITTED
                Assert-WinSecSnapshotPairAgreement $intent $pending
            }
            return [pscustomobject]@{PublicationStatus=$(if($source){'RECOVERABLE'}else{'INCOMPLETE'});Snapshot=$null}
        }
        $commit=Read-WinSecSnapshotPairManifest $layout.Commit $ExpectedIdentity $CollectedAtUTC $CatalogSha256 COMMITTED
        Assert-WinSecSnapshotPairAgreement $intent $commit
        $source=Get-WinSecSnapshotPublicationData $layout $commit $Catalog $CatalogSha256 $ExpectedIdentity -CancellationAction $CancellationAction
        if($null -eq $source){throw 'Committed pair is incomplete.'}
        return [pscustomobject]@{PublicationStatus='COMMITTED';Snapshot=$source;JsonPath=$layout.Json;MarkdownPath=$layout.Markdown}
    }catch{if($_.Exception -is [OperationCanceledException]){throw};throw 'Technical snapshot publication is missing, unsafe or invalid.'}
    finally{if($held){foreach($h in $held){$h.Dispose()}}}
}

function Repair-WinSecTechnicalSnapshotPair {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$ExpectedIdentity,[string]$CollectedAtUTC,[object]$Catalog,[string]$CatalogSha256,
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    $held=$null;$lock=$null
    try {
        $layout=Get-WinSecSnapshotPairLayout $ProjectRoot $ExpectedIdentity $CollectedAtUTC
        $held=Open-WinSecSnapshotDirectories $ProjectRoot $layout;$lock=[WinSec.SnapshotIO2]::Lock($layout.Lock)
        if([IO.File]::Exists($layout.Commit)){return Read-WinSecTechnicalSnapshotPair $ProjectRoot $ExpectedIdentity $CollectedAtUTC $Catalog $CatalogSha256 -CancellationAction $CancellationAction}
        $intent=Read-WinSecSnapshotPairManifest $layout.Intent $ExpectedIdentity $CollectedAtUTC $CatalogSha256 PREPARED
        Complete-WinSecSnapshotPublication $ProjectRoot $layout $intent $Catalog $CatalogSha256 $ExpectedIdentity $CancellationAction $ProgressCallback
        return Read-WinSecTechnicalSnapshotPair $ProjectRoot $ExpectedIdentity $CollectedAtUTC $Catalog $CatalogSha256 -CancellationAction {$false}
    }catch{if($_.Exception -is [OperationCanceledException]){throw};throw 'Technical snapshot recovery rejected; existing artifacts were preserved.'}
    finally{if($lock){$lock.Dispose()};if($held){foreach($h in $held){$h.Dispose()}}}
}

function Get-WinSecTechnicalSnapshotRemovalPlan {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$ExpectedIdentity,[string]$CollectedAtUTC,[object]$Catalog,[string]$CatalogSha256)
    # Plan only: no deletion, no recursion, no changes to legacy/device-management flows.
    $held=$null
    try {
        $layout=Get-WinSecSnapshotPairLayout $ProjectRoot $ExpectedIdentity $CollectedAtUTC
        $held=Open-WinSecSnapshotDirectories $ProjectRoot $layout
        $state=Read-WinSecTechnicalSnapshotPair $ProjectRoot $ExpectedIdentity $CollectedAtUTC $Catalog $CatalogSha256
        if($state.PublicationStatus -ceq 'INCOMPLETE'){throw 'Cannot prove ownership of incomplete bytes.'}
        $intent=Read-WinSecSnapshotPairManifest $layout.Intent $ExpectedIdentity $CollectedAtUTC $CatalogSha256 PREPARED
        $files=New-Object 'Collections.Generic.List[object]'
        foreach($name in @('Json','Markdown','Intent','Commit','JsonTemp','MarkdownTemp','CommitTemp')){
            if(-not [IO.File]::Exists($layout.$name)){continue}
            $bytes=Read-WinSecSnapshotBytes $layout.$name $(if($name -like 'Markdown*'){33554432}elseif($name -like 'Json*'){16777216}else{16384})
            $hash=Get-WinSecSnapshotByteHash $bytes
            if($name -like 'Json*' -and $hash -cne $intent.JsonSha256){throw 'Unknown JSON candidate.'}
            if($name -like 'Markdown*' -and $hash -cne $intent.MarkdownSha256){throw 'Unknown Markdown candidate.'}
            if($name -ceq 'CommitTemp'){$pending=Read-WinSecSnapshotPairManifest $layout.$name $ExpectedIdentity $CollectedAtUTC $CatalogSha256 COMMITTED;Assert-WinSecSnapshotPairAgreement $intent $pending}
            $files.Add([pscustomobject]@{Path=$layout.$name;Sha256=$hash;Bytes=$bytes.Length})
        }
        return [pscustomobject]@{SchemaVersion='1.0.0';DeviceId=$ExpectedIdentity.DeviceId;SnapshotId=$ExpectedIdentity.SnapshotId;PublicationStatus=$state.PublicationStatus;Files=$files.ToArray();RequiresConfirmation=$true}
    }finally{if($held){foreach($h in $held){$h.Dispose()}}}
}
