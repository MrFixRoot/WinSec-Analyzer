# Isolated stage 3 storage. Never imported by production indexes, startup, F or P.
. (Join-Path $PSScriptRoot 'TechnicalSourceSession.ps1')
. (Join-Path $PSScriptRoot '../Core/DeviceInventory.ps1')

function Resolve-WinSecTechnicalSessionStorageFormat {
    param([object]$ArtifactType,[object]$SchemaVersion)
    if($ArtifactType -isnot [string] -or $SchemaVersion -isnot [string] -or
        $ArtifactType -cne 'WinSec.TechnicalSourceSession' -or $SchemaVersion -cne '1.0.0'){
        throw 'Unknown technical session storage type or version.'
    }
    [pscustomobject]@{ArtifactType=$ArtifactType;SchemaVersion=$SchemaVersion;Directory='technical-sessions';MaxBytes=16384}
}

function Get-WinSecTechnicalSessionStorageLayout {
    param([string]$ProjectRoot,[object]$ExpectedIdentity)
    $owner=Copy-WinSecTechnicalSessionIdentity $ExpectedIdentity;$key=Get-WinSecSnapshotDeviceKey $owner.DeviceId
    if($owner.ScanId -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z'){throw 'Invalid technical session scan identity.'}
    $control=Get-WinSecSnapshotControl 'WSA-SYS-001'
    switch -CaseSensitive ($owner.ScopeType){
        CONTROL {if($owner.ScopeKey -cne $control.CheckId){throw 'Foreign technical session control scope.'}}
        SECTION {if($owner.ScopeKey -cne $control.SectionKey){throw 'Foreign technical session section scope.'}}
        DEVICE {if($owner.ScopeKey -cne 'ALL'){throw 'Foreign technical session device scope.'}}
        default {throw 'Unknown technical session scope.'}
    }
    $format=Resolve-WinSecTechnicalSessionStorageFormat 'WinSec.TechnicalSourceSession' '1.0.0'
    $stem=(Get-WinSecSnapshotByteHash ([Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $owner)))).ToLowerInvariant()
    $relative='scans/'+$key+'/'+$format.Directory+'/'+$stem+'.json'
    [pscustomobject]@{DeviceKey=$key;Directory=$format.Directory;Identity=$owner;
        Path=(Assert-WinSecSnapshotStoragePath $ProjectRoot $relative -AllowExistingArtifact);
        Temporary=(Assert-WinSecSnapshotStoragePath $ProjectRoot ($relative+'.tmp') -AllowExistingArtifact)}
}

function Open-WinSecTechnicalSessionDirectories {
    param([string]$ProjectRoot,[object]$Layout,[switch]$Create)
    Initialize-WinSecSnapshotFileIO;$held=New-Object 'Collections.Generic.List[IDisposable]'
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sddl='O:'+$sid+'D:P(A;OICI;FA;;;'+$sid+')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    try{
        $parents=New-Object 'Collections.Generic.List[string]';$cursor=[IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
        while($cursor){$parents.Insert(0,$cursor);$cursor=[IO.Path]::GetDirectoryName($cursor)}
        foreach($parent in $parents){$held.Add([WinSec.SnapshotIO3]::HoldDirectory($parent))}
        $dir=[IO.Path]::GetFullPath($ProjectRoot)
        foreach($segment in @('scans',$Layout.DeviceKey,$Layout.Directory)){
            $dir=Join-Path $dir $segment
            if($Create){[WinSec.SnapshotIO3]::CreatePrivateDirectory($dir,$sddl)}
            $held.Add([WinSec.SnapshotIO3]::HoldDirectory($dir))
            if($segment -cne 'scans'){Assert-WinSecSnapshotPrivateAcl $dir -Directory}
        };return ,$held
    }catch{foreach($h in $held){$h.Dispose()};throw 'Cannot secure technical session directories.'}
}

function Open-WinSecTechnicalSessionOwner {
    param([string]$ProjectRoot,[object]$Identity)
    $lease=Open-WinSecDeviceInventoryStore $ProjectRoot
    try{
        $fingerprint=Get-WinSecDeviceInventoryFingerprint $ProjectRoot
        $inventory=Import-WinSecDeviceInventory $ProjectRoot
        if(@($inventory.targets|Where-Object DeviceId -CEQ $Identity.DeviceId).Count -ne 1 -or
            (Test-WinSecDeviceInventoryRemoval $inventory $Identity.DeviceId)){throw 'Technical session owner is not managed.'}
        if((Get-WinSecDeviceInventoryFingerprint $ProjectRoot) -cne $fingerprint){throw 'Technical session inventory changed.'}
        $lease|Add-Member -NotePropertyName InventorySha256 -NotePropertyValue $fingerprint
        return $lease
    }catch{$lease.Lock.Dispose();throw 'Technical session owner is missing, removed or invalid.'}
}

function Assert-WinSecTechnicalSessionOwnerUnchanged {
    param([object]$Lease)
    if((Get-WinSecDeviceInventoryFingerprint $Lease.ProjectRoot) -cne $Lease.InventorySha256){throw 'Technical session inventory changed during storage.'}
}

function Open-WinSecTechnicalSessionSourceLeases {
    param([string]$ProjectRoot,[object]$Session)
    $held=New-Object 'Collections.Generic.List[IDisposable]'
    try{
        foreach($entry in $Session.Sources){
            $ref=$entry.Reference;$layout=Get-WinSecSnapshotPairLayout $ProjectRoot $ref.Identity $ref.CollectedAtUTC
            $directories=Open-WinSecSnapshotDirectories $ProjectRoot $layout
            foreach($directory in $directories){$held.Add($directory)}
            foreach($name in @('Intent','Commit','Json','Markdown')){$held.Add([WinSec.SnapshotIO3]::Read($layout.$name))}
        };return ,$held
    }catch{foreach($handle in $held){$handle.Dispose()};throw 'Cannot hold technical session sources.'}
}

function Open-WinSecStoredTechnicalSession {
    param([string]$ProjectRoot,[string]$Path,[object]$Identity,[object]$ExpectedContentSha256,[scriptblock]$CancellationAction)
    $stream=$null;$sources=$null
    try{
        if($null -ne $ExpectedContentSha256 -and ($ExpectedContentSha256 -isnot [string] -or $ExpectedContentSha256 -cnotmatch '\A[A-F0-9]{64}\z')){
            throw 'Invalid expected technical session digest.'
        }
        $stream=[WinSec.SnapshotIO3]::Read($Path)
        $bytes=Read-WinSecSnapshotBytes $Path 16384 $CancellationAction;$utf8=New-Object Text.UTF8Encoding($false,$true)
        $session=ConvertFrom-WinSecSnapshotPairJson ($utf8.GetString($bytes))
        Assert-WinSecSnapshotFields $session @('ArtifactType','SchemaVersion','Identity','Sources','ContentSha256')
        $null=Resolve-WinSecTechnicalSessionStorageFormat $session.ArtifactType $session.SchemaVersion
        Assert-WinSecTechnicalSourceSession $session $Identity
        if($null -ne $ExpectedContentSha256 -and $session.ContentSha256 -cne $ExpectedContentSha256){throw 'Foreign technical session content.'}
        if((Get-WinSecSnapshotByteHash $bytes) -cne (Get-WinSecSnapshotByteHash ($utf8.GetBytes((Get-WinSecPublicHistoryJson $session))))){
            throw 'Noncanonical or altered technical session bytes.'
        }
        $sources=Open-WinSecTechnicalSessionSourceLeases $ProjectRoot $session
        $frozen=Resolve-WinSecTechnicalSourceSession $ProjectRoot $session $Identity -CancellationAction $CancellationAction
        return [pscustomobject]@{Session=$frozen;FileSha256=(Get-WinSecSnapshotByteHash $bytes);FileLease=$stream;SourceLeases=$sources}
    }catch{
        if($stream){$stream.Dispose()};if($sources){foreach($h in $sources){$h.Dispose()}}
        if($_.Exception -is [OperationCanceledException]){throw}
        throw 'Stored technical session or its sources are unsafe, incomplete or invalid.'
    }
}

function Close-WinSecStoredTechnicalSession {
    param([object]$Opened)
    if($Opened){if($Opened.FileLease){$Opened.FileLease.Dispose()};if($Opened.SourceLeases){foreach($h in $Opened.SourceLeases){$h.Dispose()}}}
}

function Send-WinSecTechnicalSessionStorageProgress {
    param([string]$Phase,[int]$Completed,[scriptblock]$ProgressCallback,[scriptblock]$CancellationAction,[Diagnostics.Stopwatch]$Clock)
    Assert-WinSecSnapshotValidationBudget $Clock $CancellationAction
    if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Activity='TECHNICAL_SESSION_STORAGE';Phase=$Phase;Completed=$Completed;Total=3;CanCancel=$true})}
    Assert-WinSecSnapshotValidationBudget $Clock $CancellationAction
}

function Read-WinSecTechnicalSourceSession {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$ExpectedIdentity,[object]$ExpectedContentSha256=$null,[scriptblock]$CancellationAction,
        [object]$ArtifactType='WinSec.TechnicalSourceSession',[object]$SchemaVersion='1.0.0')
    $null=Resolve-WinSecTechnicalSessionStorageFormat $ArtifactType $SchemaVersion
    $layout=Get-WinSecTechnicalSessionStorageLayout $ProjectRoot $ExpectedIdentity;$lease=$null;$held=$null;$opened=$null
    $clock=[Diagnostics.Stopwatch]::StartNew();Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    try{
        $lease=Open-WinSecTechnicalSessionOwner $ProjectRoot $layout.Identity
        $held=Open-WinSecTechnicalSessionDirectories $ProjectRoot $layout
        if([IO.File]::Exists($layout.Temporary)){throw 'Pending technical session requires explicit recovery.'}
        $opened=Open-WinSecStoredTechnicalSession $ProjectRoot $layout.Path $layout.Identity $ExpectedContentSha256 $CancellationAction
        Assert-WinSecSnapshotValidationBudget $clock $null
        Assert-WinSecTechnicalSessionOwnerUnchanged $lease
        [pscustomobject]@{PublicationStatus='COMMITTED';Path=$layout.Path;Session=$opened.Session;FileSha256=$opened.FileSha256}
    }finally{Close-WinSecStoredTechnicalSession $opened;if($held){foreach($h in $held){$h.Dispose()}};if($lease){$lease.Lock.Dispose()}}
}

function Write-WinSecTechnicalSourceSession {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$Session,[object]$ExpectedIdentity,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    $owner=Copy-WinSecTechnicalSessionIdentity $ExpectedIdentity
    $json=ConvertTo-WinSecTechnicalSourceSessionJson $Session $owner
    $frozen=ConvertFrom-WinSecTechnicalSourceSessionJson $json $owner
    $null=Resolve-WinSecTechnicalSessionStorageFormat $frozen.ArtifactType $frozen.SchemaVersion
    $layout=Get-WinSecTechnicalSessionStorageLayout $ProjectRoot $owner;$bytes=[Text.Encoding]::UTF8.GetBytes($json)
    $clock=[Diagnostics.Stopwatch]::StartNew();$lease=$null;$held=$null;$opened=$null
    Send-WinSecTechnicalSessionStorageProgress 'VALIDATING' 0 $ProgressCallback $CancellationAction $clock
    try{
        $lease=Open-WinSecTechnicalSessionOwner $ProjectRoot $layout.Identity
        $held=Open-WinSecTechnicalSessionDirectories $ProjectRoot $layout -Create
        if([IO.File]::Exists($layout.Path) -or [IO.File]::Exists($layout.Temporary)){throw 'Technical session collision or pending publication.'}
        Write-WinSecSnapshotBytes $layout.Temporary $bytes $CancellationAction
        Send-WinSecTechnicalSessionStorageProgress 'STAGED' 1 $ProgressCallback $CancellationAction $clock
        Send-WinSecTechnicalSessionStorageProgress 'VERIFYING' 2 $ProgressCallback $CancellationAction $clock
        $opened=Open-WinSecStoredTechnicalSession $ProjectRoot $layout.Temporary $owner $frozen.ContentSha256 $CancellationAction
        if($opened.FileSha256 -cne (Get-WinSecSnapshotByteHash $bytes)){throw 'Staged technical session differs from its frozen input.'}
        Assert-WinSecSnapshotValidationBudget $clock $null
        Assert-WinSecTechnicalSessionOwnerUnchanged $lease
        # Exclusive rename is the single-file commit. No caller callbacks between verification and rename.
        $opened.FileLease.Dispose();$opened.FileLease=$null
        [WinSec.SnapshotIO3]::MoveExclusive($layout.Temporary,$layout.Path)
        $opened.FileLease=[WinSec.SnapshotIO3]::Read($layout.Path)
        $saved=Read-WinSecSnapshotBytes $layout.Path 16384
        if((Get-WinSecSnapshotByteHash $saved) -cne $opened.FileSha256){throw 'Published technical session verification failed.'}
        if($ProgressCallback){try{$null=& $ProgressCallback ([pscustomobject]@{Activity='TECHNICAL_SESSION_STORAGE';Phase='COMMITTED';Completed=3;Total=3;CanCancel=$false})}catch{}}
        [pscustomobject]@{PublicationStatus='COMMITTED';Path=$layout.Path;Session=$opened.Session;FileSha256=$opened.FileSha256}
    }finally{
        # Preserve staged bytes on failure/cancel/crash. Only explicit digest-pinned recovery may publish them.
        Close-WinSecStoredTechnicalSession $opened;if($held){foreach($h in $held){$h.Dispose()}};if($lease){$lease.Lock.Dispose()}
    }
}

function Repair-WinSecTechnicalSourceSession {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$ExpectedIdentity,[Parameter(Mandatory)][object]$ExpectedContentSha256,
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback,
        [object]$ArtifactType='WinSec.TechnicalSourceSession',[object]$SchemaVersion='1.0.0')
    $null=Resolve-WinSecTechnicalSessionStorageFormat $ArtifactType $SchemaVersion
    if($ExpectedContentSha256 -isnot [string] -or $ExpectedContentSha256 -cnotmatch '\A[A-F0-9]{64}\z'){throw 'Recovery requires the exact expected digest.'}
    $layout=Get-WinSecTechnicalSessionStorageLayout $ProjectRoot $ExpectedIdentity;$lease=$null;$held=$null;$opened=$null
    $clock=[Diagnostics.Stopwatch]::StartNew();Send-WinSecTechnicalSessionStorageProgress 'RECOVERING' 0 $ProgressCallback $CancellationAction $clock
    try{
        $lease=Open-WinSecTechnicalSessionOwner $ProjectRoot $layout.Identity
        $held=Open-WinSecTechnicalSessionDirectories $ProjectRoot $layout
        $exists=[IO.File]::Exists($layout.Path)
        if($exists -and [IO.File]::Exists($layout.Temporary)){throw 'Conflicting technical session publications.'}
        $path=if($exists){$layout.Path}else{$layout.Temporary}
        $opened=Open-WinSecStoredTechnicalSession $ProjectRoot $path $layout.Identity $ExpectedContentSha256 $CancellationAction
        Assert-WinSecSnapshotValidationBudget $clock $null
        Assert-WinSecTechnicalSessionOwnerUnchanged $lease
        if(-not $exists){
            $opened.FileLease.Dispose();$opened.FileLease=$null
            [WinSec.SnapshotIO3]::MoveExclusive($layout.Temporary,$layout.Path)
            $opened.FileLease=[WinSec.SnapshotIO3]::Read($layout.Path)
            if((Get-WinSecSnapshotByteHash (Read-WinSecSnapshotBytes $layout.Path 16384)) -cne $opened.FileSha256){throw 'Recovered technical session verification failed.'}
        }
        if($ProgressCallback){try{$null=& $ProgressCallback ([pscustomobject]@{Activity='TECHNICAL_SESSION_STORAGE';Phase='COMMITTED';Completed=3;Total=3;CanCancel=$false})}catch{}}
        [pscustomobject]@{PublicationStatus='COMMITTED';Path=$layout.Path;Session=$opened.Session;FileSha256=$opened.FileSha256}
    }finally{Close-WinSecStoredTechnicalSession $opened;if($held){foreach($h in $held){$h.Dispose()}};if($lease){$lease.Lock.Dispose()}}
}
