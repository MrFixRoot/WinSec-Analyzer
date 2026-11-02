[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceSessionStore.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$counter=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wst-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-SSI {param([bool]$Value);if(-not $Value){throw 'Technical session storage integration assertion failed.'}}
function Reject-SSI {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SSI $caught}
function Test-SSI {param([string]$Case,[scriptblock]$Action)
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
function New-SSI {
    param([string]$Family='CANDIDATE',[string]$Scope='CONTROL')
    $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x4');$null=[IO.Directory]::CreateDirectory($dir)
    $core=Join-Path $dir 'src/Core';$null=[IO.Directory]::CreateDirectory($core)
    Copy-Item -LiteralPath (Join-Path $root 'src/Core/TargetRegistry.ps1') -Destination (Join-Path $core 'TargetRegistry.ps1')
    $f=New-WinSecTechnicalSourceFixture -Family $Family -ScopeType $Scope
    $null=Save-WinSecTechnicalSourceFixture $dir $f
    $owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$f.Identity.ScanId;ScopeType=$f.Identity.ScopeType;ScopeKey=$f.Identity.ScopeKey}
    $stamp=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
    $s=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
        [pscustomobject]@{Reference=$stamp.Reference;SnapshotSha256=$stamp.SnapshotSha256;Collection=$f.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
    $s.ContentSha256=Get-WinSecTechnicalSessionDigest $s;Assert-WinSecTechnicalSourceSession $s $owner
    $null=[IO.Directory]::CreateDirectory((Join-Path $dir 'data'))
    $inventory=[pscustomobject]@{schemaVersion='1.0.0';targets=@([pscustomobject]@{DeviceId=$owner.DeviceId;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true})}
    [IO.File]::WriteAllText((Join-Path $dir 'data/devices.json'),(ConvertTo-Json $inventory -Depth 6 -Compress))
    [pscustomobject]@{Root=$dir;Fixture=$f;Owner=$owner;Session=$s;Layout=(Get-WinSecTechnicalSessionStorageLayout $dir $owner)}
}
function Save-SSI {param($F,[scriptblock]$Progress,[scriptblock]$Cancel)
    Write-WinSecTechnicalSourceSession $F.Root $F.Session $F.Owner -ProgressCallback $Progress -CancellationAction $Cancel}
function Load-SSI {param($F,[scriptblock]$Cancel)
    Read-WinSecTechnicalSourceSession $F.Root $F.Owner -ExpectedContentSha256 $F.Session.ContentSha256 -CancellationAction $Cancel}
function Stage-SSI {param($F)
    Reject-SSI {Save-SSI $F -Progress {param($e);if($e.Phase -ceq 'STAGED'){throw 'Synthetic interruption.'}}}
    Assert-SSI ([IO.File]::Exists($F.Layout.Temporary) -and -not [IO.File]::Exists($F.Layout.Path))}
try{
    foreach($family in @('CANDIDATE','PROJECTION')){foreach($scope in @('CONTROL','SECTION','DEVICE')){
        Test-SSI ('Atomic publication, protected files and exact source roundtrip: '+$family+'/'+$scope) {
            $f=New-SSI $family $scope;$before=[IO.File]::ReadAllText((Join-Path $f.Root 'data/devices.json'))
            $saved=Save-SSI $f;$read=Load-SSI $f
            Assert-SSI ($saved.PublicationStatus -ceq 'COMMITTED' -and $read.FileSha256 -ceq $saved.FileSha256 -and
                (Get-WinSecPublicHistoryJson $read.Session) -ceq (Get-WinSecPublicHistoryJson $f.Session) -and -not [IO.File]::Exists($f.Layout.Temporary))
            Assert-WinSecSnapshotPrivateAcl $saved.Path;Assert-WinSecSnapshotPrivateAcl ([IO.Path]::GetDirectoryName($saved.Path)) -Directory
            Assert-SSI ([IO.File]::ReadAllText((Join-Path $f.Root 'data/devices.json')) -ceq $before -and
                -not [IO.Directory]::Exists((Join-Path $f.Root ('scans/'+$f.Layout.DeviceKey+'/sessions'))))
        }
    }}
    Test-SSI 'A fresh process in both runtimes reads the same versioned container and original source pairs' {
        $f=New-SSI;$saved=Save-SSI $f
        foreach($exe in @('pwsh.exe','powershell.exe')){
            $loader=(Join-Path $root 'src/Services/TechnicalSourceSessionStore.ps1').Replace("'","''");$fixtureRoot=$f.Root.Replace("'","''")
            $code="`$ErrorActionPreference='Stop';. '$loader';function Get-CimInstance {throw 'Native forbidden.'};function Get-MpPreference {throw 'Native forbidden.'};"+
                "`$owner=[pscustomobject]@{DeviceId='$($f.Owner.DeviceId)';ScanId='$($f.Owner.ScanId)';ScopeType='$($f.Owner.ScopeType)';ScopeKey='$($f.Owner.ScopeKey)'};"+
                "`$r=Read-WinSecTechnicalSourceSession '$fixtureRoot' `$owner -ExpectedContentSha256 '$($f.Session.ContentSha256)';"+
                "if(`$r.FileSha256 -cne '$($saved.FileSha256)'){throw 'Fresh-process mismatch.'};'TECHNICAL_SESSION_CONFIRMED'"
            $result=@(& $exe -NoLogo -NoProfile -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))))
            Assert-SSI ($LASTEXITCODE -eq 0 -and $result[-1] -ceq 'TECHNICAL_SESSION_CONFIRMED')
        }
    }
    Test-SSI 'Collision never overwrites an existing session or changes its bytes' {
        $f=New-SSI;$saved=Save-SSI $f;Reject-SSI {Save-SSI $f}
        Assert-SSI ((Get-FileHash -LiteralPath $saved.Path).Hash -ceq $saved.FileSha256 -and -not [IO.File]::Exists($f.Layout.Temporary))
    }
    Test-SSI 'Unmanaged and removed owners cannot publish even if their source pairs exist' {
        $f=New-SSI;$inventoryPath=Join-Path $f.Root 'data/devices.json'
        [IO.File]::WriteAllText($inventoryPath,'{"schemaVersion":"1.0.0","targets":[]}');Reject-SSI {Save-SSI $f}
        $removed=[pscustomobject]@{schemaVersion='1.1.0';targets=@();removedDeviceHashes=@((Get-WinSecDeviceInventoryIdentityHash $f.Owner.DeviceId))}
        [IO.File]::WriteAllText($inventoryPath,(ConvertTo-Json $removed -Compress));Reject-SSI {Save-SSI $f}
        Assert-SSI (-not [IO.File]::Exists($f.Layout.Path) -and -not [IO.File]::Exists($f.Layout.Temporary))
    }
    Test-SSI 'An actual inventory lease rejects a concurrent writer before session publication' {
        $f=New-SSI;$lease=Open-WinSecDeviceInventoryStore $f.Root
        try{Reject-SSI {Save-SSI $f};Assert-SSI (-not [IO.File]::Exists($f.Layout.Path))}finally{$lease.Lock.Dispose()}
        $null=Save-SSI $f
    }
    Test-SSI 'Cancellation before I/O does not publish or stage any container' {
        $f=New-SSI;$cancelled=$false
        try{$null=Save-SSI $f -Cancel {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-SSI ($cancelled -and -not [IO.File]::Exists($f.Layout.Path) -and -not [IO.File]::Exists($f.Layout.Temporary))
    }
    Test-SSI 'A cancelled staged write stays pending and can only be recovered explicitly with the expected digest' {
        $f=New-SSI;$script:cancelStage=$false;$cancelled=$false
        try{$null=Save-SSI $f -Progress {param($e);if($e.Phase -ceq 'STAGED'){$script:cancelStage=$true}} -Cancel {$script:cancelStage}}
        catch [OperationCanceledException]{$cancelled=$true}
        Assert-SSI $cancelled;Reject-SSI {Load-SSI $f};Reject-SSI {Repair-WinSecTechnicalSourceSession $f.Root $f.Owner ('A'*64)}
        $r=Repair-WinSecTechnicalSourceSession $f.Root $f.Owner $f.Session.ContentSha256
        Assert-SSI ($r.PublicationStatus -ceq 'COMMITTED' -and -not [IO.File]::Exists($f.Layout.Temporary))
        Assert-SSI ((Repair-WinSecTechnicalSourceSession $f.Root $f.Owner $f.Session.ContentSha256).FileSha256 -ceq $r.FileSha256)
    }
    Test-SSI 'A complete staged file survives an interruption and a new reader never treats it as committed' {
        $f=New-SSI;Stage-SSI $f;$hash=(Get-FileHash -LiteralPath $f.Layout.Temporary).Hash
        Reject-SSI {Load-SSI $f};Reject-SSI {Save-SSI $f}
        Assert-SSI ((Get-FileHash -LiteralPath $f.Layout.Temporary).Hash -ceq $hash)
        $r=Repair-WinSecTechnicalSourceSession $f.Root $f.Owner $f.Session.ContentSha256;Assert-SSI ($r.FileSha256 -ceq $hash)
    }
    foreach($damage in @('Truncated','Whitespace','UnknownVersion','UnknownType','ForeignIdentity')){Test-SSI ('Invalid staged files are preserved and cannot be recovered: '+$damage) {
        $f=New-SSI;Stage-SSI $f;$text=[IO.File]::ReadAllText($f.Layout.Temporary)
        switch($damage){Truncated {$text=$text.Substring(0,20)};Whitespace {$text+=' '}
            UnknownVersion {$text=$text.Replace('"SchemaVersion":"1.0.0"','"SchemaVersion":"9.0.0"')}
            UnknownType {$text=$text.Replace('WinSec.TechnicalSourceSession','WinSec.StoredSession')}
            ForeignIdentity {$text=$text.Replace($f.Owner.DeviceId,('local:hw1-'+('c'*64)))}}
        [IO.File]::WriteAllText($f.Layout.Temporary,$text);$hash=(Get-FileHash -LiteralPath $f.Layout.Temporary).Hash
        Reject-SSI {Repair-WinSecTechnicalSourceSession $f.Root $f.Owner $f.Session.ContentSha256}
        Assert-SSI (-not [IO.File]::Exists($f.Layout.Path) -and (Get-FileHash -LiteralPath $f.Layout.Temporary).Hash -ceq $hash)
    }}
    foreach($damage in @('Container','SourceJson','SourceMarkdown','SourceCommit')){Test-SSI ('A saved container is unreadable when its committed source or bytes are altered: '+$damage) {
        $f=New-SSI;$null=Save-SSI $f
        $pair=Get-WinSecSnapshotPairLayout $f.Root $f.Fixture.Identity $f.Fixture.Reference.CollectedAtUTC
        switch($damage){Container {[IO.File]::AppendAllText($f.Layout.Path,' ')};SourceJson {[IO.File]::AppendAllText($pair.Json,' ')}
            SourceMarkdown {[IO.File]::AppendAllText($pair.Markdown,' ')};SourceCommit {Remove-Item -LiteralPath $pair.Commit}}
        Reject-SSI {Load-SSI $f}
    }}
    Test-SSI 'Recomputed container digests cannot conceal changed coverage' {
        $f=New-SSI;$null=Save-SSI $f;$changed=Copy-WinSecResultData $f.Session;$changed.Sources[0].Collection.Unknown++
        $changed.ContentSha256=Get-WinSecTechnicalSessionDigest $changed
        [IO.File]::WriteAllText($f.Layout.Path,(Get-WinSecPublicHistoryJson $changed))
        Reject-SSI {Read-WinSecTechnicalSourceSession $f.Root $f.Owner}
    }
    Test-SSI 'Cancellation during source verification preserves the pending container and releases all leases' {
        $f=New-SSI;Stage-SSI $f;$script:polls=0;$cancelled=$false
        try{$null=Repair-WinSecTechnicalSourceSession $f.Root $f.Owner $f.Session.ContentSha256 -CancellationAction {$script:polls++;$script:polls -ge 8}}
        catch [OperationCanceledException]{$cancelled=$true}
        $probe=[IO.File]::Open($f.Layout.Temporary,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$probe.Dispose()
        Assert-SSI ($cancelled -and -not [IO.File]::Exists($f.Layout.Path))
    }
    Test-SSI 'Source files and the inventory stay leased during publication callbacks' {
        $f=New-SSI;$pair=Get-WinSecSnapshotPairLayout $f.Root $f.Fixture.Identity $f.Fixture.Reference.CollectedAtUTC
        $script:lockedPair=$pair.Json;$script:callbackRoot=$f.Root;$script:blocked=0;$script:polls=0
        $r=Save-SSI $f -Cancel {
            $script:polls++;if($script:polls -eq 10){
                try{[IO.File]::AppendAllText($script:lockedPair,'tamper')}catch{$script:blocked++}
                try{$badLease=Open-WinSecDeviceInventoryStore $script:callbackRoot;$badLease.Lock.Dispose()}catch{$script:blocked++}
            };$false
        }
        Assert-SSI ($script:blocked -eq 2 -and $r.PublicationStatus -ceq 'COMMITTED')
    }
    Test-SSI 'A failure in the final progress notification cannot roll back a committed container' {
        $f=New-SSI;$r=Save-SSI $f -Progress {param($e);if($e.Phase -ceq 'COMMITTED'){throw 'Synthetic notification failure.'}}
        Assert-SSI ((Load-SSI $f).FileSha256 -ceq $r.FileSha256)
    }
    Test-SSI 'Unknown or pre-existing temporary artifacts are never overwritten or deleted by the writer' {
        $f=New-SSI;$held=Open-WinSecTechnicalSessionDirectories $f.Root $f.Layout -Create
        try{Write-WinSecSnapshotBytes $f.Layout.Temporary ([Text.Encoding]::UTF8.GetBytes('PRIVATE-FOREIGN-TEMP'))}finally{foreach($h in $held){$h.Dispose()}}
        $hash=(Get-FileHash -LiteralPath $f.Layout.Temporary).Hash;Reject-SSI {Save-SSI $f}
        Assert-SSI ((Get-FileHash -LiteralPath $f.Layout.Temporary).Hash -ceq $hash -and -not [IO.File]::Exists($f.Layout.Path))
    }
    Test-SSI 'Hard-linked session files are rejected without changing either link' {
        $f=New-SSI;$saved=Save-SSI $f;$extra=Join-Path $f.Root 'hardlink-copy.json'
        $null=New-Item -ItemType HardLink -Path $extra -Target $saved.Path
        try{Reject-SSI {Load-SSI $f};Assert-SSI ((Get-FileHash -LiteralPath $extra).Hash -ceq $saved.FileSha256)}
        finally{Remove-Item -LiteralPath $extra}
    }
    Test-SSI 'A junction in the metadata namespace cannot redirect publication to another directory' {
        $f=New-SSI;$target=Join-Path $f.Root 'foreign';$null=[IO.Directory]::CreateDirectory($target)
        $parent=[IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($f.Layout.Path));$null=[IO.Directory]::CreateDirectory($parent)
        $link=[IO.Path]::GetDirectoryName($f.Layout.Path);$null=New-Item -ItemType Junction -Path $link -Target $target
        try{Reject-SSI {Save-SSI $f};Assert-SSI (@(Get-ChildItem -LiteralPath $target -Force).Count -eq 0)}
        finally{[IO.Directory]::Delete($link)}
    }
    Test-SSI 'Broad namespace permissions reject reads and writes without silently repairing the ACL' {
        $f=New-SSI;$null=Save-SSI $f;$dir=[IO.Path]::GetDirectoryName($f.Layout.Path);$original=Get-Acl -LiteralPath $dir
        $changed=Get-Acl -LiteralPath $dir;$world=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($world,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow');$changed.AddAccessRule($rule)
        $info=New-Object IO.DirectoryInfo($dir)
        try{
            if('System.IO.FileSystemAclExtensions' -as [type]){[IO.FileSystemAclExtensions]::SetAccessControl($info,$changed)}else{$info.SetAccessControl($changed)}
            Reject-SSI {Load-SSI $f};Reject-SSI {Save-SSI $f}
            Assert-SSI (@((Get-Acl -LiteralPath $dir).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -eq 'S-1-1-0'}).Count -gt 0)
        }finally{if('System.IO.FileSystemAclExtensions' -as [type]){[IO.FileSystemAclExtensions]::SetAccessControl($info,$original)}else{$info.SetAccessControl($original)}}
    }
    Test-SSI 'Inventory changes outside its cooperative lock are detected before commit' {
        $f=New-SSI;$script:changedInventory=Join-Path $f.Root 'data/devices.json'
        Reject-SSI {Save-SSI $f -Progress {param($e);if($e.Phase -ceq 'STAGED'){[IO.File]::WriteAllText($script:changedInventory,'{"schemaVersion":"1.0.0","targets":[]}')}}}
        Assert-SSI (-not [IO.File]::Exists($f.Layout.Path) -and [IO.File]::Exists($f.Layout.Temporary))
    }
    Test-SSI 'Committed progress cannot mutate the file before the writer returns' {
        $f=New-SSI;$script:committedPath=$f.Layout.Path;$script:blocked=0
        $r=Save-SSI $f -Progress {param($e);if($e.Phase -ceq 'COMMITTED'){
            try{[IO.File]::AppendAllText($script:committedPath,'tamper')}catch{$script:blocked++}
            try{[IO.File]::Delete($script:committedPath)}catch{$script:blocked++}
        }}
        Assert-SSI ($script:blocked -eq 2 -and (Load-SSI $f).FileSha256 -ceq $r.FileSha256)
    }
    Test-SSI 'A partial write failure preserves incomplete bytes without publishing or repairing them' {
        $f=New-SSI;$script:originalSnapshotWriter=${function:Write-WinSecSnapshotBytes}
        function Write-WinSecSnapshotBytes {
            param($Path,[byte[]]$Bytes,[scriptblock]$CancellationAction)
            & $script:originalSnapshotWriter $Path ([byte[]]$Bytes[0..19]) $CancellationAction
            throw 'Synthetic disk write failure.'
        }
        Reject-SSI {Save-SSI $f}
        Assert-SSI ((Get-Item -LiteralPath $f.Layout.Temporary).Length -eq 20 -and -not [IO.File]::Exists($f.Layout.Path))
        Reject-SSI {Repair-WinSecTechnicalSourceSession $f.Root $f.Owner $f.Session.ContentSha256}
        Assert-SSI ((Get-Item -LiteralPath $f.Layout.Temporary).Length -eq 20)
    }
    Test-SSI 'A destination collision at rename preserves both the prior destination and pending bytes' {
        $f=New-SSI;$script:collisionPath=$f.Layout.Path
        Reject-SSI {Save-SSI $f -Progress {param($e);if($e.Phase -ceq 'VERIFYING'){[IO.File]::WriteAllText($script:collisionPath,'FOREIGN-DESTINATION')}}}
        Assert-SSI ([IO.File]::ReadAllText($f.Layout.Path) -ceq 'FOREIGN-DESTINATION' -and [IO.File]::Exists($f.Layout.Temporary))
        Reject-SSI {Repair-WinSecTechnicalSourceSession $f.Root $f.Owner $f.Session.ContentSha256}
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awst-[a-f0-9]{8}\z'){throw 'Unsafe storage integration fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical session storage integration: $passed passed; $failed failed.");if($failed){exit 1}
