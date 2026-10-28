[CmdletBinding()]param([switch]$TraceFailures,[switch]$ReaderOnly,[switch]$WriterOnly,[string]$ReaderRoot,[string]$ReaderSnapshotId)
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSnapshotStore.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSnapshotMemory.ps1')
function Get-CimInstance {throw 'Native queries prohibited.'}
function Get-MpPreference {throw 'Native queries prohibited.'}
if($ReaderOnly -or $WriterOnly){
    $f=New-WinSecSnapshotFixture;$f.Identity.SnapshotId=$ReaderSnapshotId;$f.Snapshot.Identity.SnapshotId=$ReaderSnapshotId;$f.Snapshot.Batches[0].SnapshotId=$ReaderSnapshotId
    try {if($WriterOnly){$null=Write-WinSecTechnicalSnapshotPair $ReaderRoot $f.Snapshot $f.Catalog $f.Hash $f.Identity}
        else {$result=Read-WinSecTechnicalSnapshotPair $ReaderRoot $f.Identity $f.Snapshot.CollectedAtUTC $f.Catalog $f.Hash;if($result.PublicationStatus -cne 'COMMITTED'){exit 1}}
        Write-Output 'COMMITTED';exit 0
    }catch{Write-Output 'REJECTED';exit 1}
}
$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $base ('wsp-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0;$counter=0
function Assert-WinSecStore {param([bool]$Condition);if(-not $Condition){throw 'Snapshot store assertion failed.'}}
function Reject-WinSecStore {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecStore $caught}
function Test-WinSecStore {
    param($Label,[scriptblock]$Action)
    $script:counter++;$f=New-WinSecSnapshotFixture;$f.Identity.SnapshotId=$counter.ToString('x32');$f.Snapshot.Identity.SnapshotId=$f.Identity.SnapshotId
    foreach($batch in $f.Snapshot.Batches){$batch.SnapshotId=$f.Identity.SnapshotId}
    try {& $Action;$script:passed++;Write-Host ('[PASS] '+$Label)}catch{$script:failed++;Write-Host ('[FAIL] '+$Label+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace;if($TraceFailures){$Error|Select-Object -First 4|ForEach-Object {Write-Host ($_.Exception.Message+' '+$_.ScriptStackTrace)}}}
}
function Save-WinSecStore {param([scriptblock]$Progress,[scriptblock]$Cancel);Write-WinSecTechnicalSnapshotPair $sandbox $f.Snapshot $f.Catalog $f.Hash $f.Identity -ProgressCallback $Progress -CancellationAction $Cancel}
function Load-WinSecStore {Read-WinSecTechnicalSnapshotPair $sandbox $f.Identity $f.Snapshot.CollectedAtUTC $f.Catalog $f.Hash}
function Recover-WinSecStore {Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $f.Snapshot.CollectedAtUTC $f.Catalog $f.Hash}
function Set-WinSecFixtureDirectoryAcl {
    param($Path,$Acl)
    $directory=New-Object IO.DirectoryInfo($Path)
    if('System.IO.FileSystemAclExtensions' -as [type]){[IO.FileSystemAclExtensions]::SetAccessControl($directory,$Acl)}else{$directory.SetAccessControl($Acl)}
}
try {
    Test-WinSecStore 'First publication, verified ACL, fresh-process recovery and exact JSON/Markdown pair' {
        $saved=Save-WinSecStore;$state=Load-WinSecStore
        Assert-WinSecStore ($saved.PublicationStatus -ceq 'COMMITTED' -and $state.Snapshot.Collection.Status -ceq 'COMPLETE')
        Assert-WinSecSnapshotPrivateAcl ([IO.Path]::GetDirectoryName($saved.JsonPath)) -Directory
        $layout=Get-WinSecSnapshotPairLayout $sandbox $f.Identity $f.Snapshot.CollectedAtUTC
        Assert-WinSecStore (-not [IO.File]::Exists($layout.Lock) -and [IO.File]::Exists($layout.Intent) -and [IO.File]::Exists($layout.Commit))
        $plan=Get-WinSecTechnicalSnapshotRemovalPlan $sandbox $f.Identity $f.Snapshot.CollectedAtUTC $f.Catalog $f.Hash
        Assert-WinSecStore ($plan.Files.Count -eq 4 -and $plan.RequiresConfirmation)
        foreach($engine in @('pwsh.exe','powershell.exe')){
            $result=@(& $engine -NoLogo -NoProfile -File $PSCommandPath -ReaderOnly -ReaderRoot $sandbox -ReaderSnapshotId $f.Identity.SnapshotId)
            Assert-WinSecStore ($LASTEXITCODE -eq 0 -and $result[-1] -ceq 'COMMITTED')
        }
    }
    Test-WinSecStore 'Duplicates cannot overwrite a committed snapshot or its history' {
        $saved=Save-WinSecStore;$before=(Get-FileHash -LiteralPath $saved.JsonPath).Hash
        Reject-WinSecStore {Save-WinSecStore};Assert-WinSecStore ((Get-FileHash -LiteralPath $saved.JsonPath).Hash -ceq $before)
    }
    foreach($stage in @('PREPARED','JSON_STAGED','MARKDOWN_STAGED','JSON_PUBLISHED','MARKDOWN_PUBLISHED','COMMIT_STAGED')){
        Test-WinSecStore ('Interrupted '+$stage+' stays unpublished; recovery is explicit') {
            $stopAt=$stage
            Reject-WinSecStore {Save-WinSecStore -Progress {param($e);if($e.Stage -ceq $stopAt){throw 'SYNTHETIC INTERRUPTION'}}}
            $state=Load-WinSecStore
            $recoverable=$stage -cin @('MARKDOWN_STAGED','JSON_PUBLISHED','MARKDOWN_PUBLISHED','COMMIT_STAGED')
            Assert-WinSecStore ($null -eq $state.Snapshot -and $state.PublicationStatus -ceq $(if($recoverable){'RECOVERABLE'}else{'INCOMPLETE'}))
            if($recoverable){$fixed=Recover-WinSecStore;Assert-WinSecStore ($fixed.PublicationStatus -ceq 'COMMITTED');$null=Recover-WinSecStore}
            else {Reject-WinSecStore {Recover-WinSecStore};Reject-WinSecStore {Get-WinSecTechnicalSnapshotRemovalPlan $sandbox $f.Identity $f.Snapshot.CollectedAtUTC $f.Catalog $f.Hash}}
        }
    }
    Test-WinSecStore 'A valid PARTIAL snapshot can commit without becoming a complete scan' {
        $i=$f.Snapshot.Inventories[0];$i.Complete=$false;$i.Reason='RESOURCE_LIMIT';$i.ReportedRecords=2
        $f.Snapshot.Collection.Status='PARTIAL';$f.Snapshot.Collection.Coverage='LIMITED'
        $null=Save-WinSecStore;$state=Load-WinSecStore
        Assert-WinSecStore ($state.PublicationStatus -ceq 'COMMITTED' -and $state.Snapshot.Collection.Status -ceq 'PARTIAL')
    }
    Test-WinSecStore 'Cancellation before writing leaves no pair and cannot alter earlier snapshots' {
        Reject-WinSecStore {Save-WinSecStore -Cancel {$true}}
        $layout=Get-WinSecSnapshotPairLayout $sandbox $f.Identity $f.Snapshot.CollectedAtUTC
        Assert-WinSecStore (-not [IO.File]::Exists($layout.Intent) -and -not [IO.File]::Exists($layout.Json))
    }
    Test-WinSecStore 'Cancellation between renames leaves a recoverable uncommitted pair' {
        $script:cancelStore=$false
        Reject-WinSecStore {Save-WinSecStore -Progress {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){$script:cancelStore=$true}} -Cancel {$script:cancelStore}}
        Assert-WinSecStore ((Load-WinSecStore).PublicationStatus -ceq 'RECOVERABLE');$null=Recover-WinSecStore
    }
    Test-WinSecStore 'Corruption, mismatched owners and modified Markdown are rejected without deletion' {
        $saved=Save-WinSecStore
        $foreign=$f.Identity.PSObject.Copy();$foreign.ScanId='foreign'
        Reject-WinSecStore {Read-WinSecTechnicalSnapshotPair $sandbox $foreign $f.Snapshot.CollectedAtUTC $f.Catalog $f.Hash}
        [IO.File]::AppendAllText($saved.MarkdownPath,'SYNTHETIC CORRUPTION')
        Reject-WinSecStore {Load-WinSecStore};Reject-WinSecStore {Recover-WinSecStore}
        Reject-WinSecStore {Get-WinSecTechnicalSnapshotRemovalPlan $sandbox $f.Identity $f.Snapshot.CollectedAtUTC $f.Catalog $f.Hash}
        Assert-WinSecStore ([IO.File]::Exists($saved.JsonPath) -and [IO.File]::Exists($saved.MarkdownPath))
    }
    Test-WinSecStore 'Removal plan verifies recoverable final/staged files but performs no deletion' {
        Reject-WinSecStore {Save-WinSecStore -Progress {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC'}}}
        $plan=Get-WinSecTechnicalSnapshotRemovalPlan $sandbox $f.Identity $f.Snapshot.CollectedAtUTC $f.Catalog $f.Hash
        Assert-WinSecStore ($plan.PublicationStatus -ceq 'RECOVERABLE' -and $plan.Files.Count -eq 3)
        foreach($file in $plan.Files){Assert-WinSecStore ([IO.File]::Exists($file.Path))}
    }
    Test-WinSecStore 'Holding the publication lock prevents a concurrent writer' {
        $layout=Get-WinSecSnapshotPairLayout $sandbox $f.Identity $f.Snapshot.CollectedAtUTC
        $held=Open-WinSecSnapshotDirectories $sandbox $layout -Create;$lock=[WinSec.SnapshotIO3]::Lock($layout.Lock)
        try {
            Reject-WinSecStore {Save-WinSecStore}
            $engine=Join-Path $PSHOME $(if($PSVersionTable.PSEdition -ceq 'Desktop'){'powershell.exe'}else{'pwsh.exe'})
            $result=@(& $engine -NoLogo -NoProfile -File $PSCommandPath -WriterOnly -ReaderRoot $sandbox -ReaderSnapshotId $f.Identity.SnapshotId)
            Assert-WinSecStore ($LASTEXITCODE -ne 0 -and $result[-1] -ceq 'REJECTED')
        }finally{$lock.Dispose();foreach($h in $held){$h.Dispose()}}
        $null=Save-WinSecStore
    }
    Test-WinSecStore 'Reader fails closed on a hard-linked technical artifact' {
        $saved=Save-WinSecStore;$extra=Join-Path $sandbox 'hardlink'
        $null=New-Item -ItemType HardLink -Path $extra -Target $saved.JsonPath
        Reject-WinSecStore {Load-WinSecStore}
        Remove-Item -LiteralPath $extra -Force
    }
    Test-WinSecStore 'Broad permissions reject reads and writes without silently replacing the ACL' {
        $saved=Save-WinSecStore;$dir=[IO.Path]::GetDirectoryName($saved.JsonPath)
        $original=New-Object Security.AccessControl.DirectorySecurity;$changed=New-Object Security.AccessControl.DirectorySecurity
        $sddl=(Get-Acl -LiteralPath $dir).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        $original.SetSecurityDescriptorSddlForm($sddl,[Security.AccessControl.AccessControlSections]::Access)
        $changed.SetSecurityDescriptorSddlForm($sddl,[Security.AccessControl.AccessControlSections]::Access)
        $everyone=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($everyone,'ReadAndExecute','Allow');$changed.AddAccessRule($rule)
        try {Set-WinSecFixtureDirectoryAcl $dir $changed;Reject-WinSecStore {Load-WinSecStore};Reject-WinSecStore {Save-WinSecStore}
            Assert-WinSecStore (@((Get-Acl -LiteralPath $dir).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -eq 'S-1-1-0'}).Count -gt 0)
        }finally{Set-WinSecFixtureDirectoryAcl $dir $original}
    }
    Test-WinSecStore 'Junction storage root is rejected before writing to its target' {
        $other=Join-Path $sandbox 'r';$target=Join-Path $sandbox 'target';$null=New-Item -ItemType Directory -Path $other;$null=New-Item -ItemType Directory -Path $target
        $link=Join-Path $other 'scans';$null=New-Item -ItemType Junction -Path $link -Target $target
        try {Reject-WinSecStore {Write-WinSecTechnicalSnapshotPair $other $f.Snapshot $f.Catalog $f.Hash $f.Identity};Assert-WinSecStore (@(Get-ChildItem -LiteralPath $target -Force).Count -eq 0)}
        finally{Remove-Item -LiteralPath $link -Force}
    }
    Test-WinSecStore 'Failed disk write leaves an invalid temporary and never publishes a complete scan' {
        $originalWrite=${function:Write-WinSecSnapshotBytes}
        function Write-WinSecSnapshotBytes {param($Path,$Bytes,$CancellationAction)
            if([IO.Path]::GetFileName($Path).StartsWith('.j')){
                $stream=[WinSec.SnapshotIO3]::Create($Path);try{$stream.WriteByte(123);$stream.Flush($true)}finally{$stream.Dispose()};throw 'SYNTHETIC DISK FAILURE'
            }
            & $originalWrite $Path $Bytes $CancellationAction
        }
        Reject-WinSecStore {Save-WinSecStore};Reject-WinSecStore {Load-WinSecStore}
        Reject-WinSecStore {Recover-WinSecStore}
        $layout=Get-WinSecSnapshotPairLayout $sandbox $f.Identity $f.Snapshot.CollectedAtUTC
        Assert-WinSecStore ([IO.File]::Exists($layout.JsonTemp) -and -not [IO.File]::Exists($layout.Commit))
    }
    Test-WinSecStore 'A replaced Markdown with recomputed hashes still fails snapshot equivalence' {
        $saved=Save-WinSecStore;$layout=Get-WinSecSnapshotPairLayout $sandbox $f.Identity $f.Snapshot.CollectedAtUTC
        $bytes=[Text.Encoding]::UTF8.GetBytes('SYNTHETIC FOREIGN MARKDOWN');[IO.File]::WriteAllBytes($saved.MarkdownPath,$bytes)
        foreach($path in @($layout.Intent,$layout.Commit)){
            $marker=ConvertFrom-WinSecSnapshotPairJson ([IO.File]::ReadAllText($path));$marker.MarkdownSha256=Get-WinSecSnapshotByteHash $bytes;$marker.MarkdownBytes=$bytes.Length
            [IO.File]::WriteAllText($path,(ConvertTo-Json -InputObject $marker -Depth 8 -Compress),(New-Object Text.UTF8Encoding($false)))
        }
        Reject-WinSecStore {Load-WinSecStore};Reject-WinSecStore {Get-WinSecTechnicalSnapshotRemovalPlan $sandbox $f.Identity $f.Snapshot.CollectedAtUTC $f.Catalog $f.Hash}
    }
    Test-WinSecStore 'A truncated commit temporary cannot be accepted as recoverable or overwritten' {
        Reject-WinSecStore {Save-WinSecStore -Progress {param($e);if($e.Stage -ceq 'COMMIT_STAGED'){throw 'SYNTHETIC'}}}
        $layout=Get-WinSecSnapshotPairLayout $sandbox $f.Identity $f.Snapshot.CollectedAtUTC;[IO.File]::WriteAllText($layout.CommitTemp,'{')
        Reject-WinSecStore {Load-WinSecStore};Reject-WinSecStore {Recover-WinSecStore}
        Assert-WinSecStore ([IO.File]::ReadAllText($layout.CommitTemp) -ceq '{' -and -not [IO.File]::Exists($layout.Commit))
    }
    Test-WinSecStore 'All 300 records survive JSON and Markdown across multiple batches' {
        $f.Catalog.Inventories[0].Singleton=$false;$f.Hash=Get-WinSecSnapshotCatalogHash $f.Catalog;$f.Snapshot.CatalogSha256=$f.Hash
        $template=$f.Snapshot.Batches[0];$all=@();$batches=@()
        for($n=0;$n -lt 300;$n++){$all += [pscustomobject]@{Id=('Row'+$n);Readings=$template.Records[0].Readings}}
        for($n=0;$n -lt 300;$n+=128){$batch=$template.PSObject.Copy();$batch.Sequence=$batches.Count+1;$batch.Records=@($all[$n..([Math]::Min(299,$n+127))]);$batches+=$batch}
        $f.Snapshot.Batches=$batches;$f.Snapshot.Inventories[0].RetainedRecords=300;$f.Snapshot.Inventories[0].ReportedRecords=300
        $f.Snapshot.Collection.RetainedRecords=300;$f.Snapshot.Collection.Observed=900
        $saved=Save-WinSecStore;$state=Load-WinSecStore
        Assert-WinSecStore ($state.Snapshot.Batches.Count -eq 3 -and $state.Snapshot.Collection.RetainedRecords -eq 300 -and [IO.File]::ReadAllText($saved.MarkdownPath).Contains('Row299'))
    }
    Test-WinSecStore 'Exclusive publication never replaces an unrelated existing file' {
        $layout=Get-WinSecSnapshotPairLayout $sandbox $f.Identity $f.Snapshot.CollectedAtUTC;$held=Open-WinSecSnapshotDirectories $sandbox $layout -Create
        try {[IO.File]::WriteAllText($layout.Json,'SYNTHETIC FOREIGN FILE');Reject-WinSecStore {Save-WinSecStore};Assert-WinSecStore ([IO.File]::ReadAllText($layout.Json) -ceq 'SYNTHETIC FOREIGN FILE')}
        finally{foreach($h in $held){$h.Dispose()}}
    }
    Test-WinSecStore 'Held ancestors cannot be renamed between validation and publication' {
        $layout=Get-WinSecSnapshotPairLayout $sandbox $f.Identity $f.Snapshot.CollectedAtUTC;$held=Open-WinSecSnapshotDirectories $sandbox $layout -Create
        try {$dir=[IO.Path]::GetDirectoryName($layout.Json);Reject-WinSecStore {[IO.Directory]::Move($dir,$dir+'-moved')}}finally{foreach($h in $held){$h.Dispose()}}
        $null=Save-WinSecStore
    }
    Test-WinSecStore 'Section and device sources retain their original ScanId and scope' {
        foreach($scope in @('SECTION','DEVICE')){
            $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=if($scope -ceq 'SECTION'){'IdentityAccess'}else{'ALL'}
            $f.Snapshot.Identity.ScopeType=$f.Identity.ScopeType;$f.Snapshot.Identity.ScopeKey=$f.Identity.ScopeKey
            $f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');$f.Snapshot.Identity.SnapshotId=$f.Identity.SnapshotId;$f.Snapshot.Batches[0].SnapshotId=$f.Identity.SnapshotId
            $null=Save-WinSecStore;$state=Load-WinSecStore
            Assert-WinSecStore ($state.Snapshot.Identity.ScanId -ceq 'synthetic-scan' -and $state.Snapshot.Identity.ScopeType -ceq $scope)
        }
    }
    Test-WinSecStore 'Storage remains explicitly selected and preserves eleven enabled controls' {
        Assert-WinSecStore ((Get-Content -Raw -LiteralPath (Join-Path $root 'src/Core/ScanCoordinator.ps1')) -match 'NewTechnicalStorageEnabled\s*=\s*\$false')
        $checks=Get-Content -Raw -LiteralPath (Join-Path $root 'config/checks.json')|ConvertFrom-Json
        Assert-WinSecStore (@($checks.checks|Where-Object {$_.execution.enabled}).Count -eq 11)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if(-not $full.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '\Awsp-[a-f0-9]{12}\z'){throw 'Unsafe synthetic cleanup target.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Snapshot store integration: $passed passed; $failed failed.");if($failed){exit 1}
