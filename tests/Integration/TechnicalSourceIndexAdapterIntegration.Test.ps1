[CmdletBinding()]param([string]$CasePattern='')
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceIndexAdapter.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$counter=0;$scanCounter=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wji-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-II {param([bool]$Value);if(-not $Value){throw 'Technical index integration assertion failed.'}}
function Reject-II {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-II $caught}
function New-II {param([string]$Family='CANDIDATE',[string]$Scope='CONTROL',[string]$Catalog='1.1.0',[string]$IntoRoot='')
    if($IntoRoot){$dir=$IntoRoot}else{
        $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
        foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
    }
    $script:scanCounter++;$scan='index-'+$script:scanCounter.ToString('x4')
    $f=New-WinSecTechnicalSourceFixture -Family $Family -ScopeType $Scope -CatalogVersion $Catalog
    if($Family -ceq 'PROJECTION'){
        $report=ConvertFrom-WinSecProjectionSnapshot $f.Package.Snapshot;$report.ScanId=$scan
        $f.Package=New-WinSecProjectionSnapshot $report;$f.Identity=$f.Package.Identity.PSObject.Copy();$f.Reference.Identity=$f.Identity.PSObject.Copy()
    }
    foreach($identity in @($f.Identity,$f.Reference.Identity,$f.Package.Identity,$f.Package.Snapshot.Identity)){$identity.ScanId=$scan}
    foreach($batch in $f.Package.Snapshot.Batches){$batch.ScanId=$scan}
    $null=Save-WinSecTechnicalSourceFixture $dir $f
    $owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$scan;ScopeType=$f.Identity.ScopeType;ScopeKey=$f.Identity.ScopeKey}
    $stamp=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
    $s=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
        [pscustomobject]@{Reference=$stamp.Reference;SnapshotSha256=$stamp.SnapshotSha256;Collection=$f.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
    $s.ContentSha256=Get-WinSecTechnicalSessionDigest $s
    if(-not $IntoRoot){
        $null=[IO.Directory]::CreateDirectory((Join-Path $dir 'data'))
        $inventory=[pscustomobject]@{schemaVersion='1.0.0';targets=@([pscustomobject]@{DeviceId=$owner.DeviceId;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true})}
        [IO.File]::WriteAllText((Join-Path $dir 'data/devices.json'),(ConvertTo-Json $inventory -Depth 6 -Compress))
    }
    $saved=Write-WinSecTechnicalSourceSession $dir $s $owner
    [pscustomobject]@{Root=$dir;Fixture=$f;Owner=$owner;Session=$s;Saved=$saved;Layout=(Get-WinSecTechnicalSessionStorageLayout $dir $owner);
        Pair=(Get-WinSecSnapshotPairLayout $dir $f.Identity $f.Reference.CollectedAtUTC)}
}
function Restore-II {param([object]$Fixture)
    $d=Read-WinSecTechnicalSourceSessions $Fixture.Root $Fixture.Owner.DeviceId
    Restore-WinSecTechnicalSourceIndex $Fixture.Root $d $Fixture.Owner.DeviceId
}
function Test-II {param([string]$Case,[scriptblock]$Action)
    if($CasePattern -and $Case -notmatch $CasePattern){return}
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try{
    Test-II 'All scopes restore with exact original identities, both source families and coverage' {
        $f=New-II;$all=@($f)
        foreach($scope in @('SECTION','DEVICE')){$all+=New-II -Scope $scope -IntoRoot $f.Root}
        $all+=New-II -Family PROJECTION -IntoRoot $f.Root
        $d=Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId;$before=Get-WinSecPublicHistoryJson $d
        $i=Restore-WinSecTechnicalSourceIndex $f.Root $d $f.Owner.DeviceId
        Assert-II ($i.Sessions.Count -eq 4 -and $i.Origin -ceq 'RECORDS' -and (Get-WinSecPublicHistoryJson $d) -ceq $before)
        foreach($x in $all){
            $entry=Read-WinSecIndexedTechnicalSession $f.Root $i $x.Owner
            Assert-II ($entry.FileSha256 -ceq $x.Saved.FileSha256 -and (Get-WinSecPublicHistoryJson $entry.Session) -ceq (Get-WinSecPublicHistoryJson $x.Session))
        }
    }
    Test-II 'Complete and partial attempts coexist without silently selecting or replacing either one' {
        $f=New-II -Catalog '1.0.0';$partial=New-II -IntoRoot $f.Root;$i=Restore-II $f
        $a=Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner;$b=Read-WinSecIndexedTechnicalSession $f.Root $i $partial.Owner
        Assert-II ($i.Sessions.Count -eq 2 -and $a.Session.Sources[0].Collection.Status -ceq 'COMPLETE' -and
            $b.Session.Sources[0].Collection.Status -ceq 'PARTIAL' -and $b.Session.Sources[0].Collection.Coverage -ceq 'LIMITED')
    }
    Test-II 'A cold process rebuilds and consumes the same index in both runtimes without collector calls' {
        $f=New-II;$i=Restore-II $f
        foreach($exe in @('pwsh.exe','powershell.exe')){
            $loader=(Join-Path $f.Root 'src/Services/TechnicalSourceIndexAdapter.ps1').Replace("'","''");$install=$f.Root.Replace("'","''")
            $code="`$ErrorActionPreference='Stop';. '$loader';function Get-CimInstance {throw 'Native forbidden.'};function Get-MpPreference {throw 'Native forbidden.'};"+
                "`$d=Read-WinSecTechnicalSourceSessions '$install' '$($f.Owner.DeviceId)';`$i=Restore-WinSecTechnicalSourceIndex '$install' `$d '$($f.Owner.DeviceId)';"+
                "`$e=Read-WinSecIndexedTechnicalSession '$install' `$i `$i.Sessions[0].Session.Identity;if(`$i.ContentSha256 -cne '$($i.ContentSha256)' -or `$e.FileSha256 -cne '$($f.Saved.FileSha256)'){throw 'Restart mismatch.'};'INDEX_RESTORED'"
            $out=@(& $exe -NoLogo -NoProfile -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))))
            Assert-II ($LASTEXITCODE -eq 0 -and $out[-1] -ceq 'INDEX_RESTORED')
        }
    }
    Test-II 'A stale discovery cannot restore a source changed after discovery' {
        $f=New-II;$d=Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId
        [IO.File]::AppendAllText($f.Pair.Markdown,' ')
        Reject-II {Restore-WinSecTechnicalSourceIndex $f.Root $d $f.Owner.DeviceId}
        Assert-II ([IO.File]::Exists($f.Saved.Path) -and [IO.File]::Exists($f.Pair.Markdown))
    }
    foreach($damage in @('Container','Markdown','MissingCommit','Pending','ResignedPin')){
        Test-II ('Consumption revalidates physical artifacts instead of trusting the index: '+$damage) {
            $f=New-II;$i=Restore-II $f;$before=Get-WinSecPublicHistoryJson $i
            switch($damage){
                Container {[IO.File]::AppendAllText($f.Saved.Path,' ')}
                Markdown {[IO.File]::AppendAllText($f.Pair.Markdown,' ')}
                MissingCommit {Remove-Item -LiteralPath $f.Pair.Commit}
                Pending {[IO.File]::WriteAllText($f.Layout.Temporary,'INTERRUPTED')}
                ResignedPin {
                    $d=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.0.0';DeviceId=$i.DeviceId;Sessions=(Copy-WinSecResultData $i.Sessions)}
                    $d.Sessions[0].FileSha256='B'*64;$i=Copy-WinSecTechnicalIndexMetadata $f.Root $d $i.DeviceId DISCOVERY;$before=Get-WinSecPublicHistoryJson $i
                }
            }
            Reject-II {Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner}
            Assert-II ((Get-WinSecPublicHistoryJson $i) -ceq $before -and [IO.File]::Exists($f.Saved.Path) -and [IO.File]::Exists($f.Pair.Json))
        }
    }
    foreach($wrong in @('Device','Scope','Scan')){
        Test-II ('Exact lookup cannot cross identity boundaries: '+$wrong) {
            $f=New-II;$i=Restore-II $f;$owner=$f.Owner.PSObject.Copy()
            switch($wrong){Device {$owner.DeviceId='local:hw1-'+('c'*64)};Scope {$owner.ScopeType='SECTION';$owner.ScopeKey='SystemSecurity'};Scan {$owner.ScanId='missing-scan'}}
            Reject-II {Read-WinSecIndexedTechnicalSession $f.Root $i $owner}
            Assert-II ((Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner).FileSha256 -ceq $f.Saved.FileSha256)
        }
    }
    Test-II 'Cancellation during restoration preserves previous records and releases inventory and source leases' {
        $f=New-II;$i=Restore-II $f;$d=Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId;$before=Get-WinSecPublicHistoryJson $i;$script:polls=0;$cancelled=$false
        try{$null=Restore-WinSecTechnicalSourceIndex $f.Root $d $f.Owner.DeviceId -CancellationAction {$script:polls++;$script:polls -ge 6}}
        catch [OperationCanceledException]{$cancelled=$true}
        $stream=[IO.File]::Open($f.Saved.Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$stream.Dispose()
        $lease=Open-WinSecDeviceInventoryStore $f.Root;$lease.Lock.Dispose()
        Assert-II ($cancelled -and (Get-WinSecPublicHistoryJson $i) -ceq $before)
    }
    Test-II 'Cancellation during indexed consumption returns no entry and releases its leases' {
        $f=New-II;$i=Restore-II $f;$script:polls=0;$cancelled=$false
        try{$null=Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner -CancellationAction {$script:polls++;$script:polls -ge 6}}
        catch [OperationCanceledException]{$cancelled=$true}
        Assert-II ($cancelled -and (Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner).FileSha256 -ceq $f.Saved.FileSha256)
    }
    Test-II 'The actual inventory lock blocks restoration and consumption without altering a previous index' {
        $f=New-II;$i=Restore-II $f;$d=Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId;$before=Get-WinSecPublicHistoryJson $i
        $lease=Open-WinSecDeviceInventoryStore $f.Root
        try{Reject-II {Restore-WinSecTechnicalSourceIndex $f.Root $d $f.Owner.DeviceId};Reject-II {Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner}}
        finally{$lease.Lock.Dispose()}
        Assert-II ((Get-WinSecPublicHistoryJson $i) -ceq $before -and (Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner).FileSha256 -ceq $f.Saved.FileSha256)
    }
    Test-II 'Retired owners cannot consume still-present files through an old index' {
        $f=New-II;$i=Restore-II $f;$inventory=[pscustomobject]@{schemaVersion='1.1.0';targets=@();removedDeviceHashes=@((Get-WinSecDeviceInventoryIdentityHash $f.Owner.DeviceId))}
        [IO.File]::WriteAllText((Join-Path $f.Root 'data/devices.json'),(ConvertTo-Json $inventory -Compress))
        Reject-II {Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner};Assert-II ([IO.File]::Exists($f.Saved.Path))
    }
    Test-II 'Caller mutation of the original index does not modify the detached selection being consumed' {
        $f=New-II;$script:indexToMutate=Restore-II $f
        $entry=Read-WinSecIndexedTechnicalSession $f.Root $script:indexToMutate $f.Owner -CancellationAction {$script:indexToMutate.Sessions=@();$false}
        Assert-II ($entry.FileSha256 -ceq $f.Saved.FileSha256 -and $script:indexToMutate.Sessions.Count -eq 0)
    }
    Test-II 'Inventory mutation outside the cooperative lock rejects a restored entry' {
        $f=New-II;$i=Restore-II $f;$script:inventoryPath=Join-Path $f.Root 'data/devices.json';$script:polls=0
        Reject-II {Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner -CancellationAction {
            $script:polls++;if($script:polls -eq 2){[IO.File]::WriteAllText($script:inventoryPath,'{"schemaVersion":"1.0.0","targets":[]}')};$false
        }}
        Assert-II ([IO.File]::Exists($f.Saved.Path) -and [IO.File]::Exists($f.Pair.Json))
    }
    Test-II 'A hard-linked container introduced after indexing is rejected without cleanup' {
        $f=New-II;$i=Restore-II $f;$extra=Join-Path $f.Root 'linked.json';$null=New-Item -ItemType HardLink -Path $extra -Target $f.Saved.Path
        try{Reject-II {Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner};Assert-II ([IO.File]::Exists($extra))}finally{Remove-Item -LiteralPath $extra}
    }
    Test-II 'StoredSession 1.0 and its historical reference cache remain independently readable and unchanged' {
        $f=New-II -Family PROJECTION;$i=Restore-II $f
        . (Join-Path $f.Root 'src/Core/ScanCoordinator.ps1')
        $s=$f.Fixture.Package.Snapshot;$id=$f.Fixture.Identity
        $control=[pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$id.ScanId;CheckId=$id.CheckId;SectionKey='SystemSecurity';Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';TimestampUTC=$s.CollectedAtUTC;Evidence=[pscustomobject]@{}}
        $session=New-WinSecResultSession -DeviceId $id.DeviceId -ScanId $id.ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @($id.CheckId) `
            -ControlResults @($control) -StartedAtUTC $s.StartedAtUTC -CompletedAtUTC $s.CompletedAtUTC -ExecutionStatus COMPLETED -ScopeType CONTROL -ScopeKey $id.CheckId
        $c=[pscustomobject]@{ProjectRoot=$f.Root;TechnicalLocations=@{}}
        Write-WinSecTransitionSession $c $session ([pscustomobject]@{Status='SAVED';Files=@([pscustomobject]@{Reference=(Get-WinSecLegacySourceFixtureReference $f.Fixture)})})
        $oldPath=(Get-WinSecTransitionSessionLayout $f.Root $id.DeviceId $id.ScanId).Path;$oldHash=(Get-FileHash -LiteralPath $oldPath).Hash;$cache=Get-WinSecPublicHistoryJson $c.TechnicalLocations
        $legacy=Read-WinSecTransitionSessions $f.Root @([pscustomobject]@{DeviceId=$id.DeviceId})
        $again=Restore-II $f;$entry=Read-WinSecIndexedTechnicalSession $f.Root $again $f.Owner
        Assert-II ($legacy.Records.Count -eq 1 -and $again.Sessions.Count -eq 1 -and $again.ContentSha256 -ceq $i.ContentSha256 -and
            (Get-FileHash -LiteralPath $oldPath).Hash -ceq $oldHash -and (Get-WinSecPublicHistoryJson $c.TechnicalLocations) -ceq $cache -and
            $entry.Session.Sources[0].Reference.SnapshotSchemaVersion -ceq '2.1.0')
    }
    Test-II 'Unrelated device files are not consumed by the requested index' {
        $f=New-II;$i=Restore-II $f;$foreign=Join-Path $f.Root ('scans/'+(Get-WinSecSnapshotDeviceKey ('local:hw1-'+('c'*64)))+'/technical-sessions')
        $null=[IO.Directory]::CreateDirectory($foreign);[IO.File]::WriteAllText((Join-Path $foreign 'corrupt.json'),'FOREIGN')
        Assert-II ((Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner).FileSha256 -ceq $f.Saved.FileSha256 -and [IO.File]::ReadAllText((Join-Path $foreign 'corrupt.json')) -ceq 'FOREIGN')
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awji-[a-f0-9]{8}\z'){throw 'Unsafe index integration cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical source index integration: $passed passed; $failed failed.");if($failed){exit 1}
