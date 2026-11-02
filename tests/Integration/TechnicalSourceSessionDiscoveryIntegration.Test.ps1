[CmdletBinding()]param([string]$CasePattern='')
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceSessionDiscovery.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$counter=0;$scanCounter=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wdi-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-TDI {param([bool]$Value);if(-not $Value){throw 'Technical discovery integration assertion failed.'}}
function Reject-TDI {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-TDI $caught}
function New-TDI {
    param([string]$Family='CANDIDATE',[string]$Scope='CONTROL',[string]$Catalog='1.1.0',[string]$IntoRoot='')
    if($IntoRoot){$dir=$IntoRoot}else{
        $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
        foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
    }
    $script:scanCounter++;$scan='discovery-'+$script:scanCounter.ToString('x4')
    $f=New-WinSecTechnicalSourceFixture -Family $Family -ScopeType $Scope -CatalogVersion $Catalog
    if($Family -ceq 'PROJECTION'){
        # Rebuild through the historical producer so its embedded reviewed header has the same ScanId.
        $report=ConvertFrom-WinSecProjectionSnapshot $f.Package.Snapshot;$report.ScanId=$scan
        $f.Package=New-WinSecProjectionSnapshot $report;$f.Identity=$f.Package.Identity.PSObject.Copy()
        $f.Reference.Identity=$f.Identity.PSObject.Copy()
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
function Test-TDI {param([string]$Case,[scriptblock]$Action)
    if($CasePattern -and $Case -notmatch $CasePattern){return}
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try{
    Test-TDI 'All original scopes and both source families are discovered without projection or source selection' {
        $first=New-TDI;$fixtures=@($first)
        foreach($scope in @('SECTION','DEVICE')){$fixtures+=New-TDI -Scope $scope -IntoRoot $first.Root}
        $fixtures+=New-TDI -Family PROJECTION -IntoRoot $first.Root
        $before=Get-WinSecDeviceInventoryFingerprint $first.Root;$r=Read-WinSecTechnicalSourceSessions $first.Root $first.Owner.DeviceId
        Assert-TDI ($r.Sessions.Count -eq 4 -and $r.DeviceId -ceq $first.Owner.DeviceId -and (Get-WinSecDeviceInventoryFingerprint $first.Root) -ceq $before)
        foreach($f in $fixtures){
            $entry=@($r.Sessions|Where-Object {$_.Session.Identity.ScanId -ceq $f.Owner.ScanId})
            Assert-TDI ($entry.Count -eq 1 -and $entry[0].FileSha256 -ceq $f.Saved.FileSha256 -and
                (Get-WinSecPublicHistoryJson $entry[0].Session) -ceq (Get-WinSecPublicHistoryJson $f.Session))
        }
    }
    Test-TDI 'Complete and partial collections of the same scope are both retained with original coverage and versions' {
        $complete=New-TDI -Catalog '1.0.0';$partial=New-TDI -IntoRoot $complete.Root
        $r=Read-WinSecTechnicalSourceSessions $complete.Root $complete.Owner.DeviceId
        Assert-TDI ($r.Sessions.Count -eq 2 -and @($r.Sessions|Where-Object {$_.Session.Sources[0].Collection.Status -ceq 'COMPLETE'}).Count -eq 1 -and
            @($r.Sessions|Where-Object {$_.Session.Sources[0].Collection.Status -ceq 'PARTIAL'}).Count -eq 1 -and
            @($r.Sessions|Where-Object {$_.Session.Sources[0].Reference.CatalogVersion -ceq '1.1.0'}).Count -eq 1)
    }
    Test-TDI 'A cold process in either runtime discovers the same persisted session without fixture imports' {
        $f=New-TDI
        foreach($exe in @('pwsh.exe','powershell.exe')){
            $loader=(Join-Path $f.Root 'src/Services/TechnicalSourceSessionDiscovery.ps1').Replace("'","''");$readerRoot=$f.Root.Replace("'","''")
            $code="`$ErrorActionPreference='Stop';. '$loader';function Get-CimInstance {throw 'Native forbidden.'};function Get-MpPreference {throw 'Native forbidden.'};"+
                "`$r=Read-WinSecTechnicalSourceSessions '$readerRoot' '$($f.Owner.DeviceId)';if(`$r.Sessions.Count -ne 1 -or `$r.Sessions[0].FileSha256 -cne '$($f.Saved.FileSha256)'){throw 'Cold discovery mismatch.'};'TECHNICAL_DISCOVERY_CONFIRMED'"
            $out=@(& $exe -NoLogo -NoProfile -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))))
            Assert-TDI ($LASTEXITCODE -eq 0 -and $out[-1] -ceq 'TECHNICAL_DISCOVERY_CONFIRMED')
        }
    }
    Test-TDI 'StoredSession 1.0 remains independently readable and is never imported into technical discovery' {
        $f=New-TDI -Family PROJECTION
        # Load the historical dependency graph as the application does, without invoking any check.
        . (Join-Path $f.Root 'src/Core/ScanCoordinator.ps1')
        $s=$f.Fixture.Package.Snapshot;$identity=$f.Fixture.Identity
        $control=[pscustomobject]@{DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CheckId=$identity.CheckId;SectionKey='SystemSecurity';Status='INFORMATIONAL';
            ObservedStatus='INFORMATIONAL';TimestampUTC=$s.CollectedAtUTC;Evidence=[pscustomobject]@{}}
        $session=New-WinSecResultSession -DeviceId $identity.DeviceId -ScanId $identity.ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @($identity.CheckId) `
            -ControlResults @($control) -StartedAtUTC $s.StartedAtUTC -CompletedAtUTC $s.CompletedAtUTC -ExecutionStatus COMPLETED -ScopeType CONTROL -ScopeKey $identity.CheckId
        $c=[pscustomobject]@{ProjectRoot=$f.Root;TechnicalLocations=@{}}
        Write-WinSecTransitionSession $c $session ([pscustomobject]@{Status='SAVED';Files=@([pscustomobject]@{Reference=(Get-WinSecLegacySourceFixtureReference $f.Fixture)})})
        $path=(Get-WinSecTransitionSessionLayout $f.Root $identity.DeviceId $identity.ScanId).Path;$hash=(Get-FileHash -LiteralPath $path).Hash
        $device=[pscustomobject]@{DeviceId=$identity.DeviceId}
        $legacy=Read-WinSecTransitionSessions $f.Root @($device);$r=Read-WinSecTechnicalSourceSessions $f.Root $identity.DeviceId
        Assert-TDI ($legacy.Records.Count -eq 1 -and $r.Sessions.Count -eq 1 -and (Get-FileHash -LiteralPath $path).Hash -ceq $hash -and
            $r.Sessions[0].Session.ArtifactType -ceq 'WinSec.TechnicalSourceSession' -and $r.Sessions[0].Session.Sources[0].Reference.SnapshotSchemaVersion -ceq '2.1.0')
    }
    Test-TDI 'Another device namespace is never read or included even when its contents are corrupt' {
        $f=New-TDI;$other='local:hw1-'+('c'*64);$dir=Join-Path $f.Root ('scans/'+(Get-WinSecSnapshotDeviceKey $other)+'/technical-sessions')
        $null=[IO.Directory]::CreateDirectory($dir);[IO.File]::WriteAllText((Join-Path $dir 'foreign.json'),'PRIVATE-FOREIGN-DATA')
        Assert-TDI ((Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId).Sessions.Count -eq 1 -and
            [IO.File]::ReadAllText((Join-Path $dir 'foreign.json')) -ceq 'PRIVATE-FOREIGN-DATA')
    }
    foreach($damage in @('Pending','WrongName','UnknownType','UnknownVersion','ForeignDevice','ContainerBytes','Truncated','SourceBytes','MissingSourceCommit','FalseCoverage','FalseSnapshotHash','IncompatibleReference')){
        Test-TDI ('Invalid discovery is rejected as a whole without repairing or hiding entries: '+$damage) {
            $f=New-TDI;$previous=Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId;$previousHash=$previous.Sessions[0].FileSha256
            $before=Get-WinSecDeviceInventoryFingerprint $f.Root
            switch($damage){Pending {[IO.File]::WriteAllText($f.Layout.Temporary,'INTERRUPTED')}
                WrongName {[IO.File]::Move($f.Saved.Path,(Join-Path ([IO.Path]::GetDirectoryName($f.Saved.Path)) (('a'*64)+'.json')))}
                UnknownType {[IO.File]::WriteAllText($f.Saved.Path,([IO.File]::ReadAllText($f.Saved.Path)).Replace('WinSec.TechnicalSourceSession','WinSec.StoredSession'))}
                UnknownVersion {[IO.File]::WriteAllText($f.Saved.Path,([IO.File]::ReadAllText($f.Saved.Path)).Replace('"SchemaVersion":"1.0.0"','"SchemaVersion":"9.0.0"'))}
                ForeignDevice {[IO.File]::WriteAllText($f.Saved.Path,([IO.File]::ReadAllText($f.Saved.Path)).Replace($f.Owner.DeviceId,('local:hw1-'+('c'*64))))}
                ContainerBytes {[IO.File]::AppendAllText($f.Saved.Path,' ')}
                Truncated {[IO.File]::WriteAllText($f.Saved.Path,'{"ArtifactType":')}
                SourceBytes {[IO.File]::AppendAllText($f.Pair.Markdown,' ')}
                MissingSourceCommit {Remove-Item -LiteralPath $f.Pair.Commit}
                default {$changed=Copy-WinSecResultData $f.Session
                    switch($damage){FalseCoverage {$changed.Sources[0].Collection.Unknown++};FalseSnapshotHash {$changed.Sources[0].SnapshotSha256='A'*64}
                        IncompatibleReference {$changed.Sources[0].Reference.CollectorVersion='1.2.0'}}
                    $changed.ContentSha256=Get-WinSecTechnicalSessionDigest $changed;[IO.File]::WriteAllText($f.Saved.Path,(Get-WinSecPublicHistoryJson $changed))}
            }
            Reject-TDI {Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId}
            Assert-TDI ($previous.Sessions[0].FileSha256 -ceq $previousHash -and [IO.File]::Exists($f.Pair.Json) -and
                (Get-WinSecDeviceInventoryFingerprint $f.Root) -ceq $before)
        }
    }
    Test-TDI 'Cancellation during validation preserves earlier results, files and all leases' {
        $f=New-TDI;$previous=Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId;$script:polls=0;$cancelled=$false
        try{$null=Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId -CancellationAction {$script:polls++;$script:polls -ge 8}}
        catch [OperationCanceledException]{$cancelled=$true}
        $probe=[IO.File]::Open($f.Saved.Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$probe.Dispose()
        $lease=Open-WinSecDeviceInventoryStore $f.Root;$lease.Lock.Dispose()
        Assert-TDI ($cancelled -and $previous.Sessions.Count -eq 1 -and (Get-FileHash -LiteralPath $f.Saved.Path).Hash -ceq $previous.Sessions[0].FileSha256)
    }
    Test-TDI 'The actual inventory lease prevents concurrent cooperative discovery' {
        $f=New-TDI;$lease=Open-WinSecDeviceInventoryStore $f.Root
        try{Reject-TDI {Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId}}finally{$lease.Lock.Dispose()}
        Assert-TDI ((Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId).Sessions.Count -eq 1)
    }
    Test-TDI 'Removed owners cannot discover records that remain on disk' {
        $f=New-TDI;$inventory=[pscustomobject]@{schemaVersion='1.1.0';targets=@();removedDeviceHashes=@((Get-WinSecDeviceInventoryIdentityHash $f.Owner.DeviceId))}
        [IO.File]::WriteAllText((Join-Path $f.Root 'data/devices.json'),(ConvertTo-Json $inventory -Compress))
        Reject-TDI {Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId};Assert-TDI ([IO.File]::Exists($f.Saved.Path))
    }
    Test-TDI 'Hard-linked containers are rejected without following or removing either link' {
        $f=New-TDI;$extra=Join-Path $f.Root 'hardlink.json';$null=New-Item -ItemType HardLink -Path $extra -Target $f.Saved.Path
        try{Reject-TDI {Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId};Assert-TDI ([IO.File]::Exists($extra))}finally{Remove-Item -LiteralPath $extra}
    }
    Test-TDI 'A junction namespace cannot redirect discovery' {
        $f=New-TDI;$dir=[IO.Path]::GetDirectoryName($f.Saved.Path);$moved=$dir+'-moved';[IO.Directory]::Move($dir,$moved)
        $null=New-Item -ItemType Junction -Path $dir -Target $moved
        try{Reject-TDI {Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId}}
        finally{[IO.Directory]::Delete($dir);[IO.Directory]::Move($moved,$dir)}
    }
    Test-TDI 'An inventory change outside its cooperative lock rejects the discovery result' {
        $f=New-TDI;$script:inventoryToChange=Join-Path $f.Root 'data/devices.json';$script:polls=0
        Reject-TDI {Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId -CancellationAction {
            $script:polls++;if($script:polls -eq 2){[IO.File]::WriteAllText($script:inventoryToChange,'{"schemaVersion":"1.0.0","targets":[]}')};$false
        }}
        Assert-TDI ([IO.File]::Exists($f.Saved.Path) -and [IO.File]::Exists($f.Pair.Json))
    }
    Test-TDI 'A namespace insertion outside its cooperative lock never becomes an incomplete success' {
        $f=New-TDI;$script:insertedFile=Join-Path ([IO.Path]::GetDirectoryName($f.Saved.Path)) 'unexpected.txt';$script:polls=0
        Reject-TDI {Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId -CancellationAction {
            $script:polls++;if($script:polls -eq 2){[IO.File]::WriteAllText($script:insertedFile,'UNRELATED')};$false
        }}
        Assert-TDI ([IO.File]::ReadAllText($script:insertedFile) -ceq 'UNRELATED' -and [IO.File]::Exists($f.Saved.Path))
    }
    Test-TDI 'The final cancellation callback cannot bypass the namespace verification' {
        $f=New-TDI;$script:polls=0
        $previous=Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId -CancellationAction {$script:polls++;$false}
        $script:lastPoll=$script:polls;$script:polls=0
        $script:insertedFile=Join-Path ([IO.Path]::GetDirectoryName($f.Saved.Path)) 'late.txt'
        Reject-TDI {Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId -CancellationAction {
            $script:polls++;if($script:polls -eq $script:lastPoll){[IO.File]::WriteAllText($script:insertedFile,'LATE')};$false
        }}
        Assert-TDI ($previous.Sessions.Count -eq 1 -and [IO.File]::ReadAllText($script:insertedFile) -ceq 'LATE')
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awdi-[a-f0-9]{8}\z'){throw 'Unsafe discovery integration fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical session discovery integration: $passed passed; $failed failed.");if($failed){exit 1}
