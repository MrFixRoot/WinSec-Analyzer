[CmdletBinding()]param([string]$CasePattern='')
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$counter=0;$scanCounter=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wri-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-RI {param([bool]$Value);if(-not $Value){throw 'Technical restoration integration assertion failed.'}}
function Reject-RI {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-RI $caught}
function New-RI {param([string]$Family='CANDIDATE',[string]$Catalog='1.1.0',[int]$Day=0,[string]$IntoRoot='',[switch]$Empty)
    if($IntoRoot){$dir=$IntoRoot}else{
        $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
        foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
    }
    $device='local:hw1-'+('a'*64)
    if(-not $IntoRoot){
        $null=[IO.Directory]::CreateDirectory((Join-Path $dir 'data'))
        $inventory=[pscustomobject]@{schemaVersion='1.0.0';targets=@([pscustomobject]@{DeviceId=$device;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true})}
        [IO.File]::WriteAllText((Join-Path $dir 'data/devices.json'),(ConvertTo-Json $inventory -Depth 6 -Compress))
    }
    if($Empty){return [pscustomobject]@{Root=$dir;DeviceId=$device}}
    $script:scanCounter++;$scan='restoration-'+$script:scanCounter.ToString('x4')
    $f=New-WinSecTechnicalSourceFixture -Family $Family -CatalogVersion $Catalog
    if($Family -ceq 'PROJECTION'){
        $report=ConvertFrom-WinSecProjectionSnapshot $f.Package.Snapshot;$report.ScanId=$scan
        foreach($name in @('StartedAtUTC','CollectedAtUTC','CompletedAtUTC','GeneratedAtUTC')){$report.$name=(ConvertTo-WinSecSnapshotUtc $report.$name).AddDays($Day).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')}
        $f.Package=New-WinSecProjectionSnapshot $report;$f.Identity=$f.Package.Identity.PSObject.Copy();$f.Reference.Identity=$f.Identity.PSObject.Copy()
    }else{
        foreach($name in @('StartedAtUTC','CollectedAtUTC','CompletedAtUTC','GeneratedAtUTC')){$f.Package.Snapshot.$name=(ConvertTo-WinSecSnapshotUtc $f.Package.Snapshot.$name).AddDays($Day).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')}
    }
    foreach($identity in @($f.Identity,$f.Reference.Identity,$f.Package.Identity,$f.Package.Snapshot.Identity)){$identity.ScanId=$scan}
    foreach($batch in $f.Package.Snapshot.Batches){$batch.ScanId=$scan};$f.Reference.CollectedAtUTC=$f.Package.Snapshot.CollectedAtUTC
    $null=Save-WinSecTechnicalSourceFixture $dir $f
    $owner=[pscustomobject]@{DeviceId=$device;ScanId=$scan;ScopeType='CONTROL';ScopeKey='WSA-SYS-001'}
    $stamp=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
    $s=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
        [pscustomobject]@{Reference=$stamp.Reference;SnapshotSha256=$stamp.SnapshotSha256;Collection=$f.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
    $s.ContentSha256=Get-WinSecTechnicalSessionDigest $s;$saved=Write-WinSecTechnicalSourceSession $dir $s $owner
    [pscustomobject]@{Root=$dir;DeviceId=$device;Fixture=$f;Owner=$owner;Session=$s;Saved=$saved;
        Pair=(Get-WinSecSnapshotPairLayout $dir $f.Identity $f.Reference.CollectedAtUTC)}
}
function Context-RI {param($f)
    . (Join-Path $f.Root 'src/Core/ScanCoordinator.ps1')
    $devices=@(foreach($d in (Import-WinSecDeviceInventory $f.Root).targets){ConvertTo-WinSecRegisteredTarget $d})
    $coordinator=New-WinSecScanCoordinator -ProjectRoot $f.Root
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=$devices};$coordinator.NewTechnicalStorageEnabled=$true
    [pscustomobject]@{ProjectRoot=$f.Root;Devices=$devices;ScanCoordinator=$coordinator;PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{}}
}
function Restore-RI {param($f,$Context,[switch]$LegacyOnly,[scriptblock]$Cancel)
    # Same installed dependency graph as startup, with no scan/coordinator initialization side effects.
    . (Join-Path $f.Root 'src/Core/ScanCoordinator.ps1')
    if($LegacyOnly){Restore-WinSecPublicHistory $Context}else{Restore-WinSecPublicHistory $Context -RestoreTechnicalSources -CancellationAction $Cancel}
}
function Select-RI {param($Context,[string]$Family='DEFENDER_CANDIDATE',[string]$Preference='PREFER_COMPLETE')
    Select-WinSecRestoredTechnicalSource $Context $Context.Devices[0].DeviceId $Family CONTROL WSA-SYS-001 -SourcePreference $Preference
}
function Test-RI {param([string]$Case,[scriptblock]$Action)
    if($CasePattern -and $Case -notmatch $CasePattern){return}
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try{
    Test-RI 'Explicit restoration publishes RECORDS indexes without manufacturing public sessions or changing source selection maps' {
        $a=New-RI -Catalog '1.0.0';$b=New-RI -Day 1 -IntoRoot $a.Root;$c=Context-RI $a;Restore-RI $a $c
        $s=Select-RI $c;$latest=Select-RI $c -Preference LATEST_ATTEMPT
        Assert-RI ($c.HistoryReady -and $c.TechnicalSourcesReady -and $c.TechnicalSourceIndexes[$a.DeviceId].Origin -ceq 'RECORDS' -and
            $c.PublicScans.Count -eq 0 -and $c.ScanCoordinator.Sessions.Count -eq 0 -and $c.ActiveScanByScope.Count -eq 0 -and $c.ActiveScanByDevice.Count -eq 0 -and
            $c.TechnicalSourceIndexes[$a.DeviceId].Sessions.Count -eq 2 -and $s.Selected.SessionIdentity.ScanId -ceq $a.Owner.ScanId -and
            $s.LatestAttempt.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and $latest.Selected.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and $s.Origin -ceq 'RECORDS')
    }
    Test-RI 'Historical restoration remains opt-out and never reads technical namespaces or exposes new cache properties' {
        $a=New-RI;[IO.File]::AppendAllText($a.Pair.Markdown,' ');$c=Context-RI $a;Restore-RI $a $c -LegacyOnly
        Assert-RI ($c.HistoryReady -and $null -eq $c.PSObject.Properties['TechnicalSourceIndexes'] -and $null -eq $c.PSObject.Properties['TechnicalSourcesReady'])
    }
    Test-RI 'Empty registered histories restore an empty RECORDS index and remain non-scanned public history' {
        $a=New-RI -Empty;$c=Context-RI $a;Restore-RI $a $c
        Assert-RI ($c.TechnicalSourceIndexes[$a.DeviceId].Sessions.Count -eq 0 -and $c.TechnicalSourceIndexes[$a.DeviceId].Origin -ceq 'RECORDS' -and $c.PublicScans.Count -eq 0)
    }
    Test-RI 'Different known families stay distinct after restoration and explicit cache consumption' {
        $a=New-RI -Family PROJECTION;$b=New-RI -Day 1 -IntoRoot $a.Root;$c=Context-RI $a;Restore-RI $a $c
        $reviewed=Select-RI $c -Family REVIEWED_PROJECTION;$candidate=Select-RI $c
        Assert-RI ($reviewed.Selected.Source.Reference.SnapshotSchemaVersion -ceq '2.1.0' -and $candidate.Selected.Source.Reference.SnapshotSchemaVersion -ceq '2.0.0' -and
            $reviewed.History.Count -eq 2 -and $reviewed.History[0].Eligibility -ceq 'OTHER_FAMILY')
    }
    Test-RI 'A fresh process restores the same original references in either runtime without Windows providers' {
        $a=New-RI
        foreach($exe in @('pwsh.exe','powershell.exe')){
            $install=$a.Root.Replace("'","''");$loader=(Join-Path $a.Root 'src/Core/ScanCoordinator.ps1').Replace("'","''")
            $code="`$ErrorActionPreference='Stop';. '$loader';function Get-CimInstance {throw 'Native forbidden.'};function Get-MpPreference {throw 'Native forbidden.'};"+
                "`$devices=@(foreach(`$d in (Import-WinSecDeviceInventory '$install').targets){ConvertTo-WinSecRegisteredTarget `$d});"+
                "`$coord=New-WinSecScanCoordinator -ProjectRoot '$install';`$coord.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=`$devices};`$coord.NewTechnicalStorageEnabled=`$true;"+
                "`$c=[pscustomobject]@{ProjectRoot='$install';Devices=`$devices;ScanCoordinator=`$coord;PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{}};"+
                "Restore-WinSecPublicHistory `$c -RestoreTechnicalSources;. '$install/src/Services/TechnicalSourceRestoration.ps1';"+
                "`$s=Select-WinSecRestoredTechnicalSource `$c '$($a.DeviceId)' DEFENDER_CANDIDATE CONTROL WSA-SYS-001;"+
                "if(`$s.Selected.SessionIdentity.ScanId -cne '$($a.Owner.ScanId)' -or `$s.Origin -cne 'RECORDS' -or `$c.PublicScans.Count -ne 0){throw 'Restart mismatch.'};'TECHNICAL_RESTORE_CONFIRMED'"
            $output=@(& $exe -NoLogo -NoProfile -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))))
            Assert-RI ($LASTEXITCODE -eq 0 -and $output[-1] -ceq 'TECHNICAL_RESTORE_CONFIRMED')
        }
    }
    Test-RI 'A corrupt source rejects all cache publication and never falls back to public history' {
        $a=New-RI;$c=Context-RI $a;[IO.File]::AppendAllText($a.Pair.Markdown,' ')
        Reject-RI {Restore-RI $a $c}
        Assert-RI ($c.PublicScans.Count -eq 0 -and $c.ScanCoordinator.Sessions.Count -eq 0 -and $null -eq $c.PSObject.Properties['TechnicalSourceIndexes'] -and $null -eq $c.PSObject.Properties['HistoryReady'])
    }
    Test-RI 'Revalidation under the public inventory lease catches changes after technical preparation' {
        $a=New-RI;$c=Context-RI $a;$script:dirtyPath=$a.Pair.Markdown;$script:changed=$false
        Reject-RI {Restore-RI $a $c -Cancel {
            if(-not $script:changed -and @(Get-PSCallStack|Where-Object FunctionName -CEQ Assert-WinSecTechnicalRestoreIndexes).Count){[IO.File]::AppendAllText($script:dirtyPath,' ');$script:changed=$true};$false
        }}
        Assert-RI ($script:changed -and $c.PublicScans.Count -eq 0 -and $null -eq $c.PSObject.Properties['TechnicalSourceIndexes'])
    }
    Test-RI 'Namespace changes after preparation reject stale manifests instead of caching a partial directory' {
        $a=New-RI;$c=Context-RI $a;$script:latePath=Join-Path ([IO.Path]::GetDirectoryName($a.Saved.Path)) 'late.json';$script:changed=$false
        Reject-RI {Restore-RI $a $c -Cancel {
            if(-not $script:changed -and @(Get-PSCallStack|Where-Object FunctionName -CEQ Assert-WinSecTechnicalRestoreIndexes).Count){[IO.File]::WriteAllText($script:latePath,'UNKNOWN');$script:changed=$true};$false
        }}
        Assert-RI ($script:changed -and [IO.File]::ReadAllText($script:latePath) -ceq 'UNKNOWN' -and $null -eq $c.PSObject.Properties['TechnicalSourceIndexes'])
    }
    Test-RI 'Cancellation rejects publication, preserves context maps and releases the inventory lease' {
        $a=New-RI;$c=Context-RI $a;$script:polls=0;$cancelled=$false
        try{Restore-RI $a $c -Cancel {$script:polls++;$script:polls -ge 6}}catch [OperationCanceledException]{$cancelled=$true}
        $lease=Open-WinSecDeviceInventoryStore $a.Root;$lease.Lock.Dispose()
        Assert-RI ($cancelled -and $c.PublicScans.Count -eq 0 -and $null -eq $c.PSObject.Properties['TechnicalSourceIndexes'] -and $null -eq $c.PSObject.Properties['HistoryReady'])
    }
    Test-RI 'Stale populated or ready technical caches are rejected without replacement' {
        $a=New-RI;$c=Context-RI $a;$old=@{$a.DeviceId='STALE'};$c|Add-Member NoteProperty TechnicalSourceIndexes $old
        Reject-RI {Restore-RI $a $c};Assert-RI ([object]::ReferenceEquals($old,$c.TechnicalSourceIndexes) -and $c.TechnicalSourceIndexes[$a.DeviceId] -ceq 'STALE')
    }
    Test-RI 'A caller cache mutation during restoration cannot be overwritten by final publication' {
        $a=New-RI;$script:mutatingContext=Context-RI $a;$script:changed=$false
        Reject-RI {Restore-RI $a $script:mutatingContext -Cancel {
            if(-not $script:changed -and @(Get-PSCallStack|Where-Object FunctionName -CEQ Assert-WinSecTechnicalRestoreIndexes).Count){$script:mutatingContext.PublicScans['caller']='KEEP';$script:changed=$true};$false
        }}
        Assert-RI ($script:changed -and $script:mutatingContext.PublicScans['caller'] -ceq 'KEEP' -and $null -eq $script:mutatingContext.PSObject.Properties['TechnicalSourceIndexes'])
    }
    Test-RI 'Consuming restored caches revalidates changed files and never uses a stale choice' {
        $a=New-RI;$c=Context-RI $a;Restore-RI $a $c;$prior=Select-RI $c;$hash=Get-WinSecPublicHistoryJson $prior
        [IO.File]::AppendAllText($a.Pair.Markdown,' ');Reject-RI {Select-RI $c}
        Assert-RI ((Get-WinSecPublicHistoryJson $prior) -ceq $hash -and $c.TechnicalSourceIndexes[$a.DeviceId].Origin -ceq 'RECORDS')
    }
    Test-RI 'Removed devices cannot consume a previously restored technical cache' {
        $a=New-RI;$c=Context-RI $a;Restore-RI $a $c
        [IO.File]::WriteAllText((Join-Path $a.Root 'data/devices.json'),'{"schemaVersion":"1.0.0","targets":[]}')
        Reject-RI {Select-RI $c};Assert-RI ([IO.File]::Exists($a.Saved.Path))
    }
    Test-RI 'StoredSession 1.0 public caches and new technical indexes publish together with independent identities' {
        $a=New-RI -Family PROJECTION
        . (Join-Path $a.Root 'src/Core/ScanCoordinator.ps1')
        $s=$a.Fixture.Package.Snapshot;$id=$a.Fixture.Identity
        $control=[pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$id.ScanId;CheckId=$id.CheckId;SectionKey='SystemSecurity';Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';TimestampUTC=$s.CollectedAtUTC;Evidence=[pscustomobject]@{}}
        $session=New-WinSecResultSession -DeviceId $id.DeviceId -ScanId $id.ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @($id.CheckId) `
            -ControlResults @($control) -StartedAtUTC $s.StartedAtUTC -CompletedAtUTC $s.CompletedAtUTC -ExecutionStatus COMPLETED -ScopeType CONTROL -ScopeKey $id.CheckId
        $writer=[pscustomobject]@{ProjectRoot=$a.Root;TechnicalLocations=@{}}
        Write-WinSecTransitionSession $writer $session ([pscustomobject]@{Status='SAVED';Files=@([pscustomobject]@{Reference=(Get-WinSecLegacySourceFixtureReference $a.Fixture)})})
        $path=(Get-WinSecTransitionSessionLayout $a.Root $id.DeviceId $id.ScanId).Path;$hash=(Get-FileHash -LiteralPath $path).Hash
        $c=Context-RI $a;Restore-RI $a $c;$picked=Select-RI $c -Family REVIEWED_PROJECTION
        Assert-RI ($c.PublicScans.Count -eq 1 -and $c.ScanCoordinator.Sessions.Count -eq 1 -and $c.ActiveScanByScope.Count -eq 1 -and
            $c.ScanCoordinator.TechnicalLocations.Count -eq 1 -and $c.TechnicalSourceIndexes[$a.DeviceId].Sessions.Count -eq 1 -and
            $picked.Selected.SessionIdentity.ScanId -ceq $id.ScanId -and (Get-FileHash -LiteralPath $path).Hash -ceq $hash)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awri-[a-f0-9]{8}\z'){throw 'Unsafe restoration integration cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical source restoration integration: $passed passed; $failed failed.");if($failed){exit 1}
