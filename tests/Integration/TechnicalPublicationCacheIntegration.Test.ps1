[CmdletBinding()]param([string]$CasePattern='')
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}}
$passed=0;$failed=0;$counter=0;$scanCounter=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wpc-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-PC {param([bool]$Value);if(-not $Value){throw 'Technical publication integration assertion failed.'}}
function Reject-PC {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PC $caught}
function New-PC {param([string]$IntoRoot='',[string]$Catalog='1.0.0',[int]$Day=0,[string]$Scope='CONTROL')
    if($IntoRoot){$dir=$IntoRoot}else{
        $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
        foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
        $device='local:hw1-'+('a'*64);$other='local:hw1-'+('c'*64)
        $null=[IO.Directory]::CreateDirectory((Join-Path $dir 'data'))
        [IO.File]::WriteAllText((Join-Path $dir 'data/devices.json'),(ConvertTo-Json ([pscustomobject]@{schemaVersion='1.0.0';targets=@(
            [pscustomobject]@{DeviceId=$device;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true},
            [pscustomobject]@{DeviceId=$other;Hostname='OTHER';Mode='LOCAL';Enabled=$true})}) -Depth 6 -Compress))
    }
    . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
    $script:scanCounter++;$scan='publication-'+$script:scanCounter.ToString('x4')
    $f=New-WinSecTechnicalSourceFixture -CatalogVersion $Catalog -ScopeType $Scope
    foreach($identity in @($f.Identity,$f.Reference.Identity,$f.Package.Identity,$f.Package.Snapshot.Identity)){$identity.ScanId=$scan}
    foreach($batch in $f.Package.Snapshot.Batches){$batch.ScanId=$scan}
    foreach($name in @('StartedAtUTC','CollectedAtUTC','CompletedAtUTC','GeneratedAtUTC')){
        $f.Package.Snapshot.$name=(ConvertTo-WinSecSnapshotUtc $f.Package.Snapshot.$name).AddDays($Day).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
    }
    $f.Reference.CollectedAtUTC=$f.Package.Snapshot.CollectedAtUTC;$null=Save-WinSecTechnicalSourceFixture $dir $f
    $owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$scan;ScopeType=$f.Identity.ScopeType;ScopeKey=$f.Identity.ScopeKey}
    $stamp=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
    $s=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
        [pscustomobject]@{Reference=$stamp.Reference;SnapshotSha256=$stamp.SnapshotSha256;Collection=$f.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
    $s.ContentSha256=Get-WinSecTechnicalSessionDigest $s
    [pscustomobject]@{Root=$dir;Owner=$owner;Session=$s;Pair=(Get-WinSecSnapshotPairLayout $dir $f.Identity $f.Reference.CollectedAtUTC);
        Layout=(Get-WinSecTechnicalSessionStorageLayout $dir $owner);Other=('local:hw1-'+('c'*64))}
}
function Context-PC {param($f)
    . (Join-Path $f.Root 'src/Core/ScanCoordinator.ps1')
    $devices=@(foreach($d in (Import-WinSecDeviceInventory $f.Root).targets){ConvertTo-WinSecRegisteredTarget $d})
    $coordinator=New-WinSecScanCoordinator $f.Root;$coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=$devices};$coordinator.NewTechnicalStorageEnabled=$true
    [pscustomobject]@{ProjectRoot=$f.Root;Devices=$devices;ScanCoordinator=$coordinator;PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{}}
}
function Publish-PC {param($f,$Context,[scriptblock]$Cancel,[scriptblock]$Progress)
    Write-WinSecTechnicalSourceSession $f.Root $f.Session $f.Owner -TechnicalCacheCoordinator $Context.ScanCoordinator -CancellationAction $Cancel -ProgressCallback $Progress
}
function Select-PC {param($Context,[string]$Preference='PREFER_COMPLETE')
    Select-WinSecRestoredTechnicalSource $Context $Context.Devices[0].DeviceId DEFENDER_CANDIDATE CONTROL WSA-SYS-001 -SourcePreference $Preference
}
function Test-PC {param([string]$Case,[scriptblock]$Action,[switch]$Empty)
    if($CasePattern -and $Case -notmatch $CasePattern){return}
    try{
        $a=New-PC
        . (Join-Path $a.Root 'src/Core/ScanCoordinator.ps1')
        . (Join-Path $a.Root 'src/Services/TechnicalSourceRestoration.ps1')
        if(-not $Empty){$old=Write-WinSecTechnicalSourceSession $a.Root $a.Session $a.Owner}
        $c=Context-PC $a;Restore-WinSecPublicHistory $c -RestoreTechnicalSources
        $map=$c.TechnicalSourceIndexes;$prior=$map[$a.Owner.DeviceId];$other=$map[$a.Other]
        & $Action;$script:passed++;Write-Host ('[PASS] '+$Case)
    }catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
try{
    Test-PC 'First explicit technical Scan publishes a verified RECORDS index without replacing the shared map' {
        $p=Publish-PC $a $c
        Assert-PC ($p.PublicationStatus -ceq 'COMMITTED' -and @($p.PSObject.Properties).Count -eq 4 -and
            [object]::ReferenceEquals($map,$c.ScanCoordinator.TechnicalSourceIndexes) -and [object]::ReferenceEquals($other,$map[$a.Other]) -and
            $map[$a.Owner.DeviceId].Sessions.Count -eq 1 -and $map[$a.Owner.DeviceId].Origin -ceq 'RECORDS')
        Assert-PC ((Select-PC $c).Selected.SessionIdentity.ScanId -ceq $a.Owner.ScanId)
    } -Empty
    Test-PC 'Rescan preserves complete history and a later partial attempt under both source policies' {
        $b=New-PC $a.Root '1.1.0' 1;$before=(Get-FileHash -LiteralPath $old.Path -Algorithm SHA256).Hash;$p=Publish-PC $b $c
        $preferred=Select-PC $c;$latest=Select-PC $c LATEST_ATTEMPT
        Assert-PC ($preferred.Selected.SessionIdentity.ScanId -ceq $a.Owner.ScanId -and $preferred.LatestAttempt.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and
            $latest.Selected.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and $preferred.History.Count -eq 2 -and $preferred.SelectedDiffersFromLatest -and
            $preferred.LatestAttempt.Source.Collection.Status -ceq 'PARTIAL' -and $map[$a.Owner.DeviceId].Sessions.Count -eq 2 -and
            [object]::ReferenceEquals($other,$map[$a.Other]) -and (Get-FileHash -LiteralPath $old.Path -Algorithm SHA256).Hash -ceq $before)
    }
    foreach($phase in @('VALIDATING','STAGED')){
        Test-PC ('Precommit cancellation preserves the previous cache and never indexes the attempt: '+$phase) {
            $b=New-PC $a.Root '1.1.0' 1;$script:cancelPublication=$false;$script:cancelPhase=$phase
            Reject-PC {Publish-PC $b $c -Cancel {$script:cancelPublication} -Progress {param($e);if($e.Phase -ceq $script:cancelPhase){$script:cancelPublication=$true}}}
            Assert-PC ([object]::ReferenceEquals($prior,$map[$a.Owner.DeviceId]) -and -not [IO.File]::Exists($b.Layout.Path) -and
                (Select-PC $c).Selected.SessionIdentity.ScanId -ceq $a.Owner.ScanId)
        }
    }
    Test-PC 'A failed staged publication preserves the previous cache and immutable older session' {
        $b=New-PC $a.Root '1.1.0' 1;$script:temporaryPath=$b.Layout.Temporary
        Reject-PC {Publish-PC $b $c -Progress {param($e);if($e.Phase -ceq 'STAGED'){[IO.File]::AppendAllText($script:temporaryPath,' ')}}}
        Assert-PC ([object]::ReferenceEquals($prior,$map[$a.Owner.DeviceId]) -and [IO.File]::Exists($old.Path) -and -not [IO.File]::Exists($b.Layout.Path))
    }
    Test-PC 'A caller cache replacement before commit rejects publication without silently overwriting either map' {
        $b=New-PC $a.Root '1.1.0' 1;$script:publicationCoordinator=$c.ScanCoordinator;$script:oldIndex=$prior;$script:ownerId=$a.Owner.DeviceId
        Reject-PC {Publish-PC $b $c -Progress {param($e);if($e.Phase -ceq 'STAGED'){$script:publicationCoordinator.TechnicalSourceIndexes=@{$script:ownerId=$script:oldIndex}}}}
        Assert-PC ([object]::ReferenceEquals($prior,$map[$a.Owner.DeviceId]) -and -not [IO.File]::Exists($b.Layout.Path))
    }
    Test-PC 'Postcommit cancellation leaves the published attempt durable and the target cache unavailable' {
        $b=New-PC $a.Root '1.1.0' 1;$script:committedPath=$b.Layout.Path
        Reject-PC {Publish-PC $b $c -Cancel {[IO.File]::Exists($script:committedPath)}}
        Assert-PC ([IO.File]::Exists($b.Layout.Path) -and -not $map.ContainsKey($a.Owner.DeviceId) -and [object]::ReferenceEquals($other,$map[$a.Other]))
        Reject-PC {Select-PC $c}
        $next=Context-PC $a;Restore-WinSecPublicHistory $next -RestoreTechnicalSources
        Assert-PC ((Select-PC $next LATEST_ATTEMPT).Selected.SessionIdentity.ScanId -ceq $b.Owner.ScanId)
    }
    Test-PC 'A concurrent publication namespace change rejects reload and cannot advertise a stale index' {
        $b=New-PC $a.Root '1.1.0' 1;$script:committedPath=$b.Layout.Path;$script:foreignPath=Join-Path ([IO.Path]::GetDirectoryName($b.Layout.Path)) 'foreign.json';$script:added=$false
        Reject-PC {Publish-PC $b $c -Cancel {if([IO.File]::Exists($script:committedPath) -and -not $script:added){[IO.File]::WriteAllText($script:foreignPath,'UNKNOWN');$script:added=$true};$false}}
        Assert-PC ([IO.File]::Exists($b.Layout.Path) -and [IO.File]::Exists($old.Path) -and -not $map.ContainsKey($a.Owner.DeviceId) -and [object]::ReferenceEquals($other,$map[$a.Other]))
    }
    Test-PC 'Inventory lease contention prevents publication and preserves cached history' {
        $b=New-PC $a.Root '1.1.0' 1;$lock=Open-WinSecDeviceInventoryStore $a.Root
        try{Reject-PC {Publish-PC $b $c}}finally{$lock.Lock.Dispose()}
        Assert-PC ([object]::ReferenceEquals($prior,$map[$a.Owner.DeviceId]) -and -not [IO.File]::Exists($b.Layout.Path))
    }
    Test-PC 'The original writer remains opt-out and does not invent an automatic cache event' {
        $b=New-PC $a.Root '1.1.0' 1;$p=Write-WinSecTechnicalSourceSession $b.Root $b.Session $b.Owner
        Assert-PC ($p.PSObject.Properties.Name.Count -eq 4 -and $p.PublicationStatus -ceq 'COMMITTED' -and [object]::ReferenceEquals($prior,$map[$a.Owner.DeviceId]))
        $next=Context-PC $a;Restore-WinSecPublicHistory $next -RestoreTechnicalSources
        Assert-PC ((Select-PC $next LATEST_ATTEMPT).Selected.SessionIdentity.ScanId -ceq $b.Owner.ScanId)
    }
    Test-PC 'Published sources are physically revalidated on consumption after a successful reload' {
        $b=New-PC $a.Root '1.1.0' 1;$null=Publish-PC $b $c
        [IO.File]::AppendAllText($b.Pair.Markdown,' ');Reject-PC {Select-PC $c}
        Assert-PC ([object]::ReferenceEquals($other,$map[$a.Other]) -and [IO.File]::Exists($old.Path))
    }
    Test-PC 'A section publication retains its original scope without fabricating a control session' {
        $b=New-PC $a.Root '1.1.0' 1 SECTION;$null=Publish-PC $b $c
        $picked=Select-WinSecRestoredTechnicalSource $c $a.Owner.DeviceId DEFENDER_CANDIDATE SECTION SystemSecurity -SourcePreference LATEST_ATTEMPT
        Assert-PC ($picked.Selected.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and $picked.Selected.SessionIdentity.ScopeType -ceq 'SECTION' -and
            $picked.Selected.Source.Reference.Identity.ScopeKey -ceq 'SystemSecurity' -and $map[$a.Owner.DeviceId].Sessions.Count -eq 2)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awpc-[a-f0-9]{8}\z'){throw 'Unsafe publication cache fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical publication cache integration: $passed passed; $failed failed.");if($failed){exit 1}
