[CmdletBinding()]param([string]$CasePattern='')
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$counter=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wcr-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-CR {param([bool]$Value);if(-not $Value){throw 'Technical cache removal assertion failed.'}}
function Reject-CR {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-CR $caught}
function New-CR {
    $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
    foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
    $f=New-WinSecTechnicalSourceFixture;$null=Save-WinSecTechnicalSourceFixture $dir $f
    $owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$f.Identity.ScanId;ScopeType=$f.Identity.ScopeType;ScopeKey=$f.Identity.ScopeKey}
    $stamp=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
    $session=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
        [pscustomobject]@{Reference=$stamp.Reference;SnapshotSha256=$stamp.SnapshotSha256;Collection=$f.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
    $session.ContentSha256=Get-WinSecTechnicalSessionDigest $session
    $device=[pscustomobject]@{DeviceId=$owner.DeviceId;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true}
    $other=[pscustomobject]@{DeviceId=('local:hw1-'+('c'*64));Hostname='OTHER';Mode='LOCAL';Enabled=$true}
    $null=[IO.Directory]::CreateDirectory((Join-Path $dir 'data'))
    [IO.File]::WriteAllText((Join-Path $dir 'data/devices.json'),(ConvertTo-Json ([pscustomobject]@{schemaVersion='1.0.0';targets=@($device,$other)}) -Depth 6 -Compress))
    $saved=Write-WinSecTechnicalSourceSession $dir $session $owner
    [pscustomobject]@{Root=$dir;Owner=$owner;Device=$device;Other=$other;Saved=$saved;Session=$session;
        Pair=(Get-WinSecSnapshotPairLayout $dir $f.Identity $f.Reference.CollectedAtUTC)}
}
function Context-CR {param($Fixture)
    $devices=@(foreach($d in (Import-WinSecDeviceInventory $Fixture.Root).targets){ConvertTo-WinSecRegisteredTarget $d})
    $coordinator=New-WinSecScanCoordinator -ProjectRoot $Fixture.Root
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=$devices};$coordinator.NewTechnicalStorageEnabled=$true
    [pscustomobject]@{ProjectRoot=$Fixture.Root;Devices=$devices;ScanCoordinator=$coordinator;PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{}}
}
function Remove-CR {param($Fixture,$Context,[scriptblock]$Confirm)
    Remove-WinSecManagedDevice $Fixture.Root $Fixture.Device.DeviceId $Context.ScanCoordinator $Context.Devices -ConfirmAction $Confirm
}
function Select-CR {param($Fixture,$Context)
    Select-WinSecRestoredTechnicalSource $Context $Fixture.Device.DeviceId DEFENDER_CANDIDATE CONTROL WSA-SYS-001
}
function Test-CR {param([string]$Case,[scriptblock]$Action)
    if($CasePattern -and $Case -notmatch $CasePattern){return}
    try{
        $f=New-CR
        . (Join-Path $f.Root 'src/Core/ScanCoordinator.ps1')
        . (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1')
        $script:removalDevice=$f.Device
        function New-WinSecLocalTarget {return $script:removalDevice.PSObject.Copy()}
        $c=Context-CR $f;Restore-WinSecPublicHistory $c -RestoreTechnicalSources
        & $Action;$script:passed++;Write-Host ('[PASS] '+$Case)
    }catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
try{
    Test-CR 'Restoration binds one map to context and coordinator while preserving partial RECORDS and other devices' {
        Assert-CR ([object]::ReferenceEquals($c.TechnicalSourceIndexes,$c.ScanCoordinator.TechnicalSourceIndexes) -and
            $c.TechnicalSourceIndexes.Count -eq 2 -and $c.TechnicalSourceIndexes[$f.Device.DeviceId].Origin -ceq 'RECORDS' -and
            $c.TechnicalSourceIndexes[$f.Device.DeviceId].Sessions[0].Session.Sources[0].Collection.Status -ceq 'PARTIAL')
        $picked=Select-CR $f $c;Assert-CR ($picked.Selected.Source.Reference.Identity.ScanId -ceq $f.Owner.ScanId)
    }
    Test-CR 'A rejected confirmation preserves every cache alias, source file and inventory record' {
        $map=$c.TechnicalSourceIndexes;$hash=Get-WinSecPublicHistoryJson $map[$f.Device.DeviceId];$before=Get-WinSecDeviceInventoryFingerprint $f.Root
        $result=Remove-CR $f $c {$false}
        Assert-CR ($null -eq $result -and [object]::ReferenceEquals($map,$c.ScanCoordinator.TechnicalSourceIndexes) -and $map.Count -eq 2 -and
            (Get-WinSecPublicHistoryJson $map[$f.Device.DeviceId]) -ceq $hash -and [IO.File]::Exists($f.Saved.Path) -and
            (Get-WinSecDeviceInventoryFingerprint $f.Root) -ceq $before)
    }
    Test-CR 'Ambiguous confirmation never starts removal or invalidates records' {
        Reject-CR {Remove-CR $f $c {'true'}}
        Assert-CR ($c.TechnicalSourceIndexes.ContainsKey($f.Device.DeviceId) -and [IO.File]::Exists($f.Saved.Path))
    }
    Test-CR 'Confirmed backend removal invalidates every shared context alias and only the selected device' {
        $second=$c.PSObject.Copy();$map=$c.TechnicalSourceIndexes;$other=$map[$f.Other.DeviceId]
        $result=Remove-CR $f $c {$true}
        Assert-CR ($result.Status -ceq 'REMOVED' -and -not $map.ContainsKey($f.Device.DeviceId) -and
            -not $second.TechnicalSourceIndexes.ContainsKey($f.Device.DeviceId) -and [object]::ReferenceEquals($map[$f.Other.DeviceId],$other) -and
            $map.Count -eq 1 -and $c.TechnicalSourcesReady -and -not [IO.File]::Exists($f.Saved.Path))
        Reject-CR {Select-CR $f $c};Reject-CR {Select-CR $f $second}
    }
    Test-CR 'An INCOMPLETE physical removal invalidates the target even when inventory still contains it' {
        $map=$c.TechnicalSourceIndexes;$other=$map[$f.Other.DeviceId]
        $locked=[IO.File]::Open($f.Saved.Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try{$result=Remove-CR $f $c {$true}}finally{$locked.Dispose()}
        Assert-CR ($result.Status -ceq 'INCOMPLETE' -and -not $map.ContainsKey($f.Device.DeviceId) -and
            [object]::ReferenceEquals($other,$map[$f.Other.DeviceId]) -and
            @((Import-WinSecDeviceInventory $f.Root).targets|Where-Object DeviceId -CEQ $f.Device.DeviceId).Count -eq 1)
        Reject-CR {Select-CR $f $c}
    }
    Test-CR 'Failure saving inventory after deletion started also invalidates technical references' {
        function Save-WinSecDeviceInventory {throw 'Synthetic inventory storage failure.'}
        $result=Remove-CR $f $c {$true}
        Assert-CR ($result.Status -ceq 'INCOMPLETE' -and $result.FailureStage -ceq 'INVENTORY_SAVE' -and
            -not $c.TechnicalSourceIndexes.ContainsKey($f.Device.DeviceId) -and $c.TechnicalSourceIndexes.ContainsKey($f.Other.DeviceId))
    }
    Test-CR 'A changed confirmed manifest is rejected before removal and preserves cached history' {
        $script:changePath=$f.Pair.Markdown
        Reject-CR {Remove-CR $f $c {[IO.File]::AppendAllText($script:changePath,' ');$true}}
        Assert-CR ($c.TechnicalSourceIndexes.ContainsKey($f.Device.DeviceId) -and [IO.File]::Exists($f.Saved.Path))
    }
    Test-CR 'Concurrent inventory ownership prevents removal without invalidating the previous cache' {
        $store=Open-WinSecDeviceInventoryStore $f.Root
        try{Reject-CR {Remove-CR $f $c {$true}}}finally{$store.Lock.Dispose()}
        Assert-CR ($c.TechnicalSourceIndexes.Count -eq 2 -and (Select-CR $f $c).Selected.SessionIdentity.ScanId -ceq $f.Owner.ScanId)
    }
    foreach($side in @('Context','Coordinator')){
        Test-CR ('Detaching a cache alias cannot resurrect historical references: '+$side) {
            $copy=@{};foreach($key in $c.TechnicalSourceIndexes.Keys){$copy[$key]=$c.TechnicalSourceIndexes[$key]}
            if($side -ceq 'Context'){$c.TechnicalSourceIndexes=$copy}else{$c.ScanCoordinator.TechnicalSourceIndexes=$copy}
            Reject-CR {Select-CR $f $c};Assert-CR ([IO.File]::Exists($f.Saved.Path))
        }
    }
    Test-CR 'A fresh restoration after cancelled deletion preserves original references and shared ownership' {
        $prior=(Select-CR $f $c).Selected.Source.SnapshotSha256;$null=Remove-CR $f $c {$false}
        $next=Context-CR $f;Restore-WinSecPublicHistory $next -RestoreTechnicalSources
        Assert-CR ([object]::ReferenceEquals($next.TechnicalSourceIndexes,$next.ScanCoordinator.TechnicalSourceIndexes) -and
            (Select-CR $f $next).Selected.Source.SnapshotSha256 -ceq $prior)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awcr-[a-f0-9]{8}\z'){throw 'Unsafe cache removal fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical cache removal integration: $passed passed; $failed failed.");if($failed){exit 1}
