[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceSessionRemoval.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$counter=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wrd-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-TRI {param([bool]$Value);if(-not $Value){throw 'Technical session removal integration assertion failed.'}}
function Reject-TRI {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-TRI $caught}
function New-TRI {
    param([string]$Family,[string]$Scope)
    $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
    foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
    $f=New-WinSecTechnicalSourceFixture -Family $Family -ScopeType $Scope;$null=Save-WinSecTechnicalSourceFixture $dir $f
    $owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$f.Identity.ScanId;ScopeType=$f.Identity.ScopeType;ScopeKey=$f.Identity.ScopeKey}
    $stamp=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
    $s=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
        [pscustomobject]@{Reference=$stamp.Reference;SnapshotSha256=$stamp.SnapshotSha256;Collection=$f.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
    $s.ContentSha256=Get-WinSecTechnicalSessionDigest $s
    $device=[pscustomobject]@{DeviceId=$owner.DeviceId;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true}
    $other=[pscustomobject]@{DeviceId=('local:hw1-'+('c'*64));Hostname='OTHER';Mode='LOCAL';Enabled=$true}
    $null=[IO.Directory]::CreateDirectory((Join-Path $dir 'data'))
    [IO.File]::WriteAllText((Join-Path $dir 'data/devices.json'),(ConvertTo-Json ([pscustomobject]@{schemaVersion='1.0.0';targets=@($device,$other)}) -Depth 6 -Compress))
    $saved=Write-WinSecTechnicalSourceSession $dir $s $owner
    $markerRoot=Join-Path $dir ('data/scans/'+(Get-WinSecSnapshotDeviceKey $other.DeviceId));$null=[IO.Directory]::CreateDirectory($markerRoot)
    $marker=Join-Path $markerRoot 'foreign.json';[IO.File]::WriteAllText($marker,'OTHER-DEVICE-DATA')
    [pscustomobject]@{Root=$dir;Fixture=$f;Owner=$owner;Session=$s;Device=$device;Other=$other;Saved=$saved;Marker=$marker;
        Layout=(Get-WinSecTechnicalSessionStorageLayout $dir $owner);Pair=(Get-WinSecSnapshotPairLayout $dir $f.Identity $f.Reference.CollectedAtUTC)}
}
function Test-TRI {
    param([string]$Case,[scriptblock]$Action,[string]$Family='CANDIDATE',[string]$Scope='CONTROL')
    try{
        $f=New-TRI $Family $Scope
        . (Join-Path $f.Root 'src/Core/ScanCoordinator.ps1')
        $script:syntheticRemovalTarget=$f.Device
        function New-WinSecLocalTarget {return $script:syntheticRemovalTarget.PSObject.Copy()}
        $devices=@((Import-WinSecDeviceInventory $f.Root).targets)
        $c=New-WinSecScanCoordinator $f.Root;$c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=$devices}
        & $Action;$script:passed++;Write-Host ('[PASS] '+$Case)
    }catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function Get-TRIPlan {Get-WinSecDeviceRemovalPlan $f.Root $f.Owner.DeviceId $c $devices}
function Remove-TRI {param([scriptblock]$Confirm);Remove-WinSecManagedDevice $f.Root $f.Owner.DeviceId $c $devices -ConfirmAction $Confirm}
try{
    foreach($family in @('CANDIDATE','PROJECTION')){foreach($scope in @('CONTROL','SECTION','DEVICE')){
        Test-TRI ('Verified container and four source files enter the existing removal plan: '+$family+'/'+$scope) {
            $before=Get-WinSecDeviceInventoryFingerprint $f.Root;$plan=Get-TRIPlan
            Assert-TRI ($plan.Files.Count -eq 5 -and @($plan.Files|Where-Object Path -CEQ $f.Saved.Path).Count -eq 1 -and
                (Get-WinSecDeviceInventoryFingerprint $f.Root) -ceq $before -and [IO.File]::Exists($f.Marker))
            foreach($file in $plan.Files){Assert-TRI ((Get-FileHash -LiteralPath $file.Path).Hash -ceq $file.Hash)}
        } -Family $family -Scope $scope
    }}
    Test-TRI 'Denial, missing consent and ambiguous consent preserve every file and the inventory' {
        $before=Get-WinSecDeviceInventoryFingerprint $f.Root;$plan=Get-TRIPlan
        Assert-TRI ($null -eq (Remove-TRI {$false}))
        Reject-TRI {Remove-TRI $null};Reject-TRI {Remove-TRI {'yes'}}
        foreach($file in $plan.Files){Assert-TRI ([IO.File]::Exists($file.Path))}
        Assert-TRI ((Get-WinSecDeviceInventoryFingerprint $f.Root) -ceq $before)
    }
    Test-TRI 'A confirmed existing deletion removes only this device and its verified technical history' {
        $plan=Get-TRIPlan;$script:confirmedFileCount=0
        $r=Remove-TRI {param($request);$script:confirmedFileCount=$request.StoredFileCount;$true}
        Assert-TRI ($r.Status -ceq 'REMOVED' -and $script:confirmedFileCount -eq 5)
        foreach($file in $plan.Files){Assert-TRI (-not [IO.File]::Exists($file.Path))}
        $inventory=Import-WinSecDeviceInventory $f.Root
        Assert-TRI ($inventory.targets.Count -eq 1 -and $inventory.targets[0].DeviceId -ceq $f.Other.DeviceId -and
            (Test-WinSecDeviceInventoryRemoval $inventory $f.Owner.DeviceId) -and [IO.File]::ReadAllText($f.Marker) -ceq 'OTHER-DEVICE-DATA')
    }
    Test-TRI 'Changes during confirmation reject the second plan before any physical removal' {
        $script:changedTechnicalPath=$f.Saved.Path;$before=Get-WinSecDeviceInventoryFingerprint $f.Root
        Reject-TRI {Remove-TRI {param($request);[IO.File]::AppendAllText($script:changedTechnicalPath,' ');$true}}
        Assert-TRI ([IO.File]::Exists($f.Pair.Json) -and [IO.File]::Exists($f.Pair.Markdown) -and
            (Get-WinSecDeviceInventoryFingerprint $f.Root) -ceq $before)
    }
    Test-TRI 'A modified confirmation preview cannot authorize deletion' {
        Reject-TRI {Remove-TRI {param($request);$request.StoredFileCount=0;$true}}
        Assert-TRI ([IO.File]::Exists($f.Saved.Path) -and [IO.File]::Exists($f.Pair.Json))
    }
    Test-TRI 'The actual inventory lock still blocks a concurrent confirmed removal' {
        $lease=Open-WinSecDeviceInventoryStore $f.Root
        try{Reject-TRI {Remove-TRI {$true}};Assert-TRI ([IO.File]::Exists($f.Saved.Path))}finally{$lease.Lock.Dispose()}
    }
    Test-TRI 'StoredSession 1.0 and a technical session share verified source files without duplicate removal' {
        $s=$f.Fixture.Package.Snapshot;$identity=$f.Fixture.Identity
        $control=[pscustomobject]@{DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CheckId=$identity.CheckId;SectionKey='SystemSecurity';Status='INFORMATIONAL';
            ObservedStatus='INFORMATIONAL';TimestampUTC=$s.CollectedAtUTC;Evidence=[pscustomobject]@{}}
        $session=New-WinSecResultSession -DeviceId $identity.DeviceId -ScanId $identity.ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @($identity.CheckId) `
            -ControlResults @($control) -StartedAtUTC $s.StartedAtUTC -CompletedAtUTC $s.CompletedAtUTC -ExecutionStatus COMPLETED -ScopeType CONTROL -ScopeKey $identity.CheckId
        $receipt=[pscustomobject]@{Status='SAVED';Files=@([pscustomobject]@{Reference=(Get-WinSecLegacySourceFixtureReference $f.Fixture)})}
        Write-WinSecTransitionSession $c $session $receipt
        $path=(Get-WinSecTransitionSessionLayout $f.Root $identity.DeviceId $identity.ScanId).Path;$hash=(Get-FileHash -LiteralPath $path).Hash
        $plan=Get-TRIPlan
        Assert-TRI ($plan.Files.Count -eq 6 -and @($plan.Files|Where-Object Path -CEQ $f.Pair.Json).Count -eq 1 -and (Get-FileHash -LiteralPath $path).Hash -ceq $hash)
        Assert-TRI ($null -eq (Remove-TRI {$false}) -and (Get-FileHash -LiteralPath $path).Hash -ceq $hash)
        Assert-TRI ((Remove-TRI {$true}).Status -ceq 'REMOVED' -and -not [IO.File]::Exists($path) -and [IO.File]::Exists($f.Marker))
    } -Family PROJECTION
    foreach($damage in @('Temporary','ForeignFile','WrongFilename','UnknownVersion','UnknownType','ForeignDevice','WrongScope','CorruptContainer','CorruptSource','MissingSourceCommit','FalseCoverage')){
        Test-TRI ('Invalid, incomplete or foreign artifacts block the whole deletion: '+$damage) {
            $before=Get-WinSecDeviceInventoryFingerprint $f.Root
            switch($damage){
                Temporary {[IO.File]::WriteAllText($f.Layout.Temporary,'INTERRUPTED')}
                ForeignFile {[IO.File]::WriteAllText((Join-Path ([IO.Path]::GetDirectoryName($f.Saved.Path)) 'foreign.json'),'FOREIGN')}
                WrongFilename {[IO.File]::Move($f.Saved.Path,(Join-Path ([IO.Path]::GetDirectoryName($f.Saved.Path)) (('a'*64)+'.json')))}
                UnknownVersion {[IO.File]::WriteAllText($f.Saved.Path,([IO.File]::ReadAllText($f.Saved.Path)).Replace('"SchemaVersion":"1.0.0"','"SchemaVersion":"9.0.0"'))}
                UnknownType {[IO.File]::WriteAllText($f.Saved.Path,([IO.File]::ReadAllText($f.Saved.Path)).Replace('WinSec.TechnicalSourceSession','WinSec.StoredSession'))}
                ForeignDevice {[IO.File]::WriteAllText($f.Saved.Path,([IO.File]::ReadAllText($f.Saved.Path)).Replace($f.Owner.DeviceId,$f.Other.DeviceId))}
                WrongScope {$changed=Copy-WinSecResultData $f.Session;$changed.Identity.ScopeType='SECTION';$changed.Identity.ScopeKey='SystemSecurity';$changed.ContentSha256=Get-WinSecTechnicalSessionDigest $changed;[IO.File]::WriteAllText($f.Saved.Path,(Get-WinSecPublicHistoryJson $changed))}
                CorruptContainer {[IO.File]::AppendAllText($f.Saved.Path,' ')}
                CorruptSource {[IO.File]::AppendAllText($f.Pair.Markdown,' ')}
                MissingSourceCommit {Remove-Item -LiteralPath $f.Pair.Commit}
                FalseCoverage {$changed=Copy-WinSecResultData $f.Session;$changed.Sources[0].Collection.Unknown++;$changed.ContentSha256=Get-WinSecTechnicalSessionDigest $changed;[IO.File]::WriteAllText($f.Saved.Path,(Get-WinSecPublicHistoryJson $changed))}
            }
            $script:confirmationCalls=0
            Reject-TRI {Remove-TRI {$script:confirmationCalls++;$true}}
            Assert-TRI ($script:confirmationCalls -eq 0 -and [IO.File]::Exists($f.Pair.Json) -and
                (Get-WinSecDeviceInventoryFingerprint $f.Root) -ceq $before -and [IO.File]::Exists($f.Marker))
        }
    }
    Test-TRI 'Hard-linked containers cannot enter a deletion plan' {
        $extra=Join-Path $f.Root 'hardlink.json';$null=New-Item -ItemType HardLink -Path $extra -Target $f.Saved.Path
        try{Reject-TRI {Get-TRIPlan};Assert-TRI ([IO.File]::Exists($f.Pair.Json))}finally{Remove-Item -LiteralPath $extra}
    }
    Test-TRI 'A linked metadata namespace is rejected without following it' {
        $directory=[IO.Path]::GetDirectoryName($f.Saved.Path);$moved=$directory+'-moved';[IO.Directory]::Move($directory,$moved)
        $null=New-Item -ItemType Junction -Path $directory -Target $moved
        try{Reject-TRI {Get-TRIPlan};Assert-TRI ([IO.File]::Exists((Join-Path $moved ([IO.Path]::GetFileName($f.Saved.Path)))))}
        finally{[IO.Directory]::Delete($directory);[IO.Directory]::Move($moved,$directory)}
    }
    Test-TRI 'Recognition cancellation returns no plan and releases file and inventory handles' {
        $before=Get-WinSecDeviceInventoryFingerprint $f.Root;$cancelled=$false
        try{$null=Get-WinSecTechnicalSessionRemovalFiles $f.Root $f.Owner.DeviceId $f.Device -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        $probe=[IO.File]::Open($f.Saved.Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$probe.Dispose()
        Assert-TRI ($cancelled -and (Get-WinSecDeviceInventoryFingerprint $f.Root) -ceq $before)
    }
    Test-TRI 'A valid but still staged snapshot extra is not authorized for automatic cleanup' {
        [IO.File]::Copy($f.Pair.Json,$f.Pair.JsonTemp)
        Reject-TRI {Get-TRIPlan};Assert-TRI ([IO.File]::Exists($f.Pair.JsonTemp) -and [IO.File]::Exists($f.Saved.Path))
    }
    Test-TRI 'Broad metadata directory permissions block removal without modifying the ACL' {
        $dir=[IO.Path]::GetDirectoryName($f.Saved.Path);$original=Get-Acl -LiteralPath $dir;$changed=Get-Acl -LiteralPath $dir
        $world=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($world,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow');$changed.AddAccessRule($rule)
        $info=New-Object IO.DirectoryInfo($dir)
        try{
            if('System.IO.FileSystemAclExtensions' -as [type]){[IO.FileSystemAclExtensions]::SetAccessControl($info,$changed)}else{$info.SetAccessControl($changed)}
            Reject-TRI {Get-TRIPlan}
            Assert-TRI ([IO.File]::Exists($f.Saved.Path) -and @((Get-Acl -LiteralPath $dir).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -eq 'S-1-1-0'}).Count -gt 0)
        }finally{if('System.IO.FileSystemAclExtensions' -as [type]){[IO.FileSystemAclExtensions]::SetAccessControl($info,$original)}else{$info.SetAccessControl($original)}}
    }
    Test-TRI 'Inventory changes during recognition reject the plan and preserve its artifacts' {
        $script:recognitionInventory=Join-Path $f.Root 'data/devices.json';$script:recognitionPolls=0
        Reject-TRI {Get-WinSecTechnicalSessionRemovalFiles $f.Root $f.Owner.DeviceId $f.Device -CancellationAction {
            $script:recognitionPolls++;if($script:recognitionPolls -eq 1){[IO.File]::WriteAllText($script:recognitionInventory,'{"schemaVersion":"1.0.0","targets":[]}')};$false
        }}
        Assert-TRI ([IO.File]::Exists($f.Saved.Path) -and [IO.File]::Exists($f.Pair.Json) -and [IO.File]::Exists($f.Marker))
    }
    Test-TRI 'Both PowerShell runtimes recognize a candidate from a cold process without fixture imports' {
        foreach($exe in @('pwsh.exe','powershell.exe')){
            $loader=(Join-Path $f.Root 'src/Core/ScanCoordinator.ps1').Replace("'","''");$readerRoot=$f.Root.Replace("'","''")
            $code="`$ErrorActionPreference='Stop';. '$loader';function Get-CimInstance {throw 'Native forbidden.'};"+
                "`$device=[pscustomobject]@{DeviceId='$($f.Owner.DeviceId)'};`$p=Get-WinSecTransitionDeviceFiles '$readerRoot' '$($f.Owner.DeviceId)' `$device;"+
                "if(`$p.Files.Count -ne 5){throw 'Cold removal recognition failed.'};'TECHNICAL_REMOVAL_CONFIRMED'"
            $out=@(& $exe -NoLogo -NoProfile -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))))
            Assert-TRI ($LASTEXITCODE -eq 0 -and $out[-1] -ceq 'TECHNICAL_REMOVAL_CONFIRMED')
        }
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awrd-[a-f0-9]{8}\z'){throw 'Unsafe technical removal integration cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical session removal integration: $passed passed; $failed failed.");if($failed){exit 1}
