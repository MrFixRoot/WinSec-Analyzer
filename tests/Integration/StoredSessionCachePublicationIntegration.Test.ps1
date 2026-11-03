[CmdletBinding()]param([string]$CasePattern='')
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
. (Join-Path $root 'tests/Fixtures/ValidatedCatalog.ps1')
$passed=0;$failed=0;$counter=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wsp-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-SP {param([bool]$Value);if(-not $Value){throw 'Stored publication integration assertion failed.'}}
function Reject-SP {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SP $caught}
function New-SP {
    $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
    foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
    $device='local:hw1-'+('a'*64);$other='local:hw1-'+('c'*64);$null=[IO.Directory]::CreateDirectory((Join-Path $dir 'data'))
    $targets=@([pscustomobject]@{DeviceId=$device;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true},
        [pscustomobject]@{DeviceId=$other;Hostname='OTHER';Mode='LOCAL';Enabled=$true})
    [IO.File]::WriteAllText((Join-Path $dir 'data/devices.json'),(ConvertTo-Json ([pscustomobject]@{schemaVersion='1.0.0';targets=$targets}) -Depth 6 -Compress))
    [pscustomobject]@{Root=$dir;Device=$device;Other=$other;Targets=$targets;ChecksSha256=(Get-FileHash (Join-Path $dir 'config/checks.json')).Hash}
}
function Context-SP {param($f)
    $c=New-WinSecScanCoordinator $f.Root;$c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($f.Targets)}
    $c.RequireDeviceInventory=$true;$c.PublicHistoryEnabled=$true;$c.TechnicalReportsEnabled=$true;$c.NewTechnicalStorageEnabled=$true
    $ctx=[pscustomobject]@{ProjectRoot=$f.Root;Devices=@($f.Targets);ScanCoordinator=$c;PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{}}
    Restore-WinSecPublicHistory $ctx -RestoreTechnicalSources;return $ctx
}
function Scan-SP {param($f,$ctx,[string]$Scan='scan-one',[string]$Scope='CONTROL',[scriptblock]$Confirm={$true},[scriptblock]$Cancel)
    $key=switch($Scope){CONTROL {'WSA-SYS-001'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
    Invoke-WinSecCoordinatedScan $ctx.ScanCoordinator -DeviceId $f.Device -ScanId $Scan -ScopeType $Scope -ScopeKey $key -ConfirmAction $Confirm -CancellationAction $Cancel
}
function Read-SPBytes {param([string]$Path,[int]$MaxBytes,[scriptblock]$CancellationAction)
    $bytes=& $script:originalRead $Path $MaxBytes $CancellationAction
    if($Path -ceq $script:readTrigger -and -not $script:triggered){
        $script:triggered=$true
        if($script:readMode -ceq 'TEMP'){return ,([Text.Encoding]::UTF8.GetBytes('INVALID'))}
        if($script:readMode -ceq 'SOURCE'){[IO.File]::AppendAllText($script:liveCoordinator.LastTechnicalReports.Files[0].Path,' ')}
    }
    return ,$bytes
}
function Write-SPBytes {param([string]$Path,[byte[]]$Bytes,[scriptblock]$CancellationAction)
    & $script:originalWrite $Path $Bytes $CancellationAction
    if($Path -ceq $script:writeTrigger){$script:liveCoordinator.TechnicalSourceIndexes=@{}}
}
function Throw-SPNotice {throw 'Synthetic postcommit notification failure.'}
function Test-SP {param([string]$Name,[scriptblock]$Action)
    if($CasePattern -and $Name -notmatch $CasePattern){return}
    try{
        $f=New-SP
        . (Join-Path $f.Root 'src/Core/ScanCoordinator.ps1')
        . (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1')
        Assert-SP (Test-WinSecValidatedCatalogFixture (ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $f.Root 'config/checks.json')))))
        # Restrict only the in-memory test catalog to the real validated Defender entry.
        # No execution policy/configuration is edited; all other controls are outside this pilot.
        $script:pilotRegistry=(Get-WinSecCheckRegistry $f.Root).PSObject.Copy()
        $script:pilotRegistry.Checks=@($script:pilotRegistry.Checks|Where-Object CheckId -CEQ WSA-SYS-001)
        function Get-WinSecCheckRegistry {param($ProjectRoot,$Path);return $script:pilotRegistry}
        $script:localTarget=$f.Targets[0];$script:auditCalls=0;$script:auditMode='COMPLETE'
        function New-WinSecLocalTarget {return $script:localTarget.PSObject.Copy()}
        function Invoke-WinSecAudit {
            param($DeviceId,$ScanId,$CheckIds,$Registry,[switch]$SkipScoring,[scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
            Assert-SP ($SkipScoring -and @($CheckIds).Count -eq 1 -and $CheckIds[0] -ceq 'WSA-SYS-001');$script:auditCalls++
            if($script:auditMode -ceq 'CANCEL'){throw [OperationCanceledException]::new('Synthetic audit cancelled.')}
            $now=[DateTime]::UtcNow.ToString('o');$status=if($script:auditMode -ceq 'ERROR'){'ERROR'}else{'INFORMATIONAL'}
            $e=[pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId='WSA-SYS-001';CollectedAtUTC=$now;CollectionSuccessful=$true;CollectionComplete=($status -cne 'ERROR');
                DefenderStatus=[pscustomobject]@{AntivirusEnabled=$false;AMRunningMode='Normal'};DefenderPreferences=[pscustomobject]@{PUAProtection=0};
                AttackSurfaceReduction=[pscustomobject]@{Available=$true;Complete=$true;ConfiguredRuleCount=0;Rules=@()}}
            $records=@([pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId='WSA-SYS-001';SectionKey='SystemSecurity';CollectionMode='LOCAL';Status=$status;ObservedStatus=$status;Evidence=$e})
            [pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;AuditId=$ScanId;CollectionMode='LOCAL';ComputerName='SYNTHETIC';CatalogVersion=$Registry.CatalogVersion;StartedAtUTC=$now;CompletedAtUTC=$now;
                ExecutionStatus=$(if($status -ceq 'ERROR'){'COMPLETED_WITH_ERRORS'}else{'COMPLETED'});ControlResults=$records;ScoringEnabled=$false}
        }
        $ctx=Context-SP $f;$c=$ctx.ScanCoordinator;$map=$ctx.TechnicalSourceIndexes;$prior=$map[$f.Device];$other=$map[$f.Other]
        $script:originalRead=(Get-Command Read-WinSecSnapshotBytes -CommandType Function).ScriptBlock
        $script:originalWrite=(Get-Command Write-WinSecSnapshotBytes -CommandType Function).ScriptBlock
        $script:triggered=$false
        & $Action
        Assert-SP ((Get-FileHash (Join-Path $f.Root 'config/checks.json')).Hash -ceq $f.ChecksSha256)
        $script:passed++;Write-Host ('[PASS] '+$Name)
    }catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
    finally{foreach($alias in @('Read-WinSecSnapshotBytes','Write-WinSecSnapshotBytes','Confirm-WinSecStoredSessionCachePublication')){
        if(Test-Path ('Alias:'+$alias)){Remove-Item -LiteralPath ('Alias:'+$alias) -Force}
    }}
}
try{
    foreach($scope in @('CONTROL','SECTION','DEVICE')){
        Test-SP ('Real coordinator '+$scope+' publication invalidates only its device without publishing a duplicate session') {
            $result=Scan-SP $f $ctx -Scope $scope
            $path=(Get-WinSecTransitionSessionLayout $f.Root $f.Device scan-one).Path
            $e=ConvertFrom-WinSecTransitionJson ([IO.File]::ReadAllText($path))
            Assert-SP ($result.ExecutionStatus -ceq 'COMPLETED' -and $script:auditCalls -eq 1 -and -not $map.ContainsKey($f.Device) -and
                [object]::ReferenceEquals($other,$map[$f.Other]) -and [object]::ReferenceEquals($map,$c.TechnicalSourceIndexes) -and
                $e.ArtifactType -ceq 'WinSec.StoredSession' -and $e.SchemaVersion -ceq '1.0.0' -and $e.Record.ScopeType -ceq $scope -and
                @($e.Sources[0].PSObject.Properties).Count -eq 3 -and $c.Sessions.Count -eq 1)
            Assert-SP (-not [IO.Directory]::Exists((Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($path))) 'technical-sessions')))
            Reject-SP {Select-WinSecRestoredTechnicalSource $ctx $f.Device DEFENDER_CANDIDATE CONTROL WSA-SYS-001}
        }
    }
    Test-SP 'Rescan preserves older StoredSession bytes and exposes complete and error attempts through historical readers' {
        $null=Scan-SP $f $ctx;$path=(Get-WinSecTransitionSessionLayout $f.Root $f.Device scan-one).Path;$hash=(Get-FileHash $path).Hash
        $next=Context-SP $f;$nextOther=$next.TechnicalSourceIndexes[$f.Other];$script:auditMode='ERROR'
        $r=Scan-SP $f $next -Scan rescan-two
        $records=(Read-WinSecTransitionSessions $f.Root $f.Targets).Records
        Assert-SP ($r.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS' -and $records.Count -eq 2 -and $next.ScanCoordinator.Sessions.Count -eq 2 -and
            (Get-FileHash $path).Hash -ceq $hash -and -not $next.TechnicalSourceIndexes.ContainsKey($f.Device) -and
            [object]::ReferenceEquals($nextOther,$next.TechnicalSourceIndexes[$f.Other]))
    }
    Test-SP 'Cancelled confirmation preserves cached history and does not execute the audit boundary' {
        $r=Scan-SP $f $ctx -Confirm {$false}
        Assert-SP ($null -eq $r -and $script:auditCalls -eq 0 -and [object]::ReferenceEquals($prior,$map[$f.Device]) -and $c.Sessions.Count -eq 0)
    }
    Test-SP 'Cancellation during the synthetic audit does not invalidate or persist a session' {
        $script:auditMode='CANCEL';$r=Scan-SP $f $ctx
        Assert-SP ($null -eq $r -and [object]::ReferenceEquals($prior,$map[$f.Device]) -and $c.Sessions.Count -eq 0)
    }
    Test-SP 'Failed temporary verification leaves the technical cache and older history unchanged' {
        $script:readTrigger=(Get-WinSecTransitionSessionLayout $f.Root $f.Device scan-one).Path+'.tmp';$script:readMode='TEMP'
        Set-Alias Read-WinSecSnapshotBytes Read-SPBytes -Scope Script
        Reject-SP {Scan-SP $f $ctx}
        Assert-SP ($script:triggered -and [object]::ReferenceEquals($prior,$map[$f.Device]) -and $c.Sessions.Count -eq 0 -and
            -not [IO.File]::Exists($script:readTrigger.Substring(0,$script:readTrigger.Length-4)))
    }
    Test-SP 'Postcommit notification failure invalidates the target despite the producer reporting an error' {
        Set-Alias Confirm-WinSecStoredSessionCachePublication Throw-SPNotice -Scope Script
        Reject-SP {Scan-SP $f $ctx}
        Assert-SP ([IO.File]::Exists((Get-WinSecTransitionSessionLayout $f.Root $f.Device scan-one).Path) -and
            -not $map.ContainsKey($f.Device) -and [object]::ReferenceEquals($other,$map[$f.Other]) -and $c.Sessions.Count -eq 0)
    }
    Test-SP 'Changed source after rename cannot be advertised as a validated cached source' {
        $script:readTrigger=(Get-WinSecTransitionSessionLayout $f.Root $f.Device scan-one).Path;$script:readMode='SOURCE'
        $script:liveCoordinator=$c
        Set-Alias Read-WinSecSnapshotBytes Read-SPBytes -Scope Script
        Reject-SP {Scan-SP $f $ctx}
        Assert-SP ($script:triggered -and [IO.File]::Exists($script:readTrigger) -and
            [IO.File]::ReadAllText($c.LastTechnicalReports.Files[0].Path).EndsWith(' ') -and
            -not $map.ContainsKey($f.Device) -and [object]::ReferenceEquals($other,$map[$f.Other]))
    }
    Test-SP 'Cache replacement while staging rejects before rename without overwriting the previous map' {
        $script:writeTrigger=(Get-WinSecTransitionSessionLayout $f.Root $f.Device scan-one).Path+'.tmp';$script:liveCoordinator=$c
        Set-Alias Write-WinSecSnapshotBytes Write-SPBytes -Scope Script
        Reject-SP {Scan-SP $f $ctx}
        Assert-SP ([object]::ReferenceEquals($prior,$map[$f.Device]) -and -not [IO.File]::Exists($script:writeTrigger.Substring(0,$script:writeTrigger.Length-4)))
    }
    Test-SP 'Concurrent inventory lease prevents publication without invalidating previous records' {
        $lock=Open-WinSecDeviceInventoryStore $f.Root
        try{Reject-SP {Scan-SP $f $ctx}}finally{$lock.Lock.Dispose()}
        Assert-SP ([object]::ReferenceEquals($prior,$map[$f.Device]) -and $c.Sessions.Count -eq 0)
    }
    Test-SP 'A coordinator without restored technical caches retains its original storage behavior' {
        $c.PSObject.Properties.Remove('TechnicalSourceIndexes');$r=Scan-SP $f $ctx
        Assert-SP ($r.ExecutionStatus -ceq 'COMPLETED' -and $null -eq $c.PSObject.Properties['TechnicalSourceIndexes'] -and
            [object]::ReferenceEquals($prior,$map[$f.Device]) -and $c.TechnicalLocations.Count -eq 1)
    }
    Test-SP 'Production publication preserves candidate files without creating or relabelling candidate references' {
        $candidate=New-WinSecTechnicalSourceFixture -CatalogVersion '1.0.0';$null=Save-WinSecTechnicalSourceFixture $f.Root $candidate
        $owner=[pscustomobject]@{DeviceId=$candidate.Identity.DeviceId;ScanId=$candidate.Identity.ScanId;ScopeType=$candidate.Identity.ScopeType;ScopeKey=$candidate.Identity.ScopeKey}
        $pin=Get-WinSecTechnicalSourcePackageStamp $candidate.Package $candidate.Identity
        $technical=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
            [pscustomobject]@{Reference=$pin.Reference;SnapshotSha256=$pin.SnapshotSha256;Collection=$candidate.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
        $technical.ContentSha256=Get-WinSecTechnicalSessionDigest $technical;$saved=Write-WinSecTechnicalSourceSession $f.Root $technical $owner
        $hash=(Get-FileHash $saved.Path).Hash;$next=Context-SP $f
        Assert-SP ($next.TechnicalSourceIndexes[$f.Device].Sessions[0].Session.Sources[0].Reference.SnapshotSchemaVersion -ceq '2.0.0')
        $r=Scan-SP $f $next
        Assert-SP ($r.ExecutionStatus -ceq 'COMPLETED' -and -not $next.TechnicalSourceIndexes.ContainsKey($f.Device) -and
            (Get-FileHash $saved.Path).Hash -ceq $hash -and @(Get-ChildItem ([IO.Path]::GetDirectoryName($saved.Path)) -File).Count -eq 1)
        $stored=ConvertFrom-WinSecTransitionJson ([IO.File]::ReadAllText((Get-WinSecTransitionSessionLayout $f.Root $f.Device scan-one).Path))
        $resolved=Read-WinSecVersionedTechnicalSource $f.Root $stored.Sources[0] $stored.Sources[0].Identity
        Assert-SP ($resolved.Resolution.Family -ceq 'REVIEWED_PROJECTION' -and $resolved.Resolution.SnapshotSchemaVersion -ceq '2.1.0' -and @($stored.Sources[0].PSObject.Properties).Count -eq 3)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awsp-[a-f0-9]{8}\z'){throw 'Unsafe stored publication cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Stored publication integration: $passed passed; $failed failed.");if($failed){exit 1}
