[CmdletBinding()]param([string]$CasePattern='')
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($name in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){Set-Item ('Function:script:'+$name) {throw 'Native acquisition forbidden.'}}
$passed=0;$failed=0;$counter=0;$scanCount=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wix-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-SX {param([bool]$Value);if(-not $Value){throw 'Stored index integration assertion failed.'}}
function Reject-SX {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SX $caught}
function New-SX {param([string]$IntoRoot='',[string]$Scope='CONTROL',[int]$Day=0,[switch]$Partial)
    if($IntoRoot){$dir=$IntoRoot}else{
        $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
        foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
    }
    . (Join-Path $dir 'src/Core/ScanCoordinator.ps1')
    . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
    $script:scanCount++;$scan='stored-index-'+$script:scanCount.ToString('x4')
    $f=New-WinSecTechnicalSourceFixture -Family PROJECTION -ScopeType $Scope
    $report=ConvertFrom-WinSecProjectionSnapshot $f.Package.Snapshot;$report.ScanId=$scan
    if($Partial){$report.CollectorStatus='ERROR'}
    foreach($field in @('StartedAtUTC','CollectedAtUTC','CompletedAtUTC','GeneratedAtUTC')){$report.$field=(ConvertTo-WinSecSnapshotUtc $report.$field).AddDays($Day).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}
    $p=New-WinSecProjectionSnapshot $report
    $null=Write-WinSecTechnicalSnapshotPair $dir $p.Snapshot $p.Catalog $p.CatalogSha256 $p.Identity
    if(-not $IntoRoot){
        $null=[IO.Directory]::CreateDirectory((Join-Path $dir 'data'))
        $target=[pscustomobject]@{DeviceId=$p.Identity.DeviceId;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true}
        [IO.File]::WriteAllText((Join-Path $dir 'data/devices.json'),(ConvertTo-Json ([pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}) -Depth 5 -Compress))
    }
    $id=$p.Identity;$s=$p.Snapshot;$status=if($Partial){'ERROR'}else{'INFORMATIONAL'}
    $control=[pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$scan;CheckId=$id.CheckId;SectionKey=$id.SectionKey;Status=$status;ObservedStatus=$status;TimestampUTC=$s.CollectedAtUTC;Evidence=[pscustomobject]@{}}
    $session=New-WinSecResultSession -DeviceId $id.DeviceId -ScanId $scan -CatalogVersion '1.0.0' -ExpectedCheckIds @($id.CheckId) -ControlResults @($control) `
        -StartedAtUTC $s.StartedAtUTC -CompletedAtUTC $s.CompletedAtUTC -ExecutionStatus $(if($Partial){'COMPLETED_WITH_ERRORS'}else{'COMPLETED'}) -ScopeType $Scope -ScopeKey $id.ScopeKey
    $ref=[pscustomobject]@{Identity=$id;CollectedAtUTC=$s.CollectedAtUTC;CatalogSha256=$p.CatalogSha256}
    Write-WinSecTransitionSession ([pscustomobject]@{ProjectRoot=$dir;TechnicalLocations=@{}}) $session ([pscustomobject]@{Status='SAVED';Files=@([pscustomobject]@{Reference=$ref})})
    $owner=[pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$scan;ScopeType=$Scope;ScopeKey=$id.ScopeKey}
    [pscustomobject]@{Root=$dir;Owner=$owner;Reference=$ref;Layout=(Get-WinSecTransitionSessionLayout $dir $id.DeviceId $scan);
        Pair=(Get-WinSecSnapshotPairLayout $dir $id $s.CollectedAtUTC)}
}
function Entry-SX {param($f);Read-WinSecStoredTechnicalIndexEntry $f.Root $f.Owner}
function Index-SX {param($f,[object[]]$Entries,[scriptblock]$Cancel)
    $d=Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId
    Restore-WinSecTechnicalSourceIndex $f.Root $d $f.Owner.DeviceId -StoredSessions $Entries -CancellationAction $Cancel
}
function Select-SX {param($f,$Index,[string]$Preference='PREFER_COMPLETE')
    Select-WinSecTechnicalSource $f.Root $Index $f.Owner.DeviceId REVIEWED_PROJECTION $f.Owner.ScopeType $f.Owner.ScopeKey -SourcePreference $Preference
}
function Test-SX {param([string]$Name,[scriptblock]$Action)
    if($CasePattern -and $Name -notmatch $CasePattern){return}
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
try{
    foreach($scope in @('CONTROL','SECTION','DEVICE')){
        Test-SX ('Direct StoredSession restoration retains '+$scope+' and original version/reference provenance') {
            $f=New-SX -Scope $scope;. (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1')
            $hash=(Get-FileHash $f.Layout.Path).Hash;$e=Entry-SX $f;$i=Index-SX $f @($e);$picked=Select-SX $f $i
            Assert-SX ($i.SchemaVersion -ceq '1.1.0' -and $i.Sessions.Count -eq 0 -and $i.StoredSessions.Count -eq 1 -and
                $e.ArtifactType -ceq 'WinSec.StoredSession' -and $picked.Selected.SessionIdentity.ScopeType -ceq $scope -and
                $picked.Selected.Source.Reference.Identity.ScanId -ceq $f.Owner.ScanId -and @($picked.Selected.Source.Reference.PSObject.Properties).Count -eq 3 -and
                (Get-FileHash $f.Layout.Path).Hash -ceq $hash)
            $read=Read-WinSecIndexedTechnicalSession $f.Root $i $f.Owner;Assert-SX ($read.ContentSha256 -ceq $e.ContentSha256)
            Assert-SX (-not [IO.Directory]::Exists((Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($f.Layout.Path))) 'technical-sessions')))
        }
    }
    Test-SX 'Rescan preserves a complete source and a later partial attempt under both unchanged policies' {
        $a=New-SX;. (Join-Path $a.Root 'src/Services/TechnicalSourceRestoration.ps1');$old=Entry-SX $a;$hash=(Get-FileHash $a.Layout.Path).Hash
        $b=New-SX $a.Root -Day 1 -Partial;$i=Index-SX $a @($old,(Entry-SX $b));$preferred=Select-SX $a $i;$latest=Select-SX $a $i LATEST_ATTEMPT
        Assert-SX ($preferred.Selected.SessionIdentity.ScanId -ceq $a.Owner.ScanId -and $preferred.LatestAttempt.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and
            $latest.Selected.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and $preferred.Selected.Source.Collection.Status -ceq 'COMPLETE' -and
            $preferred.LatestAttempt.Source.Collection.Status -ceq 'PARTIAL' -and $preferred.History.Count -eq 2 -and (Get-FileHash $a.Layout.Path).Hash -ceq $hash)
    }
    Test-SX 'A serialized index can be parsed and consumed without reusing source objects' {
        $f=New-SX;. (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1');$e=Entry-SX $f;$i=Index-SX $f @($e)
        $json=Get-WinSecPublicHistoryJson $i;$parsed=ConvertFrom-WinSecSnapshotPairJson $json
        $p=Select-SX $f $parsed
        Assert-SX ($p.Selected.FileSha256 -ceq $e.FileSha256 -and $p.Selected.Source.SnapshotSha256 -ceq $e.Sources[0].SnapshotSha256)
    }
    Test-SX 'New PowerShell processes revalidate the same stored index across both runtimes' {
        $f=New-SX;. (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1');$i=Index-SX $f @((Entry-SX $f))
        $indexPath=Join-Path $f.Root 'index-fixture.json';[IO.File]::WriteAllText($indexPath,(Get-WinSecPublicHistoryJson $i))
        $helper=Join-Path $f.Root 'restart-fixture.ps1'
        [IO.File]::WriteAllText($helper,@'
param([string]$Root,[string]$IndexPath)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'src/Services/TechnicalSourceSelection.ps1')
foreach($name in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){Set-Item ('Function:script:'+$name) {throw 'Native query forbidden.'}}
$i=ConvertFrom-WinSecSnapshotPairJson ([IO.File]::ReadAllText($IndexPath))
$p=Select-WinSecTechnicalSource $Root $i $i.DeviceId REVIEWED_PROJECTION CONTROL WSA-SYS-001
[pscustomobject]@{ScanId=$p.Selected.SessionIdentity.ScanId;FileSha256=$p.Selected.FileSha256}|ConvertTo-Json -Compress
'@)
        foreach($runtime in @('pwsh.exe','powershell.exe')){
            $exe=(Get-Command $runtime -CommandType Application|Select-Object -First 1).Source
            $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=$exe;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
            $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
            $systemModules=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'
            $start.EnvironmentVariables['PSModulePath']=if($runtime -ceq 'powershell.exe'){$systemModules}else{(Join-Path ([IO.Path]::GetDirectoryName($exe)) 'Modules')+';'+$systemModules}
            $start.Arguments='-NoLogo -NoProfile -File "'+$helper+'" -Root "'+$f.Root+'" -IndexPath "'+$indexPath+'"'
            $process=New-Object Diagnostics.Process;$process.StartInfo=$start;$null=$process.Start()
            $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
            try{
                if(-not $process.WaitForExit(60000)){$process.Kill();throw 'Synthetic restart timed out.'}
                if($process.ExitCode -ne 0){throw 'Synthetic cross-runtime index restart rejected.'}
                $r=ConvertFrom-Json ($output.GetAwaiter().GetResult());$null=$errors.GetAwaiter().GetResult()
                Assert-SX ($r.ScanId -ceq $f.Owner.ScanId -and $r.FileSha256 -ceq $i.StoredSessions[0].FileSha256)
            }finally{$process.Dispose()}
        }
    }
    Test-SX 'Candidate and stored projections retain separate families in the same versioned index' {
        $f=New-SX;. (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1');$candidate=New-WinSecTechnicalSourceFixture -CatalogVersion '1.0.0'
        $null=Save-WinSecTechnicalSourceFixture $f.Root $candidate
        $id=$candidate.Identity;$owner=[pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$id.ScanId;ScopeType=$id.ScopeType;ScopeKey=$id.ScopeKey}
        $pin=Get-WinSecTechnicalSourcePackageStamp $candidate.Package $id
        $session=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
            [pscustomobject]@{Reference=$pin.Reference;SnapshotSha256=$pin.SnapshotSha256;Collection=$candidate.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
        $session.ContentSha256=Get-WinSecTechnicalSessionDigest $session;$saved=Write-WinSecTechnicalSourceSession $f.Root $session $owner
        $hash=(Get-FileHash $saved.Path).Hash;$i=Index-SX $f @((Entry-SX $f));$production=Select-SX $f $i
        $isolated=Select-WinSecTechnicalSource $f.Root $i $f.Owner.DeviceId DEFENDER_CANDIDATE CONTROL WSA-SYS-001
        Assert-SX ($i.Sessions.Count -eq 1 -and $i.StoredSessions.Count -eq 1 -and $production.Selected.Source.Reference.Identity.ScanId -ceq $f.Owner.ScanId -and
            $isolated.Selected.Source.Reference.SnapshotSchemaVersion -ceq '2.0.0' -and $production.History.Count -eq 2 -and (Get-FileHash $saved.Path).Hash -ceq $hash)
    }
    Test-SX 'Corrupt source before reload rejects without altering a previous index' {
        $f=New-SX;. (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1');$e=Entry-SX $f;$i=Index-SX $f @($e);$before=Get-WinSecPublicHistoryJson $i
        [IO.File]::AppendAllText($f.Pair.Markdown,' ');Reject-SX {Index-SX $f @($e)}
        Assert-SX ((Get-WinSecPublicHistoryJson $i) -ceq $before)
    }
    Test-SX 'Corrupt latest partial is rejected without fallback to the older complete source' {
        $a=New-SX;. (Join-Path $a.Root 'src/Services/TechnicalSourceRestoration.ps1');$b=New-SX $a.Root -Day 1 -Partial
        $i=Index-SX $a @((Entry-SX $a),(Entry-SX $b));[IO.File]::AppendAllText($b.Pair.Markdown,' ')
        Reject-SX {Select-SX $a $i};Assert-SX ([IO.File]::Exists($a.Layout.Path))
    }
    Test-SX 'Stored container bytes changed after indexing cannot be consumed' {
        $f=New-SX;. (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1');$i=Index-SX $f @((Entry-SX $f))
        [IO.File]::AppendAllText($f.Layout.Path,' ');Reject-SX {Select-SX $f $i}
    }
    Test-SX 'Pending StoredSession publication is not indexed or repaired' {
        $f=New-SX;. (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1')
        [IO.File]::Move($f.Layout.Path,($f.Layout.Path+'.tmp'));Reject-SX {Entry-SX $f}
        Assert-SX ([IO.File]::Exists($f.Layout.Path+'.tmp') -and -not [IO.File]::Exists($f.Layout.Path))
    }
    Test-SX 'Cancelled reload preserves the caller index and releases inventory ownership' {
        $f=New-SX;. (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1');$e=Entry-SX $f;$i=Index-SX $f @($e);$before=Get-WinSecPublicHistoryJson $i
        Reject-SX {Index-SX $f @($e) -Cancel {$true}}
        $lock=Open-WinSecDeviceInventoryStore $f.Root;$lock.Lock.Dispose();Assert-SX ((Get-WinSecPublicHistoryJson $i) -ceq $before)
    }
    Test-SX 'Concurrent inventory ownership prevents read and reload without stale fallback' {
        $f=New-SX;. (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1');$e=Entry-SX $f;$lock=Open-WinSecDeviceInventoryStore $f.Root
        try{Reject-SX {Entry-SX $f};Reject-SX {Index-SX $f @($e)}}finally{$lock.Lock.Dispose()}
        Assert-SX ((Entry-SX $f).FileSha256 -ceq $e.FileSha256)
    }
    Test-SX 'A stored entry belonging to another device cannot enter this index' {
        $f=New-SX;. (Join-Path $f.Root 'src/Services/TechnicalSourceRestoration.ps1');$e=Entry-SX $f;$e.Identity.DeviceId='local:hw1-'+('c'*64)
        Reject-SX {Index-SX $f @($e)}
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awix-[a-f0-9]{8}\z'){throw 'Unsafe stored index fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Stored index integration: $passed passed; $failed failed.");if($failed){exit 1}
