[CmdletBinding()]param([string]$CasePattern='')
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalIndexDiscoveryMemory.ps1')
foreach($name in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){Set-Item ('Function:script:'+$name) {throw 'Native query forbidden.'}}
$passed=0;$failed=0;$counter=0;$id='local:hw1-'+('a'*64);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wcd-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-CD {param([bool]$Value);if(-not $Value){throw 'Combined discovery assertion failed.'}}
function Reject-CD {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-CD $caught}
function New-CD {
    $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
    foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
    $null=[IO.Directory]::CreateDirectory((Join-Path $dir 'data'))
    [IO.File]::WriteAllText((Join-Path $dir 'data/devices.json'),(ConvertTo-Json ([pscustomobject]@{schemaVersion='1.0.0';targets=@(
        [pscustomobject]@{DeviceId=$id;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true})}) -Depth 5 -Compress))
    $dir
}
function Test-CD {param([string]$Name,[scriptblock]$Action)
    if($CasePattern -and $Name -notmatch $CasePattern){return}
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
try{
    Test-CD 'Empty combined discovery is explicit 1.1 and creates no session namespace or shared cache' {
        $dir=New-CD;. (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
        $d=Read-WinSecTechnicalIndexDiscovery $dir $id
        Assert-CD ($d.SchemaVersion -ceq '1.1.0' -and $d.Sessions.Count -eq 0 -and $d.StoredSessions.Count -eq 0 -and -not [IO.Directory]::Exists((Join-Path $dir 'scans')))
    }
    foreach($scope in @('CONTROL','SECTION','DEVICE')){
        Test-CD ('Both namespaces preserve original '+$scope+' identities and remain separate families') {
            $dir=New-CD;$s=Save-WinSecStoredDiscoveryFixture $dir -ScopeType $scope;$c=Save-WinSecCandidateDiscoveryFixture $dir -ScopeType $scope
            . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
            $before=(Get-FileHash $s.Layout.Path).Hash;$d=Read-WinSecTechnicalIndexDiscovery $dir $id;$i=Restore-WinSecTechnicalSourceIndex $dir $d $id
            $p=Select-WinSecTechnicalSource $dir $i $id REVIEWED_PROJECTION $scope $s.Identity.ScopeKey
            $q=Select-WinSecTechnicalSource $dir $i $id DEFENDER_CANDIDATE $scope $s.Identity.ScopeKey
            Assert-CD ($i.SchemaVersion -ceq '1.1.0' -and $i.StoredSessions.Count -eq 1 -and $i.Sessions.Count -eq 1 -and
                $p.Selected.SessionIdentity.ScanId -ceq $s.Identity.ScanId -and $q.Selected.SessionIdentity.ScanId -ceq $c.Identity.ScanId -and
                $p.Selected.SessionIdentity.ScopeType -ceq $scope -and @($p.Selected.Source.Reference.PSObject.Properties).Count -eq 3 -and (Get-FileHash $s.Layout.Path).Hash -ceq $before)
        }
    }
    Test-CD 'Explicit shared-index preparation preserves complete and partial StoredSession history after Rescan' {
        $dir=New-CD;$a=Save-WinSecStoredDiscoveryFixture $dir;$b=Save-WinSecStoredDiscoveryFixture $dir -Day 1 -Partial
        $null=Save-WinSecCandidateDiscoveryFixture $dir;. (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
        $m=Read-WinSecTechnicalRestoreIndexes $dir @([pscustomobject]@{DeviceId=$id}) -IncludeStoredSessions;$i=$m[$id]
        $p=Select-WinSecTechnicalSource $dir $i $id REVIEWED_PROJECTION CONTROL WSA-SYS-001
        $q=Select-WinSecTechnicalSource $dir $i $id REVIEWED_PROJECTION CONTROL WSA-SYS-001 -SourcePreference LATEST_ATTEMPT
        Assert-CD ($i.StoredSessions.Count -eq 2 -and $p.History.Count -eq 3 -and $p.Selected.SessionIdentity.ScanId -ceq $a.Identity.ScanId -and
            $q.Selected.SessionIdentity.ScanId -ceq $b.Identity.ScanId -and $p.LatestAttempt.Source.Collection.Status -ceq 'PARTIAL')
        $prior=Read-WinSecTechnicalSourceSessions $dir $id
        Assert-CD ($prior.SchemaVersion -ceq '1.0.0' -and $prior.Sessions.Count -eq 1)
        $lease=Open-WinSecDeviceInventoryStore $dir
        try{Reject-CD {Assert-WinSecTechnicalRestoreIndexes $dir $m @([pscustomobject]@{DeviceId=$id})}}finally{$lease.Lock.Dispose()}
    }
    Test-CD 'Restart discovers both namespaces in new processes without serialized in-memory references' {
        $dir=New-CD;$s=Save-WinSecStoredDiscoveryFixture $dir;$null=Save-WinSecCandidateDiscoveryFixture $dir
        $helper=Join-Path $dir 'restart-fixture.ps1'
        [IO.File]::WriteAllText($helper,@'
param([string]$Root,[string]$DeviceId)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'src/Services/TechnicalSourceRestoration.ps1')
foreach($name in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){Set-Item ('Function:script:'+$name) {throw 'Native query forbidden.'}}
$m=Read-WinSecTechnicalRestoreIndexes $Root @([pscustomobject]@{DeviceId=$DeviceId}) -IncludeStoredSessions
$p=Select-WinSecTechnicalSource $Root $m[$DeviceId] $DeviceId REVIEWED_PROJECTION CONTROL WSA-SYS-001
[pscustomobject]@{Stored=$m[$DeviceId].StoredSessions.Count;Technical=$m[$DeviceId].Sessions.Count;ScanId=$p.Selected.SessionIdentity.ScanId}|ConvertTo-Json -Compress
'@)
        foreach($runtime in @('pwsh.exe','powershell.exe')){
            $exe=(Get-Command $runtime -CommandType Application|Select-Object -First 1).Source
            $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=$exe;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
            $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
            $systemModules=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'
            $start.EnvironmentVariables['PSModulePath']=if($runtime -ceq 'powershell.exe'){$systemModules}else{(Join-Path ([IO.Path]::GetDirectoryName($exe)) 'Modules')+';'+$systemModules}
            $start.Arguments='-NoLogo -NoProfile -File "'+$helper+'" -Root "'+$dir+'" -DeviceId "'+$id+'"'
            $process=New-Object Diagnostics.Process;$process.StartInfo=$start;$null=$process.Start()
            $out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
            try{
                if(-not $process.WaitForExit(60000)){$process.Kill();throw 'Synthetic discovery restart timed out.'}
                if($process.ExitCode -ne 0){throw 'Synthetic discovery restart failed.'}
                $r=ConvertFrom-Json ($out.GetAwaiter().GetResult());$null=$err.GetAwaiter().GetResult()
                Assert-CD ($r.Stored -eq 1 -and $r.Technical -eq 1 -and $r.ScanId -ceq $s.Identity.ScanId)
            }finally{$process.Dispose()}
        }
    }
    foreach($scope in @('SECTION','DEVICE')){
        Test-CD ('A valid multi-control '+$scope+' session blocks the entire combined discovery without filtering or rewriting history') {
            $dir=New-CD;$s=Save-WinSecStoredDiscoveryFixture $dir -ScopeType $scope -CheckIds @('WSA-SYS-001','WSA-SYS-002')
            $null=Save-WinSecCandidateDiscoveryFixture $dir;. (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
            $hash=(Get-FileHash $s.Layout.Path).Hash;$envelope=ConvertFrom-WinSecTransitionJson ([IO.File]::ReadAllText($s.Layout.Path))
            $null=Assert-WinSecTransitionSession $envelope;$caught=$false
            try{$null=Read-WinSecTechnicalIndexDiscovery $dir $id}catch [NotSupportedException]{$caught=($_.Exception.Message -ceq 'MULTI_CONTROL_SESSION_NOT_SUPPORTED')}
            $historical=Read-WinSecTransitionSessions $dir @([pscustomobject]@{DeviceId=$id})
            Assert-CD ($caught -and $envelope.Sources.Count -eq 2 -and $historical.Records.Count -eq 1 -and (Get-FileHash $s.Layout.Path).Hash -ceq $hash)
        }
    }
    foreach($damage in @('StoredBytes','StoredVersion','ForeignPath','PartialPublication','SourceBody')){
        Test-CD ('Invalid productive artifacts reject combined discovery without candidate-only fallback: '+$damage) {
            $dir=New-CD;$s=Save-WinSecStoredDiscoveryFixture $dir;$null=Save-WinSecCandidateDiscoveryFixture $dir
            . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
            switch($damage){
                StoredBytes {[IO.File]::WriteAllText($s.Layout.Path,'{}')}
                StoredVersion {
                    $e=ConvertFrom-WinSecTransitionJson ([IO.File]::ReadAllText($s.Layout.Path));$e.SchemaVersion='9.0.0'
                    [IO.File]::WriteAllText($s.Layout.Path,(Get-WinSecPublicHistoryJson $e))
                }
                ForeignPath {[IO.File]::Move($s.Layout.Path,(Join-Path ([IO.Path]::GetDirectoryName($s.Layout.Path)) (('b'*64)+'.json')))}
                PartialPublication {[IO.File]::Move($s.Layout.Path,($s.Layout.Path+'.tmp'))}
                SourceBody {[IO.File]::AppendAllText($s.Pair.Markdown,' ')}
            }
            Reject-CD {Read-WinSecTechnicalIndexDiscovery $dir $id}
            Assert-CD ((Read-WinSecTechnicalSourceSessions $dir $id).Sessions.Count -eq 1)
        }
    }
    Test-CD 'Other device namespaces are never read even when their stored metadata is corrupt' {
        $dir=New-CD;$null=Save-WinSecStoredDiscoveryFixture $dir;. (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
        $foreign=Join-Path $dir ('scans/'+(Get-WinSecSnapshotDeviceKey ('local:hw1-'+('c'*64)))+'/sessions')
        $null=[IO.Directory]::CreateDirectory($foreign);$path=Join-Path $foreign (('d'*64)+'.json');[IO.File]::WriteAllText($path,'INVALID')
        Assert-CD ((Read-WinSecTechnicalIndexDiscovery $dir $id).StoredSessions.Count -eq 1 -and [IO.File]::ReadAllText($path) -ceq 'INVALID')
    }
    Test-CD 'A non-pilot single-control StoredSession is not silently skipped or relabelled as Defender' {
        $dir=New-CD;$s=Save-WinSecStoredDiscoveryFixture $dir -ScopeType SECTION -CheckIds @('WSA-SYS-002')
        . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1');$caught=$false
        try{$null=Read-WinSecTechnicalIndexDiscovery $dir $id}catch [NotSupportedException]{$caught=($_.Exception.Message -ceq 'STORED_CONTROL_NOT_SUPPORTED')}
        Assert-CD ($caught -and [IO.File]::Exists($s.Layout.Path))
    }
    Test-CD 'Inventory lease contention rejects combined discovery and releases handles afterwards' {
        $dir=New-CD;$s=Save-WinSecStoredDiscoveryFixture $dir;. (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
        $lease=Open-WinSecDeviceInventoryStore $dir
        try{Reject-CD {Read-WinSecTechnicalIndexDiscovery $dir $id}}finally{$lease.Lock.Dispose()}
        Assert-CD ((Read-WinSecTechnicalIndexDiscovery $dir $id).StoredSessions.Count -eq 1)
    }
    Test-CD 'Cancellation during discovery preserves the previous index and physical history' {
        $dir=New-CD;$s=Save-WinSecStoredDiscoveryFixture $dir;$null=Save-WinSecCandidateDiscoveryFixture $dir
        . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
        $m=Read-WinSecTechnicalRestoreIndexes $dir @([pscustomobject]@{DeviceId=$id}) -IncludeStoredSessions;$before=Get-WinSecPublicHistoryJson $m[$id]
        $state=[pscustomobject]@{Calls=0};$cancel={$state.Calls++;$state.Calls -gt 12}.GetNewClosure();$caught=$false
        try{$null=Read-WinSecTechnicalIndexDiscovery $dir $id -CancellationAction $cancel}catch [OperationCanceledException]{$caught=$true}
        Assert-CD ($caught -and (Get-WinSecPublicHistoryJson $m[$id]) -ceq $before -and (Read-WinSecTechnicalIndexDiscovery $dir $id).StoredSessions.Count -eq 1)
    }
    Test-CD 'A namespace change between historical discovery and the combined owner lease cannot disappear silently' {
        $dir=New-CD;$null=Save-WinSecStoredDiscoveryFixture $dir;$c=Save-WinSecCandidateDiscoveryFixture $dir
        . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
        $original=${function:Read-WinSecTechnicalSourceSessions};$script:changedNamespace=$false
        function Read-WinSecTechnicalSourceSessions {
            param($ProjectRoot,$DeviceId,$CancellationAction)
            $r=& $original $ProjectRoot $DeviceId -CancellationAction $CancellationAction
            [IO.File]::WriteAllText(($c.Saved.Path+'.tmp'),'UNPUBLISHED');$script:changedNamespace=$true;$r
        }
        try{Reject-CD {Read-WinSecTechnicalIndexDiscovery $dir $id};Assert-CD $script:changedNamespace}
        finally{Set-Item Function:Read-WinSecTechnicalSourceSessions $original}
        Assert-CD ([IO.File]::Exists($c.Saved.Path+'.tmp'))
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awcd-[a-f0-9]{8}\z'){throw 'Unsafe combined discovery fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical index discovery integration: $passed passed; $failed failed.");if($failed){exit 1}
