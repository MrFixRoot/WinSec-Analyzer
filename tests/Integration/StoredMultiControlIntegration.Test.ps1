[CmdletBinding()]param([string]$CasePattern='')
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalIndexDiscoveryMemory.ps1')
foreach($name in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){Set-Item ('Function:script:'+$name) {throw 'Native acquisition forbidden.'}}
$passed=0;$failed=0;$counter=0;$id='local:hw1-'+('a'*64);$checks=@('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')
$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $base ('wmc-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-MI {param([bool]$Value);if(-not $Value){throw 'Stored multi-control integration assertion failed.'}}
function Reject-MI {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-MI $caught}
function New-MI {
    $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
    foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
    $null=[IO.Directory]::CreateDirectory((Join-Path $dir 'data'))
    [IO.File]::WriteAllText((Join-Path $dir 'data/devices.json'),(ConvertTo-Json ([pscustomobject]@{schemaVersion='1.0.0';targets=@(
        [pscustomobject]@{DeviceId=$id;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true})}) -Depth 5 -Compress));$dir
}
function Index-MI {param([string]$Dir)
    Read-WinSecTechnicalRestoreIndexes $Dir @([pscustomobject]@{DeviceId=$id}) -IncludeStoredSessions
}
function Pick-MI {param([string]$Dir,$Index,[string]$Check,[string]$Policy='PREFER_COMPLETE')
    Select-WinSecTechnicalSource $Dir $Index $id REVIEWED_PROJECTION CONTROL $Check -CheckId $Check -SourcePreference $Policy
}
function Rewrite-MI {param($File,$Envelope)
    $copy=Copy-WinSecResultData $Envelope;$copy.PSObject.Properties.Remove('ContentSha256')
    $Envelope.ContentSha256=Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson $copy)
    [IO.File]::WriteAllText($File,(Get-WinSecPublicHistoryJson $Envelope),(New-Object Text.UTF8Encoding($false)))
}
function Test-MI {param([string]$Name,[scriptblock]$Action)
    if($CasePattern -and $Name -notmatch $CasePattern){return}
    $priorError=if($Error.Count){$Error[0]}else{$null}
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{
        $script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace
        foreach($record in $Error){
            if([object]::ReferenceEquals($record,$priorError)){break}
            if($record.Exception.Message -ceq 'Snapshot validation time budget exceeded.'){
                $frames=@([regex]::Matches($record.ScriptStackTrace,'(?:at|en) ([A-Za-z]+-WinSec[A-Za-z0-9]+),')|ForEach-Object {$_.Groups[1].Value})
                $callers=@($frames|Where-Object {$_ -cin @('Read-WinSecTechnicalIndexDiscovery','Open-WinSecStoredTechnicalIndexEntry','Read-WinSecVersionedTechnicalSource','Get-WinSecTechnicalSourcePackageStamp','Copy-WinSecTechnicalIndexMetadata')})
                Write-Host ('[DIAGNOSTIC] TIME_BUDGET_EXCEEDED'+$(if($callers.Count){':'+$callers[0]}else{''}));break
            }
        }
    }
}
try{
    foreach($check in $checks){
        Test-MI ('CONTROL preserves the exact productive check and its historical reference: '+$check) {
            $dir=New-MI;$s=Save-WinSecStoredDiscoveryFixture $dir -CheckIds @($check)
            . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1')
            $e=Read-WinSecStoredTechnicalIndexEntry $dir $s.Identity;$m=Index-MI $dir;$pick=Pick-MI $dir $m[$id] $check
            $exact=Read-WinSecIndexedTechnicalSession $dir $m[$id] $s.Identity
            Assert-MI ($pick.Selected.Source.Reference.Identity.CheckId -ceq $check -and $exact.Sources.Count -eq 1 -and
                $pick.Selected.Source.Reference.Identity.ScopeKey -ceq $check -and @($e.Sources[0].Reference.PSObject.Properties).Count -eq 3)
        }
    }
    foreach($scope in @('SECTION','DEVICE')){
        Test-MI ('Three sources retain one '+$scope+' StoredSession and remain separate from the Defender candidate') {
            $dir=New-MI;$s=Save-WinSecStoredDiscoveryFixture $dir -ScopeType $scope -CheckIds $checks;$c=Save-WinSecCandidateDiscoveryFixture $dir
            . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1');$hash=(Get-FileHash $s.Layout.Path).Hash;$m=Index-MI $dir;$i=$m[$id]
            $entry=Read-WinSecIndexedTechnicalSession $dir $i $s.Identity
            Assert-MI ($i.StoredSessions.Count -eq 1 -and $entry.Sources.Count -eq 3 -and $i.Sessions.Count -eq 1 -and $entry.Identity.ScopeType -ceq $scope)
            foreach($check in $checks){
                $p=Pick-MI $dir $i $check
                Assert-MI ($p.Selected.SessionIdentity.ScanId -ceq $s.Identity.ScanId -and $p.Selected.Source.Reference.Identity.CheckId -ceq $check -and
                    $p.Selected.Source.Reference.Identity.ScopeType -ceq $scope -and @($p.History|Where-Object {$_.Source.Reference.Identity.CheckId -cne $check -and $_.Eligibility -ceq 'ELIGIBLE'}).Count -eq 0)
            }
            $old=Read-WinSecTransitionSessions $dir @([pscustomobject]@{DeviceId=$id})
            Assert-MI ($old.Records.Count -eq 1 -and (Get-FileHash $s.Layout.Path).Hash -ceq $hash -and (Read-WinSecTechnicalSourceSessions $dir $id).Sessions.Count -eq 1)
        }
    }
    Test-MI 'Rescan applies complete and latest policies independently per check without fabricating scans' {
        $dir=New-MI;$a=Save-WinSecStoredDiscoveryFixture $dir -ScopeType SECTION -CheckIds $checks
        $b=Save-WinSecStoredDiscoveryFixture $dir -ScopeType SECTION -CheckIds $checks -Day 1 -PartialCheckIds @('WSA-SYS-002')
        . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1');$m=Index-MI $dir;$i=$m[$id]
        $p=Pick-MI $dir $i WSA-SYS-002;$latest=Pick-MI $dir $i WSA-SYS-002 LATEST_ATTEMPT;$update=Pick-MI $dir $i WSA-SYS-003
        Assert-MI ($i.StoredSessions.Count -eq 2 -and $p.History.Count -eq 6 -and $p.Selected.SessionIdentity.ScanId -ceq $a.Identity.ScanId -and
            $latest.Selected.SessionIdentity.ScanId -ceq $b.Identity.ScanId -and $latest.Selected.Source.Collection.Status -ceq 'PARTIAL' -and
            $update.Selected.SessionIdentity.ScanId -ceq $b.Identity.ScanId -and $update.Selected.Source.Collection.Status -ceq 'COMPLETE')
    }
    foreach($damage in @('MissingSource','DuplicateSource','ForeignCheck','MissingBody','CorruptUnselectedBody','IncompatibleCollector')){
        Test-MI ('A required incompatible source rejects the entire session without filtering: '+$damage) {
            $dir=New-MI;$s=Save-WinSecStoredDiscoveryFixture $dir -ScopeType SECTION -CheckIds $checks
            . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1');$m=Index-MI $dir;$before=Get-WinSecPublicHistoryJson $m[$id]
            $e=ConvertFrom-WinSecTransitionJson ([IO.File]::ReadAllText($s.Layout.Path));$ref=$e.Sources[1];$pair=Get-WinSecSnapshotPairLayout $dir $ref.Identity $ref.CollectedAtUTC
            switch($damage){
                MissingSource {$e.Sources=@($e.Sources[0],$e.Sources[2]);Rewrite-MI $s.Layout.Path $e}
                DuplicateSource {$e.Sources[1]=Copy-WinSecResultData $e.Sources[0];Rewrite-MI $s.Layout.Path $e}
                ForeignCheck {$e.Sources[1].Identity.CheckId='WSA-SYS-003';Rewrite-MI $s.Layout.Path $e}
                MissingBody {[IO.File]::Move($pair.Markdown,($pair.Markdown+'.removed'))}
                CorruptUnselectedBody {[IO.File]::AppendAllText($pair.Markdown,' ')}
                IncompatibleCollector {
                    $saved=Read-WinSecVersionedTechnicalSource $dir $ref $ref.Identity;$snapshot=$saved.Snapshot
                    $snapshot.Identity.SnapshotId=[guid]::NewGuid().ToString('N');$snapshot.CollectorVersion='99.0.0'
                    foreach($batch in $snapshot.Batches){$batch.SnapshotId=$snapshot.Identity.SnapshotId}
                    $null=Write-WinSecTechnicalSnapshotPair $dir $snapshot $saved.Catalog $saved.CatalogSha256 $snapshot.Identity
                    $e.Sources[1].Identity=$snapshot.Identity.PSObject.Copy();Rewrite-MI $s.Layout.Path $e
                }
            }
            Reject-MI {Read-WinSecStoredTechnicalIndexEntry $dir $s.Identity};Reject-MI {Index-MI $dir};Reject-MI {Pick-MI $dir $m[$id] WSA-SYS-001}
            Assert-MI ((Get-WinSecPublicHistoryJson $m[$id]) -ceq $before -and [IO.File]::Exists($s.Layout.Path))
        }
    }
    Test-MI 'A DEVICE session containing an unsupported control is rejected whole and retained historically' {
        $dir=New-MI;$s=Save-WinSecStoredDiscoveryFixture $dir -ScopeType DEVICE -CheckIds @('WSA-SYS-001','WSA-NET-002')
        . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1');$caught=$false
        try{$null=Read-WinSecTechnicalIndexDiscovery $dir $id}catch [NotSupportedException]{$caught=($_.Exception.Message -ceq 'STORED_CONTROL_NOT_SUPPORTED')}
        Assert-MI ($caught -and (Read-WinSecTransitionSessions $dir @([pscustomobject]@{DeviceId=$id})).Records.Count -eq 1)
    }
    Test-MI 'CONTROL cannot be reinterpreted as a session of multiple different controls' {
        $dir=New-MI;Reject-MI {Save-WinSecStoredDiscoveryFixture $dir -ScopeType CONTROL -CheckIds $checks}
    }
    Test-MI 'Cancellation during multi-source validation preserves prior indexes and releases all leases' {
        $dir=New-MI;$s=Save-WinSecStoredDiscoveryFixture $dir -ScopeType SECTION -CheckIds $checks
        . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1');$m=Index-MI $dir;$before=Get-WinSecPublicHistoryJson $m[$id]
        $state=[pscustomobject]@{Calls=0};$cancel={$state.Calls++;$state.Calls -gt 20}.GetNewClosure();$caught=$false
        try{$null=Read-WinSecStoredTechnicalIndexEntry $dir $s.Identity -CancellationAction $cancel}catch [OperationCanceledException]{$caught=$true}
        Assert-MI ($caught -and (Get-WinSecPublicHistoryJson $m[$id]) -ceq $before -and (Read-WinSecStoredTechnicalIndexEntry $dir $s.Identity).Sources.Count -eq 3)
    }
    Test-MI 'The managed inventory lease prevents concurrent multi-source discovery' {
        $dir=New-MI;$s=Save-WinSecStoredDiscoveryFixture $dir -ScopeType DEVICE -CheckIds $checks
        . (Join-Path $dir 'src/Services/TechnicalSourceRestoration.ps1');$lease=Open-WinSecDeviceInventoryStore $dir
        try{Reject-MI {Read-WinSecStoredTechnicalIndexEntry $dir $s.Identity};Reject-MI {Index-MI $dir}}finally{$lease.Lock.Dispose()}
        Assert-MI ((Read-WinSecStoredTechnicalIndexEntry $dir $s.Identity).Sources.Count -eq 3)
    }
    Test-MI 'Cold processes in both runtimes restore the same three-source session without fixture imports' {
        $dir=New-MI;$s=Save-WinSecStoredDiscoveryFixture $dir -ScopeType SECTION -CheckIds $checks;$helper=Join-Path $dir 'restart-fixture.ps1'
        [IO.File]::WriteAllText($helper,@'
param([string]$Root,[string]$DeviceId)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'src/Services/TechnicalSourceRestoration.ps1')
foreach($name in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){Set-Item ('Function:script:'+$name) {throw 'Native query forbidden.'}}
try{
    $m=Read-WinSecTechnicalRestoreIndexes $Root @([pscustomobject]@{DeviceId=$DeviceId}) -IncludeStoredSessions
    $p=Select-WinSecTechnicalSource $Root $m[$DeviceId] $DeviceId REVIEWED_PROJECTION CONTROL WSA-SYS-002 -CheckId WSA-SYS-002
    [pscustomobject]@{Count=$m[$DeviceId].StoredSessions[0].Sources.Count;ScanId=$p.Selected.SessionIdentity.ScanId;CheckId=$p.Selected.Source.Reference.Identity.CheckId}|ConvertTo-Json -Compress
}catch{
    # Synthetic child only: report reviewed function identifiers, never raw exceptions or payloads.
    $names=@(foreach($record in $Error){$name=$record.CategoryInfo.TargetName
        if($record.CategoryInfo.Reason -ceq 'CommandNotFoundException' -and $name -is [string] -and $name -cmatch '\A[A-Za-z]+-WinSec[A-Za-z0-9]+\z'){$name}})
    $names=@($names|Sort-Object -Unique)
    $budget=@($Error|Where-Object {$_.Exception.Message -ceq 'Snapshot validation time budget exceeded.'})
    $category=if($budget.Count){
        $frames=@([regex]::Matches($budget[0].ScriptStackTrace,'(?:at|en) ([A-Za-z]+-WinSec[A-Za-z0-9]+),')|ForEach-Object {$_.Groups[1].Value})
        $callers=@($frames|Where-Object {$_ -cin @('Read-WinSecTechnicalIndexDiscovery','Open-WinSecStoredTechnicalIndexEntry','Read-WinSecVersionedTechnicalSource','Get-WinSecTechnicalSourcePackageStamp','Copy-WinSecTechnicalIndexMetadata')})
        'TIME_BUDGET_EXCEEDED'+$(if($callers.Count){':'+$callers[0]}else{''})
    }elseif($names.Count){'MISSING_LOCAL_DEPENDENCY:'+($names -join ',')}else{'STORED_MULTI_RESTART_REJECTED'}
    [Console]::Error.WriteLine($category);exit 1
}
'@)
        foreach($runtime in @('pwsh.exe','powershell.exe')){
            $exe=(Get-Command $runtime -CommandType Application|Select-Object -First 1).Source
            $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=$exe;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
            $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
            $modules=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'
            $start.EnvironmentVariables['PSModulePath']=if($runtime -ceq 'powershell.exe'){$modules}else{(Join-Path ([IO.Path]::GetDirectoryName($exe)) 'Modules')+';'+$modules}
            $start.Arguments='-NoLogo -NoProfile -File "'+$helper+'" -Root "'+$dir+'" -DeviceId "'+$id+'"'
            $process=New-Object Diagnostics.Process;$process.StartInfo=$start;$null=$process.Start();$out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
            try{
                if(-not $process.WaitForExit(60000)){$process.Kill();throw 'Multi-source restart timed out.'}
                if($process.ExitCode -ne 0){
                    $detail=$err.GetAwaiter().GetResult().Trim()
                    if($detail -cnotmatch '\A(?:STORED_MULTI_RESTART_REJECTED|TIME_BUDGET_EXCEEDED(?::[A-Za-z]+-WinSec[A-Za-z0-9]+)?|MISSING_LOCAL_DEPENDENCY:[A-Za-z]+-WinSec[A-Za-z0-9]+(?:,[A-Za-z]+-WinSec[A-Za-z0-9]+)*)\z'){$detail='UNCLASSIFIED_CHILD_FAILURE'}
                    throw ('Multi-source restart rejected: '+$detail)
                }
                $r=ConvertFrom-Json ($out.GetAwaiter().GetResult());$null=$err.GetAwaiter().GetResult()
                Assert-MI ($r.Count -eq 3 -and $r.ScanId -ceq $s.Identity.ScanId -and $r.CheckId -ceq 'WSA-SYS-002')
            }finally{$process.Dispose()}
        }
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awmc-[a-f0-9]{8}\z'){throw 'Unsafe multi-control fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Stored multi-control integration: $passed passed; $failed failed.");if($failed){exit 1}
