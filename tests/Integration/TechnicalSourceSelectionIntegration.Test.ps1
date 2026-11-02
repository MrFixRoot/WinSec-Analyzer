[CmdletBinding()]param([string]$CasePattern='')
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceSelection.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$counter=0;$scanCounter=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wpi-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-PI {param([bool]$Value);if(-not $Value){throw 'Technical selection integration assertion failed.'}}
function Reject-PI {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PI $caught}
function New-PI {param([string]$Family='CANDIDATE',[string]$Scope='CONTROL',[string]$Catalog='1.1.0',[int]$Day=0,[string]$IntoRoot='',[string]$Scan='')
    if($IntoRoot){$dir=$IntoRoot}else{
        $script:counter++;$dir=Join-Path $sandbox $script:counter.ToString('x3');$null=[IO.Directory]::CreateDirectory($dir)
        foreach($part in @('src','config')){Copy-Item -LiteralPath (Join-Path $root $part) -Destination (Join-Path $dir $part) -Recurse}
    }
    $script:scanCounter++;if(-not $Scan){$Scan='selection-'+$script:scanCounter.ToString('x4')}
    $f=New-WinSecTechnicalSourceFixture -Family $Family -ScopeType $Scope -CatalogVersion $Catalog
    if($Family -ceq 'PROJECTION'){
        $report=ConvertFrom-WinSecProjectionSnapshot $f.Package.Snapshot;$report.ScanId=$Scan
        foreach($name in @('StartedAtUTC','CollectedAtUTC','CompletedAtUTC','GeneratedAtUTC')){
            $report.$name=(ConvertTo-WinSecSnapshotUtc $report.$name).AddDays($Day).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
        }
        $f.Package=New-WinSecProjectionSnapshot $report;$f.Identity=$f.Package.Identity.PSObject.Copy();$f.Reference.Identity=$f.Identity.PSObject.Copy()
    }else{
        foreach($name in @('StartedAtUTC','CollectedAtUTC','CompletedAtUTC','GeneratedAtUTC')){
            $f.Package.Snapshot.$name=(ConvertTo-WinSecSnapshotUtc $f.Package.Snapshot.$name).AddDays($Day).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
        }
    }
    foreach($identity in @($f.Identity,$f.Reference.Identity,$f.Package.Identity,$f.Package.Snapshot.Identity)){$identity.ScanId=$Scan}
    foreach($batch in $f.Package.Snapshot.Batches){$batch.ScanId=$Scan}
    $f.Reference.CollectedAtUTC=$f.Package.Snapshot.CollectedAtUTC
    $null=Save-WinSecTechnicalSourceFixture $dir $f
    $owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$Scan;ScopeType=$f.Identity.ScopeType;ScopeKey=$f.Identity.ScopeKey}
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
function Index-PI {param($f);$d=Read-WinSecTechnicalSourceSessions $f.Root $f.Owner.DeviceId;Restore-WinSecTechnicalSourceIndex $f.Root $d $f.Owner.DeviceId}
function Select-PI {param($f,$Index,[string]$Policy='PREFER_COMPLETE',[string]$Scope='CONTROL',[string]$Family='DEFENDER_CANDIDATE',[scriptblock]$Cancel)
    $key=switch($Scope){CONTROL {'WSA-SYS-001'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
    Select-WinSecTechnicalSource $f.Root $Index $f.Owner.DeviceId $Family $Scope $key -SourcePreference $Policy -CancellationAction $Cancel
}
function Test-PI {param([string]$Case,[scriptblock]$Action)
    if($CasePattern -and $Case -notmatch $CasePattern){return}
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try{
    Test-PI 'Preferred complete and latest partial stay distinct, original and physically verified' {
        $old=New-PI -Catalog '1.0.0';$new=New-PI -Day 1 -IntoRoot $old.Root;$i=Index-PI $old;$before=Get-WinSecPublicHistoryJson $i
        $s=Select-PI $old $i;$latest=Select-PI $old $i LATEST_ATTEMPT
        Assert-PI ($s.Selected.SessionIdentity.ScanId -ceq $old.Owner.ScanId -and $s.LatestAttempt.SessionIdentity.ScanId -ceq $new.Owner.ScanId -and
            $s.Selected.Source.Collection.Status -ceq 'COMPLETE' -and $s.LatestAttempt.Source.Collection.Status -ceq 'PARTIAL' -and
            $s.SelectedDiffersFromLatest -and $s.History.Count -eq 2 -and $s.History[0].Verification -ceq 'VERIFIED_AT_SELECTION' -and
            $s.History[1].Verification -ceq 'VERIFIED_AT_SELECTION' -and $latest.Selected.SessionIdentity.ScanId -ceq $new.Owner.ScanId -and
            (Get-WinSecPublicHistoryJson $i) -ceq $before -and $s.Selected.Source.SnapshotSha256 -ceq $old.Session.Sources[0].SnapshotSha256)
    }
    Test-PI 'All partial sources explicitly fall back to the newest original source' {
        $a=New-PI;$b=New-PI -Day 1 -IntoRoot $a.Root;$s=Select-PI $a (Index-PI $a)
        Assert-PI ($s.Reason -ceq 'NO_COMPLETE_USE_LATEST' -and $s.Selected.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and $s.History.Count -eq 2)
    }
    Test-PI 'Equal timestamps use scope specificity while SECTION and DEVICE remain exact' {
        $a=New-PI -Catalog '1.0.0';$b=New-PI -Catalog '1.0.0' -Scope SECTION -IntoRoot $a.Root;$c=New-PI -Catalog '1.0.0' -Scope DEVICE -IntoRoot $a.Root;$i=Index-PI $a
        $control=Select-PI $a $i;$section=Select-PI $a $i -Scope SECTION;$device=Select-PI $a $i -Scope DEVICE
        Assert-PI ($control.Selected.SessionIdentity.ScanId -ceq $a.Owner.ScanId -and $section.Selected.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and
            $device.Selected.SessionIdentity.ScanId -ceq $c.Owner.ScanId -and @($section.History|Where-Object Eligibility -CEQ OUT_OF_SCOPE).Count -eq 2)
    }
    Test-PI 'Newer parent scope data wins by actual source collection time without changing provenance' {
        $a=New-PI -Catalog '1.0.0';$b=New-PI -Catalog '1.0.0' -Day 1 -Scope DEVICE -IntoRoot $a.Root;$s=Select-PI $a (Index-PI $a)
        Assert-PI ($s.Selected.SessionIdentity.ScopeType -ceq 'DEVICE' -and $s.Selected.Source.Reference.Identity.ScopeKey -ceq 'ALL' -and
            $s.Selected.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and $s.RequestedScope.ScopeType -ceq 'CONTROL')
    }
    Test-PI 'Case-distinct scan identities and deterministic ordering survive physical restoration' {
        $a=New-PI -Catalog '1.0.0' -Scan A;$b=New-PI -Catalog '1.0.0' -Scan a -Scope SECTION -IntoRoot $a.Root;$s=Select-PI $a (Index-PI $a)
        Assert-PI ($s.History.Count -eq 2 -and $s.Selected.SessionIdentity.ScanId -ceq 'A')
    }
    Test-PI 'Known productive and candidate families remain isolated with exclusions visible' {
        $a=New-PI -Family PROJECTION;$b=New-PI -Day 1 -IntoRoot $a.Root;$i=Index-PI $a
        $reviewed=Select-PI $a $i -Family REVIEWED_PROJECTION;$candidate=Select-PI $a $i
        Assert-PI ($reviewed.Selected.Source.Reference.SnapshotSchemaVersion -ceq '2.1.0' -and $candidate.Selected.Source.Reference.SnapshotSchemaVersion -ceq '2.0.0' -and
            $reviewed.History[0].Eligibility -ceq 'OTHER_FAMILY' -and $reviewed.History[0].Verification -ceq 'REFERENCE_ONLY')
    }
    Test-PI 'Restart rebuilds the index and produces the same choices in both runtimes without collectors' {
        $a=New-PI -Catalog '1.0.0';$b=New-PI -Day 1 -IntoRoot $a.Root
        foreach($exe in @('pwsh.exe','powershell.exe')){
            $loader=(Join-Path $a.Root 'src/Services/TechnicalSourceSelection.ps1').Replace("'","''");$install=$a.Root.Replace("'","''")
            $code="`$ErrorActionPreference='Stop';. '$loader';function Get-CimInstance {throw 'Native forbidden.'};function Get-MpPreference {throw 'Native forbidden.'};"+
                "`$d=Read-WinSecTechnicalSourceSessions '$install' '$($a.Owner.DeviceId)';`$i=Restore-WinSecTechnicalSourceIndex '$install' `$d '$($a.Owner.DeviceId)';"+
                "`$s=Select-WinSecTechnicalSource '$install' `$i '$($a.Owner.DeviceId)' DEFENDER_CANDIDATE CONTROL WSA-SYS-001;"+
                "if(`$s.Selected.SessionIdentity.ScanId -cne '$($a.Owner.ScanId)' -or `$s.LatestAttempt.SessionIdentity.ScanId -cne '$($b.Owner.ScanId)' -or `$s.History.Count -ne 2){throw 'Restart selection mismatch.'};'SOURCE_SELECTION_CONFIRMED'"
            $output=@(& $exe -NoLogo -NoProfile -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))))
            Assert-PI ($LASTEXITCODE -eq 0 -and $output[-1] -ceq 'SOURCE_SELECTION_CONFIRMED')
        }
    }
    foreach($which in @('LATEST','PREFERRED')){
        Test-PI ('Alterations never silently fall back to an apparently usable source: '+$which) {
            $a=New-PI -Catalog '1.0.0';$b=New-PI -Day 1 -IntoRoot $a.Root;$i=Index-PI $a;$prior=Select-PI $a $i;$hash=Get-WinSecPublicHistoryJson $prior
            $target=if($which -ceq 'LATEST'){$b.Pair.Markdown}else{$a.Pair.Markdown};[IO.File]::AppendAllText($target,' ')
            Reject-PI {Select-PI $a $i}
            Assert-PI ((Get-WinSecPublicHistoryJson $prior) -ceq $hash -and [IO.File]::Exists($a.Saved.Path) -and [IO.File]::Exists($b.Saved.Path))
        }
    }
    Test-PI 'Older unconsumed history stays reference-only rather than falsely validated' {
        $a=New-PI;$b=New-PI -Catalog '1.0.0' -Day 1 -IntoRoot $a.Root;$i=Index-PI $a;[IO.File]::AppendAllText($a.Pair.Markdown,' ')
        $s=Select-PI $a $i
        Assert-PI ($s.Selected.SessionIdentity.ScanId -ceq $b.Owner.ScanId -and $s.History[1].Verification -ceq 'REFERENCE_ONLY')
    }
    Test-PI 'Cancellation during verification preserves prior choices, immutable artifacts and leases' {
        $a=New-PI -Catalog '1.0.0';$b=New-PI -Day 1 -IntoRoot $a.Root;$i=Index-PI $a;$prior=Select-PI $a $i;$hash=Get-WinSecPublicHistoryJson $prior;$script:polls=0;$cancelled=$false
        try{$null=Select-PI $a $i -Cancel {$script:polls++;$script:polls -ge 6}}catch [OperationCanceledException]{$cancelled=$true}
        $stream=[IO.File]::Open($b.Saved.Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$stream.Dispose()
        $lease=Open-WinSecDeviceInventoryStore $a.Root;$lease.Lock.Dispose()
        Assert-PI ($cancelled -and (Get-WinSecPublicHistoryJson $prior) -ceq $hash -and (Get-FileHash -LiteralPath $b.Saved.Path).Hash -ceq $b.Saved.FileSha256)
    }
    Test-PI 'The actual inventory lease prevents concurrent selection and releases normally afterwards' {
        $a=New-PI;$i=Index-PI $a;$lease=Open-WinSecDeviceInventoryStore $a.Root
        try{Reject-PI {Select-PI $a $i}}finally{$lease.Lock.Dispose()}
        Assert-PI ((Select-PI $a $i).Selected.SessionIdentity.ScanId -ceq $a.Owner.ScanId)
    }
    Test-PI 'Owner retirement cannot be bypassed by a restored index' {
        $a=New-PI;$i=Index-PI $a;$inventory=[pscustomobject]@{schemaVersion='1.1.0';targets=@();removedDeviceHashes=@((Get-WinSecDeviceInventoryIdentityHash $a.Owner.DeviceId))}
        [IO.File]::WriteAllText((Join-Path $a.Root 'data/devices.json'),(ConvertTo-Json $inventory -Compress))
        Reject-PI {Select-PI $a $i};Assert-PI ([IO.File]::Exists($a.Saved.Path))
    }
    Test-PI 'Foreign device, incompatible metadata and changed index digests are rejected before fallback' {
        $a=New-PI;$i=Index-PI $a
        Reject-PI {Select-WinSecTechnicalSource $a.Root $i ('local:hw1-'+('c'*64)) DEFENDER_CANDIDATE CONTROL WSA-SYS-001}
        $i.Sessions[0].Session.Sources[0].Reference.CollectorVersion='9.0.0';Reject-PI {Select-PI $a $i}
    }
    Test-PI 'StoredSession 1.0 readers and reference caches remain unchanged by new source selection' {
        $a=New-PI -Family PROJECTION;$i=Index-PI $a
        . (Join-Path $a.Root 'src/Core/ScanCoordinator.ps1')
        $s=$a.Fixture.Package.Snapshot;$id=$a.Fixture.Identity
        $control=[pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$id.ScanId;CheckId=$id.CheckId;SectionKey='SystemSecurity';Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';TimestampUTC=$s.CollectedAtUTC;Evidence=[pscustomobject]@{}}
        $session=New-WinSecResultSession -DeviceId $id.DeviceId -ScanId $id.ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @($id.CheckId) `
            -ControlResults @($control) -StartedAtUTC $s.StartedAtUTC -CompletedAtUTC $s.CompletedAtUTC -ExecutionStatus COMPLETED -ScopeType CONTROL -ScopeKey $id.CheckId
        $c=[pscustomobject]@{ProjectRoot=$a.Root;TechnicalLocations=@{}}
        Write-WinSecTransitionSession $c $session ([pscustomobject]@{Status='SAVED';Files=@([pscustomobject]@{Reference=(Get-WinSecLegacySourceFixtureReference $a.Fixture)})})
        $path=(Get-WinSecTransitionSessionLayout $a.Root $id.DeviceId $id.ScanId).Path;$hash=(Get-FileHash -LiteralPath $path).Hash;$cache=Get-WinSecPublicHistoryJson $c.TechnicalLocations
        $old=Read-WinSecTransitionSessions $a.Root @([pscustomobject]@{DeviceId=$id.DeviceId});$picked=Select-PI $a $i -Family REVIEWED_PROJECTION
        Assert-PI ($old.Records.Count -eq 1 -and $picked.Selected.Source.Reference.SnapshotSchemaVersion -ceq '2.1.0' -and
            (Get-FileHash -LiteralPath $path).Hash -ceq $hash -and (Get-WinSecPublicHistoryJson $c.TechnicalLocations) -ceq $cache)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awpi-[a-f0-9]{8}\z'){throw 'Unsafe selection integration cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical source selection integration: $passed passed; $failed failed.");if($failed){exit 1}
