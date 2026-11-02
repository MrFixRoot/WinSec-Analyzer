[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceIndexAdapter.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wju-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-IU {param([bool]$Value);if(-not $Value){throw 'Technical index unit assertion failed.'}}
function Reject-IU {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-IU $caught}
function New-IU {param([string]$Family='CANDIDATE')
    $f=New-WinSecTechnicalSourceFixture -Family $Family;$owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$f.Identity.ScanId;ScopeType=$f.Identity.ScopeType;ScopeKey=$f.Identity.ScopeKey}
    $stamp=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
    $session=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
        [pscustomobject]@{Reference=$stamp.Reference;SnapshotSha256=$stamp.SnapshotSha256;Collection=$f.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
    $session.ContentSha256=Get-WinSecTechnicalSessionDigest $session
    [pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.0.0';DeviceId=$owner.DeviceId;Sessions=@(
        [pscustomobject]@{PublicationStatus='COMMITTED';Path=(Get-WinSecTechnicalSessionStorageLayout $sandbox $owner).Path;FileSha256=('A'*64);Session=$session})}
}
function Test-IU {param([string]$Case,[scriptblock]$Action)
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try{
    $d=New-IU;$id=$d.DeviceId
    Test-IU 'Metadata index preserves the candidate family and original partial coverage without reading files' {
        $i=Copy-WinSecTechnicalIndexMetadata $sandbox $d $id DISCOVERY
        Assert-WinSecTechnicalSourceIndex $sandbox $i $id
        Assert-IU ($i.ArtifactType -ceq 'WinSec.TechnicalSourceIndex' -and $i.SchemaVersion -ceq '1.0.0' -and $i.Origin -ceq 'RECORDS' -and
            $i.Sessions[0].Session.Sources[0].Reference.SnapshotSchemaVersion -ceq '2.0.0' -and $i.Sessions[0].Session.Sources[0].Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecPublicHistoryJson $i.Sessions) -ceq (Get-WinSecPublicHistoryJson $d.Sessions) -and -not [IO.Directory]::Exists((Join-Path $sandbox 'data')))
    }
    Test-IU 'Reviewed projections keep their explicit 2.1 versions and do not become candidates' {
        $p=New-IU PROJECTION;$i=Copy-WinSecTechnicalIndexMetadata $sandbox $p $id DISCOVERY
        Assert-IU ($i.Sessions[0].Session.Sources[0].Reference.SnapshotSchemaVersion -ceq '2.1.0' -and
            $i.Sessions[0].Session.Sources[0].Reference.CollectorVersion -ceq '0.9.0')
    }
    Test-IU 'An empty manifest is an empty array with a deterministic metadata digest' {
        $empty=Copy-WinSecResultData $d;$empty.Sessions=@();$i=Copy-WinSecTechnicalIndexMetadata $sandbox $empty $id DISCOVERY
        Assert-WinSecTechnicalSourceIndex $sandbox $i $id
        Assert-IU ($i.Sessions -is [array] -and $i.Sessions.Count -eq 0)
    }
    Test-IU 'Bounded metadata JSON roundtrip retains the same index digest and exact references' {
        $i=Copy-WinSecTechnicalIndexMetadata $sandbox $d $id DISCOVERY
        $round=ConvertFrom-WinSecSnapshotPairJson (Get-WinSecPublicHistoryJson $i)
        Assert-WinSecTechnicalSourceIndex $sandbox $round $id
        Assert-IU ($round.ContentSha256 -ceq $i.ContentSha256)
    }
    Test-IU 'Path apostrophes, ampersands and Unicode produce the same metadata digest in the other runtime' {
        $special=Join-Path $sandbox ('q'+[char]39+[char]38+[char]0x00E9);$null=[IO.Directory]::CreateDirectory($special)
        $sample=Copy-WinSecResultData $d;$sample.Sessions[0].Path=(Get-WinSecTechnicalSessionStorageLayout $special $sample.Sessions[0].Session.Identity).Path
        $i=Copy-WinSecTechnicalIndexMetadata $special $sample $id DISCOVERY
        $payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $sample)))
        $loader=(Join-Path $root 'src/Services/TechnicalSourceIndexAdapter.ps1').Replace("'","''");$target=$special.Replace("'","''")
        $code="`$ErrorActionPreference='Stop';. '$loader';`$d=ConvertFrom-WinSecSnapshotPairJson ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$payload')));"+
            "`$i=Copy-WinSecTechnicalIndexMetadata '$target' `$d '$id' DISCOVERY;if(`$i.ContentSha256 -cne '$($i.ContentSha256)'){throw 'Cross-runtime digest mismatch.'};'INDEX_DIGEST_CONFIRMED'"
        $exe=if($PSVersionTable.PSVersion.Major -lt 6){'pwsh.exe'}else{'powershell.exe'}
        $output=@(& $exe -NoLogo -NoProfile -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))))
        Assert-IU ($LASTEXITCODE -eq 0 -and $output[-1] -ceq 'INDEX_DIGEST_CONFIRMED')
    }
    foreach($type in @('WinSec.StoredSession','WinSec.TechnicalSourceDiscovery','UNKNOWN')){Test-IU 'Unknown index artifact type never falls back to historical formats' {
        $i=Copy-WinSecTechnicalIndexMetadata $sandbox $d $id DISCOVERY;$i.ArtifactType=$type
        Reject-IU {Assert-WinSecTechnicalSourceIndex $sandbox $i $id}
    }}
    foreach($version in @('0.9.0','1.1.0','2.0.0',@('1.0.0'))){Test-IU 'Unknown or non-scalar index version is rejected' {
        $i=Copy-WinSecTechnicalIndexMetadata $sandbox $d $id DISCOVERY;$i.SchemaVersion=$version
        Reject-IU {Assert-WinSecTechnicalSourceIndex $sandbox $i $id}
    }}
    foreach($damage in @('Extra','Device','Origin','Digest','FileHash','Coverage','Duplicate','NotArray','Path','ReferenceVersion','Scope','ForeignSource')){
        Test-IU ('Index metadata rejects contradiction or alteration: '+$damage) {
            $i=Copy-WinSecTechnicalIndexMetadata $sandbox $d $id DISCOVERY
            switch($damage){
                Extra {$i|Add-Member NoteProperty Unknown 'UNREVIEWED'}
                Device {$i.DeviceId='local:hw1-'+('c'*64)}
                Origin {$i.Origin='LIVE'}
                Digest {$i.ContentSha256='B'*64}
                FileHash {$i.Sessions[0].FileSha256='B'*64}
                Coverage {$i.Sessions[0].Session.Sources[0].Collection.Unknown++}
                Duplicate {$i.Sessions+=@($i.Sessions[0])}
                NotArray {$i.Sessions=$i.Sessions[0]}
                Path {$i.Sessions[0].Path=Join-Path $sandbox '../foreign.json'}
                ReferenceVersion {$i.Sessions[0].Session.Sources[0].Reference.CollectorVersion='9.0.0';$i.Sessions[0].Session.ContentSha256=Get-WinSecTechnicalSessionDigest $i.Sessions[0].Session}
                Scope {$i.Sessions[0].Session.Identity.ScopeKey='WSA-SYS-002'}
                ForeignSource {$i.Sessions[0].Session.Sources[0].Reference.Identity.DeviceId='local:hw1-'+('c'*64)}
            }
            Reject-IU {Assert-WinSecTechnicalSourceIndex $sandbox $i $id}
        }
    }
    Test-IU 'A session property getter is rejected without execution' {
        $bad=Copy-WinSecResultData $d;$script:getterRan=$false
        $bad.Sessions[0].Session.PSObject.Properties.Remove('Identity')
        $bad.Sessions[0].Session|Add-Member ScriptProperty Identity {$script:getterRan=$true;throw 'Getter executed.'}
        Reject-IU {Copy-WinSecTechnicalIndexMetadata $sandbox $bad $id DISCOVERY};Assert-IU (-not $script:getterRan)
    }
    Test-IU 'The descriptor is detached before the first caller callback' {
        $script:toMutate=Copy-WinSecResultData $d
        $i=Copy-WinSecTechnicalIndexMetadata $sandbox $script:toMutate $id DISCOVERY {$script:toMutate.Sessions=@();$false}
        Assert-IU ($i.Sessions.Count -eq 1 -and $script:toMutate.Sessions.Count -eq 0)
        Assert-WinSecTechnicalSourceIndex $sandbox $i $id
    }
    Test-IU 'Cancellation rejects restoration before acquiring an inventory lease' {
        function Open-WinSecTechnicalSessionOwner {throw 'Unexpected inventory access.'}
        $cancelled=$false;try{$null=Restore-WinSecTechnicalSourceIndex $sandbox $d $id -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-IU ($cancelled -and -not [IO.Directory]::Exists((Join-Path $sandbox 'data')))
    }
    Test-IU 'A non-Boolean cancellation response is not treated as approval or cancellation' {
        Reject-IU {Restore-WinSecTechnicalSourceIndex $sandbox $d $id -CancellationAction {'yes'}}
    }
    Test-IU 'An empty registered history restores only a RECORDS manifest and creates no technical index file' {
        $core=Join-Path $sandbox 'src/Core';$null=[IO.Directory]::CreateDirectory($core)
        Copy-Item -LiteralPath (Join-Path $root 'src/Core/TargetRegistry.ps1') -Destination (Join-Path $core 'TargetRegistry.ps1')
        $null=[IO.Directory]::CreateDirectory((Join-Path $sandbox 'data'))
        $inventory=[pscustomobject]@{schemaVersion='1.0.0';targets=@([pscustomobject]@{DeviceId=$id;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true})}
        [IO.File]::WriteAllText((Join-Path $sandbox 'data/devices.json'),(ConvertTo-Json $inventory -Depth 6 -Compress))
        $before=Get-WinSecDeviceInventoryFingerprint $sandbox;$empty=Read-WinSecTechnicalSourceSessions $sandbox $id
        $i=Restore-WinSecTechnicalSourceIndex $sandbox $empty $id
        Assert-IU ($i.Sessions.Count -eq 0 -and $i.Origin -ceq 'RECORDS' -and -not [IO.Directory]::Exists((Join-Path $sandbox 'scans')) -and
            (Get-WinSecDeviceInventoryFingerprint $sandbox) -ceq $before)
    }
    Test-IU 'A metadata-valid index does not bypass physical ownership and source verification' {
        $i=Copy-WinSecTechnicalIndexMetadata $sandbox $d $id DISCOVERY
        Reject-IU {Read-WinSecIndexedTechnicalSession $sandbox $i $d.Sessions[0].Session.Identity}
        Assert-IU (-not [IO.File]::Exists($d.Sessions[0].Path))
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awju-[a-f0-9]{8}\z'){throw 'Unsafe index unit cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical source index unit: $passed passed; $failed failed.");if($failed){exit 1}
