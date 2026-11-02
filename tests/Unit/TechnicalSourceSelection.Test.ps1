[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceSelection.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wpu-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
$script:reads=@();$script:corrupt=@{};$script:owners=0
# Only I/O boundaries are synthetic in this unit suite. Metadata, resolver, policy and digest stay real.
function Open-WinSecTechnicalSessionOwner {param($ProjectRoot,$Identity);$script:owners++;[pscustomobject]@{Lock=(New-Object IO.MemoryStream)}}
function Assert-WinSecTechnicalSessionOwnerUnchanged {param($Lease)}
function Read-WinSecTechnicalIndexEntry {param($ProjectRoot,$Entry,$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    $id=$Entry.Session.Sources[0].Reference.Identity.SnapshotId;$script:reads+=@($id)
    if($script:corrupt.ContainsKey($id)){throw 'Synthetic physical corruption.'};$Entry
}
function Assert-PU {param([bool]$Value);if(-not $Value){throw 'Technical selection unit assertion failed.'}}
function Reject-PU {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PU $caught}
$candidate=New-WinSecTechnicalSourceFixture -CatalogVersion '1.0.0';$projection=New-WinSecTechnicalSourceFixture -Family PROJECTION
$device=$candidate.Identity.DeviceId
function New-PUEntry {param([string]$Scan,[string]$Status='PARTIAL',[int]$Day=0,[string]$Scope='CONTROL',[string]$Family='CANDIDATE',[int]$Errors=0,[string]$Snapshot='')
    $f=if($Family -ceq 'CANDIDATE'){$candidate}else{$projection};$ref=Copy-WinSecResultData $f.Reference
    $ref.Identity.ScanId=$Scan;$ref.Identity.ScopeType=$Scope;$ref.Identity.ScopeKey=switch($Scope){CONTROL {'WSA-SYS-001'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
    $ref.Identity.SnapshotId=if($Snapshot){$Snapshot}else{[guid]::NewGuid().ToString('N')}
    $ref.CollectedAtUTC=([datetime]'2026-10-28T01:02:04Z').AddDays($Day).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    $owner=[pscustomobject]@{DeviceId=$device;ScanId=$Scan;ScopeType=$Scope;ScopeKey=$ref.Identity.ScopeKey}
    $collection=$f.Package.Snapshot.Collection.PSObject.Copy();$collection.Status=$Status;$collection.Coverage='LIMITED';$collection.Errors=$Errors
    $s=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
        [pscustomobject]@{Reference=$ref;SnapshotSha256=('A'*64);Collection=$collection});ContentSha256=''}
    $s.ContentSha256=Get-WinSecTechnicalSessionDigest $s
    [pscustomobject]@{PublicationStatus='COMMITTED';Path=(Get-WinSecTechnicalSessionStorageLayout $sandbox $owner).Path;FileSha256=('A'*64);Session=$s}
}
function New-PUIndex {param([object[]]$Entries)
    $d=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.0.0';DeviceId=$device;Sessions=@($Entries)}
    Copy-WinSecTechnicalIndexMetadata $sandbox $d $device DISCOVERY
}
function Select-PU {param($Index,[string]$Policy='PREFER_COMPLETE',[string]$Scope='CONTROL',[string]$Family='DEFENDER_CANDIDATE',[scriptblock]$Cancel)
    $key=switch($Scope){CONTROL {'WSA-SYS-001'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
    Select-WinSecTechnicalSource $sandbox $Index $device $Family $Scope $key -SourcePreference $Policy -CancellationAction $Cancel
}
function Test-PU {param([string]$Case,[scriptblock]$Action)
    $script:reads=@();$script:corrupt=@{};$script:owners=0
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try{
    Test-PU 'Prefer complete keeps the latest partial errors and the entire history visible' {
        $i=New-PUIndex @((New-PUEntry old COMPLETE),(New-PUEntry recent PARTIAL 1 -Errors 2));$s=Select-PU $i
        Assert-PU ($s.Selected.SessionIdentity.ScanId -ceq 'old' -and $s.LatestAttempt.SessionIdentity.ScanId -ceq 'recent' -and
            $s.LatestAttempt.Source.Collection.Errors -eq 2 -and $s.History.Count -eq 2 -and $s.SelectedDiffersFromLatest -and
            $s.TemporalBasis -ceq 'REFERENCE_COLLECTED_AT_UTC' -and $script:reads.Count -eq 2)
    }
    Test-PU 'Latest attempt selects the newest partial and revalidates it only once' {
        $i=New-PUIndex @((New-PUEntry old COMPLETE),(New-PUEntry recent PARTIAL 1));$s=Select-PU $i LATEST_ATTEMPT
        Assert-PU ($s.Selected.SessionIdentity.ScanId -ceq 'recent' -and -not $s.SelectedDiffersFromLatest -and $script:reads.Count -eq 1)
    }
    Test-PU 'No complete source explicitly falls back to latest partial' {
        $i=New-PUIndex @((New-PUEntry old),(New-PUEntry recent PARTIAL 1));$s=Select-PU $i
        Assert-PU ($s.Reason -ceq 'NO_COMPLETE_USE_LATEST' -and $s.Selected.SessionIdentity.ScanId -ceq 'recent')
    }
    Test-PU 'Completeness does not overwrite limited coverage or source error counters' {
        $i=New-PUIndex @((New-PUEntry complete COMPLETE -Errors 1));$s=Select-PU $i
        Assert-PU ($s.Selected.Source.Collection.Status -ceq 'COMPLETE' -and $s.Selected.Source.Collection.Coverage -ceq 'LIMITED' -and $s.Selected.Source.Collection.Errors -eq 1)
    }
    Test-PU 'Temporal order wins over specificity when timestamps differ' {
        $i=New-PUIndex @((New-PUEntry control COMPLETE),(New-PUEntry device COMPLETE 1 DEVICE));$s=Select-PU $i
        Assert-PU ($s.Selected.SessionIdentity.ScopeType -ceq 'DEVICE' -and $s.Selected.SessionIdentity.ScanId -ceq 'device')
    }
    Test-PU 'Equal timestamps prefer CONTROL then SECTION then DEVICE regardless of manifest order' {
        $a=New-PUEntry a COMPLETE -Scope DEVICE;$b=New-PUEntry z COMPLETE -Scope SECTION;$c=New-PUEntry x COMPLETE
        $s=Select-PU (New-PUIndex @($a,$b,$c));Assert-PU ($s.Selected.SessionIdentity.ScanId -ceq 'x' -and $s.History[1].SessionIdentity.ScopeType -ceq 'SECTION')
    }
    Test-PU 'Ordinal ScanId tie breaking is independent of current culture and manifest order' {
        $i=New-PUIndex @((New-PUEntry i COMPLETE),(New-PUEntry I COMPLETE));$prior=[Threading.Thread]::CurrentThread.CurrentCulture
        try{[Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]'tr-TR';$s=Select-PU $i}
        finally{[Threading.Thread]::CurrentThread.CurrentCulture=$prior}
        Assert-PU ($s.Selected.SessionIdentity.ScanId -ceq 'I')
    }
    Test-PU 'SECTION is exact and retains out-of-scope history explicitly' {
        $i=New-PUIndex @((New-PUEntry section COMPLETE -Scope SECTION),(New-PUEntry control COMPLETE 2),(New-PUEntry device COMPLETE 3 DEVICE));$s=Select-PU $i -Scope SECTION
        Assert-PU ($s.Selected.SessionIdentity.ScanId -ceq 'section' -and @($s.History|Where-Object Eligibility -CEQ OUT_OF_SCOPE).Count -eq 2)
    }
    Test-PU 'DEVICE never manufactures a session from narrower scopes' {
        $i=New-PUIndex @((New-PUEntry control COMPLETE));$s=Select-PU $i -Scope DEVICE
        Assert-PU ($null -eq $s.Selected -and $null -eq $s.LatestAttempt -and $s.Reason -ceq 'NO_ELIGIBLE_SOURCE' -and $s.History.Count -eq 1)
    }
    Test-PU 'Different known families remain separate and excluded family references remain visible' {
        $i=New-PUIndex @((New-PUEntry reviewed COMPLETE -Family PROJECTION),(New-PUEntry candidate PARTIAL 1));$s=Select-PU $i -Family REVIEWED_PROJECTION
        Assert-PU ($s.Selected.Source.Reference.SnapshotSchemaVersion -ceq '2.1.0' -and $s.Selected.SessionIdentity.ScanId -ceq 'reviewed' -and
            $s.History[0].Eligibility -ceq 'OTHER_FAMILY' -and $s.History[0].Source.Reference.SnapshotSchemaVersion -ceq '2.0.0')
    }
    Test-PU 'An empty registered manifest has no fabricated latest attempt or collection' {
        $s=Select-PU (New-PUIndex @());Assert-PU ($s.History.Count -eq 0 -and $null -eq $s.Selected -and $script:reads.Count -eq 0 -and $script:owners -eq 1)
    }
    Test-PU 'Duplicate snapshot identities across sessions are rejected instead of deduplicated' {
        $i=New-PUIndex @((New-PUEntry a COMPLETE -Snapshot ('b'*32)),(New-PUEntry b PARTIAL 1 -Snapshot ('b'*32)))
        Reject-PU {Select-PU $i};Assert-PU ($script:owners -eq 0)
    }
    Test-PU 'One ScanId cannot be reused across contradictory original scopes' {
        $i=New-PUIndex @((New-PUEntry same COMPLETE),(New-PUEntry same PARTIAL 1 SECTION));Reject-PU {Select-PU $i}
    }
    Test-PU 'Case-distinct ScanIds remain distinct across scopes under the ordinal identity contract' {
        $i=New-PUIndex @((New-PUEntry A COMPLETE),(New-PUEntry a COMPLETE -Scope SECTION));$s=Select-PU $i
        Assert-PU ($s.History.Count -eq 2 -and $s.Selected.SessionIdentity.ScanId -ceq 'A')
    }
    Test-PU 'Duplicate session entries and altered index digests remain rejected by the existing index validator' {
        $i=New-PUIndex @((New-PUEntry one));$i.Sessions+=@($i.Sessions[0]);Reject-PU {Select-PU $i}
    }
    Test-PU 'A corrupt latest partial blocks selection of an older complete source' {
        $a=New-PUEntry old COMPLETE;$b=New-PUEntry new PARTIAL 1;$i=New-PUIndex @($a,$b);$script:corrupt[$b.Session.Sources[0].Reference.Identity.SnapshotId]=$true
        Reject-PU {Select-PU $i};Assert-PU ($script:reads.Count -eq 1)
    }
    Test-PU 'Corruption of the preferred older complete source also blocks selection' {
        $a=New-PUEntry old COMPLETE;$b=New-PUEntry new PARTIAL 1;$i=New-PUIndex @($a,$b);$script:corrupt[$a.Session.Sources[0].Reference.Identity.SnapshotId]=$true
        Reject-PU {Select-PU $i};Assert-PU ($script:reads.Count -eq 2)
    }
    Test-PU 'Unconsumed older history is explicitly reference-only rather than falsely physically verified' {
        $i=New-PUIndex @((New-PUEntry older PARTIAL),(New-PUEntry new COMPLETE 1));$s=Select-PU $i
        Assert-PU ($s.History[1].Verification -ceq 'REFERENCE_ONLY' -and $s.History[0].Verification -ceq 'VERIFIED_AT_SELECTION' -and $script:reads.Count -eq 1)
    }
    Test-PU 'Caller mutation after metadata freeze cannot change the selected source' {
        $script:inputIndex=New-PUIndex @((New-PUEntry source COMPLETE));$s=Select-PU $script:inputIndex -Cancel {$script:inputIndex.Sessions=@();$false}
        Assert-PU ($s.Selected.SessionIdentity.ScanId -ceq 'source' -and $script:inputIndex.Sessions.Count -eq 0)
    }
    Test-PU 'Cancellation before ownership acquisition returns no selection' {
        $cancelled=$false;try{$null=Select-PU (New-PUIndex @((New-PUEntry source))) -Cancel {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-PU ($cancelled -and $script:owners -eq 0)
    }
    Test-PU 'Cancellation during physical consumption does not return a partially verified selection' {
        $i=New-PUIndex @((New-PUEntry source));$script:polls=0;$cancelled=$false
        try{$null=Select-PU $i -Cancel {$script:polls++;$script:polls -ge 3}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-PU $cancelled
    }
    foreach($version in @('0.9.0','1.1.0',@('1.0.0'))){Test-PU 'Unknown or non-scalar policy versions reject before I/O' {
        $i=New-PUIndex @((New-PUEntry source))
        Reject-PU {Select-WinSecTechnicalSource $sandbox $i $device DEFENDER_CANDIDATE CONTROL WSA-SYS-001 -PolicyVersion $version};Assert-PU ($script:owners -eq 0)
    }}
    foreach($scopeCase in @(@('UNKNOWN','CONTROL','WSA-SYS-001'),@('DEFENDER_CANDIDATE','SECTION','Other'),@('DEFENDER_CANDIDATE','control','WSA-SYS-001'))){
        Test-PU 'Unknown families or contradictory scopes do not silently widen selection' {
            $i=New-PUIndex @((New-PUEntry source))
            Reject-PU {Select-WinSecTechnicalSource $sandbox $i $device $scopeCase[0] $scopeCase[1] $scopeCase[2]};Assert-PU ($script:owners -eq 0)
        }
    }
    Test-PU 'Unknown preference, foreign device and incompatible source versions are rejected' {
        $i=New-PUIndex @((New-PUEntry source));Reject-PU {Select-PU $i UNKNOWN}
        Reject-PU {Select-WinSecTechnicalSource $sandbox $i ('local:hw1-'+('c'*64)) DEFENDER_CANDIDATE CONTROL WSA-SYS-001}
        $i.Sessions[0].Session.Sources[0].Reference.CollectorVersion='9.0.0';Reject-PU {Select-PU $i}
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awpu-[a-f0-9]{8}\z'){throw 'Unsafe selection unit cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical source selection unit: $passed passed; $failed failed.");if($failed){exit 1}
