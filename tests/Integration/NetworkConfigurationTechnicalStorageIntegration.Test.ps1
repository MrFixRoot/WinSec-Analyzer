# Candidate pairs in an owned temporary root. No Windows, sockets, DNS or process queries.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Network/NetworkConfigurationTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/NetworkConfigurationTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-CimClass {throw 'Native audit forbidden.'}
function Get-NetTCPConnection {throw 'Native audit forbidden.'}
function Get-NetUDPEndpoint {throw 'Native audit forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('nct-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Network/Test-NetworkConfiguration.ps1','src/Core/NetworkConfigurationTelemetry.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Network/OpenPortsTechnicalCatalog.ps1','src/Checks/Network/OpenPortsTechnicalSnapshot.ps1','src/Checks/Network/OpenPortsTechnicalStorage.ps1','src/Checks/Network/RdpTechnicalCatalog.ps1','src/Checks/Network/RdpTechnicalSnapshot.ps1','src/Checks/Network/RdpTechnicalStorage.ps1',
    'src/Checks/Network/SmbTechnicalCatalog.ps1','src/Checks/Firewall/FirewallTechnicalCatalog.ps1',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-NetworkStorage {param([bool]$Value);if(-not $Value){throw 'Network Configuration candidate storage assertion failed.'}}
function Reject-NetworkStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-NetworkStorage $caught}
function Test-NetworkStorage {param($Name,[scriptblock]$Action);$f=New-WinSecNetworkCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-NetworkStorage ('JSON and Markdown preserve the same network readings and original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-NET-005'};SECTION {'NetworkSecurity'};DEVICE {'ALL'}}
        $p=New-WinSecNetworkFixturePackage $f;$saved=Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecNetworkCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-NetworkStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-NetworkStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'LOCAL_CONFIGURATION_NO_TRAFFIC_OR_RESOLUTION')) -and
            $md.Contains((ConvertTo-WinSecSnapshotMarkdownCell '192.0.2.53')) -and $md.Contains('18446744073709551615') -and $md.Contains('DNSServer.ServerAddresses') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('NetworkConfiguration_'))
    }}
    Test-NetworkStorage 'A collision cannot overwrite either immutable body' {
        $p=New-WinSecNetworkFixturePackage $f;$saved=Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-NetworkStorage {Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity}
        Assert-NetworkStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-NetworkStorage 'Partial network data remain partial after a committed publication' {
        ($f.Sources|Where-Object SourceId -CEQ Profile).Data[0].NetworkCategory=[uint32]99;$p=New-WinSecNetworkFixturePackage $f
        $null=Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecNetworkCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-NetworkStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecNetworkFixtureReadings $read.Snapshot Profile.NetworkCategory)[0].Value -eq 99)
    }
    Test-NetworkStorage 'Empty inventories retain source timestamps without inventing a security verdict' {
        $f=New-WinSecNetworkCandidateFixture 0;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');$f.Sources[2].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecNetworkFixturePackage $f;$null=Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecNetworkCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-NetworkStorage ($read.Snapshot.Collection.Status -ceq 'COMPLETE' -and $read.Snapshot.CollectedAtUTC -ceq $f.Sources[2].CollectedAtUTC -and
            @(Get-WinSecNetworkFixtureReadings $read.Snapshot IPAddress.IPAddress).Count -eq 0)
    }
    Test-NetworkStorage 'An explicitly absent registry value survives without inventing policy defaults' {
        ($f.Sources|Where-Object SourceId -CEQ Registry).Data.EnableMulticast=[pscustomobject]@{State='NOT_CONFIGURED';Kind=$null;Value=$null}
        $p=New-WinSecNetworkFixturePackage $f;$null=Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecNetworkCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-NetworkStorage ((Get-WinSecNetworkFixtureReadings $read.Snapshot Registry.EnableMulticast)[0].State -ceq 'NOT_CONFIGURED' -and
            $null -eq (Get-WinSecNetworkFixtureReadings $read.Snapshot Registry.EnableMulticast)[0].Value)
    }
    Test-NetworkStorage 'Foreign devices cannot read an existing pair' {
        $p=New-WinSecNetworkFixturePackage $f;$null=Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity
        $other=$f.Identity.PSObject.Copy();$other.DeviceId='local:hw1-'+('c'*64)
        Reject-NetworkStorage {Read-WinSecNetworkCandidatePair $sandbox $other $p.Snapshot.CollectedAtUTC}
    }
    Test-NetworkStorage 'Corruption is rejected without deleting previous history' {
        $p=New-WinSecNetworkFixturePackage $f;$saved=Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-NetworkStorage {Read-WinSecNetworkCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-NetworkStorage ((Read-WinSecNetworkCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-NetworkStorage 'An interrupted pair remains recoverable without presenting a confirmed snapshot' {
        $p=New-WinSecNetworkFixturePackage $f;$caught=$false
        try{$null=Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecNetworkCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-NetworkStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-NetworkStorage ((Read-WinSecNetworkCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-NetworkStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecNetworkFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-NetworkStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('address','catalog','secret','path')){Test-NetworkStorage ('Forged candidates cannot write filesystem data: '+$damage) {
        $p=New-WinSecNetworkFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){address {(Get-WinSecNetworkFixtureReadings $p.Snapshot DNSServer.ServerAddressesRetainedCount)[0].Value=[uint32]99}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-NetworkStorage {Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity}
        Assert-NetworkStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-NetworkStorage 'Peer addresses process paths and credentials never reach either artifact' {
        foreach($name in @('RemoteAddress','ExecutablePath','Credential','CommandLine')){$f.Sources[1].Data[0]|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
        $p=New-WinSecNetworkFixturePackage $f;$saved=Write-WinSecNetworkCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-NetworkStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|RemoteAddress|ExecutablePath|CommandLine')}
    }
    Test-NetworkStorage 'Production execution historical models and other candidates stay unchanged without public sessions' {
        foreach($file in $protected){Assert-NetworkStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-NetworkStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'NetworkConfigurationTechnical')
        Assert-NetworkStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Anct-[a-f0-9]{12}\z'){throw 'Unsafe network fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Network Configuration candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
