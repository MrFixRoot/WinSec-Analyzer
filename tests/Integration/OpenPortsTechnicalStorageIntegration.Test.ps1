# Candidate pairs in an owned temporary root. No Windows, sockets, DNS or process queries.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Network/OpenPortsTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/OpenPortsTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-CimClass {throw 'Native audit forbidden.'}
function Get-NetTCPConnection {throw 'Native audit forbidden.'}
function Get-NetUDPEndpoint {throw 'Native audit forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('opt-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Network/Test-OpenPorts.ps1','src/Core/OpenPortsTelemetry.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Network/RdpTechnicalCatalog.ps1','src/Checks/Network/RdpTechnicalSnapshot.ps1','src/Checks/Network/RdpTechnicalStorage.ps1',
    'src/Checks/Network/SmbTechnicalCatalog.ps1','src/Checks/Firewall/FirewallTechnicalCatalog.ps1',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-PortsStorage {param([bool]$Value);if(-not $Value){throw 'Open Ports candidate storage assertion failed.'}}
function Reject-PortsStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PortsStorage $caught}
function Test-PortsStorage {param($Name,[scriptblock]$Action);$f=New-WinSecOpenPortsCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-PortsStorage ('JSON and Markdown preserve the same endpoint readings and original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-NET-004'};SECTION {'NetworkSecurity'};DEVICE {'ALL'}}
        $p=New-WinSecOpenPortsFixturePackage $f;$saved=Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecOpenPortsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-PortsStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-PortsStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'PASSIVE_TCP_LISTEN_UDP_BINDINGS_NO_PEERS')) -and
            $md.Contains('FE80:0:0:0:0:0:0:1%5') -and $md.Contains('TCP.CreationTimeBasis') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('OpenPorts_'))
    }}
    Test-PortsStorage 'A collision cannot overwrite either immutable body' {
        $p=New-WinSecOpenPortsFixturePackage $f;$saved=Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-PortsStorage {Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity}
        Assert-PortsStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-PortsStorage 'Partial endpoint data remain partial after a committed publication' {
        $f.Sources[1].Data[0].LocalPort=[uint16]0;$p=New-WinSecOpenPortsFixturePackage $f
        $null=Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecOpenPortsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PortsStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecOpenPortsFixtureReadings $read.Snapshot TCP.LocalPort)[0].Value -eq 0)
    }
    Test-PortsStorage 'Empty inventories retain source timestamps without inventing a security verdict' {
        $f=New-WinSecOpenPortsCandidateFixture 0;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');$f.Sources[2].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecOpenPortsFixturePackage $f;$null=Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecOpenPortsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PortsStorage ($read.Snapshot.Collection.Status -ceq 'COMPLETE' -and $read.Snapshot.CollectedAtUTC -ceq $f.Sources[2].CollectedAtUTC -and
            @(Get-WinSecOpenPortsFixtureReadings $read.Snapshot TCP.LocalAddress).Count -eq 0)
    }
    Test-PortsStorage 'Local wall-clock readings and their explicit basis survive without conversion to UTC' {
        $f.Sources[1].Data[0].CreationTime=[datetime]::SpecifyKind([datetime]'2026-10-29T01:00:00',[DateTimeKind]::Local)
        $p=New-WinSecOpenPortsFixturePackage $f;$null=Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecOpenPortsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PortsStorage ((Get-WinSecOpenPortsFixtureReadings $read.Snapshot TCP.CreationTime)[0].Value -ceq '2026-10-29T01:00:00.0000000' -and
            (Get-WinSecOpenPortsFixtureReadings $read.Snapshot TCP.CreationTimeBasis)[0].Value -ceq 'LOCAL')
    }
    Test-PortsStorage 'Foreign devices cannot read an existing pair' {
        $p=New-WinSecOpenPortsFixturePackage $f;$null=Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity
        $other=$f.Identity.PSObject.Copy();$other.DeviceId='local:hw1-'+('c'*64)
        Reject-PortsStorage {Read-WinSecOpenPortsCandidatePair $sandbox $other $p.Snapshot.CollectedAtUTC}
    }
    Test-PortsStorage 'Corruption is rejected without deleting previous history' {
        $p=New-WinSecOpenPortsFixturePackage $f;$saved=Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-PortsStorage {Read-WinSecOpenPortsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-PortsStorage ((Read-WinSecOpenPortsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-PortsStorage 'An interrupted pair remains recoverable without presenting a confirmed snapshot' {
        $p=New-WinSecOpenPortsFixturePackage $f;$caught=$false
        try{$null=Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecOpenPortsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PortsStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-PortsStorage ((Read-WinSecOpenPortsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-PortsStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecOpenPortsFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-PortsStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('address','catalog','secret','path')){Test-PortsStorage ('Forged candidates cannot write filesystem data: '+$damage) {
        $p=New-WinSecOpenPortsFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){address {(Get-WinSecOpenPortsFixtureReadings $p.Snapshot TCP.LocalAddressCanonical)[0].Value='192.0.2.11'}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-PortsStorage {Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity}
        Assert-PortsStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-PortsStorage 'Peer addresses process paths and credentials never reach either artifact' {
        foreach($name in @('RemoteAddress','ExecutablePath','Credential','CommandLine')){$f.Sources[1].Data[0]|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
        $p=New-WinSecOpenPortsFixturePackage $f;$saved=Write-WinSecOpenPortsCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-PortsStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|RemoteAddress|ExecutablePath|CommandLine')}
    }
    Test-PortsStorage 'Production execution historical models and other candidates stay unchanged without public sessions' {
        foreach($file in $protected){Assert-PortsStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-PortsStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'OpenPortsTechnical')
        Assert-PortsStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Aopt-[a-f0-9]{12}\z'){throw 'Unsafe endpoint fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Open Ports candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
