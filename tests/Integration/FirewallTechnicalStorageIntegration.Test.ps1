# Candidate I/O in own temporary roots; no native Firewall or network calls.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Firewall/FirewallTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/FirewallTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-NetFirewallRule {throw 'Native audit forbidden.'}
function Get-NetFirewallPortFilter {throw 'Native audit forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('fwt-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Firewall/Test-Firewall.ps1','src/Core/FirewallTelemetry.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-FirewallStorage {param([bool]$Value);if(-not $Value){throw 'Firewall candidate storage assertion failed.'}}
function Reject-FirewallStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-FirewallStorage $caught}
function Test-FirewallStorage {param($Name,[scriptblock]$Action);$f=New-WinSecFirewallCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-FirewallStorage ('JSON and Markdown preserve the same sources, links and scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-NET-001'};SECTION {'NetworkSecurity'};DEVICE {'ALL'}}
        $p=New-WinSecFirewallFixturePackage $f;$saved=Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecFirewallCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-FirewallStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-FirewallStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'HOST_PROFILES_RULES_PORTS_ASSOCIATIONS')) -and
            $md.Contains('ActiveLinks.RuleInstanceID') -and $md.Contains('PersistentPorts.LocalPort') -and $saved.JsonPath.Contains('\scans\') -and
            $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('Firewall_'))
    }}
    Test-FirewallStorage 'A collision preserves both immutable bodies' {
        $p=New-WinSecFirewallFixturePackage $f;$saved=Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-FirewallStorage {Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity}
        Assert-FirewallStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-FirewallStorage 'Orphan associations survive publication as partial without inventing a match' {
        $f.Sources[4].Data[0].FilterInstanceID='Missing';$p=New-WinSecFirewallFixturePackage $f
        $null=Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecFirewallCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-FirewallStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecFirewallFixtureReadings $read.Snapshot ActiveLinks.FilterInstanceID)[0].Value -ceq 'Missing')
    }
    Test-FirewallStorage 'Empty rule inventories retain their exact subset scope and source timestamps' {
        $f=New-WinSecFirewallCandidateFixture 0;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');$f.Sources[4].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecFirewallFixturePackage $f;$null=Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecFirewallCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-FirewallStorage ($read.Snapshot.CollectedAtUTC -ceq $f.Sources[4].CollectedAtUTC -and
            @(Get-WinSecFirewallFixtureReadings $read.Snapshot ActiveRules.InstanceID).Count -eq 0)
    }
    Test-FirewallStorage 'Other device identities cannot read a saved pair' {
        $p=New-WinSecFirewallFixturePackage $f;$null=Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity
        $foreign=$f.Identity.PSObject.Copy();$foreign.DeviceId='local:hw1-'+('c'*64)
        Reject-FirewallStorage {Read-WinSecFirewallCandidatePair $sandbox $foreign $p.Snapshot.CollectedAtUTC}
    }
    Test-FirewallStorage 'Corruption is rejected without removing old history' {
        $p=New-WinSecFirewallFixturePackage $f;$saved=Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-FirewallStorage {Read-WinSecFirewallCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-FirewallStorage ((Read-WinSecFirewallCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-FirewallStorage 'An interrupted publication remains recoverable without exposing a committed snapshot' {
        $p=New-WinSecFirewallFixturePackage $f;$caught=$false
        try{$null=Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecFirewallCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-FirewallStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-FirewallStorage ((Read-WinSecFirewallCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-FirewallStorage 'Cancellation before publication does not create files' {
        $p=New-WinSecFirewallFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-FirewallStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('association','catalog','secret','path')){Test-FirewallStorage ('A forged candidate cannot publish filesystem data: '+$damage) {
        $p=New-WinSecFirewallFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){association {(Get-WinSecFirewallFixtureReadings $p.Snapshot ActiveLinks.FilterInstanceID)[0].Value='Missing'}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-FirewallStorage {Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity}
        Assert-FirewallStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-FirewallStorage 'Unreviewed text and paths never enter JSON or Markdown' {
        $f.Sources[2].Data[0]|Add-Member NoteProperty Owner 'PRIVATE-SECRET'
        $f.Sources[1].Data[0]|Add-Member NoteProperty LogFileName 'C:\PRIVATE-SECRET'
        $p=New-WinSecFirewallFixturePackage $f;$saved=Write-WinSecFirewallCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-FirewallStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|LogFileName')}
    }
    Test-FirewallStorage 'Production, historical models and the other candidates stay unchanged' {
        foreach($file in $protected){Assert-FirewallStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-FirewallStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'FirewallTechnical')
        Assert-FirewallStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Afwt-[a-f0-9]{12}\z'){throw 'Unsafe Firewall fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Firewall candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
