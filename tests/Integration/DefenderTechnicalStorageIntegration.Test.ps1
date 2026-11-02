# Candidate persistence only: own temporary files and captured synthetic data, no Windows audit.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Defender/DefenderTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderTechnicalMemory.ps1')
function Get-MpComputerStatus {throw 'Native audit forbidden.'}
function Get-MpPreference {throw 'Native audit forbidden.'}
function Get-CimInstance {throw 'Native audit forbidden.'}
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $tempParent ('wdt-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$productionPath=Join-Path $root 'src/Checks/Defender/Test-Defender.ps1';$productionHash=(Get-FileHash $productionPath).Hash
$checksPath=Join-Path $root 'config/checks.json';$checksHash=(Get-FileHash $checksPath).Hash
function Assert-DefenderStorage {param([bool]$Value);if(-not $Value){throw 'Defender candidate storage assertion failed.'}}
function Reject-DefenderStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-DefenderStorage $caught}
function Test-DefenderStorage {param($Name,[scriptblock]$Action);$f=New-WinSecDefenderTechnicalFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-DefenderStorage ('Typed CIM capture persists as the same validated JSON/Markdown pair: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-SYS-001'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
        $f=ConvertTo-WinSecDefenderCimFixture $f
        try{$p=New-WinSecDefenderFixturePackage $f}finally{Close-WinSecDefenderCimFixture $f}
        $saved=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity
        $read=Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        $md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-DefenderStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.CollectorVersion -ceq '1.3.0' -and
            (ConvertTo-Json -InputObject $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json -InputObject $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity) -and
            $md -notmatch 'PRIVATE-DEFENDER|CimInstanceProperties|CimSystemProperties')
    }}
    foreach($legacyVersion in @('1.0.0','1.1.0','1.2.0')){Test-DefenderStorage ('Historical candidate collector pairs still render and read without migration: '+$legacyVersion) {
        $p=New-WinSecDefenderFixturePackage $f;$p.Snapshot.CollectorVersion=$legacyVersion
        $saved=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity
        $before=(Get-FileHash $saved.JsonPath).Hash;$read=Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-DefenderStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.CollectorVersion -ceq $legacyVersion -and
            (Get-FileHash $saved.JsonPath).Hash -ceq $before)
    }}
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-DefenderStorage ('One validated source produces the same JSON and Markdown readings with original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-SYS-001'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
        $p=New-WinSecDefenderFixturePackage $f;$saved=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity
        $read=Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-DefenderStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json -InputObject $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json -InputObject $p.Snapshot -Depth 16 -Compress))
        $md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-DefenderStorage ($md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity) -and
            $md -notmatch 'PRIVATE-DEFENDER|PRIVATE-SECRET' -and $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\'))
    }}
    Test-DefenderStorage 'Repeated publication cannot overwrite an immutable pair' {
        $p=New-WinSecDefenderFixturePackage $f;$saved=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity;$before=(Get-FileHash $saved.JsonPath).Hash
        Reject-DefenderStorage {Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity}
        Assert-DefenderStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $before)
    }
    Test-DefenderStorage 'A committed partial snapshot remains partial on recovery reads' {
        $f.Sources[2].Data.AttackSurfaceReductionRules_Ids=$null;$f.Sources[2].Data.AttackSurfaceReductionRules_Actions=$null
        $p=New-WinSecDefenderFixturePackage $f;$null=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity
        $read=Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-DefenderStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and $read.Snapshot.Collection.Coverage -ceq 'LIMITED')
    }
    Test-DefenderStorage 'Other-device reads cannot retrieve an existing pair' {
        $p=New-WinSecDefenderFixturePackage $f;$saved=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity;$before=(Get-FileHash $saved.JsonPath).Hash
        $foreign=$f.Identity.PSObject.Copy();$foreign.DeviceId='local:hw1-'+('c'*64)
        Reject-DefenderStorage {Read-WinSecDefenderTechnicalPair $sandbox $foreign $p.Snapshot.CollectedAtUTC}
        Assert-DefenderStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $before)
    }
    Test-DefenderStorage 'JSON corruption rejects the pair without deleting or rewriting it' {
        $p=New-WinSecDefenderFixturePackage $f;$saved=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try {[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-DefenderStorage {Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-DefenderStorage ((Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-DefenderStorage 'Unreviewed observed values are rejected before filesystem mutation' {
        $p=New-WinSecDefenderFixturePackage $f;(Get-WinSecDefenderFixtureReading $p.Snapshot Status.AMProductVersion).Value='PRIVATE-SECRET'
        $before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        Reject-DefenderStorage {Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity}
        Assert-DefenderStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    Test-DefenderStorage 'A resumable interrupted pair is not a scan completion' {
        $p=New-WinSecDefenderFixturePackage $f;$interrupted=$false
        try{$null=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity -ProgressCallback {param($event);if($event.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$interrupted=$true}
        Assert-DefenderStorage $interrupted
        $read=Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-DefenderStorage ($read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-DefenderStorage ((Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-DefenderStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecDefenderFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-DefenderStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    Test-DefenderStorage 'Candidate imports do not alter the validated collector or execution catalogue' {
        Assert-DefenderStorage ((Get-FileHash $productionPath).Hash -ceq $productionHash -and (Get-FileHash $checksPath).Hash -ceq $checksHash)
        $text=Get-Content -LiteralPath $checksPath -Raw;Assert-DefenderStorage ($text -notmatch 'DefenderTechnical')
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $tempParent -or [IO.Path]::GetFileName($full) -cnotmatch '\Awdt-[a-f0-9]{12}\z'){throw 'Unsafe candidate fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Defender candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
