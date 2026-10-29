# Prepared synthetic data, own temporary files and explicit candidate I/O only.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/BitLocker/BitLockerTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/BitLockerTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Invoke-CimMethod {throw 'Native audit forbidden.'}
function Get-BitLockerVolume {throw 'Native audit forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('wbt-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/BitLocker/Test-BitLocker.ps1','config/checks.json','config/scoring.json','src/Checks/Defender/DefenderTechnicalCatalog.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-BitLockerStorage {param([bool]$Value);if(-not $Value){throw 'BitLocker candidate storage assertion failed.'}}
function Reject-BitLockerStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-BitLockerStorage $caught}
function Test-BitLockerStorage {param($Name,[scriptblock]$Action);$f=New-WinSecBitLockerTechnicalFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-BitLockerStorage ('One normalized capture generates identical JSON and Markdown readings: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-SYS-002'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
        $p=New-WinSecBitLockerFixturePackage $f;$saved=Write-WinSecBitLockerTechnicalPair $sandbox $p $f.Identity
        $read=Read-WinSecBitLockerTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-BitLockerStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress))
        $md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-BitLockerStorage ($md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity) -and
            $md.Contains('Conversion.WipingStatus') -and $md.Contains('HardwareTest.TestError') -and $saved.JsonPath.Contains('\scans\') -and
            $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('BitLocker_'))
    }}
    Test-BitLockerStorage 'Immutable publication rejects collisions and preserves both existing bodies' {
        $p=New-WinSecBitLockerFixturePackage $f;$saved=Write-WinSecBitLockerTechnicalPair $sandbox $p $f.Identity
        $json=(Get-FileHash $saved.JsonPath).Hash;$md=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-BitLockerStorage {Write-WinSecBitLockerTechnicalPair $sandbox $p $f.Identity}
        Assert-BitLockerStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $json -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $md)
    }
    Test-BitLockerStorage 'A saved method failure remains partial and preserves only safe diagnostic codes' {
        $f.Sources[3].Data.ReturnValue=[uint32]2150694912;$p=New-WinSecBitLockerFixturePackage $f
        $null=Write-WinSecBitLockerTechnicalPair $sandbox $p $f.Identity;$read=Read-WinSecBitLockerTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-BitLockerStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecBitLockerFixtureReading $read.Snapshot Conversion.ReturnValue).Value -eq 2150694912 -and
            (Get-WinSecBitLockerFixtureReading $read.Snapshot Conversion.EncryptionPercentage).State -ceq 'ERROR')
    }
    Test-BitLockerStorage 'A foreign device cannot retrieve the saved pair' {
        $p=New-WinSecBitLockerFixturePackage $f;$null=Write-WinSecBitLockerTechnicalPair $sandbox $p $f.Identity
        $foreign=$f.Identity.PSObject.Copy();$foreign.DeviceId='local:hw1-'+('c'*64)
        Reject-BitLockerStorage {Read-WinSecBitLockerTechnicalPair $sandbox $foreign $p.Snapshot.CollectedAtUTC}
    }
    Test-BitLockerStorage 'Corruption is rejected without changing previous history' {
        $p=New-WinSecBitLockerFixturePackage $f;$saved=Write-WinSecBitLockerTechnicalPair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-BitLockerStorage {Read-WinSecBitLockerTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-BitLockerStorage ((Read-WinSecBitLockerTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-BitLockerStorage 'An interrupted pair is recoverable without exposing a completed scan' {
        $p=New-WinSecBitLockerFixturePackage $f;$caught=$false
        try{$null=Write-WinSecBitLockerTechnicalPair $sandbox $p $f.Identity -ProgressCallback {param($event);if($event.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecBitLockerTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-BitLockerStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-BitLockerStorage ((Read-WinSecBitLockerTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-BitLockerStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecBitLockerFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecBitLockerTechnicalPair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-BitLockerStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('volume','catalog','secret','path')){Test-BitLockerStorage ('Invalid candidate package is rejected before filesystem mutation: '+$damage) {
        $p=New-WinSecBitLockerFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){
            volume {(Get-WinSecBitLockerFixtureReading $p.Snapshot Lock.TargetVolumeId).Value='\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\'}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty RecoveryKey 'PRIVATE-SECRET'}
            path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-BitLockerStorage {Write-WinSecBitLockerTechnicalPair $sandbox $p $f.Identity}
        Assert-BitLockerStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-BitLockerStorage 'Unreviewed fields never enter JSON or Markdown' {
        $f.Sources[4].Data|Add-Member NoteProperty RecoveryKey 'PRIVATE-SECRET'
        $f.Sources[4].Data|Add-Member NoteProperty SelfEncryptionDriveEncryptionMethod 'PRIVATE-SECRET'
        $p=New-WinSecBitLockerFixturePackage $f;$saved=Write-WinSecBitLockerTechnicalPair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-BitLockerStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|RecoveryKey|SelfEncryptionDriveEncryptionMethod')}
    }
    Test-BitLockerStorage 'The candidate does not register production collection or alter other controls' {
        foreach($file in $protected){Assert-BitLockerStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-BitLockerStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'BitLockerTechnical')
        Assert-BitLockerStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Awbt-[a-f0-9]{12}\z'){throw 'Unsafe candidate fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("BitLocker candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
