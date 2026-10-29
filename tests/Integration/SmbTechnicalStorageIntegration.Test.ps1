# Candidate I/O in an owned disposable root. No native SMB queries or real history.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Network/SmbTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/SmbTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-SmbServerConfiguration {throw 'Native audit forbidden.'}
function Get-SmbClientConfiguration {throw 'Native audit forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('smt-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Network/Test-SMBv1.ps1','src/Core/SmbTelemetry.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Firewall/FirewallTechnicalCatalog.ps1','src/Checks/Firewall/FirewallTechnicalSnapshot.ps1','src/Checks/Firewall/FirewallTechnicalStorage.ps1',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-SmbStorage {param([bool]$Value);if(-not $Value){throw 'SMB candidate storage assertion failed.'}}
function Reject-SmbStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SmbStorage $caught}
function Test-SmbStorage {param($Name,[scriptblock]$Action);$f=New-WinSecSmbCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-SmbStorage ('JSON and Markdown preserve all normalized SMB readings and scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-NET-002'};SECTION {'NetworkSecurity'};DEVICE {'ALL'}}
        $p=New-WinSecSmbFixturePackage $f;$saved=Write-WinSecSmbCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecSmbCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-SmbStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-SmbStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'LOCAL_CONFIGURATION_NO_NEGOTIATED_SESSIONS')) -and
            $md.Contains('Registry.ClientDependencies') -and $md.Contains('Features.InstallationState') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('SMBv1_'))
    }}
    Test-SmbStorage 'Collisions preserve both immutable bodies' {
        $p=New-WinSecSmbFixturePackage $f;$saved=Write-WinSecSmbCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-SmbStorage {Write-WinSecSmbCandidatePair $sandbox $p $f.Identity}
        Assert-SmbStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-SmbStorage 'A published unknown installation state remains partial with its native code' {
        $f.Sources[3].Data[0].InstallState=[uint32]4;$p=New-WinSecSmbFixturePackage $f
        $null=Write-WinSecSmbCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecSmbCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-SmbStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecSmbFixtureReadings $read.Snapshot Features.InstallState)[0].Value -eq 4 -and
            (Get-WinSecSmbFixtureReadings $read.Snapshot Features.InstallationState)[0].Value -ceq 'UNKNOWN')
    }
    Test-SmbStorage 'Dependencies above the old count limit survive both artifacts without hashing or deduplication' {
        $f.Sources[5].Data.ClientDependencies.Value=@('MRxSMB10')*129;$f.Sources[5].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecSmbFixturePackage $f;$saved=Write-WinSecSmbCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecSmbCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-SmbStorage ((Get-WinSecSmbFixtureReadings $read.Snapshot Registry.ClientDependencies)[0].Value.Count -eq 129 -and
            $read.Snapshot.CollectedAtUTC -ceq $f.Sources[5].CollectedAtUTC -and (Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8).Contains('MRxSMB10'))
    }
    Test-SmbStorage 'Other devices cannot read a saved pair' {
        $p=New-WinSecSmbFixturePackage $f;$null=Write-WinSecSmbCandidatePair $sandbox $p $f.Identity
        $foreign=$f.Identity.PSObject.Copy();$foreign.DeviceId='local:hw1-'+('c'*64)
        Reject-SmbStorage {Read-WinSecSmbCandidatePair $sandbox $foreign $p.Snapshot.CollectedAtUTC}
    }
    Test-SmbStorage 'Corruption is rejected without deleting previous history' {
        $p=New-WinSecSmbFixturePackage $f;$saved=Write-WinSecSmbCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-SmbStorage {Read-WinSecSmbCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-SmbStorage ((Read-WinSecSmbCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-SmbStorage 'An interrupted pair exposes no committed snapshot until explicit validated recovery' {
        $p=New-WinSecSmbFixturePackage $f;$caught=$false
        try{$null=Write-WinSecSmbCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecSmbCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-SmbStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-SmbStorage ((Read-WinSecSmbCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-SmbStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecSmbFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecSmbCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-SmbStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('feature','catalog','secret','path')){Test-SmbStorage ('Forged candidates cannot publish filesystem data: '+$damage) {
        $p=New-WinSecSmbFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){feature {(Get-WinSecSmbFixtureReadings $p.Snapshot Features.InstallationState)[0].Value='ENABLED'}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-SmbStorage {Write-WinSecSmbCandidatePair $sandbox $p $f.Identity}
        Assert-SmbStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-SmbStorage 'Descriptions paths and null session contents are excluded from JSON and Markdown' {
        $f.Sources[1].Data|Add-Member NoteProperty AnnounceComment 'PRIVATE-SECRET'
        $f.Sources[1].Data|Add-Member NoteProperty NullSessionPipes 'PRIVATE-SECRET'
        $f.Sources[4].Data[0]|Add-Member NoteProperty StartName 'PRIVATE-SECRET'
        $p=New-WinSecSmbFixturePackage $f;$saved=Write-WinSecSmbCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-SmbStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|AnnounceComment|NullSessionPipes|StartName')}
    }
    Test-SmbStorage 'Production collectors permissions and other candidates remain unchanged with no public session' {
        foreach($file in $protected){Assert-SmbStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-SmbStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'SmbTechnical')
        Assert-SmbStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Asmt-[a-f0-9]{12}\z'){throw 'Unsafe SMB fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("SMB candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
