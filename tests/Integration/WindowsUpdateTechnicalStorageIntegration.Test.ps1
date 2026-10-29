# Candidate persistence: prepared synthetic sources and own temporary files only.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/System/WindowsUpdateTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/WindowsUpdateTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Invoke-CimMethod {throw 'Native audit forbidden.'}
function Get-HotFix {throw 'Native audit forbidden.'}
function Get-Service {throw 'Native audit forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('wut-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/System/Test-WindowsUpdate.ps1','src/Checks/System/WindowsUpdatePolicyReader.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-UpdateStorage {param([bool]$Value);if(-not $Value){throw 'Windows Update candidate storage assertion failed.'}}
function Reject-UpdateStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-UpdateStorage $caught}
function Test-UpdateStorage {param($Name,[scriptblock]$Action);$f=New-WinSecWindowsUpdateTechnicalFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-UpdateStorage ('One source produces identical JSON and Markdown with original identity and scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-SYS-003'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
        $p=New-WinSecWindowsUpdateFixturePackage $f;$saved=Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity
        $read=Read-WinSecWindowsUpdateTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        $md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-UpdateStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-UpdateStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'CBS_QFE_ONLY')) -and $md.Contains('InstalledCBSUpdates.HotFixID') -and $md.Contains('GPOAU.AUOptions') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('WindowsUpdate_'))
    }}
    Test-UpdateStorage 'Collision rejection preserves both existing bodies' {
        $p=New-WinSecWindowsUpdateFixturePackage $f;$saved=Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity
        $json=(Get-FileHash $saved.JsonPath).Hash;$md=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-UpdateStorage {Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity}
        Assert-UpdateStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $json -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $md)
    }
    Test-UpdateStorage 'Committed publication preserves incomplete data and source failure metadata' {
        $f.Sources[6].State='ERROR';$f.Sources[6].Data=$null;$p=New-WinSecWindowsUpdateFixturePackage $f
        $null=Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity;$read=Read-WinSecWindowsUpdateTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-UpdateStorage ($read.Snapshot.Collection.Status -ceq 'PARTIAL' -and $read.Snapshot.Collection.Coverage -ceq 'LIMITED' -and
            (Get-WinSecWindowsUpdateFixtureReadings $read.Snapshot Capture.InstalledCBSUpdatesState)[0].Value -ceq 'ERROR')
    }
    Test-UpdateStorage 'An empty QFE inventory retains its documented coverage limit after reading' {
        $f=New-WinSecWindowsUpdateTechnicalFixture 0;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N')
        $p=New-WinSecWindowsUpdateFixturePackage $f;$null=Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity
        $read=Read-WinSecWindowsUpdateTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-UpdateStorage ((Get-WinSecWindowsUpdateFixtureReadings $read.Snapshot Capture.InstalledInventoryScope)[0].Value -ceq 'CBS_QFE_ONLY' -and
            @(Get-WinSecWindowsUpdateFixtureReadings $read.Snapshot InstalledCBSUpdates.HotFixID).Count -eq 0)
    }
    Test-UpdateStorage 'Foreign device identity cannot retrieve a saved pair' {
        $p=New-WinSecWindowsUpdateFixturePackage $f;$null=Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity
        $foreign=$f.Identity.PSObject.Copy();$foreign.DeviceId='local:hw1-'+('c'*64)
        Reject-UpdateStorage {Read-WinSecWindowsUpdateTechnicalPair $sandbox $foreign $p.Snapshot.CollectedAtUTC}
    }
    Test-UpdateStorage 'Corruption is rejected without destroying previous history' {
        $p=New-WinSecWindowsUpdateFixturePackage $f;$saved=Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-UpdateStorage {Read-WinSecWindowsUpdateTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-UpdateStorage ((Read-WinSecWindowsUpdateTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-UpdateStorage 'An interrupted pair stays recoverable until explicit verified recovery' {
        $p=New-WinSecWindowsUpdateFixturePackage $f;$caught=$false
        try{$null=Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity -ProgressCallback {param($event);if($event.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecWindowsUpdateTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-UpdateStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-UpdateStorage ((Read-WinSecWindowsUpdateTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-UpdateStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecWindowsUpdateFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-UpdateStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('scope','catalog','secret','path')){Test-UpdateStorage ('A forged package cannot publish files: '+$damage) {
        $p=New-WinSecWindowsUpdateFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){scope {(Get-WinSecWindowsUpdateFixtureReadings $p.Snapshot Capture.InstalledInventoryScope)[0].Value='ALL_UPDATES'}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-UpdateStorage {Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity}
        Assert-UpdateStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-UpdateStorage 'Only reviewed data enter JSON and Markdown without installer identities or WSUS URLs' {
        $f.Sources[3].Data|Add-Member NoteProperty WUServer 'https://PRIVATE-SECRET'
        $f.Sources[6].Data[0]|Add-Member NoteProperty InstalledBy 'PRIVATE-SECRET'
        $p=New-WinSecWindowsUpdateFixturePackage $f;$saved=Write-WinSecWindowsUpdateTechnicalPair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-UpdateStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|InstalledBy')}
    }
    Test-UpdateStorage 'Candidate imports preserve production and do not register a public session' {
        foreach($file in $protected){Assert-UpdateStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-UpdateStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'WindowsUpdateTechnical')
        Assert-UpdateStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Awut-[a-f0-9]{12}\z'){throw 'Unsafe candidate fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Windows Update candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
