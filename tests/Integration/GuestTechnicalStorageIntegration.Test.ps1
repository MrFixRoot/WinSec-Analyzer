# Candidate pairs in an owned temporary root. No Windows, sockets, DNS or process queries.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Accounts/GuestTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/GuestTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-CimClass {throw 'Native audit forbidden.'}
function Get-LocalGroupMember {throw 'Native account lookup forbidden.'}
function Get-LocalUser {throw 'Native account lookup forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('gst-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Accounts/Test-LocalAdmins.ps1','src/Checks/Accounts/LocalAdminsTechnicalCatalog.ps1','src/Checks/Accounts/LocalAdminsTechnicalSnapshot.ps1','src/Checks/Accounts/LocalAdminsTechnicalStorage.ps1','src/Checks/Accounts/IdentityAccessCollector.ps1','src/Core/IdentityAccessTelemetry.ps1','src/Core/IdentityNativeReadOnly.ps1','src/Checks/Accounts/Test-GuestAccount.ps1','src/Checks/Policies/Test-PasswordPolicy.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Network/NetworkConfigurationTechnicalCatalog.ps1','src/Checks/Network/NetworkConfigurationTechnicalSnapshot.ps1','src/Checks/Network/NetworkConfigurationTechnicalStorage.ps1','src/Checks/Network/OpenPortsTechnicalCatalog.ps1','src/Checks/Network/OpenPortsTechnicalSnapshot.ps1','src/Checks/Network/OpenPortsTechnicalStorage.ps1','src/Checks/Network/RdpTechnicalCatalog.ps1','src/Checks/Network/RdpTechnicalSnapshot.ps1','src/Checks/Network/RdpTechnicalStorage.ps1',
    'src/Checks/Network/SmbTechnicalCatalog.ps1','src/Checks/Firewall/FirewallTechnicalCatalog.ps1',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-GuestStorage {param([bool]$Value);if(-not $Value){throw 'Guest Account candidate storage assertion failed.'}}
function Reject-GuestStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-GuestStorage $caught}
function Test-GuestStorage {param($CaseName,[scriptblock]$Action);$f=New-WinSecGuestCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-GuestStorage ('JSON and Markdown preserve the same local group readings and original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-IAM-002'};SECTION {'IdentityAccess'};DEVICE {'ALL'}}
        $p=New-WinSecGuestFixturePackage $f;$saved=Write-WinSecGuestCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecGuestCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-GuestStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-GuestStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'LOCAL_BUILTIN_GUEST_RID501_ONLY')) -and
            $md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'S-1-5-21-11-22-33-501')) -and $md.Contains('Guest.AccountDomainSID') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('GuestAccount_'))
    }}
    Test-GuestStorage 'A collision cannot overwrite either immutable body' {
        $p=New-WinSecGuestFixturePackage $f;$saved=Write-WinSecGuestCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-GuestStorage {Write-WinSecGuestCandidatePair $sandbox $p $f.Identity}
        Assert-GuestStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-GuestStorage 'Partial local group data remain partial after a committed publication' {
        $f.Sources[1].Data[0].Disabled=$null;$p=New-WinSecGuestFixturePackage $f
        $null=Write-WinSecGuestCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecGuestCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-GuestStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecGuestFixtureReadings $read.Snapshot Guest.Disabled)[0].State -ceq 'UNKNOWN')
    }
    Test-GuestStorage 'An empty account selection keeps source timestamps and partial status without invented presence' {
        $f.Sources[1].Data=@();$f.Sources[1].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecGuestFixturePackage $f;$null=Write-WinSecGuestCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecGuestCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-GuestStorage ($read.Snapshot.Collection.Status -ceq 'PARTIAL' -and $read.Snapshot.CollectedAtUTC -ceq $f.Sources[1].CollectedAtUTC -and
            @(Get-WinSecGuestFixtureReadings $read.Snapshot Guest.Present).Count -eq 0)
    }
    Test-GuestStorage 'Localized account names and informational unknowns survive without account resolution' {
        $name='Invit'+[char]0xE9;$f.Sources[1].Data[0].Name=$name;$f.Sources[1].Data[0].SIDType=$null
        $p=New-WinSecGuestFixturePackage $f;$null=Write-WinSecGuestCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecGuestCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-GuestStorage ((Get-WinSecGuestFixtureReadings $read.Snapshot Guest.Name)[0].Value -ceq $name -and
            (Get-WinSecGuestFixtureReadings $read.Snapshot Guest.SIDType)[0].State -ceq 'UNKNOWN' -and $read.Snapshot.Collection.Coverage -ceq 'LIMITED')
    }
    Test-GuestStorage 'Foreign devices cannot read an existing pair' {
        $p=New-WinSecGuestFixturePackage $f;$null=Write-WinSecGuestCandidatePair $sandbox $p $f.Identity
        $other=$f.Identity.PSObject.Copy();$other.DeviceId='local:hw1-'+('c'*64)
        Reject-GuestStorage {Read-WinSecGuestCandidatePair $sandbox $other $p.Snapshot.CollectedAtUTC}
    }
    Test-GuestStorage 'Corruption is rejected without deleting previous history' {
        $p=New-WinSecGuestFixturePackage $f;$saved=Write-WinSecGuestCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-GuestStorage {Read-WinSecGuestCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-GuestStorage ((Read-WinSecGuestCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-GuestStorage 'An interrupted pair remains recoverable without presenting a confirmed snapshot' {
        $p=New-WinSecGuestFixturePackage $f;$caught=$false
        try{$null=Write-WinSecGuestCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecGuestCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-GuestStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-GuestStorage ((Read-WinSecGuestCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-GuestStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecGuestFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecGuestCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-GuestStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('address','catalog','secret','path')){Test-GuestStorage ('Forged candidates cannot write filesystem data: '+$damage) {
        $p=New-WinSecGuestFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){address {(Get-WinSecGuestFixtureReadings $p.Snapshot Guest.AccountDomainSID)[0].Value='S-1-5-21-44-55-66'}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-GuestStorage {Write-WinSecGuestCandidatePair $sandbox $p $f.Identity}
        Assert-GuestStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-GuestStorage 'Credential values tokens and free personal descriptions never reach either artifact' {
        foreach($name in @('Password','PasswordHash','Token','Credential','FullName','Description')){$f.Sources[1].Data[0]|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
        $p=New-WinSecGuestFixturePackage $f;$saved=Write-WinSecGuestCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-GuestStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|Guest.FullName|PasswordHash|Credential')}
    }
    Test-GuestStorage 'Production execution historical models and other candidates stay unchanged without public sessions' {
        foreach($file in $protected){Assert-GuestStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-GuestStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'GuestTechnical')
        Assert-GuestStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Agst-[a-f0-9]{12}\z'){throw 'Unsafe local group fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Guest Account candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
