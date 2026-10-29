# Candidate pairs in an owned temporary root. No Windows, sockets, DNS or process queries.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Accounts/LocalAdminsTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/LocalAdminsTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-CimClass {throw 'Native audit forbidden.'}
function Get-LocalGroupMember {throw 'Native account lookup forbidden.'}
function Get-LocalUser {throw 'Native account lookup forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('lat-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Accounts/Test-LocalAdmins.ps1','src/Checks/Accounts/IdentityAccessCollector.ps1','src/Core/IdentityAccessTelemetry.ps1','src/Core/IdentityNativeReadOnly.ps1','src/Checks/Accounts/Test-GuestAccount.ps1','src/Checks/Policies/Test-PasswordPolicy.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Network/NetworkConfigurationTechnicalCatalog.ps1','src/Checks/Network/NetworkConfigurationTechnicalSnapshot.ps1','src/Checks/Network/NetworkConfigurationTechnicalStorage.ps1','src/Checks/Network/OpenPortsTechnicalCatalog.ps1','src/Checks/Network/OpenPortsTechnicalSnapshot.ps1','src/Checks/Network/OpenPortsTechnicalStorage.ps1','src/Checks/Network/RdpTechnicalCatalog.ps1','src/Checks/Network/RdpTechnicalSnapshot.ps1','src/Checks/Network/RdpTechnicalStorage.ps1',
    'src/Checks/Network/SmbTechnicalCatalog.ps1','src/Checks/Firewall/FirewallTechnicalCatalog.ps1',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-LocalAdminsStorage {param([bool]$Value);if(-not $Value){throw 'Local Administrators candidate storage assertion failed.'}}
function Reject-LocalAdminsStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-LocalAdminsStorage $caught}
function Test-LocalAdminsStorage {param($CaseName,[scriptblock]$Action);$f=New-WinSecLocalAdminsCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-LocalAdminsStorage ('JSON and Markdown preserve the same local group readings and original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-IAM-001'};SECTION {'IdentityAccess'};DEVICE {'ALL'}}
        $p=New-WinSecLocalAdminsFixturePackage $f;$saved=Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecLocalAdminsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-LocalAdminsStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-LocalAdminsStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'DIRECT_LOCAL_ADMINISTRATORS_MEMBERSHIP_ONLY')) -and
            $md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'S-1-5-21-11-22-33-1000')) -and $md.Contains('Members.PageSequence') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('LocalAdministrators_'))
    }}
    Test-LocalAdminsStorage 'A collision cannot overwrite either immutable body' {
        $p=New-WinSecLocalAdminsFixturePackage $f;$saved=Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-LocalAdminsStorage {Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity}
        Assert-LocalAdminsStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-LocalAdminsStorage 'Partial local group data remain partial after a committed publication' {
        $f.Sources[2].Data.Pages[0].Records[1].SID=$f.Sources[2].Data.Pages[0].Records[0].SID;$p=New-WinSecLocalAdminsFixturePackage $f
        $null=Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecLocalAdminsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-LocalAdminsStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecLocalAdminsFixtureReadings $read.Snapshot Members.SID)[0].Value -ceq (Get-WinSecLocalAdminsFixtureReadings $read.Snapshot Members.SID)[1].Value)
    }
    Test-LocalAdminsStorage 'Empty inventories retain source timestamps without inventing a security verdict' {
        $f=New-WinSecLocalAdminsCandidateFixture 0;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');$f.Sources[2].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecLocalAdminsFixturePackage $f;$null=Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecLocalAdminsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-LocalAdminsStorage ($read.Snapshot.Collection.Status -ceq 'COMPLETE' -and $read.Snapshot.CollectedAtUTC -ceq $f.Sources[2].CollectedAtUTC -and
            @(Get-WinSecLocalAdminsFixtureReadings $read.Snapshot Members.SID).Count -eq 0)
    }
    Test-LocalAdminsStorage 'Localized group names and informational unknowns survive without account resolution' {
        $name=([string][char]0xC9)+'quipe d'+[char]0x2019+'administration';$f.Sources[1].Data.Name=$name;$f.Sources[1].Data.SIDType=$null
        $p=New-WinSecLocalAdminsFixturePackage $f;$null=Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecLocalAdminsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-LocalAdminsStorage ((Get-WinSecLocalAdminsFixtureReadings $read.Snapshot Group.Name)[0].Value -ceq $name -and
            (Get-WinSecLocalAdminsFixtureReadings $read.Snapshot Group.SIDType)[0].State -ceq 'UNKNOWN' -and $read.Snapshot.Collection.Coverage -ceq 'LIMITED')
    }
    Test-LocalAdminsStorage 'Foreign devices cannot read an existing pair' {
        $p=New-WinSecLocalAdminsFixturePackage $f;$null=Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity
        $other=$f.Identity.PSObject.Copy();$other.DeviceId='local:hw1-'+('c'*64)
        Reject-LocalAdminsStorage {Read-WinSecLocalAdminsCandidatePair $sandbox $other $p.Snapshot.CollectedAtUTC}
    }
    Test-LocalAdminsStorage 'Corruption is rejected without deleting previous history' {
        $p=New-WinSecLocalAdminsFixturePackage $f;$saved=Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-LocalAdminsStorage {Read-WinSecLocalAdminsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-LocalAdminsStorage ((Read-WinSecLocalAdminsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-LocalAdminsStorage 'An interrupted pair remains recoverable without presenting a confirmed snapshot' {
        $p=New-WinSecLocalAdminsFixturePackage $f;$caught=$false
        try{$null=Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecLocalAdminsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-LocalAdminsStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-LocalAdminsStorage ((Read-WinSecLocalAdminsCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-LocalAdminsStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecLocalAdminsFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-LocalAdminsStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('address','catalog','secret','path')){Test-LocalAdminsStorage ('Forged candidates cannot write filesystem data: '+$damage) {
        $p=New-WinSecLocalAdminsFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){address {(Get-WinSecLocalAdminsFixtureReadings $p.Snapshot Members.PageSequence)[0].Value=[uint32]99}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-LocalAdminsStorage {Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity}
        Assert-LocalAdminsStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-LocalAdminsStorage 'Member names domains credentials and tokens never reach either artifact' {
        foreach($name in @('Name','Domain','Password','Token','Credential')){$f.Sources[2].Data.Pages[0].Records[0]|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
        $p=New-WinSecLocalAdminsFixturePackage $f;$saved=Write-WinSecLocalAdminsCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-LocalAdminsStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|Members.Name|Members.Domain|Credential')}
    }
    Test-LocalAdminsStorage 'Production execution historical models and other candidates stay unchanged without public sessions' {
        foreach($file in $protected){Assert-LocalAdminsStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-LocalAdminsStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'LocalAdminsTechnical')
        Assert-LocalAdminsStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Alat-[a-f0-9]{12}\z'){throw 'Unsafe local group fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Local Administrators candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
