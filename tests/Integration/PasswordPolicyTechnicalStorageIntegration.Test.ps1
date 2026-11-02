# Candidate pairs in an owned temporary root. No Windows, sockets, DNS or process queries.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Policies/PasswordPolicyTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/PasswordPolicyTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-CimClass {throw 'Native audit forbidden.'}
function Get-LocalGroupMember {throw 'Native account lookup forbidden.'}
function Get-LocalUser {throw 'Native account lookup forbidden.'}
function secedit {throw 'Native export forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('ppt-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Accounts/Test-LocalAdmins.ps1','src/Checks/Accounts/LocalAdminsTechnicalCatalog.ps1','src/Checks/Accounts/LocalAdminsTechnicalSnapshot.ps1','src/Checks/Accounts/LocalAdminsTechnicalStorage.ps1','src/Checks/Accounts/IdentityAccessCollector.ps1','src/Core/IdentityAccessTelemetry.ps1','src/Core/IdentityNativeReadOnly.ps1','src/Checks/Accounts/Test-GuestAccount.ps1','src/Checks/Accounts/GuestTechnicalCatalog.ps1','src/Checks/Accounts/GuestTechnicalSnapshot.ps1','src/Checks/Accounts/GuestTechnicalStorage.ps1','src/Checks/Policies/Test-PasswordPolicy.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Network/NetworkConfigurationTechnicalCatalog.ps1','src/Checks/Network/NetworkConfigurationTechnicalSnapshot.ps1','src/Checks/Network/NetworkConfigurationTechnicalStorage.ps1','src/Checks/Network/OpenPortsTechnicalCatalog.ps1','src/Checks/Network/OpenPortsTechnicalSnapshot.ps1','src/Checks/Network/OpenPortsTechnicalStorage.ps1','src/Checks/Network/RdpTechnicalCatalog.ps1','src/Checks/Network/RdpTechnicalSnapshot.ps1','src/Checks/Network/RdpTechnicalStorage.ps1',
    'src/Checks/Network/SmbTechnicalCatalog.ps1','src/Checks/Firewall/FirewallTechnicalCatalog.ps1',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-PasswordPolicyStorage {param([bool]$Value);if(-not $Value){throw 'Password Policies candidate storage assertion failed.'}}
function Reject-PasswordPolicyStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PasswordPolicyStorage $caught}
function Test-PasswordPolicyStorage {param($CaseName,[scriptblock]$Action);$f=New-WinSecPasswordPolicyCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-PasswordPolicyStorage ('JSON and Markdown preserve the same policy readings and original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-IAM-003'};SECTION {'IdentityAccess'};DEVICE {'ALL'}}
        $p=New-WinSecPasswordPolicyFixturePackage $f;$saved=Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecPasswordPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-PasswordPolicyStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-PasswordPolicyStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'LOCAL_ACCOUNT_POLICY_CONFIGURATION_ONLY')) -and
            $md.Contains('Template.ClearTextPassword') -and $md.Contains('Policy.MaximumAgeSeconds') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('PasswordPolicy_'))
    }}
    Test-PasswordPolicyStorage 'A collision cannot overwrite either immutable body' {
        $p=New-WinSecPasswordPolicyFixturePackage $f;$saved=Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-PasswordPolicyStorage {Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity}
        Assert-PasswordPolicyStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-PasswordPolicyStorage 'Partial required policy data remain partial after a committed publication' {
        $f.Sources[1].Data.Settings.MinimumLength=$null;$p=New-WinSecPasswordPolicyFixturePackage $f
        $null=Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecPasswordPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PasswordPolicyStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecPasswordPolicyFixtureReadings $read.Snapshot Policy.MinimumLength)[0].State -ceq 'UNKNOWN')
    }
    Test-PasswordPolicyStorage 'Failed query keeps source timestamps and native return code' {
        $f.Sources[1].Data.ReturnValue=[uint32]5;$f.Sources[1].Data.Settings=$null;$f.Sources[1].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecPasswordPolicyFixturePackage $f;$null=Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecPasswordPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PasswordPolicyStorage ($read.Snapshot.Collection.Status -ceq 'PARTIAL' -and $read.Snapshot.CollectedAtUTC -ceq $f.Sources[1].CollectedAtUTC -and
            (Get-WinSecPasswordPolicyFixtureReadings $read.Snapshot Policy.ReturnValue)[0].Value -eq 5 -and
            (Get-WinSecPasswordPolicyFixtureReadings $read.Snapshot Policy.MinimumLength)[0].State -ceq 'ERROR')
    }
    Test-PasswordPolicyStorage 'Informational unknown template fields survive without invented defaults' {
        $f.Sources[3].Data.Settings.ClearTextPassword=$null
        $p=New-WinSecPasswordPolicyFixturePackage $f;$null=Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecPasswordPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PasswordPolicyStorage ((Get-WinSecPasswordPolicyFixtureReadings $read.Snapshot Template.ClearTextPassword)[0].State -ceq 'UNKNOWN' -and
            $read.Snapshot.Collection.Status -ceq 'COMPLETE' -and $read.Snapshot.Collection.Coverage -ceq 'LIMITED')
    }
    Test-PasswordPolicyStorage 'Foreign devices cannot read an existing pair' {
        $p=New-WinSecPasswordPolicyFixturePackage $f;$null=Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity
        $other=$f.Identity.PSObject.Copy();$other.DeviceId='local:hw1-'+('c'*64)
        Reject-PasswordPolicyStorage {Read-WinSecPasswordPolicyCandidatePair $sandbox $other $p.Snapshot.CollectedAtUTC}
    }
    Test-PasswordPolicyStorage 'Corruption is rejected without deleting previous history' {
        $p=New-WinSecPasswordPolicyFixturePackage $f;$saved=Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-PasswordPolicyStorage {Read-WinSecPasswordPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-PasswordPolicyStorage ((Read-WinSecPasswordPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-PasswordPolicyStorage 'An interrupted pair remains recoverable without presenting a confirmed snapshot' {
        $p=New-WinSecPasswordPolicyFixturePackage $f;$caught=$false
        try{$null=Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecPasswordPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PasswordPolicyStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-PasswordPolicyStorage ((Read-WinSecPasswordPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-PasswordPolicyStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecPasswordPolicyFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-PasswordPolicyStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('address','catalog','secret','path')){Test-PasswordPolicyStorage ('Forged candidates cannot write filesystem data: '+$damage) {
        $p=New-WinSecPasswordPolicyFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){address {(Get-WinSecPasswordPolicyFixtureReadings $p.Snapshot Capture.ServerTarget)[0].Value='REMOTE'}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-PasswordPolicyStorage {Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity}
        Assert-PasswordPolicyStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-PasswordPolicyStorage 'Credential values tokens and free personal descriptions never reach either artifact' {
        foreach($name in @('Password','PasswordHash','Token','Credential','FullName','Description')){$f.Sources[1].Data.Settings|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
        $p=New-WinSecPasswordPolicyFixturePackage $f;$saved=Write-WinSecPasswordPolicyCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-PasswordPolicyStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|PasswordHash|Credential')}
    }
    Test-PasswordPolicyStorage 'Production execution historical models and other candidates stay unchanged without public sessions' {
        foreach($file in $protected){Assert-PasswordPolicyStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-PasswordPolicyStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'PasswordPolicyTechnical')
        Assert-PasswordPolicyStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Appt-[a-f0-9]{12}\z'){throw 'Unsafe policy fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Password Policies candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
