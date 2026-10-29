# Candidate pairs in an owned temporary root. No Windows, sockets, DNS or process queries.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Services/WindowsServicesTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/WindowsServicesTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-CimClass {throw 'Native audit forbidden.'}
function Get-LocalGroupMember {throw 'Native account lookup forbidden.'}
function Get-LocalUser {throw 'Native account lookup forbidden.'}
function Get-WinEvent {throw 'Event contents forbidden.'}
function Get-EventLog {throw 'Event contents forbidden.'}
function Get-History {throw 'User commands forbidden.'}
function Get-ItemProperty {throw 'Registry reads forbidden.'}
function auditpol {throw 'Native audit configuration query forbidden.'}
function Get-Service {throw 'Native service enumeration forbidden.'}
function Start-Service {throw 'Service control forbidden.'}
function Stop-Service {throw 'Service control forbidden.'}
function Set-Service {throw 'Service control forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('svc-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Accounts/Test-LocalAdmins.ps1','src/Checks/Accounts/LocalAdminsTechnicalCatalog.ps1','src/Checks/Accounts/LocalAdminsTechnicalSnapshot.ps1','src/Checks/Accounts/LocalAdminsTechnicalStorage.ps1','src/Checks/Accounts/IdentityAccessCollector.ps1','src/Core/IdentityAccessTelemetry.ps1','src/Core/IdentityNativeReadOnly.ps1','src/Checks/Accounts/Test-GuestAccount.ps1','src/Checks/Accounts/GuestTechnicalCatalog.ps1','src/Checks/Accounts/GuestTechnicalSnapshot.ps1','src/Checks/Accounts/GuestTechnicalStorage.ps1','src/Checks/Policies/Test-PasswordPolicy.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Network/NetworkConfigurationTechnicalCatalog.ps1','src/Checks/Network/NetworkConfigurationTechnicalSnapshot.ps1','src/Checks/Network/NetworkConfigurationTechnicalStorage.ps1','src/Checks/Network/OpenPortsTechnicalCatalog.ps1','src/Checks/Network/OpenPortsTechnicalSnapshot.ps1','src/Checks/Network/OpenPortsTechnicalStorage.ps1','src/Checks/Network/RdpTechnicalCatalog.ps1','src/Checks/Network/RdpTechnicalSnapshot.ps1','src/Checks/Network/RdpTechnicalStorage.ps1',
    'src/Checks/Network/SmbTechnicalCatalog.ps1','src/Checks/Firewall/FirewallTechnicalCatalog.ps1',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1',
    'src/Checks/Policies/PasswordPolicyTechnicalCatalog.ps1','src/Checks/Policies/PasswordPolicyTechnicalSnapshot.ps1','src/Checks/Policies/PasswordPolicyTechnicalStorage.ps1',
    'src/Checks/System/Test-PowerShellLogging.ps1','src/Checks/Policies/Test-AuditPolicy.ps1',
    'src/Checks/System/PowerShellLoggingTechnicalCatalog.ps1','src/Checks/System/PowerShellLoggingTechnicalSnapshot.ps1','src/Checks/System/PowerShellLoggingTechnicalStorage.ps1',
    'src/Checks/Policies/AuditPolicyTechnicalCatalog.ps1','src/Checks/Policies/AuditPolicyTechnicalSnapshot.ps1','src/Checks/Policies/AuditPolicyTechnicalStorage.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-WindowsServicesStorage {param([bool]$Value);if(-not $Value){throw 'Windows Services candidate storage assertion failed.'}}
function Reject-WindowsServicesStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WindowsServicesStorage $caught}
function Test-WindowsServicesStorage {param($CaseName,[scriptblock]$Action);$f=New-WinSecWindowsServicesCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-WindowsServicesStorage ('JSON and Markdown preserve the same policy readings and original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-HRD-001'};SECTION {'ServicesHardening'};DEVICE {'ALL'}}
        $p=New-WinSecWindowsServicesFixturePackage $f;$saved=Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecWindowsServicesCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-WindowsServicesStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-WindowsServicesStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'LOCAL_WIN32_SERVICE_CONFIGURATION_ONLY')) -and
            $md.Contains('Services.StartMode') -and $md.Contains('Services.WaitHintMilliseconds') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('WindowsServices_'))
    }}
    Test-WindowsServicesStorage 'A collision cannot overwrite either immutable body' {
        $p=New-WinSecWindowsServicesFixturePackage $f;$saved=Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-WindowsServicesStorage {Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity}
        Assert-WindowsServicesStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-WindowsServicesStorage 'Partial required policy data remain partial after a committed publication' {
        $f.Sources[1].Data[0].Started=$null;$p=New-WinSecWindowsServicesFixturePackage $f
        $null=Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecWindowsServicesCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-WindowsServicesStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecWindowsServicesFixtureReadings $read.Snapshot Services.Started)[0].State -ceq 'UNKNOWN')
    }
    Test-WindowsServicesStorage 'Failed enumeration keeps source timestamps and unknown counts without invented absence' {
        $f.Sources[1].State='ERROR';$f.Sources[1].Data=$null;$f.Sources[1].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecWindowsServicesFixturePackage $f;$null=Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecWindowsServicesCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-WindowsServicesStorage ($read.Snapshot.Collection.Status -ceq 'PARTIAL' -and $read.Snapshot.CollectedAtUTC -ceq $f.Sources[1].CollectedAtUTC -and
            $null -eq ($read.Snapshot.Inventories|Where-Object Id -CEQ Services).ReportedRecords -and
            @(Get-WinSecWindowsServicesFixtureReadings $read.Snapshot Services.State).Count -eq 0)
    }
    Test-WindowsServicesStorage 'Identifiable names are escaped in Markdown while excluded account details remain absent' {
        $name='Service '+[char]0xE9+' | <tag> $literal';$f.Sources[1].Data[0].Name=$name
        $p=New-WinSecWindowsServicesFixturePackage $f;$saved=Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecWindowsServicesCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-WindowsServicesStorage ((Get-WinSecWindowsServicesFixtureReadings $read.Snapshot Services.Name)[0].Value -ceq $name -and
            (Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8).Contains((ConvertTo-WinSecSnapshotMarkdownCell $name)) -and
            (Get-WinSecWindowsServicesFixtureReadings $read.Snapshot Capture.ServiceAccounts)[0].State -ceq 'NOT_COLLECTED' -and
            $read.Snapshot.Collection.Status -ceq 'COMPLETE' -and $read.Snapshot.Collection.Coverage -ceq 'LIMITED')
    }
    Test-WindowsServicesStorage 'Foreign devices cannot read an existing pair' {
        $p=New-WinSecWindowsServicesFixturePackage $f;$null=Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity
        $other=$f.Identity.PSObject.Copy();$other.DeviceId='local:hw1-'+('c'*64)
        Reject-WindowsServicesStorage {Read-WinSecWindowsServicesCandidatePair $sandbox $other $p.Snapshot.CollectedAtUTC}
    }
    Test-WindowsServicesStorage 'Corruption is rejected without deleting previous history' {
        $p=New-WinSecWindowsServicesFixturePackage $f;$saved=Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-WindowsServicesStorage {Read-WinSecWindowsServicesCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-WindowsServicesStorage ((Read-WinSecWindowsServicesCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-WindowsServicesStorage 'An interrupted pair remains recoverable without presenting a confirmed snapshot' {
        $p=New-WinSecWindowsServicesFixturePackage $f;$caught=$false
        try{$null=Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecWindowsServicesCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-WindowsServicesStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-WindowsServicesStorage ((Read-WinSecWindowsServicesCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-WindowsServicesStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecWindowsServicesFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-WindowsServicesStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('address','catalog','secret','path')){Test-WindowsServicesStorage ('Forged candidates cannot write filesystem data: '+$damage) {
        $p=New-WinSecWindowsServicesFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){address {(Get-WinSecWindowsServicesFixtureReadings $p.Snapshot Capture.Scope)[0].Value='REMOTE'}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-WindowsServicesStorage {Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity}
        Assert-WindowsServicesStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-WindowsServicesStorage 'Credential values tokens and free personal descriptions never reach either artifact' {
        foreach($name in @('Password','PasswordHash','Token','Credential','PathName','StartName','Description','DisplayName','SecurityDescriptor')){$f.Sources[1].Data[0]|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
        $p=New-WinSecWindowsServicesFixturePackage $f;$saved=Write-WinSecWindowsServicesCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-WindowsServicesStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|PasswordHash|Credential|Services\.PathName|Services\.StartName|Services\.Description|Services\.DisplayName|Services\.SecurityDescriptor')}
        foreach($id in @('Capture.BinaryCommandLine','Capture.ServiceAccounts','Capture.SecurityDescriptors')){
            $reading=(Get-WinSecWindowsServicesFixtureReadings $p.Snapshot $id)[0]
            Assert-WindowsServicesStorage ($reading.State -ceq 'NOT_COLLECTED' -and $null -eq $reading.Value)
        }
    }
    Test-WindowsServicesStorage 'Production execution historical models and other candidates stay unchanged without public sessions' {
        foreach($file in $protected){Assert-WindowsServicesStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-WindowsServicesStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'WindowsServicesTechnical')
        Assert-WindowsServicesStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
        $checks=(Get-Content (Join-Path $root 'config/checks.json') -Raw|ConvertFrom-Json).checks
        Assert-WindowsServicesStorage (-not ($checks|Where-Object checkId -CEQ WSA-HRD-001).execution.enabled -and @($checks|Where-Object {$_.execution.enabled}).Count -eq 11)
        Assert-WindowsServicesStorage (($checks|Where-Object checkId -CEQ WSA-HRD-001).implementationStatus -ceq 'PLANNED' -and -not (Test-Path (Join-Path $root 'src/Checks/Services/Test-WindowsServices.ps1')))
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Asvc-[a-f0-9]{12}\z'){throw 'Unsafe policy fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Windows Services candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
