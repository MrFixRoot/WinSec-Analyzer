# Candidate pairs in an owned temporary root. No Windows, sockets, DNS or process queries.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/System/PowerShellLoggingTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/PowerShellLoggingTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-CimClass {throw 'Native audit forbidden.'}
function Get-LocalGroupMember {throw 'Native account lookup forbidden.'}
function Get-LocalUser {throw 'Native account lookup forbidden.'}
function Get-WinEvent {throw 'Event contents forbidden.'}
function Get-EventLog {throw 'Event contents forbidden.'}
function Get-History {throw 'User commands forbidden.'}
function Get-ItemProperty {throw 'Registry reads forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('psl-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Accounts/Test-LocalAdmins.ps1','src/Checks/Accounts/LocalAdminsTechnicalCatalog.ps1','src/Checks/Accounts/LocalAdminsTechnicalSnapshot.ps1','src/Checks/Accounts/LocalAdminsTechnicalStorage.ps1','src/Checks/Accounts/IdentityAccessCollector.ps1','src/Core/IdentityAccessTelemetry.ps1','src/Core/IdentityNativeReadOnly.ps1','src/Checks/Accounts/Test-GuestAccount.ps1','src/Checks/Accounts/GuestTechnicalCatalog.ps1','src/Checks/Accounts/GuestTechnicalSnapshot.ps1','src/Checks/Accounts/GuestTechnicalStorage.ps1','src/Checks/Policies/Test-PasswordPolicy.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Network/NetworkConfigurationTechnicalCatalog.ps1','src/Checks/Network/NetworkConfigurationTechnicalSnapshot.ps1','src/Checks/Network/NetworkConfigurationTechnicalStorage.ps1','src/Checks/Network/OpenPortsTechnicalCatalog.ps1','src/Checks/Network/OpenPortsTechnicalSnapshot.ps1','src/Checks/Network/OpenPortsTechnicalStorage.ps1','src/Checks/Network/RdpTechnicalCatalog.ps1','src/Checks/Network/RdpTechnicalSnapshot.ps1','src/Checks/Network/RdpTechnicalStorage.ps1',
    'src/Checks/Network/SmbTechnicalCatalog.ps1','src/Checks/Firewall/FirewallTechnicalCatalog.ps1',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1',
    'src/Checks/Policies/PasswordPolicyTechnicalCatalog.ps1','src/Checks/Policies/PasswordPolicyTechnicalSnapshot.ps1','src/Checks/Policies/PasswordPolicyTechnicalStorage.ps1',
    'src/Checks/System/Test-PowerShellLogging.ps1','src/Checks/Policies/Test-AuditPolicy.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-PowerShellLoggingStorage {param([bool]$Value);if(-not $Value){throw 'PowerShell Logging candidate storage assertion failed.'}}
function Reject-PowerShellLoggingStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PowerShellLoggingStorage $caught}
function Test-PowerShellLoggingStorage {param($CaseName,[scriptblock]$Action);$f=New-WinSecPowerShellLoggingCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-PowerShellLoggingStorage ('JSON and Markdown preserve the same policy readings and original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-LOG-001'};SECTION {'LoggingAuditing'};DEVICE {'ALL'}}
        $p=New-WinSecPowerShellLoggingFixturePackage $f;$saved=Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecPowerShellLoggingCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-PowerShellLoggingStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-PowerShellLoggingStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'HKLM_REGISTRY64_POLICY_FLAGS_ONLY')) -and
            $md.Contains('WinPS.EnableScriptBlockLogging') -and $md.Contains('Core.ScriptBlockPolicyFallback') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('PowerShellLogging_'))
    }}
    Test-PowerShellLoggingStorage 'A collision cannot overwrite either immutable body' {
        $p=New-WinSecPowerShellLoggingFixturePackage $f;$saved=Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-PowerShellLoggingStorage {Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity}
        Assert-PowerShellLoggingStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-PowerShellLoggingStorage 'Partial required policy data remain partial after a committed publication' {
        $f.Sources[1].Data.EnableModuleLogging.Value=$null;$p=New-WinSecPowerShellLoggingFixturePackage $f
        $null=Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecPowerShellLoggingCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PowerShellLoggingStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecPowerShellLoggingFixtureReadings $read.Snapshot WinPS.EnableModuleLogging)[0].State -ceq 'UNKNOWN')
    }
    Test-PowerShellLoggingStorage 'Failed query keeps source timestamps and unknown totals without inventing disabled logging' {
        $f.Sources[1].State='ERROR';$f.Sources[1].Data=$null;$f.Sources[1].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecPowerShellLoggingFixturePackage $f;$null=Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecPowerShellLoggingCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PowerShellLoggingStorage ($read.Snapshot.Collection.Status -ceq 'PARTIAL' -and $read.Snapshot.CollectedAtUTC -ceq $f.Sources[1].CollectedAtUTC -and
            $null -eq ($read.Snapshot.Inventories|Where-Object Id -CEQ WinPS).ReportedRecords -and
            (Get-WinSecPowerShellLoggingFixtureReadings $read.Snapshot WinPS.EnableModuleLogging)[0].State -ceq 'ERROR')
    }
    Test-PowerShellLoggingStorage 'Explicit policy absence and excluded details stay distinct after reload' {
        $f.Sources[3].Data.EnableProtectedEventLogging=[pscustomobject]@{State='NOT_CONFIGURED';Kind=$null;Value=$null}
        $p=New-WinSecPowerShellLoggingFixturePackage $f;$null=Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecPowerShellLoggingCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PowerShellLoggingStorage ((Get-WinSecPowerShellLoggingFixtureReadings $read.Snapshot Protected.EnableProtectedEventLogging)[0].State -ceq 'NOT_CONFIGURED' -and
            (Get-WinSecPowerShellLoggingFixtureReadings $read.Snapshot Capture.EncryptionCertificate)[0].State -ceq 'NOT_COLLECTED' -and
            $read.Snapshot.Collection.Status -ceq 'COMPLETE' -and $read.Snapshot.Collection.Coverage -ceq 'LIMITED')
    }
    Test-PowerShellLoggingStorage 'Foreign devices cannot read an existing pair' {
        $p=New-WinSecPowerShellLoggingFixturePackage $f;$null=Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity
        $other=$f.Identity.PSObject.Copy();$other.DeviceId='local:hw1-'+('c'*64)
        Reject-PowerShellLoggingStorage {Read-WinSecPowerShellLoggingCandidatePair $sandbox $other $p.Snapshot.CollectedAtUTC}
    }
    Test-PowerShellLoggingStorage 'Corruption is rejected without deleting previous history' {
        $p=New-WinSecPowerShellLoggingFixturePackage $f;$saved=Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-PowerShellLoggingStorage {Read-WinSecPowerShellLoggingCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-PowerShellLoggingStorage ((Read-WinSecPowerShellLoggingCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-PowerShellLoggingStorage 'An interrupted pair remains recoverable without presenting a confirmed snapshot' {
        $p=New-WinSecPowerShellLoggingFixturePackage $f;$caught=$false
        try{$null=Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecPowerShellLoggingCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-PowerShellLoggingStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-PowerShellLoggingStorage ((Read-WinSecPowerShellLoggingCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-PowerShellLoggingStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecPowerShellLoggingFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-PowerShellLoggingStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('address','catalog','secret','path')){Test-PowerShellLoggingStorage ('Forged candidates cannot write filesystem data: '+$damage) {
        $p=New-WinSecPowerShellLoggingFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){address {(Get-WinSecPowerShellLoggingFixtureReadings $p.Snapshot Capture.Scope)[0].Value='REMOTE'}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-PowerShellLoggingStorage {Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity}
        Assert-PowerShellLoggingStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-PowerShellLoggingStorage 'Credential values tokens and free personal descriptions never reach either artifact' {
        foreach($name in @('Password','PasswordHash','Token','Credential','OutputDirectory','ModuleNames','CommandLine','UserName','EventContents')){$f.Sources[1].Data|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
        $p=New-WinSecPowerShellLoggingFixturePackage $f;$saved=Write-WinSecPowerShellLoggingCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-PowerShellLoggingStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|PasswordHash|Credential|CommandLine|EventContents')}
    }
    Test-PowerShellLoggingStorage 'Production execution historical models and other candidates stay unchanged without public sessions' {
        foreach($file in $protected){Assert-PowerShellLoggingStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-PowerShellLoggingStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'PowerShellLoggingTechnical')
        Assert-PowerShellLoggingStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
        $checks=(Get-Content (Join-Path $root 'config/checks.json') -Raw|ConvertFrom-Json).checks
        Assert-PowerShellLoggingStorage (-not ($checks|Where-Object checkId -CEQ WSA-LOG-001).execution.enabled -and @($checks|Where-Object {$_.execution.enabled}).Count -eq 11)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Apsl-[a-f0-9]{12}\z'){throw 'Unsafe policy fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("PowerShell Logging candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
