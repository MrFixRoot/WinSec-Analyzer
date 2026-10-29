# Candidate pairs in an owned temporary root. No Windows, sockets, DNS or process queries.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Policies/AuditPolicyTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/AuditPolicyTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-CimClass {throw 'Native audit forbidden.'}
function Get-LocalGroupMember {throw 'Native account lookup forbidden.'}
function Get-LocalUser {throw 'Native account lookup forbidden.'}
function Get-WinEvent {throw 'Event contents forbidden.'}
function Get-EventLog {throw 'Event contents forbidden.'}
function Get-History {throw 'User commands forbidden.'}
function Get-ItemProperty {throw 'Registry reads forbidden.'}
function auditpol {throw 'Native audit configuration query forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('adt-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Accounts/Test-LocalAdmins.ps1','src/Checks/Accounts/LocalAdminsTechnicalCatalog.ps1','src/Checks/Accounts/LocalAdminsTechnicalSnapshot.ps1','src/Checks/Accounts/LocalAdminsTechnicalStorage.ps1','src/Checks/Accounts/IdentityAccessCollector.ps1','src/Core/IdentityAccessTelemetry.ps1','src/Core/IdentityNativeReadOnly.ps1','src/Checks/Accounts/Test-GuestAccount.ps1','src/Checks/Accounts/GuestTechnicalCatalog.ps1','src/Checks/Accounts/GuestTechnicalSnapshot.ps1','src/Checks/Accounts/GuestTechnicalStorage.ps1','src/Checks/Policies/Test-PasswordPolicy.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Network/NetworkConfigurationTechnicalCatalog.ps1','src/Checks/Network/NetworkConfigurationTechnicalSnapshot.ps1','src/Checks/Network/NetworkConfigurationTechnicalStorage.ps1','src/Checks/Network/OpenPortsTechnicalCatalog.ps1','src/Checks/Network/OpenPortsTechnicalSnapshot.ps1','src/Checks/Network/OpenPortsTechnicalStorage.ps1','src/Checks/Network/RdpTechnicalCatalog.ps1','src/Checks/Network/RdpTechnicalSnapshot.ps1','src/Checks/Network/RdpTechnicalStorage.ps1',
    'src/Checks/Network/SmbTechnicalCatalog.ps1','src/Checks/Firewall/FirewallTechnicalCatalog.ps1',
    'src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1',
    'src/Checks/Policies/PasswordPolicyTechnicalCatalog.ps1','src/Checks/Policies/PasswordPolicyTechnicalSnapshot.ps1','src/Checks/Policies/PasswordPolicyTechnicalStorage.ps1',
    'src/Checks/System/Test-PowerShellLogging.ps1','src/Checks/Policies/Test-AuditPolicy.ps1',
    'src/Checks/System/PowerShellLoggingTechnicalCatalog.ps1','src/Checks/System/PowerShellLoggingTechnicalSnapshot.ps1','src/Checks/System/PowerShellLoggingTechnicalStorage.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-AuditPolicyStorage {param([bool]$Value);if(-not $Value){throw 'Audit Policy candidate storage assertion failed.'}}
function Reject-AuditPolicyStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-AuditPolicyStorage $caught}
function Test-AuditPolicyStorage {param($CaseName,[scriptblock]$Action);$f=New-WinSecAuditPolicyCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-AuditPolicyStorage ('JSON and Markdown preserve the same policy readings and original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-LOG-002'};SECTION {'LoggingAuditing'};DEVICE {'ALL'}}
        $p=New-WinSecAuditPolicyFixturePackage $f;$saved=Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecAuditPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-AuditPolicyStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-AuditPolicyStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'LOCAL_SYSTEM_AUDIT_CONFIGURATION_ONLY')) -and
            $md.Contains('SystemPolicy.AuditingInformation') -and $md.Contains('Requests.AuditSubCategoryGuid') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('AuditPolicy_'))
    }}
    Test-AuditPolicyStorage 'A collision cannot overwrite either immutable body' {
        $p=New-WinSecAuditPolicyFixturePackage $f;$saved=Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-AuditPolicyStorage {Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity}
        Assert-AuditPolicyStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-AuditPolicyStorage 'Partial required policy data remain partial after a committed publication' {
        $f.Sources[4].Data[0].AuditingInformation=$null;$p=New-WinSecAuditPolicyFixturePackage $f
        $null=Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecAuditPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-AuditPolicyStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecAuditPolicyFixtureReadings $read.Snapshot SystemPolicy.AuditingInformation)[0].State -ceq 'UNKNOWN')
    }
    Test-AuditPolicyStorage 'Failed query keeps source timestamps and unknown counts without invented policies' {
        $f.Sources[4].State='ERROR';$f.Sources[4].Data=$null;$f.Sources[4].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecAuditPolicyFixturePackage $f;$null=Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecAuditPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-AuditPolicyStorage ($read.Snapshot.Collection.Status -ceq 'PARTIAL' -and $read.Snapshot.CollectedAtUTC -ceq $f.Sources[4].CollectedAtUTC -and
            $null -eq ($read.Snapshot.Inventories|Where-Object Id -CEQ SystemPolicy).ReportedRecords -and
            @(Get-WinSecAuditPolicyFixtureReadings $read.Snapshot SystemPolicy.AuditingInformation).Count -eq 0)
    }
    Test-AuditPolicyStorage 'Explicit policy absence and excluded details stay distinct after reload' {
        $f.Sources[5].Data.SCENoApplyLegacyAuditPolicy=[pscustomobject]@{State='NOT_CONFIGURED';Kind=$null;Value=$null}
        $p=New-WinSecAuditPolicyFixturePackage $f;$null=Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecAuditPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-AuditPolicyStorage ((Get-WinSecAuditPolicyFixtureReadings $read.Snapshot Options.SCENoApplyLegacyAuditPolicy)[0].State -ceq 'NOT_CONFIGURED' -and
            (Get-WinSecAuditPolicyFixtureReadings $read.Snapshot Capture.PerUserPolicy)[0].State -ceq 'NOT_COLLECTED' -and
            $read.Snapshot.Collection.Status -ceq 'COMPLETE' -and $read.Snapshot.Collection.Coverage -ceq 'LIMITED')
    }
    Test-AuditPolicyStorage 'Foreign devices cannot read an existing pair' {
        $p=New-WinSecAuditPolicyFixturePackage $f;$null=Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity
        $other=$f.Identity.PSObject.Copy();$other.DeviceId='local:hw1-'+('c'*64)
        Reject-AuditPolicyStorage {Read-WinSecAuditPolicyCandidatePair $sandbox $other $p.Snapshot.CollectedAtUTC}
    }
    Test-AuditPolicyStorage 'Corruption is rejected without deleting previous history' {
        $p=New-WinSecAuditPolicyFixturePackage $f;$saved=Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-AuditPolicyStorage {Read-WinSecAuditPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-AuditPolicyStorage ((Read-WinSecAuditPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-AuditPolicyStorage 'An interrupted pair remains recoverable without presenting a confirmed snapshot' {
        $p=New-WinSecAuditPolicyFixturePackage $f;$caught=$false
        try{$null=Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecAuditPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-AuditPolicyStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-AuditPolicyStorage ((Read-WinSecAuditPolicyCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-AuditPolicyStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecAuditPolicyFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-AuditPolicyStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('address','catalog','secret','path')){Test-AuditPolicyStorage ('Forged candidates cannot write filesystem data: '+$damage) {
        $p=New-WinSecAuditPolicyFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){address {(Get-WinSecAuditPolicyFixtureReadings $p.Snapshot Capture.Scope)[0].Value='REMOTE'}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-AuditPolicyStorage {Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity}
        Assert-AuditPolicyStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-AuditPolicyStorage 'Credential values tokens and free personal descriptions never reach either artifact' {
        foreach($name in @('Password','PasswordHash','Token','Credential','SID','CommandLine','UserName','EventContents')){$f.Sources[4].Data[0]|Add-Member NoteProperty $name 'PRIVATE-SECRET'}
        $p=New-WinSecAuditPolicyFixturePackage $f;$saved=Write-WinSecAuditPolicyCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-AuditPolicyStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|PasswordHash|Credential|CommandLine|EventContents')}
    }
    Test-AuditPolicyStorage 'Production execution historical models and other candidates stay unchanged without public sessions' {
        foreach($file in $protected){Assert-AuditPolicyStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-AuditPolicyStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'AuditPolicyTechnical')
        Assert-AuditPolicyStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
        $checks=(Get-Content (Join-Path $root 'config/checks.json') -Raw|ConvertFrom-Json).checks
        Assert-AuditPolicyStorage (-not ($checks|Where-Object checkId -CEQ WSA-LOG-002).execution.enabled -and @($checks|Where-Object {$_.execution.enabled}).Count -eq 11)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Aadt-[a-f0-9]{12}\z'){throw 'Unsafe policy fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Audit Policy candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
