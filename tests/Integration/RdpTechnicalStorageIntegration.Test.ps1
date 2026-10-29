# Candidate pairs in an owned disposable installation. No RDP, user-session or native queries.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Network/RdpTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/RdpTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-CimClass {throw 'Native audit forbidden.'}
function Get-ItemProperty {throw 'Native registry query forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('rdt-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Checks/Network/Test-RDP.ps1','src/Core/RdpTelemetry.ps1','config/checks.json','config/scoring.json',
    'src/Checks/Network/SmbTechnicalCatalog.ps1','src/Checks/Network/SmbTechnicalSnapshot.ps1','src/Checks/Network/SmbTechnicalStorage.ps1',
    'src/Checks/Firewall/FirewallTechnicalCatalog.ps1','src/Checks/Defender/DefenderTechnicalCatalog.ps1','src/Checks/BitLocker/BitLockerTechnicalCatalog.ps1','src/Checks/System/WindowsUpdateTechnicalCatalog.ps1')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-RdpStorage {param([bool]$Value);if(-not $Value){throw 'RDP candidate storage assertion failed.'}}
function Reject-RdpStorage {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-RdpStorage $caught}
function Test-RdpStorage {param($Name,[scriptblock]$Action);$f=New-WinSecRdpCandidateFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-RdpStorage ('JSON and Markdown share the same normalized readings and original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-NET-003'};SECTION {'NetworkSecurity'};DEVICE {'ALL'}}
        $p=New-WinSecRdpFixturePackage $f;$saved=Write-WinSecRdpCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecRdpCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC;$md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-RdpStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Identity.ScopeType -ceq $scope -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $p.Snapshot -Depth 16 -Compress) -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $read.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity))
        Assert-RdpStorage ($md.Contains((ConvertTo-WinSecSnapshotMarkdownCell 'LOCAL_RDP_CONFIGURATION_NO_USER_SESSIONS')) -and
            $md.Contains('General.TerminalName') -and $md.Contains('Redirection.ClipboardMapping') -and
            $saved.JsonPath.Contains('\scans\') -and $saved.MarkdownPath.Contains('\reports\') -and $saved.JsonPath.Contains('RemoteDesktop_'))
    }}
    Test-RdpStorage 'A collision cannot overwrite either immutable body' {
        $p=New-WinSecRdpFixturePackage $f;$saved=Write-WinSecRdpCandidatePair $sandbox $p $f.Identity
        $a=(Get-FileHash $saved.JsonPath).Hash;$b=(Get-FileHash $saved.MarkdownPath).Hash
        Reject-RdpStorage {Write-WinSecRdpCandidatePair $sandbox $p $f.Identity}
        Assert-RdpStorage ((Get-FileHash $saved.JsonPath).Hash -ceq $a -and (Get-FileHash $saved.MarkdownPath).Hash -ceq $b)
    }
    Test-RdpStorage 'Unresolved native principal values survive publication without becoming complete' {
        $f.Sources[3].Data[0].UserAuthenticationRequired=[uint32]99;$p=New-WinSecRdpFixturePackage $f
        $null=Write-WinSecRdpCandidatePair $sandbox $p $f.Identity;$read=Read-WinSecRdpCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-RdpStorage ($read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            (Get-WinSecRdpFixtureReadings $read.Snapshot General.UserAuthenticationRequired)[0].Value -eq 99)
    }
    Test-RdpStorage 'Real Unicode listener names and independent capture timestamps survive both artifacts' {
        $name='Terminal-'+[char]0x00F1;$f.Sources[3].Data[0].TerminalName=$name;$f.Sources[3].CollectedAtUTC='2026-10-29T01:02:05.0000000Z'
        $p=New-WinSecRdpFixturePackage $f;$saved=Write-WinSecRdpCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecRdpCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-RdpStorage ((Get-WinSecRdpFixtureReadings $read.Snapshot General.TerminalName)[0].Value -ceq $name -and
            $read.Snapshot.CollectedAtUTC -ceq $f.Sources[3].CollectedAtUTC -and
            (Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8).Contains((ConvertTo-WinSecSnapshotMarkdownCell $name)))
    }
    Test-RdpStorage 'Home exclusions preserve service and Registry64 data after recovery' {
        $f.Sources[0].Data.OperatingSystemSKU=[uint32]101;foreach($source in $f.Sources){if($source.Location -ceq 'TERMINALSERVICES'){$source.State='NOT_APPLICABLE';$source.Data=$null}}
        $p=New-WinSecRdpFixturePackage $f;$null=Write-WinSecRdpCandidatePair $sandbox $p $f.Identity
        $read=Read-WinSecRdpCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-RdpStorage (@($read.Snapshot.Inventories|Where-Object State -CEQ NOT_APPLICABLE).Count -eq 7 -and
            (Get-WinSecRdpFixtureReadings $read.Snapshot Services.Name).Count -eq 3 -and (Get-WinSecRdpFixtureReadings $read.Snapshot Registry.ListenerPort)[0].Value -eq 3389)
    }
    Test-RdpStorage 'Foreign devices cannot read an existing pair' {
        $p=New-WinSecRdpFixturePackage $f;$null=Write-WinSecRdpCandidatePair $sandbox $p $f.Identity
        $other=$f.Identity.PSObject.Copy();$other.DeviceId='local:hw1-'+('c'*64)
        Reject-RdpStorage {Read-WinSecRdpCandidatePair $sandbox $other $p.Snapshot.CollectedAtUTC}
    }
    Test-RdpStorage 'Corruption is rejected without deleting previous history' {
        $p=New-WinSecRdpFixturePackage $f;$saved=Write-WinSecRdpCandidatePair $sandbox $p $f.Identity;$bytes=[IO.File]::ReadAllBytes($saved.JsonPath)
        try{[IO.File]::AppendAllText($saved.JsonPath,'CORRUPT');Reject-RdpStorage {Read-WinSecRdpCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC}}
        finally{[IO.File]::WriteAllBytes($saved.JsonPath,$bytes)}
        Assert-RdpStorage ((Read-WinSecRdpCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-RdpStorage 'An interrupted publication exposes no confirmed snapshot until explicit repair' {
        $p=New-WinSecRdpFixturePackage $f;$caught=$false
        try{$null=Write-WinSecRdpCandidatePair $sandbox $p $f.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{$caught=$true}
        $read=Read-WinSecRdpCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        Assert-RdpStorage ($caught -and $read.PublicationStatus -ceq 'RECOVERABLE' -and $null -eq $read.Snapshot)
        $null=Repair-WinSecTechnicalSnapshotPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
        Assert-RdpStorage ((Read-WinSecRdpCandidatePair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'COMMITTED')
    }
    Test-RdpStorage 'Cancellation before publication creates no files' {
        $p=New-WinSecRdpFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count;$cancelled=$false
        try{$null=Write-WinSecRdpCandidatePair $sandbox $p $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-RdpStorage ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }
    foreach($damage in @('principal','catalog','secret','path')){Test-RdpStorage ('Forged candidates cannot write filesystem data: '+$damage) {
        $p=New-WinSecRdpFixturePackage $f;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count
        switch($damage){principal {(Get-WinSecRdpFixtureReadings $p.Snapshot General.UserAuthenticationRequired)[0].Value=[uint32]99}
            catalog {$p.Catalog.CatalogVersion='9.0.0';$p.CatalogSha256=Get-WinSecSnapshotCatalogHash $p.Catalog}
            secret {$p.Snapshot|Add-Member NoteProperty Credential 'PRIVATE-SECRET'};path {$f.Identity.ScanId='../unsafe'}
        }
        Reject-RdpStorage {Write-WinSecRdpCandidatePair $sandbox $p $f.Identity}
        Assert-RdpStorage (@(Get-ChildItem -LiteralPath $sandbox -Recurse -File).Count -eq $before)
    }}
    Test-RdpStorage 'Secrets user identities certificates and security descriptors never reach either artifact' {
        $f.Sources[4].Data[0]|Add-Member NoteProperty Password 'PRIVATE-SECRET'
        $f.Sources[3].Data[0]|Add-Member NoteProperty Certificates 'PRIVATE-SECRET'
        $f.Sources[8].Data[0]|Add-Member NoteProperty StringSecurityDescriptor 'PRIVATE-SECRET'
        $p=New-WinSecRdpFixturePackage $f;$saved=Write-WinSecRdpCandidatePair $sandbox $p $f.Identity
        foreach($path in @($saved.JsonPath,$saved.MarkdownPath)){Assert-RdpStorage ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -notmatch 'PRIVATE-SECRET|\b(?:StringSecurityDescriptor|Certificates|Password)\b')}
    }
    Test-RdpStorage 'Production historical models permissions and previous candidates stay unchanged' {
        foreach($file in $protected){Assert-RdpStorage ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        Assert-RdpStorage ((Get-Content (Join-Path $root 'config/checks.json') -Raw) -notmatch 'RdpTechnical')
        Assert-RdpStorage (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/devices.json')) -and
            @(Get-ChildItem -LiteralPath $sandbox -Recurse -Directory|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Ardt-[a-f0-9]{12}\z'){throw 'Unsafe RDP fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("RDP candidate storage: $passed passed; $failed failed.");if($failed){exit 1}
