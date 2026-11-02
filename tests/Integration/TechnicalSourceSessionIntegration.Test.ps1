[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceSession.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
# Historical contracts are imported only as declarations, never coordinator/startup or providers.
. (Join-Path $root 'src/Core/CheckRegistry.ps1')
. (Join-Path $root 'src/Core/DeviceInventory.ps1')
. (Join-Path $root 'src/Services/ExportService.ps1')
. (Join-Path $root 'src/Services/StorageTransitionService.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $tempParent ('wsc-'+[guid]::NewGuid().ToString('N').Substring(0,12));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-SessionIntegration {param([bool]$Value);if(-not $Value){throw 'Technical session integration assertion failed.'}}
function Reject-SessionIntegration {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SessionIntegration $caught}
function Test-SessionIntegration {
    param([string]$Case,[scriptblock]$Action)
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function New-SessionIntegrationFixture {
    param([string]$Family='CANDIDATE',[string]$ScopeType='CONTROL',[string]$CatalogVersion='1.1.0',[string]$CollectorVersion='1.3.0')
    $f=New-WinSecTechnicalSourceFixture -Family $Family -ScopeType $ScopeType -CatalogVersion $CatalogVersion -CollectorVersion $CollectorVersion
    $saved=Save-WinSecTechnicalSourceFixture $sandbox $f
    $owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$f.Identity.ScanId;ScopeType=$f.Identity.ScopeType;ScopeKey=$f.Identity.ScopeKey}
    [pscustomobject]@{Fixture=$f;Owner=$owner;Saved=$saved}
}
try{
    foreach($family in @('CANDIDATE','PROJECTION')){foreach($scope in @('CONTROL','SECTION','DEVICE')){
        Test-SessionIntegration ('Verified container JSON and physical roundtrip preserve source identity and coverage: '+$family+'/'+$scope) {
            $f=New-SessionIntegrationFixture -Family $family -ScopeType $scope
            $before=(Get-FileHash -LiteralPath $f.Saved.JsonPath).Hash
            $s=New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $f.Owner
            $json=ConvertTo-WinSecTechnicalSourceSessionJson $s $f.Owner
            # Test-only isolated file, not a production index writer or an approved storage convention.
            $path=Join-Path $sandbox ([guid]::NewGuid().ToString('N')+'.test-container')
            $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try{$bytes=[Text.Encoding]::UTF8.GetBytes($json);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
            $copy=ConvertFrom-WinSecTechnicalSourceSessionJson ([IO.File]::ReadAllText($path)) $f.Owner
            $verified=Resolve-WinSecTechnicalSourceSession $sandbox $copy $f.Owner
            Assert-SessionIntegration ((Get-WinSecPublicHistoryJson $verified) -ceq $json -and
                (Get-WinSecPublicHistoryJson $verified.Sources[0].Reference) -ceq (Get-WinSecPublicHistoryJson $f.Fixture.Reference) -and
                (Get-WinSecPublicHistoryJson $verified.Sources[0].Collection) -ceq (Get-WinSecPublicHistoryJson $f.Fixture.Package.Snapshot.Collection) -and
                $before -ceq (Get-FileHash -LiteralPath $f.Saved.JsonPath).Hash -and -not [IO.Directory]::Exists((Join-Path $sandbox 'data')))
        }
    }}
    foreach($collector in @('1.0.0','1.1.0','1.2.0','1.3.0')){Test-SessionIntegration ('Historical candidate files remain resolvable with their original collector: '+$collector) {
        $f=New-SessionIntegrationFixture -CatalogVersion 1.0.0 -CollectorVersion $collector
        $s=New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $f.Owner
        Assert-SessionIntegration ((Resolve-WinSecTechnicalSourceSession $sandbox $s $f.Owner).Sources[0].Reference.CollectorVersion -ceq $collector)
    }}
    Test-SessionIntegration 'StoredSession 1.0 record, digest and three-field reference remain historical and readable' {
        $f=New-SessionIntegrationFixture -Family PROJECTION;$identity=$f.Fixture.Identity;$snapshot=$f.Fixture.Package.Snapshot
        $control=[pscustomobject]@{DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CheckId=$identity.CheckId;SectionKey='SystemSecurity';Status='INFORMATIONAL';
            ObservedStatus='INFORMATIONAL';TimestampUTC=$snapshot.CollectedAtUTC;Evidence=[pscustomobject]@{}}
        $session=New-WinSecResultSession -DeviceId $identity.DeviceId -ScanId $identity.ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @($identity.CheckId) `
            -ControlResults @($control) -StartedAtUTC $snapshot.StartedAtUTC -CompletedAtUTC $snapshot.CompletedAtUTC -ExecutionStatus COMPLETED -ScopeType CONTROL -ScopeKey $identity.CheckId
        $legacy=[pscustomobject]@{ArtifactType='WinSec.StoredSession';SchemaVersion='1.0.0';Record=(New-WinSecPublicHistoryRecord $session);
            Sources=@((Get-WinSecLegacySourceFixtureReference $f.Fixture));ContentSha256=''}
        $body=$legacy.PSObject.Copy();$body.PSObject.Properties.Remove('ContentSha256');$legacy.ContentSha256=Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson $body)
        $before=Get-WinSecPublicHistoryJson $legacy;$read=ConvertFrom-WinSecTransitionJson $before
        $validated=Assert-WinSecTransitionSession $read
        Assert-SessionIntegration ($validated.Record.ScanId -ceq $identity.ScanId -and (Get-WinSecPublicHistoryJson $legacy) -ceq $before -and
            (Read-WinSecVersionedTechnicalSource $sandbox $read.Sources[0] $identity).Snapshot.SchemaVersion -ceq '2.1.0')
        Reject-SessionIntegration {Assert-WinSecTechnicalSourceSession $legacy $f.Owner}
        Reject-SessionIntegration {New-WinSecTechnicalSourceSession $sandbox $read.Sources $f.Owner}
    }
    Test-SessionIntegration 'Digest-valid coverage changes are rejected by resolving the actual saved snapshot' {
        $f=New-SessionIntegrationFixture;$s=New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $f.Owner
        $s.Sources[0].Collection.Unknown++;$s.ContentSha256=Get-WinSecTechnicalSessionDigest $s
        Assert-WinSecTechnicalSourceSession $s $f.Owner
        Reject-SessionIntegration {Resolve-WinSecTechnicalSourceSession $sandbox $s $f.Owner}
    }
    Test-SessionIntegration 'A different valid pair with identical headers cannot satisfy the frozen snapshot digest' {
        $f=New-SessionIntegrationFixture;$s=New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $f.Owner
        $reading=@($f.Fixture.Package.Snapshot.Batches|Where-Object InventoryId -CEQ Preferences)[0].Records[0].Readings[0];$reading.Value=-not $reading.Value
        # Publish altered synthetic values only to a separate empty fixture root; never overwrite a pair.
        $other=Join-Path $sandbox ('alternate-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($other)
        $null=Save-WinSecTechnicalSourceFixture $other $f.Fixture
        $null=Read-WinSecVersionedTechnicalSource $other $f.Fixture.Reference $f.Fixture.Identity
        Reject-SessionIntegration {Resolve-WinSecTechnicalSourceSession $other $s $f.Owner}
        $null=Resolve-WinSecTechnicalSourceSession $sandbox $s $f.Owner
    }
    foreach($damage in @('Json','Markdown','Commit')){Test-SessionIntegration ('Resolution rejects corrupt or incomplete source without repair: '+$damage) {
        $f=New-SessionIntegrationFixture;$s=New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $f.Owner
        $layout=Get-WinSecSnapshotPairLayout $sandbox $f.Fixture.Identity $f.Fixture.Reference.CollectedAtUTC
        if($damage -ceq 'Commit'){Remove-Item -LiteralPath $layout.Commit}else{[IO.File]::AppendAllText($layout.$damage,'tamper')}
        $before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File|ForEach-Object FullName)
        Reject-SessionIntegration {Resolve-WinSecTechnicalSourceSession $sandbox $s $f.Owner}
        Assert-SessionIntegration (@(Compare-Object $before @(Get-ChildItem -LiteralPath $sandbox -Recurse -File|ForEach-Object FullName)).Count -eq 0)
    }}
    Test-SessionIntegration 'Factory cannot create a verified container from a missing pair' {
        $f=New-WinSecTechnicalSourceFixture;$owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$f.Identity.ScanId;ScopeType=$f.Identity.ScopeType;ScopeKey=$f.Identity.ScopeKey}
        Reject-SessionIntegration {New-WinSecTechnicalSourceSession $sandbox @($f.Reference) $owner}
    }
    foreach($phase in @('New','Resolve')){Test-SessionIntegration ('Cancellation during source verification preserves files and releases leases: '+$phase) {
        $f=New-SessionIntegrationFixture;$s=New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $f.Owner;$script:polls=0;$cancelled=$false
        $before=(Get-FileHash -LiteralPath $f.Saved.JsonPath).Hash
        try{if($phase -ceq 'New'){$null=New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $f.Owner -CancellationAction {$script:polls++;$script:polls -ge 3}}
            else{$null=Resolve-WinSecTechnicalSourceSession $sandbox $s $f.Owner -CancellationAction {$script:polls++;$script:polls -ge 3}}}
        catch [OperationCanceledException]{$cancelled=$true}
        $probe=[IO.File]::Open($f.Saved.JsonPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$probe.Dispose()
        Assert-SessionIntegration ($cancelled -and $before -ceq (Get-FileHash -LiteralPath $f.Saved.JsonPath).Hash)
    }}
    Test-SessionIntegration 'Caller reference and owner mutations do not change the frozen selection' {
        $f=New-SessionIntegrationFixture;$expected=$f.Owner.PSObject.Copy();$script:mutableReference=$f.Fixture.Reference;$script:mutableOwner=$f.Owner;$script:polls=0
        $s=New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $f.Owner -CancellationAction {
            $script:polls++;if($script:polls -eq 1){$script:mutableReference.Identity.ScanId='mutated';$script:mutableOwner.ScanId='mutated'};$false
        }
        Assert-SessionIntegration ($s.Identity.ScanId -ceq $expected.ScanId -and (Resolve-WinSecTechnicalSourceSession $sandbox $s $expected).Identity.ScanId -ceq $expected.ScanId)
    }
    Test-SessionIntegration 'Each factory or resolution verifies its exact source once with real readers' {
        $f=New-SessionIntegrationFixture;$script:sourceReads=0;$script:realSourceReader=${function:Read-WinSecVersionedTechnicalSource}
        function Read-WinSecVersionedTechnicalSource {
            param($ProjectRoot,$Reference,$ExpectedIdentity,[scriptblock]$CancellationAction)
            $script:sourceReads++;& $script:realSourceReader @PSBoundParameters
        }
        $s=New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $f.Owner
        Assert-SessionIntegration ($script:sourceReads -eq 1)
        $null=Resolve-WinSecTechnicalSourceSession $sandbox $s $f.Owner
        Assert-SessionIntegration ($script:sourceReads -eq 2)
    }
    Test-SessionIntegration 'Source files remain protected against callback writes during the single read' {
        $f=New-SessionIntegrationFixture;$script:sourcePath=$f.Saved.JsonPath;$script:polls=0;$script:blocked=0
        $s=New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $f.Owner -CancellationAction {
            $script:polls++;if($script:polls -eq 3){
                try{[IO.File]::AppendAllText($script:sourcePath,'tamper')}catch{$script:blocked++}
                try{[IO.File]::Delete($script:sourcePath)}catch{$script:blocked++}
            };$false
        }
        Assert-SessionIntegration ($script:blocked -eq 2 -and (Resolve-WinSecTechnicalSourceSession $sandbox $s $f.Owner).Sources.Count -eq 1)
    }
    Test-SessionIntegration 'A rejected foreign owner or duplicate selection creates no index or technical files' {
        $f=New-SessionIntegrationFixture;$before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File|ForEach-Object FullName)
        $owner=$f.Owner.PSObject.Copy();$owner.DeviceId='local:hw1-'+('c'*64)
        Reject-SessionIntegration {New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference) $owner}
        Reject-SessionIntegration {New-WinSecTechnicalSourceSession $sandbox @($f.Fixture.Reference,$f.Fixture.Reference) $f.Owner}
        Assert-SessionIntegration (@(Compare-Object $before @(Get-ChildItem -LiteralPath $sandbox -Recurse -File|ForEach-Object FullName)).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $tempParent -or [IO.Path]::GetFileName($full) -cnotmatch '\Awsc-[a-f0-9]{12}\z'){throw 'Unsafe technical session fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical source session integration: $passed passed; $failed failed.");if($failed){exit 1}
