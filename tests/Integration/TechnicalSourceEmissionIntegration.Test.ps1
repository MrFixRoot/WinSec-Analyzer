[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceEmitter.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $tempParent ('wse-'+[guid]::NewGuid().ToString('N').Substring(0,12));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-EmissionIntegration {param([bool]$Value);if(-not $Value){throw 'Source emission integration assertion failed.'}}
function Reject-EmissionIntegration {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-EmissionIntegration $caught}
function Test-EmissionIntegration {
    param([string]$Case,[scriptblock]$Action)
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function Flip-EmissionFixtureValue {
    param([object]$Package)
    if($Package.Snapshot.SchemaVersion -ceq '2.0.0'){
        $reading=@($Package.Snapshot.Batches|Where-Object InventoryId -CEQ Preferences)[0].Records[0].Readings[0];$reading.Value=-not $reading.Value
    }else{
        $batch=@($Package.Snapshot.Batches|Where-Object InventoryId -CEQ Rows)[0]
        $record=@($batch.Records|Where-Object {$_.Readings[0].Value.SettingId -ceq 'DefenderStatus.AntivirusEnabled'})[0]
        $record.Readings[0].Value.Value=-not $record.Readings[0].Value.Value
    }
}
try{
    foreach($collector in @('1.0.0','1.1.0','1.2.0','1.3.0')){Test-EmissionIntegration ('Issue and reload a verified historical candidate reference: '+$collector) {
        $f=New-WinSecTechnicalSourceFixture -CatalogVersion 1.0.0 -CollectorVersion $collector;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
        $before=(Get-FileHash -LiteralPath $saved.JsonPath).Hash
        $reference=New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity
        $reloaded=ConvertFrom-WinSecSnapshotPairJson (ConvertTo-Json $reference -Depth 8 -Compress)
        $read=Read-WinSecVersionedTechnicalSource $sandbox $reloaded $f.Identity
        Assert-EmissionIntegration ($reference.ArtifactType -ceq 'WinSec.TechnicalSourceReference' -and @($reference.PSObject.Properties).Count -eq 10 -and
            $reference.SnapshotSchemaVersion -ceq '2.0.0' -and $reference.CollectorVersion -ceq $collector -and $read.PublicationStatus -ceq 'COMMITTED' -and
            $before -ceq (Get-FileHash -LiteralPath $saved.JsonPath).Hash)
    }}
    foreach($family in @('CANDIDATE','PROJECTION')){foreach($scope in @('CONTROL','SECTION','DEVICE')){
        Test-EmissionIntegration ('Exact original identity, scope, versions and coverage survive emission: '+$family+'/'+$scope) {
            $f=New-WinSecTechnicalSourceFixture -Family $family -ScopeType $scope;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
            $reference=New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity
            $read=Read-WinSecVersionedTechnicalSource $sandbox $reference $f.Identity
            Assert-EmissionIntegration ((Get-WinSecPublicHistoryJson $reference.Identity) -ceq (Get-WinSecPublicHistoryJson $f.Identity) -and
                $reference.SnapshotSchemaVersion -ceq $f.Package.Snapshot.SchemaVersion -and $reference.CatalogVersion -ceq $f.Package.Snapshot.CatalogVersion -and
                (Get-WinSecPublicHistoryJson $read.Snapshot.Collection) -ceq (Get-WinSecPublicHistoryJson $f.Package.Snapshot.Collection) -and
                (Get-WinSecPublicHistoryJson $read.Snapshot) -ceq (Get-WinSecPublicHistoryJson $f.Package.Snapshot))
            if($family -ceq 'CANDIDATE'){Assert-EmissionIntegration ($read.Snapshot.Collection.Status -ceq 'PARTIAL' -and $reference.CollectorVersion -ceq '1.3.0')}
        }
    }}
    foreach($family in @('CANDIDATE','PROJECTION')){Test-EmissionIntegration ('A valid in-memory package with changed readings is not the saved package: '+$family) {
        $f=New-WinSecTechnicalSourceFixture -Family $family;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f;$before=(Get-FileHash -LiteralPath $saved.JsonPath).Hash
        Flip-EmissionFixtureValue $f.Package
        $null=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
        Reject-EmissionIntegration {New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity}
        Assert-EmissionIntegration ($before -ceq (Get-FileHash -LiteralPath $saved.JsonPath).Hash)
    }}
    foreach($damage in @('Json','Markdown','MissingCommit','MissingMarkdown','MissingJson')){Test-EmissionIntegration ('Corrupted or incomplete publication cannot issue a reference: '+$damage) {
        $f=New-WinSecTechnicalSourceFixture;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
        $layout=Get-WinSecSnapshotPairLayout $sandbox $f.Identity $f.Reference.CollectedAtUTC
        switch($damage){Json {[IO.File]::AppendAllText($saved.JsonPath,' ')};Markdown {[IO.File]::AppendAllText($saved.MarkdownPath,' altered')}
            MissingCommit {Remove-Item -LiteralPath $layout.Commit};MissingMarkdown {Remove-Item -LiteralPath $saved.MarkdownPath};MissingJson {Remove-Item -LiteralPath $saved.JsonPath}}
        $before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File|ForEach-Object FullName)
        Reject-EmissionIntegration {New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity}
        Assert-EmissionIntegration (@(Compare-Object $before @(Get-ChildItem -LiteralPath $sandbox -Recurse -File|ForEach-Object FullName)).Count -eq 0)
    }}
    Test-EmissionIntegration 'Package ordering can differ while full validated values and original files remain identical' {
        $f=New-WinSecTechnicalSourceFixture;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f;$reversed=[ordered]@{}
        foreach($property in @($f.Package.Snapshot.PSObject.Properties|Sort-Object Name -Descending)){$reversed[$property.Name]=$property.Value}
        $f.Package.Snapshot=[pscustomobject]$reversed
        Assert-EmissionIntegration ((New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity).CatalogVersion -ceq '1.1.0')
    }
    Test-EmissionIntegration 'Repeated emission only reads and never creates an index, lock artifact or duplicate technical report' {
        $f=New-WinSecTechnicalSourceFixture;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
        $before=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File|ForEach-Object FullName)
        $one=New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity;$two=New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity
        Assert-EmissionIntegration ((Get-WinSecPublicHistoryJson $one) -ceq (Get-WinSecPublicHistoryJson $two) -and
            @(Compare-Object $before @(Get-ChildItem -LiteralPath $sandbox -Recurse -File|ForEach-Object FullName)).Count -eq 0 -and -not [IO.Directory]::Exists((Join-Path $sandbox 'data')))
    }
    foreach($cancelAt in @(1,3)){Test-EmissionIntegration ('Cancellation issues no reference and releases held files: callback '+$cancelAt) {
        $f=New-WinSecTechnicalSourceFixture;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f;$script:polls=0;$cancelled=$false
        try{New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity -CancellationAction {$script:polls++;return ($script:polls -ge $cancelAt)}}catch [OperationCanceledException]{$cancelled=$true}
        $probe=[IO.File]::Open($saved.JsonPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$probe.Dispose()
        Assert-EmissionIntegration $cancelled
    }}
    Test-EmissionIntegration 'Caller package mutations after freezing cannot change the emitted original reference' {
        $f=New-WinSecTechnicalSourceFixture;$null=Save-WinSecTechnicalSourceFixture $sandbox $f
        $script:mutablePackage=$f.Package;$script:mutableOwner=$f.Identity;$script:polls=0;$expected=$f.Identity.PSObject.Copy()
        $reference=New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity -CancellationAction {
            $script:polls++;if($script:polls -eq 2){Flip-EmissionFixtureValue $script:mutablePackage;$script:mutableOwner.ScanId='mutated';$script:mutablePackage.Identity.ScanId='mutated'};$false
        }
        Assert-EmissionIntegration ($reference.Identity.ScanId -ceq $expected.ScanId -and (Read-WinSecVersionedTechnicalSource $sandbox $reference $expected).PublicationStatus -ceq 'COMMITTED')
    }
    Test-EmissionIntegration 'Read leases prevent a callback from rewriting or deleting the verified pair' {
        $f=New-WinSecTechnicalSourceFixture;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
        $script:lockedJson=$saved.JsonPath;$script:polls=0;$script:blocked=0
        $reference=New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity -CancellationAction {
            $script:polls++;if($script:polls -eq 3){
                try{[IO.File]::AppendAllText($script:lockedJson,'tamper')}catch{$script:blocked++}
                try{[IO.File]::Delete($script:lockedJson)}catch{$script:blocked++}
            };$false
        }
        Assert-EmissionIntegration ($script:blocked -eq 2 -and (Read-WinSecVersionedTechnicalSource $sandbox $reference $f.Identity).PublicationStatus -ceq 'COMMITTED')
    }
    Test-EmissionIntegration 'Corruption by a callback before the read leases is detected without repair' {
        $f=New-WinSecTechnicalSourceFixture;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
        $script:unlockedMarkdown=$saved.MarkdownPath;$script:polls=0
        Reject-EmissionIntegration {New-WinSecTechnicalSourceReference $sandbox $f.Package $f.Identity -CancellationAction {
            $script:polls++;if($script:polls -eq 2){[IO.File]::AppendAllText($script:unlockedMarkdown,'tamper')};$false
        }}
        Assert-EmissionIntegration ((Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8).EndsWith('tamper'))
    }
    Test-EmissionIntegration 'Foreign expected device, session, snapshot or scope cannot emit another source reference' {
        $f=New-WinSecTechnicalSourceFixture;$null=Save-WinSecTechnicalSourceFixture $sandbox $f
        foreach($damage in @('Device','Session','Snapshot','Scope')){
            $owner=$f.Identity.PSObject.Copy()
            switch($damage){Device {$owner.DeviceId='local:hw1-'+('c'*64)};Session {$owner.ScanId='foreign'};Snapshot {$owner.SnapshotId='c'*32}
                Scope {$owner.ScopeType='SECTION';$owner.ScopeKey='SystemSecurity'}}
            Reject-EmissionIntegration {New-WinSecTechnicalSourceReference $sandbox $f.Package $owner}
        }
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $tempParent -or [IO.Path]::GetFileName($full) -cnotmatch '\Awse-[a-f0-9]{12}\z'){throw 'Unsafe emission fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Source emission integration: $passed passed; $failed failed.");if($failed){exit 1}
