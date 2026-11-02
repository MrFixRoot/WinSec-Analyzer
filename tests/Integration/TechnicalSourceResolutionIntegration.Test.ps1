[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceReader.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $tempParent ('wsr-'+[guid]::NewGuid().ToString('N').Substring(0,12));$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-SourceIntegration {param([bool]$Value);if(-not $Value){throw 'Source integration assertion failed.'}}
function Reject-SourceIntegration {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SourceIntegration $caught}
function Test-SourceIntegration {
    param([string]$Case,[scriptblock]$Action)
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function Assert-SourceFixtureBytes {
    param($Fixture,$Saved,$Read)
    $s=$Fixture.Package.Snapshot
    Assert-SourceIntegration ($Read.PublicationStatus -ceq 'COMMITTED' -and $Read.Snapshot.SchemaVersion -ceq $s.SchemaVersion -and
        $Read.Snapshot.CatalogVersion -ceq $s.CatalogVersion -and $Read.Snapshot.CollectorVersion -ceq $s.CollectorVersion -and
        (ConvertTo-Json $Read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json $s -Depth 16 -Compress) -and
        (Get-Content -LiteralPath $Saved.MarkdownPath -Raw -Encoding UTF8) -ceq (ConvertTo-WinSecSnapshotMarkdown $s $Fixture.Package.Catalog $Fixture.Package.CatalogSha256 $Fixture.Identity))
}
try{
    foreach($collector in @('1.0.0','1.1.0','1.2.0','1.3.0')){Test-SourceIntegration ('Historical candidate catalog 1.0 resolves its exact stored collector: '+$collector) {
        $f=New-WinSecTechnicalSourceFixture -CatalogVersion 1.0.0 -CollectorVersion $collector;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
        $before=(Get-FileHash -LiteralPath $saved.JsonPath).Hash
        $read=Read-WinSecVersionedTechnicalSource $sandbox $f.Reference $f.Identity
        Assert-SourceFixtureBytes $f $saved $read
        Assert-SourceIntegration ($read.Resolution.Family -ceq 'DEFENDER_CANDIDATE' -and (Get-FileHash -LiteralPath $saved.JsonPath).Hash -ceq $before)
    }}
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-SourceIntegration ('Candidate catalog 1.1 retains partial coverage and original scope: '+$scope) {
        $f=New-WinSecTechnicalSourceFixture -ScopeType $scope;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
        $read=Read-WinSecVersionedTechnicalSource $sandbox $f.Reference $f.Identity
        Assert-SourceFixtureBytes $f $saved $read
        Assert-SourceIntegration ($read.Resolution.CatalogVersion -ceq '1.1.0' -and $read.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            $read.Snapshot.Collection.Coverage -ceq 'LIMITED' -and $read.Snapshot.Identity.ScopeType -ceq $scope)
    }}
    foreach($kind in @('VERSIONED','LEGACY')){Test-SourceIntegration ('Reviewed projection keeps its format and historical reference: '+$kind) {
        $f=New-WinSecTechnicalSourceFixture -Family PROJECTION;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
        $reference=if($kind -ceq 'LEGACY'){Get-WinSecLegacySourceFixtureReference $f}else{$f.Reference}
        $read=Read-WinSecVersionedTechnicalSource $sandbox $reference $f.Identity
        Assert-SourceFixtureBytes $f $saved $read
        Assert-SourceIntegration ($read.Resolution.Family -ceq 'REVIEWED_PROJECTION' -and $read.Snapshot.SchemaVersion -ceq '2.1.0' -and
            (ConvertTo-Json $read.Snapshot -Depth 16 -Compress) -notmatch 'PRIVATE-SOURCE-SECRET')
    }}
    Test-SourceIntegration 'A stored-session reference never guesses a candidate catalog from its digest' {
        $f=New-WinSecTechnicalSourceFixture;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f;$old=Get-WinSecLegacySourceFixtureReference $f
        Reject-SourceIntegration {Read-WinSecVersionedTechnicalSource $sandbox $old $f.Identity}
        Assert-SourceIntegration ((Read-WinSecVersionedTechnicalSource $sandbox $f.Reference $f.Identity).PublicationStatus -ceq 'COMMITTED')
    }
    Test-SourceIntegration 'Two valid known collectors with the same catalog are still bound to the recorded collector' {
        $f=New-WinSecTechnicalSourceFixture -CatalogVersion 1.0.0 -CollectorVersion 1.1.0;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
        $f.Reference.CollectorVersion='1.2.0';Reject-SourceIntegration {Read-WinSecVersionedTechnicalSource $sandbox $f.Reference $f.Identity}
        $f.Reference.CollectorVersion='1.1.0';Assert-SourceIntegration ((Read-WinSecVersionedTechnicalSource $sandbox $f.Reference $f.Identity).PublicationStatus -ceq 'COMMITTED')
    }
    foreach($family in @('CANDIDATE','PROJECTION')){Test-SourceIntegration ('An otherwise committed pair with an unreviewed collector cannot pass version resolution: '+$family) {
        $f=New-WinSecTechnicalSourceFixture -Family $family;$p=$f.Package;$p.Snapshot.CollectorVersion='9.0.0'
        # The generic storage contract is not the control-specific collector allowlist.
        $null=Write-WinSecTechnicalSnapshotPair $sandbox $p.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity
        Reject-SourceIntegration {Read-WinSecVersionedTechnicalSource $sandbox $f.Reference $f.Identity}
    }}
    Test-SourceIntegration 'Missing identity, wrong device, session, snapshot, scope and timestamp never search another source' {
        $f=New-WinSecTechnicalSourceFixture;$null=Save-WinSecTechnicalSourceFixture $sandbox $f
        foreach($damage in @('Device','Session','Snapshot','Scope','Timestamp')){
            $ref=Copy-WinSecResultData $f.Reference;$owner=$f.Identity.PSObject.Copy()
            switch($damage){Device {$ref.Identity.DeviceId='local:hw1-'+('c'*64)};Session {$ref.Identity.ScanId='other'}
                Snapshot {$ref.Identity.SnapshotId='c'*32};Scope {$ref.Identity.ScopeType='SECTION';$ref.Identity.ScopeKey='SystemSecurity'}
                Timestamp {$ref.CollectedAtUTC='2026-10-28T01:02:04.0000001Z'}}
            Reject-SourceIntegration {Read-WinSecVersionedTechnicalSource $sandbox $ref $owner}
        }
    }
    foreach($damage in @('Json','Markdown','MissingCommit','MissingMarkdown')){Test-SourceIntegration ('Invalid or incomplete saved pair is never restored as complete: '+$damage) {
        $f=New-WinSecTechnicalSourceFixture;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f
        $layout=Get-WinSecSnapshotPairLayout $sandbox $f.Identity $f.Reference.CollectedAtUTC
        switch($damage){Json {[IO.File]::AppendAllText($saved.JsonPath,' ')};Markdown {[IO.File]::AppendAllText($saved.MarkdownPath,' altered')}
            MissingCommit {Remove-Item -LiteralPath $layout.Commit};MissingMarkdown {Remove-Item -LiteralPath $saved.MarkdownPath}}
        $files=@(Get-ChildItem -LiteralPath $sandbox -Recurse -File|ForEach-Object {$_.FullName})
        Reject-SourceIntegration {Read-WinSecVersionedTechnicalSource $sandbox $f.Reference $f.Identity}
        Assert-SourceIntegration (@(Compare-Object $files @(Get-ChildItem -LiteralPath $sandbox -Recurse -File|ForEach-Object {$_.FullName})).Count -eq 0)
    }}
    Test-SourceIntegration 'A fresh reference reconstructed after restart resolves the pair without a cache or index write' {
        $f=New-WinSecTechnicalSourceFixture;$null=Save-WinSecTechnicalSourceFixture $sandbox $f
        $reference=ConvertFrom-WinSecSnapshotPairJson (ConvertTo-Json $f.Reference -Depth 8 -Compress)
        $owner=$f.Identity.PSObject.Copy();$f=$null
        $read=Read-WinSecVersionedTechnicalSource $sandbox $reference $owner
        Assert-SourceIntegration ($read.Snapshot.Identity.SnapshotId -ceq $owner.SnapshotId -and -not [IO.Directory]::Exists((Join-Path $sandbox 'data')) -and
            @(Get-ChildItem -LiteralPath (Join-Path $sandbox 'scans') -Directory -Recurse|Where-Object Name -CEQ sessions).Count -eq 0)
    }
    Test-SourceIntegration 'Cancellation before reading preserves all committed bytes' {
        $f=New-WinSecTechnicalSourceFixture;$saved=Save-WinSecTechnicalSourceFixture $sandbox $f;$before=(Get-FileHash -LiteralPath $saved.JsonPath).Hash
        $cancelled=$false;try{Read-WinSecVersionedTechnicalSource $sandbox $f.Reference $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-SourceIntegration ($cancelled -and (Get-FileHash -LiteralPath $saved.JsonPath).Hash -ceq $before)
    }
    Test-SourceIntegration 'Reference and expected identity mutations during callbacks cannot redirect reading' {
        $f=New-WinSecTechnicalSourceFixture;$null=Save-WinSecTechnicalSourceFixture $sandbox $f
        $script:mutableReference=$f.Reference;$script:mutableOwner=$f.Identity
        $read=Read-WinSecVersionedTechnicalSource $sandbox $f.Reference $f.Identity -CancellationAction {
            $script:mutableReference.Identity.ScanId='mutated';$script:mutableReference.CatalogVersion='99.0.0';$script:mutableOwner.ScanId='mutated';$false
        }
        Assert-SourceIntegration ($read.Snapshot.Identity.ScanId -ceq 'candidate-defender' -and $read.Resolution.CatalogVersion -ceq '1.1.0')
    }
    Test-SourceIntegration 'Relative, traversal, UNC and drive-relative roots cannot locate a saved pair' {
        $f=New-WinSecTechnicalSourceFixture
        foreach($badRoot in @('..','C:relative','\\foreign\share',($sandbox+'\..\other'))){Reject-SourceIntegration {Read-WinSecVersionedTechnicalSource $badRoot $f.Reference $f.Identity}}
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $tempParent -or [IO.Path]::GetFileName($full) -cnotmatch '\Awsr-[a-f0-9]{12}\z'){throw 'Unsafe source fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical source integration: $passed passed; $failed failed.");if($failed){exit 1}
