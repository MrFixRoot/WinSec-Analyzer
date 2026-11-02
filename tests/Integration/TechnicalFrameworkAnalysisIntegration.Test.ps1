[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalFrameworkAnalysis.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalFrameworkMemory.ps1')
. (Join-Path $root 'src/Checks/Network/OpenPortsTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/OpenPortsTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native query forbidden.'}
function Get-CimClass {throw 'Native schema query forbidden.'}
function Get-Service {throw 'Native query forbidden.'}
function Get-SmbServerConfiguration {throw 'Native query forbidden.'}
function Get-NetTCPConnection {throw 'Native query forbidden.'}
function Invoke-WebRequest {throw 'Online analysis forbidden.'}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $parent ('tfa-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $sandbox;$passed=0;$failed=0
$protected=@('src/Services/FrameworkAnalysisService.ps1','src/Services/FrameworkReportService.ps1','src/CLI/FrameworkWorkflow.ps1','src/UI/Screens/FrameworkFindings.ps1','config/checks.json','config/framework-analysis.json','config/scoring.json','config/frameworks/nist-csf.json','config/frameworks/cis-controls.json','config/frameworks/mitre-attack.json','README.md','LICENSE','NOTICE')
$hashes=@{};foreach($file in $protected){$hashes[$file]=(Get-FileHash (Join-Path $root $file)).Hash}
function Assert-TFI {param([bool]$Condition);if(-not $Condition){throw 'Technical framework integration assertion failed.'}}
function Reject-TFI {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-TFI $caught}
function Test-TFI {param($CaseName,[scriptblock]$Action);try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
function Save-TFI {param($Fixture)
    $s=New-WinSecTechnicalFrameworkSource $Fixture;$p=[pscustomobject]@{Snapshot=$s.Snapshot;Catalog=$s.Catalog;CatalogSha256=$s.CatalogSha256;Identity=$s.Identity}
    $a=Get-WinSecTechnicalAnalysisAdapter $s.Identity.CheckId;. $a.Path
    $writer=$a.Read.Replace('Read-','Write-');$saved=& $writer $sandbox $p $s.Identity
    [pscustomobject]@{Reference=[pscustomobject]@{Identity=$s.Identity;CollectedAtUTC=$s.Snapshot.CollectedAtUTC;CatalogSha256=$s.CatalogSha256;Origin='RECORDS'};Files=$saved;Source=$s}
}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){
        Test-TFI ('Analyze a committed saved pair with original '+$scope+' source scope') {
            $f=New-WinSecTechnicalFrameworkFixture Guest;$f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-IAM-002'};SECTION {'IdentityAccess'};DEVICE {'ALL'}}
            $saved=Save-TFI $f;$selection=New-WinSecTechnicalFrameworkSelection $f
            $events=New-Object 'Collections.Generic.List[object]'
            $sources=@(Read-WinSecTechnicalAnalysisSources $sandbox $selection @($saved.Reference) -ProgressCallback {param($e);$events.Add($e)})
            $v=New-WinSecTechnicalFrameworkView $selection nist-csf $sources
            Assert-TFI ($v.Findings.Count -eq 1 -and $v.Sources[0].Identity.ScopeType -ceq $scope -and $v.Sources[0].Identity.ScanId -ceq $f.Identity.ScanId -and $events.Count -eq 1 -and $events[0].Completed -eq 1)
            $before=(Get-FileHash $saved.Files.JsonPath).Hash;$null=Assert-WinSecTechnicalFrameworkView $v $selection
            Assert-TFI ((Get-FileHash $saved.Files.JsonPath).Hash -ceq $before)
        }
    }
    Test-TFI 'One selected JSON pair yields different framework-specific findings offline' {
        $f=New-WinSecTechnicalFrameworkFixture;$saved=Save-TFI $f;$selection=New-WinSecTechnicalFrameworkSelection $f
        $sources=@(Read-WinSecTechnicalAnalysisSources $sandbox $selection @($saved.Reference));$a=New-WinSecTechnicalFrameworkView $selection nist-csf $sources;$b=New-WinSecTechnicalFrameworkView $selection mitre-attack $sources
        Assert-TFI ($a.Findings.Count -eq 1 -and $b.Findings.Count -eq 2 -and $a.Sources[0].SnapshotSha256 -ceq $b.Sources[0].SnapshotSha256 -and $a.AnalysisId -cne $b.AnalysisId)
    }
    Test-TFI 'A partial committed collection preserves a valid independently observed warning' {
        $f=New-WinSecTechnicalFrameworkFixture;$f.Sources[2].State='ERROR';$f.Sources[2].Data=$null;$saved=Save-TFI $f;$selection=New-WinSecTechnicalFrameworkSelection $f
        $sources=@(Read-WinSecTechnicalAnalysisSources $sandbox $selection @($saved.Reference));$v=New-WinSecTechnicalFrameworkView $selection nist-csf $sources
        Assert-TFI ($v.Sources[0].Collection.Status -ceq 'PARTIAL' -and $v.Findings.Count -eq 1 -and $v.Sources[0].Collection.Errors -gt 0 -and
            @($v.Readings|Where-Object {$_.FieldId -ceq 'Client.RequireSecuritySignature' -and $_.Treatment -ceq 'ERROR'}).Count -eq 1)
    }
    Test-TFI 'A section preserves distinct original ScanIds without constructing a scan' {
        $f=New-WinSecTechnicalFrameworkFixture;$saved=Save-TFI $f
        $ports=New-WinSecOpenPortsCandidateFixture;$ports.Identity.ScanId='second-independent-scan';$ports.Identity.SnapshotId=[guid]::NewGuid().ToString('N')
        foreach($s in $ports.Sources){$s.ScanId=$ports.Identity.ScanId}
        $p=New-WinSecOpenPortsFixturePackage $ports;$null=Write-WinSecOpenPortsCandidatePair $sandbox $p $ports.Identity
        $ref=[pscustomobject]@{Identity=$p.Identity;CollectedAtUTC=$p.Snapshot.CollectedAtUTC;CatalogSha256=$p.CatalogSha256;Origin='RECORDS'}
        $selection=New-WinSecTechnicalFrameworkSelection $f -Section;$sources=@(Read-WinSecTechnicalAnalysisSources $sandbox $selection @($saved.Reference,$ref))
        $v=New-WinSecTechnicalFrameworkView $selection mitre-attack $sources
        Assert-TFI ($v.Sources.Count -eq 2 -and $v.Sources[0].Identity.ScanId -cne $v.Sources[1].Identity.ScanId -and $v.Coverage.MissingCheckIds.Count -eq 3 -and $v.Findings.Count -eq 2)
    }
    Test-TFI 'An incomplete publication cannot be treated as an analysis source' {
        $f=New-WinSecTechnicalFrameworkFixture Guest;$s=New-WinSecTechnicalFrameworkSource $f;$p=[pscustomobject]@{Identity=$s.Identity;Snapshot=$s.Snapshot;Catalog=$s.Catalog;CatalogSha256=$s.CatalogSha256}
        try{$null=Write-WinSecGuestCandidatePair $sandbox $p $s.Identity -ProgressCallback {param($e);if($e.Stage -ceq 'JSON_PUBLISHED'){throw 'SYNTHETIC INTERRUPTION'}}}catch{}
        $reference=[pscustomobject]@{Identity=$s.Identity;CollectedAtUTC=$s.Snapshot.CollectedAtUTC;CatalogSha256=$s.CatalogSha256;Origin='RECORDS'}
        Reject-TFI {Read-WinSecTechnicalAnalysisSources $sandbox (New-WinSecTechnicalFrameworkSelection $f) @($reference)}
        Assert-TFI ((Read-WinSecGuestCandidatePair $sandbox $s.Identity $s.Snapshot.CollectedAtUTC).PublicationStatus -ceq 'RECOVERABLE')
    }
    Test-TFI 'Corruption rejects without replacing the previously frozen view or deleting the pair' {
        $f=New-WinSecTechnicalFrameworkFixture Guest;$saved=Save-TFI $f;$selection=New-WinSecTechnicalFrameworkSelection $f
        $sources=@(Read-WinSecTechnicalAnalysisSources $sandbox $selection @($saved.Reference));$old=New-WinSecTechnicalFrameworkView $selection nist-csf $sources
        [IO.File]::AppendAllText($saved.Files.JsonPath,'CORRUPT');Reject-TFI {Read-WinSecTechnicalAnalysisSources $sandbox $selection @($saved.Reference)}
        Assert-TFI ((Test-Path $saved.Files.JsonPath) -and (Assert-WinSecTechnicalFrameworkView $old $selection).AnalysisId -ceq $old.AnalysisId)
    }
    foreach($change in @('Device','Scope','Duplicate','Catalog','Traversal')){
        Test-TFI ('Saved-source selection rejects '+$change) {
            $f=New-WinSecTechnicalFrameworkFixture Guest;$saved=Save-TFI $f;$selection=New-WinSecTechnicalFrameworkSelection $f;$references=@($saved.Reference)
            switch($change){Device {$selection.DeviceId='local:hw1-'+('c'*64)};Scope {$selection.ScopeKey='WSA-IAM-001'};Duplicate {$references=@($saved.Reference,$saved.Reference)};Catalog {$saved.Reference.CatalogSha256='A'*64};Traversal {$saved.Reference.Identity.SectionKey='../reports'}}
            Reject-TFI {Read-WinSecTechnicalAnalysisSources $sandbox $selection $references}
        }
    }
    Test-TFI 'Cancelling a saved-source read does not write analysis artifacts' {
        $f=New-WinSecTechnicalFrameworkFixture Guest;$saved=Save-TFI $f;$before=@(Get-ChildItem -LiteralPath $sandbox -File -Recurse).Count
        Reject-TFI {Read-WinSecTechnicalAnalysisSources $sandbox (New-WinSecTechnicalFrameworkSelection $f) @($saved.Reference) -CancellationAction {$true}}
        Assert-TFI (@(Get-ChildItem -LiteralPath $sandbox -File -Recurse).Count -eq $before)
    }
    Test-TFI 'Candidate analysis does not change production, permissions, frameworks or create sessions' {
        foreach($file in $protected){Assert-TFI ((Get-FileHash (Join-Path $root $file)).Hash -ceq $hashes[$file])}
        $checks=Get-Content (Join-Path $root 'config/checks.json') -Raw|ConvertFrom-Json
        Assert-TFI (@($checks.checks|Where-Object {$_.execution.enabled -ceq $true}).Count -eq 11 -and -not(Test-Path (Join-Path $sandbox 'data/devices.json')) -and @(Get-ChildItem -LiteralPath $sandbox -Directory -Recurse|Where-Object Name -CEQ sessions).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $parent -or [IO.Path]::GetFileName($full) -cnotmatch '\Atfa-[a-f0-9]{12}\z'){throw 'Unsafe synthetic cleanup path.'}
    if(Test-Path -LiteralPath $full){Remove-Item -LiteralPath $full -Recurse -Force}
}
Write-Host ('Technical framework integration: '+$passed+' passed; '+$failed+' failed.');if($failed){exit 1}
