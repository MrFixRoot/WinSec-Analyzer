[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkWorkflowMemory.ps1')
. (Join-Path $root 'tests/Fixtures/FrozenFindingsMemory.ps1')
function Get-CimInstance {throw 'Native query forbidden.'}
function Get-MpPreference {throw 'Native query forbidden.'}
$passed=0;$failed=0
function Assert-FR {param([bool]$Value);if(-not $Value){throw 'Frozen report assertion failed.'}}
function Reject-FR {param([scriptblock]$Action);$rejected=$false;try{$null=& $Action}catch{$rejected=$true};Assert-FR $rejected}
function Test-FR {param($CaseName,[scriptblock]$Action);try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
foreach($framework in @('nist-csf','cis-controls','mitre-attack')){
    Test-FR ('Frozen view and Markdown roundtrip retain the selected framework: '+$framework) {
        $a=New-WinSecFrozenFindingsFixture $root -Framework $framework;$before=Get-WinSecFrameworkAnalysisDigest $a
        $text=New-WinSecFrozenFindingsTestArtifact $a;$r=ConvertFrom-WinSecFrozenFindingsArtifact $text $a.DeviceId
        Assert-FR ($r.Analysis.ContentSha256 -ceq $before -and (Get-WinSecFrameworkAnalysisDigest $a) -ceq $before -and $r.Analysis.FrameworkId -ceq $framework -and
            (ConvertFrom-WinSecMarkdownArtifact $text $a.DeviceId).AnalysisId -ceq $a.AnalysisId -and $text.Contains('Stored source details'))
        foreach($row in $a.Rows){Assert-FR ($text.Contains($row.Title) -and $text.Contains($row.Recommendation) -and $text.Contains($row.ScanId))}
        Assert-FR ($text -notmatch 'PRIVATE-|RecoveryPassword|ExclusionPath|/100|NOT_SCORED')
    }
}
Test-FR 'SECTION retains separate original source scopes, snapshots and scan identities' {
    $a=New-WinSecFrozenFindingsFixture $root @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003');$text=New-WinSecFrozenFindingsTestArtifact $a
    $r=(ConvertFrom-WinSecFrozenFindingsArtifact $text $a.DeviceId).Analysis
    Assert-FR ($r.ScopeType -ceq 'SECTION' -and $r.ReadingReview.Sources.Count -eq 3 -and @($r.Sources.ScanId|Sort-Object -Unique).Count -eq 3)
    foreach($source in $a.ReadingReview.Sources){Assert-FR ($text.Contains($source.Identity.SnapshotId) -and $text.Contains($source.SnapshotSha256) -and $text.Contains($source.CollectorVersion))}
}
Test-FR 'Missing readings stay explicit with zero Findings rather than invented warnings' {
    $a=New-WinSecFrozenFindingsFixture $root -Missing;$text=New-WinSecFrozenFindingsTestArtifact $a;$r=ConvertFrom-WinSecFrozenFindingsArtifact $text $a.DeviceId
    Assert-FR ($r.Analysis.Rows.Count -eq 0 -and $r.Analysis.MissingTechnicalCheckIds.Count -eq 1 -and $text.Contains('No new warnings were evaluated'))
}
Test-FR 'Legacy views remain exportable without invented observed metadata' {
    $a=New-WinSecFrozenFindingsFixture $root -Legacy;$text=New-WinSecFrozenFindingsTestArtifact $a
    Assert-FR ((ConvertFrom-WinSecFrozenFindingsArtifact $text $a.DeviceId).Analysis.SchemaVersion -ceq '1.0.0' -and $text.Contains('legacy view did not record'))
}
Test-FR 'Existing format 1.0 report reader remains compatible' {
    $a=New-WinSecFrozenFindingsFixture $root;$body=New-WinSecFrameworkMarkdown $a
    $meta=@{SchemaVersion='1.0.0';DeviceId=$a.DeviceId;AnalysisId=$a.AnalysisId;FrameworkId=$a.FrameworkId;ContentSha256=(Get-WinSecReportTextHash $body)}
    $text="<!-- WinSec framework findings`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    Assert-FR ((ConvertFrom-WinSecFrameworkMarkdownArtifact $text $a.DeviceId).AnalysisId -ceq $a.AnalysisId)
}
Test-FR 'Wrong ownership and malformed outer metadata fail closed' {
    $a=New-WinSecFrozenFindingsFixture $root;$text=New-WinSecFrozenFindingsTestArtifact $a
    Reject-FR {ConvertFrom-WinSecFrozenFindingsArtifact $text ('local:hw1-'+('c'*64))}
    Reject-FR {ConvertFrom-WinSecFrozenFindingsArtifact ($text.Replace('"ScopeType":"CONTROL"','"ScopeType":"DEVICE"')) $a.DeviceId}
    Reject-FR {ConvertFrom-WinSecFrozenFindingsArtifact ($text.Replace('"SchemaVersion":"2.0.0"','"SchemaVersion":"9.0.0"')) $a.DeviceId}
}
Test-FR 'Body corruption, control characters and excess bytes are rejected' {
    $a=New-WinSecFrozenFindingsFixture $root;$text=New-WinSecFrozenFindingsTestArtifact $a
    Reject-FR {ConvertFrom-WinSecFrozenFindingsArtifact ($text+'x') $a.DeviceId}
    Reject-FR {ConvertFrom-WinSecFrozenFindingsArtifact ($text+[char]0) $a.DeviceId}
    Reject-FR {ConvertFrom-WinSecFrozenFindingsArtifact ('x'*1048577) $a.DeviceId}
}
Test-FR 'Every metadata field requires one string rather than null or an empty array' {
    $a=New-WinSecFrozenFindingsFixture $root;$text=New-WinSecFrozenFindingsTestArtifact $a
    $null=$text -cmatch '\A<!-- WinSec framework findings\n([^\n]+)\n-->\n([\s\S]*)\z';$json=$Matches[1];$body=$Matches[2]
    foreach($field in @('SchemaVersion','DeviceId','AnalysisId','FrameworkId','ScopeType','ScopeKey','ExportedAtUTC','AnalysisSha256','ContentSha256')){
        foreach($kind in @('NULL','ARRAY')){
            $meta=ConvertFrom-WinSecStoredJson $json;$meta.$field=if($kind -ceq 'ARRAY'){,@()}else{$null}
            Reject-FR {ConvertFrom-WinSecFrozenFindingsArtifact ("<!-- WinSec framework findings`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body) $a.DeviceId}
        }
    }
}
Test-FR 'Rehashed edited presentation still contradicts its canonical frozen analysis' {
    $a=New-WinSecFrozenFindingsFixture $root;$text=New-WinSecFrozenFindingsTestArtifact $a
    $null=$text -cmatch '\A<!-- WinSec framework findings\n([^\n]+)\n-->\n([\s\S]*)\z';$meta=ConvertFrom-WinSecStoredJson $Matches[1];$body=$Matches[2]+'edited'
    $meta.ContentSha256=Get-WinSecReportTextHash $body
    Reject-FR {ConvertFrom-WinSecFrozenFindingsArtifact ("<!-- WinSec framework findings`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body) $a.DeviceId}
}
Test-FR 'Export cannot predate the frozen analysis' {
    $a=New-WinSecFrozenFindingsFixture $root;$text=New-WinSecFrozenFindingsTestArtifact $a '2000-01-01T00:00:00.0000000Z'
    Reject-FR {ConvertFrom-WinSecFrozenFindingsArtifact $text $a.DeviceId}
}
Test-FR 'Rendering and artifact validation never reevaluate rules or prompt for another framework' {
    $a=New-WinSecFrozenFindingsFixture $root
    function New-WinSecFrameworkAnalysis {throw 'Reevaluation forbidden.'}
    function New-WinSecProjectionFrameworkAnalysis {throw 'Reevaluation forbidden.'}
    function Show-WinSecExportFrameworkSelection {throw 'Framework prompt forbidden.'}
    $text=New-WinSecFrozenFindingsTestArtifact $a
    Assert-FR ((ConvertFrom-WinSecFrozenFindingsArtifact $text $a.DeviceId).Analysis.ContentSha256 -ceq $a.ContentSha256)
}
[Console]::WriteLine('Frozen Findings unit: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'Frozen Findings unit failed.'}
