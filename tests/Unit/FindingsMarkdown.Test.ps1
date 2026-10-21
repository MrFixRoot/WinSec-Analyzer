# Informe y propiedad del artefacto en memoria; no escribe ni ejecuta checks.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/TargetRegistry.ps1','src/Core/DeviceInventory.ps1','src/Core/ResultModel.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/Services/FrameworkService.ps1',
    'src/Core/FrameworkMappingEngine.ps1','src/Services/DeviceManagementService.ps1',
    'src/Services/ReportService.ps1','src/Services/ExportService.ps1')) { . (Join-Path $root $file) }
$script:passed=0;$script:failed=0
function Assert-WinSecReport {param([bool]$Condition);if(-not $Condition){throw 'Report assertion failed.'}}
function New-WinSecReportFixture {
    [pscustomobject]@{DeviceId='local:REPORT';ScanId='report-1';SourceScopeType='DEVICE';SourceScopeKey='ALL';
        ScopeType='CONTROL';ScopeKey='WSA-SYS-001';CatalogVersion='0.9.0';Findings=@(
            [pscustomobject]@{FindingId='report-finding-1';CheckId='WSA-SYS-001';DeviceId='local:REPORT';ScanId='report-1';
                Kind='EVALUATION_PENDING';EvaluationStatus='NOT_EVALUATED'})}
}
function Test-WinSecReportCase {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function Assert-WinSecReportRejects {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecReport $caught}
Test-WinSecReportCase 'Public report separates source scope from exported selection without changing source' {
    $selection=New-WinSecReportFixture;$before=ConvertTo-Json $selection -Depth 10 -Compress
    $report=New-WinSecFindingsMarkdown $selection
    Assert-WinSecReport ($report.Markdown.Contains('Source scope: DEVICE / ALL') -and
        $report.Markdown.Contains('Exported selection: CONTROL / WSA\-SYS\-001') -and
        $report.Markdown.Contains('Score: NOT_SCORED') -and $report.Markdown -notmatch '0/100|100/100|"Evidence"' -and
        $before -ceq (ConvertTo-Json $selection -Depth 10 -Compress))
}
Test-WinSecReportCase 'All four configured frameworks disclose versions and pending recommendations honestly' {
    $report=New-WinSecFindingsMarkdown (New-WinSecReportFixture)
    foreach($name in @('CIS Benchmarks','CIS Controls','NIST Cybersecurity Framework','MITRE ATT&amp;CK')) {
        Assert-WinSecReport ($report.Markdown.Contains($name))
    }
    Assert-WinSecReport ($report.Markdown.Contains('8\.1') -and $report.Markdown.Contains('2\.0') -and
        $report.Markdown.Contains('PENDING_APPROVED_CRITERIA') -and $report.Markdown.Contains('no validated framework references') -and
        @([regex]::Matches($report.Markdown,'SHA256: [A-F0-9]{64}')).Count -eq 4)
}
foreach($field in @('Evidence','RawEvidence','Recommendation','Score','Metadata','ExpectedValue')) {
    Test-WinSecReportCase ('Rejects unprojected finding field: '+$field) {
        $selection=New-WinSecReportFixture
        $selection.Findings[0] | Add-Member -NotePropertyName $field -NotePropertyValue 'PRIVATE-REPORT-MARKER'
        Assert-WinSecReportRejects {New-WinSecFindingsMarkdown $selection}
    }
}
foreach($mutation in @(
    {$args[0].DeviceId='local:OTHER'},{$args[0].ScanId='other-scan'},
    {$args[0].CheckId='WSA-NET-001'},{$args[0].Kind='PRIVATE-REPORT-MARKER'},
    {$args[0].EvaluationStatus='PRIVATE-REPORT-MARKER'},{$args[0].FindingId="bad`nID"})) {
    Test-WinSecReportCase 'Rejects foreign identities scopes and invalid public enums' {
        $selection=New-WinSecReportFixture;& $mutation $selection.Findings[0]
        Assert-WinSecReportRejects {New-WinSecFindingsMarkdown $selection}
    }
}
Test-WinSecReportCase 'Rejects duplicate findings and empty selections' {
    $selection=New-WinSecReportFixture;$selection.Findings+=@($selection.Findings[0])
    Assert-WinSecReportRejects {New-WinSecFindingsMarkdown $selection}
    $selection.Findings=@();Assert-WinSecReportRejects {New-WinSecFindingsMarkdown $selection}
}
Test-WinSecReportCase 'Rejects source scope spoofing and unsupported root properties' {
    $selection=New-WinSecReportFixture;$selection.SourceScopeType='SECTION';$selection.SourceScopeKey='NetworkSecurity'
    Assert-WinSecReportRejects {New-WinSecFindingsMarkdown $selection}
    $selection=New-WinSecReportFixture;$selection | Add-Member -NotePropertyName Evidence -NotePropertyValue 'PRIVATE-REPORT-MARKER'
    Assert-WinSecReportRejects {New-WinSecFindingsMarkdown $selection}
}
Test-WinSecReportCase 'Markdown text escapes HTML links and formatting and rejects control characters' {
    $text=ConvertTo-WinSecMarkdownText '<script>[click](https://example.com)*'
    Assert-WinSecReport ($text -notmatch '<script>|\[click\]\(https:' -and $text.Contains('&lt;'))
    Assert-WinSecReportRejects {ConvertTo-WinSecMarkdownText "private`ntext"}
}
Test-WinSecReportCase 'Report envelope binds device scan and body for deletion ownership' {
    $body="# Public`n"
    $meta=[ordered]@{SchemaVersion='1.0.0';DeviceId='local:REPORT';ScanId='report-1';ContentSha256=(Get-WinSecReportTextHash $body)}
    $text="<!-- WinSec public report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $owner=ConvertFrom-WinSecMarkdownArtifact $text 'local:REPORT'
    Assert-WinSecReport ($owner.ScanId -ceq 'report-1')
    Assert-WinSecReportRejects {ConvertFrom-WinSecMarkdownArtifact $text 'local:OTHER'}
    Assert-WinSecReportRejects {ConvertFrom-WinSecMarkdownArtifact ($text+'tampered') 'local:REPORT'}
    Assert-WinSecReportRejects {ConvertFrom-WinSecMarkdownArtifact '# Foreign markdown' 'local:REPORT'}
}
Test-WinSecReportCase 'Report envelope rejects duplicate metadata and invalid scan IDs' {
    $text="<!-- WinSec public report`n"+'{"SchemaVersion":"1.0.0","DeviceId":"local:REPORT","DeviceId":"local:REPORT","ScanId":"report-1","ContentSha256":"BAD"}'+"`n-->`n# Public"
    Assert-WinSecReportRejects {ConvertFrom-WinSecMarkdownArtifact $text 'local:REPORT'}
    $text=$text.Replace('"report-1"','["report-1"]')
    Assert-WinSecReportRejects {ConvertFrom-WinSecMarkdownArtifact $text 'local:REPORT'}
}
Test-WinSecReportCase 'External export root is rejected before reaching native I/O' {
    Assert-WinSecReportRejects {Export-WinSecFindingsMarkdown -ProjectRoot (Join-Path $root 'external') -Selection (New-WinSecReportFixture)}
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if($script:failed -gt 0){throw "$script:failed Markdown test(s) failed."}
