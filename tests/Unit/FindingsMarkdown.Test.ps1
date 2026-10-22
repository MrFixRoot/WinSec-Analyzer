# Informe y propiedad del artefacto en memoria; no escribe ni ejecuta checks.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/TargetRegistry.ps1','src/Core/DeviceInventory.ps1','src/Core/ResultModel.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1','src/Services/FrameworkService.ps1',
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
Test-WinSecReportCase 'Only the three supported frameworks disclose versions and pending recommendations honestly' {
    $report=New-WinSecFindingsMarkdown (New-WinSecReportFixture)
    Assert-WinSecReport (-not $report.Markdown.Contains('CIS Benchmarks'))
    foreach($name in @('CIS Controls','NIST Cybersecurity Framework','MITRE ATT&amp;CK')) {
        Assert-WinSecReport ($report.Markdown.Contains($name))
    }
    Assert-WinSecReport ($report.Markdown.Contains('8\.1') -and $report.Markdown.Contains('2\.0') -and
        $report.Markdown.Contains('PENDING_APPROVED_CRITERIA') -and $report.Markdown.Contains('no validated framework references') -and
        @([regex]::Matches($report.Markdown,'SHA256: [A-F0-9]{64}')).Count -eq 3)
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
foreach($id in @('cis-controls','nist-csf','mitre-attack')) {
    Test-WinSecReportCase ('Explicit framework is the only export context: '+$id) {
        $report=New-WinSecFindingsMarkdown -Selection (New-WinSecReportFixture) -FrameworkId $id
        Assert-WinSecReport ($report.Markdown.Contains('Selected export framework: '+$id) -and
            @([regex]::Matches($report.Markdown,'SHA256: [A-F0-9]{64}')).Count -eq 1 -and
            $report.Markdown.Contains('Diagnostics - not confirmed misconfigurations') -and
            $report.Markdown.Contains('No verified configuration deviations'))
        foreach($other in @('cis-controls','nist-csf','mitre-attack')|Where-Object {$_ -cne $id}) {
            Assert-WinSecReport (-not $report.Markdown.Contains('Selected export framework: '+$other))
        }
    }
}
Test-WinSecReportCase 'Unknown and case-spoofed frameworks cannot silently export another context' {
    foreach($id in @('cis-benchmarks','unknown','CIS-CONTROLS','')) {
        Assert-WinSecReportRejects {New-WinSecFindingsMarkdown -Selection (New-WinSecReportFixture) -FrameworkId $id}
    }
}
Test-WinSecReportCase 'Retired framework cannot be validated mapped or exported through another entry point' {
    $catalog=Get-WinSecFrameworkCatalog
    Assert-WinSecReport ($catalog.LoadedCount -eq 3 -and @($catalog.Frameworks|Where-Object frameworkId -CEQ 'cis-benchmarks').Count -eq 0)
    $retired=[pscustomobject]@{frameworkId='cis-benchmarks';name='Retired';enabled=$true;mappings=@()}
    Assert-WinSecReportRejects {Test-WinSecFrameworkDocument $retired -ExpectedId 'cis-benchmarks'}
    Assert-WinSecReportRejects {Export-WinSecFindingsMarkdown -ProjectRoot $root -Selection (New-WinSecReportFixture) -FrameworkId 'cis-benchmarks'}
    Assert-WinSecReport (@(Get-WinSecFrameworkMappings -CheckId WSA-SYS-001 -Platform Windows -Frameworks @($retired)).Count -eq 0)
}
Test-WinSecReportCase 'Configuration table retains original criterion and safe remediation without inventing a framework control' {
    $selection=New-WinSecReportFixture;$finding=$selection.Findings[0]
    $finding.Kind='CONFIGURATION_DEVIATION';$finding.EvaluationStatus='FAIL'
    $guidance=[pscustomobject]@{
        SchemaVersion='1.0.0';CheckId='WSA-SYS-001';CatalogId='SYNTHETIC';CatalogVersion='test-1';CatalogSha256=('A'*64)
        CriterionId='SYNTHETIC-RT';CriterionTitle='SYNTHETIC real-time | protection';Recommendation='SYNTHETIC manual review, no automatic changes.'
        Framework='LOCAL_POLICY';FrameworkVersion='test-1';ReferenceId='SYNTHETIC-POLICY-RT';ReferenceTitle='SYNTHETIC policy'
        ReferenceUrl='https://example.invalid/synthetic';VerifiedAtUTC='2026-10-16T00:00:00Z'
        OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='TEST';Profile='TEST'
    }
    $finding|Add-Member -NotePropertyName Guidance -NotePropertyValue $guidance
    $before=ConvertTo-Json $selection -Depth 25 -Compress
    $state=[pscustomobject]@{SelectedDeviceId=$selection.DeviceId;FindingsScope='Control';SectionIndex=0;ControlIndex=0;FindingsOffset=0}
    $control=[pscustomobject]@{DeviceId=$selection.DeviceId;ScanId=$selection.ScanId;CheckId='WSA-SYS-001';Status='NOT_EVALUATED'}
    $view=Get-WinSecSelectedFindings -NavigationState $state -ControlResults @($control) -Findings $selection.Findings -ScanId $selection.ScanId
    Assert-WinSecReport ($view.Findings.Count -eq 1 -and $view.Findings[0].ConfigurationState -ceq 'MISCONFIGURED' -and
        $view.Findings[0].Finding -ceq $guidance.CriterionTitle -and $view.Rows[0].ControlCode -ceq 'WSA-SYS-001 / SYNTHETIC-RT')
    $report=New-WinSecFindingsMarkdown -Selection $selection -FrameworkId cis-controls
    Assert-WinSecReport ($report.Markdown.Contains('| Finding | Configuration | Status | Original policy control | Referenced framework control |') -and
        $report.Markdown.Contains('MISCONFIGURED') -and $report.Markdown.Contains('SYNTHETIC real\-time \| protection') -and
        $report.Markdown.Contains('PENDING: no validated mapping') -and $report.Markdown.Contains('SYNTHETIC\-POLICY\-RT') -and
        $report.Markdown.Contains('SYNTHETIC manual review, no automatic changes\.') -and
        -not $report.Markdown.Contains('## Diagnostics') -and $before -ceq (ConvertTo-Json $selection -Depth 25 -Compress))
    $reader=(Get-Command Get-WinSecFrameworkMappings).ScriptBlock
    function Get-WinSecFrameworkMappings {
        param($CheckId,$Platform,$Frameworks)
        Assert-WinSecReport ($Frameworks.Count -eq 1 -and $Frameworks[0].frameworkId -ceq 'cis-controls')
        [pscustomobject]@{FrameworkName='SYNTHETIC framework';FrameworkVersion='test-1';ReferenceId='TEST.1';
            Title='SYNTHETIC control description';Url='https://example.invalid/synthetic-control'}
    }
    try {
        $mapped=New-WinSecFindingsMarkdown -Selection $selection -FrameworkId cis-controls
        Assert-WinSecReport ($mapped.Markdown.Contains('SYNTHETIC framework / TEST\.1') -and
            $mapped.Markdown.Contains('SYNTHETIC control description') -and $mapped.Markdown.Contains('synthetic\-control') -and
            $mapped.Markdown.Contains('SYNTHETIC manual review, no automatic changes\.'))
        # The same resolver must never attach a missing-control claim to a diagnostic.
        $diagnostic=New-WinSecFindingsMarkdown -Selection (New-WinSecReportFixture) -FrameworkId cis-controls
        Assert-WinSecReport (-not $diagnostic.Markdown.Contains('TEST\.1'))
    }
    finally {Set-Item -LiteralPath Function:Get-WinSecFrameworkMappings -Value $reader}
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if($script:failed -gt 0){throw "$script:failed Markdown test(s) failed."}
