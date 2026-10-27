# Historical public Windows Update results -> selected framework -> Markdown.
# Windows providers and artifact writes are synthetic; all history stays in memory.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1',
    'src/Services/ReportService.ps1','src/Services/ExportService.ps1','src/Checks/System/Test-WindowsUpdate.ps1',
    'tests/Fixtures/WindowsUpdateMemory.ps1','tests/Fixtures/WindowsUpdateAssessment.ps1')) {. (Join-Path $root $file)}
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
function Get-BitLockerVolume {throw 'Unexpected BitLocker query.'}
function Save-WinSecPublicHistory {throw 'Unexpected history write.'}
function Save-WinSecEvidence {throw 'Unexpected evidence write.'}
$script:artifactWrites=0;$script:allowArtifact=$false;$script:writtenReport=$null
function Write-WinSecMarkdownArtifact {
    param($ProjectRoot,$Report)
    if(-not $script:allowArtifact){throw 'Unexpected report write.'}
    $script:artifactWrites++;$script:writtenReport=Copy-WinSecResultData $Report
    [pscustomobject]@{RelativePath='reports/exports/SYNTHETIC.md';DeviceId=$Report.DeviceId;ScanId=$Report.ScanId}
}
$script:passed=0;$script:failed=0
function Assert-WinSecUpdateFrameworkIntegration {param([bool]$Value);if(-not $Value){throw 'Windows Update framework integration assertion failed.'}}
function Assert-WinSecUpdateFrameworkIntegrationRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecUpdateFrameworkIntegration $caught}
function Test-WinSecUpdateFrameworkIntegration {
    param([string]$Name,[scriptblock]$Action)
    $before=ConvertTo-Json $script:WU -Depth 12 -Compress
    $script:artifactWrites=0;$script:allowArtifact=$false;$script:writtenReport=$null
    try {
        $null=& $Action
        Assert-WinSecUpdateFrameworkIntegration ($before -ceq (ConvertTo-Json $script:WU -Depth 12 -Compress))
        $script:passed++;Write-Host ('[PASS] '+$Name)
    } catch {$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function New-WinSecUpdateFrameworkExportContext {
    param([object]$Public)
    $state=New-WinSecNavigationState;$state.Screen='Findings';$state.FindingsScope='Control';$state.SelectedDeviceId=$Public.DeviceId;$state.ControlIndex=2
    $key='{0}:{1}{2}:{3}' -f $Public.DeviceId.Length,$Public.DeviceId,$Public.ScanId.Length,$Public.ScanId
    [pscustomobject]@{State=$state;Context=[pscustomobject]@{ProjectRoot=$root;PublicScans=@{$key=$Public};ActiveScanByDevice=@{};
        ActiveScanByScope=@{(Get-WinSecCLIScopeKey $Public.DeviceId CONTROL WSA-SYS-003)=$Public.ScanId}}}
}
$records=@{};$expectedCriteria=@{Automation='WSA-WUP-BASE-001';Baseline='WSA-WUP-BASE-002';Support='WSA-WUP-BASE-003'}
foreach($scenario in @('Automation','Baseline','Support','Healthy','Unknown')) {
    Reset-WinSecWindowsUpdateFixture;Set-WinSecWindowsUpdateSupportedFixture
    $profile='WSA-W11-25H2-PRO-DEF-BASE'
    switch($scenario) {
        Automation {$script:WU.Services[0].StartMode='Disabled'}
        Baseline {$script:WU.VersionValues.UBR=9000}
        Support {$profile='WSA-W11-23H2-PRO-DEF-BASE';$script:WU.Systems[0].Version='10.0.22631';$script:WU.Systems[0].BuildNumber='22631';$script:WU.VersionValues.CurrentBuildNumber='22631'}
        Unknown {$script:WU.RebootValue=$true}
    }
    $f=New-WinSecWindowsUpdateAssessmentFixture -Profile $profile
    $scan='wu-framework-'+$scenario.ToLowerInvariant()
    $f.Context.ScanId=$scan;$f.Audit.ScanId=$scan;$f.Audit.ControlResults[0].ScanId=$scan;$f.Audit.ControlResults[0].Evidence.ScanId=$scan
    $r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
    $records[$scenario]=New-WinSecPublicHistoryRecord (New-WinSecWindowsUpdateAssessmentSession $f $r)
}
# Rendering/export must never revisit Windows or the current assessment policy.
function Get-CimInstance {throw 'Unexpected provider access after collection.'}
function Get-WinSecWindowsUpdateReferenceCatalog {throw 'Unexpected servicing reference reload.'}
function Get-WinSecWindowsUpdateCriteriaTemplate {throw 'Unexpected criterion reload.'}
function Get-WinSecConfigurationScoringPolicy {throw 'Unexpected scoring policy reload.'}
$frameworks=@{}
foreach($id in @('cis-controls','nist-csf','mitre-attack')) {
    $frameworks[$id]=ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath (Join-Path $root ('config/frameworks/'+$id+'.json')) -Raw -Encoding UTF8)
}
foreach($scenario in @('Automation','Baseline','Support')) {
    foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
        Test-WinSecUpdateFrameworkIntegration ('Confirmed deviation receives only the selected criterion-specific guidance: '+$scenario+' / '+$framework) {
            $before=Get-WinSecPublicHistoryJson $records[$scenario]
            $p=(ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $before)).PublicResult
            $ctx=New-WinSecUpdateFrameworkExportContext $p
            $selection=Get-WinSecCLIFindingsExportSelection $ctx.State $ctx.Context
            $report=New-WinSecFindingsMarkdown $selection -FrameworkId $framework
            $criterion=$expectedCriteria[$scenario]
            $failures=@($p.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION)
            $refs=@(Get-WinSecFrameworkMappings -CheckId WSA-SYS-003 -CriterionId $criterion -Platform Windows -Frameworks @($frameworks[$framework]))
            Assert-WinSecUpdateFrameworkIntegration ($failures.Count -eq 1 -and $failures[0].Guidance.CriterionId -ceq $criterion -and $refs.Count -eq 1 -and
                $report.Markdown.Contains((ConvertTo-WinSecMarkdownText ($refs[0].FrameworkName+' / '+$refs[0].ReferenceId))) -and
                $report.Markdown.Contains((ConvertTo-WinSecMarkdownText $refs[0].Description)) -and
                $report.Markdown.Contains((ConvertTo-WinSecMarkdownText $refs[0].Recommendation)) -and
                $report.Markdown.Contains((ConvertTo-WinSecMarkdownText $failures[0].Guidance.Recommendation)) -and
                $report.Markdown.Contains('not a framework requirement') -and $null -eq $p.OverallScore -and
                $before -ceq (Get-WinSecPublicHistoryJson $records[$scenario]) -and $script:artifactWrites -eq 0)
            foreach($other in @('cis-controls','nist-csf','mitre-attack')|Where-Object {$_ -cne $framework}) {
                Assert-WinSecUpdateFrameworkIntegration (-not $report.Markdown.Contains((ConvertTo-WinSecMarkdownText $frameworks[$other].name)))
            }
            if($scenario -ceq 'Support') {
                Assert-WinSecUpdateFrameworkIntegration ($p.ConfigurationAssessment.Controls[0].Value -eq 23.08 -and
                    $p.ConfigurationAssessment.Controls[0].Criteria[1].Status -ceq 'NOT_APPLICABLE' -and
                    $p.ReviewItems[1].Status -ceq 'OBSERVED' -and
                    $p.ReviewItems[1].WindowsUpdateSetting.State -ceq 'NOT_APPLICABLE' -and
                    $report.Markdown.Contains((ConvertTo-WinSecMarkdownText 'PATCH_BASELINE_EXCLUDED_AFTER_SUPPORT')) -and
                    $report.Markdown.Contains('normalized to 100'))
            } else {
                $expected=if($scenario -ceq 'Automation'){85}else{65}
                Assert-WinSecUpdateFrameworkIntegration ($p.ConfigurationAssessment.Controls[0].Value -eq $expected)
            }
            $lines=$report.Markdown -split "`n"
            for($i=0;$i -lt $lines.Count;$i++) {
                if(-not $lines[$i].StartsWith('|')){continue}
                if($i -eq 0 -or -not $lines[$i-1].StartsWith('|')){Assert-WinSecUpdateFrameworkIntegration ($i -gt 0 -and [string]::IsNullOrWhiteSpace($lines[$i-1]))}
                if($i+1 -eq $lines.Count -or -not $lines[$i+1].StartsWith('|')){Assert-WinSecUpdateFrameworkIntegration ($i+1 -lt $lines.Count -and [string]::IsNullOrWhiteSpace($lines[$i+1]))}
            }
            Assert-WinSecUpdateFrameworkIntegration ($report.Markdown -notmatch 'PRIVATE|"Evidence"|PolicyRegistry|VersionRegistry|AutomationPolicy|NamedPolicy')
        }
    }
}
foreach($scenario in @('Healthy','Unknown')) {
    foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
        Test-WinSecUpdateFrameworkIntegration ('Passing and unresolved criteria never imply a framework violation: '+$scenario+' / '+$framework) {
            $p=(ConvertFrom-WinSecPublicHistoryRecord $records[$scenario]).PublicResult
            $ctx=New-WinSecUpdateFrameworkExportContext $p;$selection=Get-WinSecCLIFindingsExportSelection $ctx.State $ctx.Context
            $report=New-WinSecFindingsMarkdown $selection -FrameworkId $framework
            Assert-WinSecUpdateFrameworkIntegration (@($p.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0 -and
                $report.Markdown.Contains('No confirmed Windows Update deviations require framework recommendations') -and
                -not $report.Markdown.Contains('Framework-oriented manual guidance:') -and
                -not $report.Markdown.Contains('M1051') -and -not $report.Markdown.Contains('PR.PS\-02'))
            if($scenario -ceq 'Unknown'){Assert-WinSecUpdateFrameworkIntegration ($null -eq $p.ConfigurationAssessment.Controls[0].Value)}
            else {Assert-WinSecUpdateFrameworkIntegration ($p.ConfigurationAssessment.Controls[0].Value -eq 100)}
        }
    }
}
Test-WinSecUpdateFrameworkIntegration 'Historical records without the optional diagnostic extension still receive contextual guidance without rescoring' {
    $legacy=Copy-WinSecResultData $records['Baseline'];$legacy.PublicResult.ReviewItems=@()
    $legacy.ContentSha256=Get-WinSecPublicHistoryDigest $legacy
    $before=Get-WinSecPublicHistoryJson $legacy
    $p=(ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $before)).PublicResult
    $ctx=New-WinSecUpdateFrameworkExportContext $p;$selection=Get-WinSecCLIFindingsExportSelection $ctx.State $ctx.Context
    $report=New-WinSecFindingsMarkdown $selection -FrameworkId cis-controls
    Assert-WinSecUpdateFrameworkIntegration ($p.ReviewItems.Count -eq 0 -and $p.ConfigurationAssessment.Controls[0].Value -eq 65 -and
        $report.Markdown.Contains('CIS Controls / 7\.3') -and $report.Markdown.Contains('not a framework requirement') -and
        $before -ceq (Get-WinSecPublicHistoryJson $legacy))
}
Test-WinSecUpdateFrameworkIntegration 'Unavailable mapping remains pending while preserving the legitimate local deviation and score' {
    $p=(ConvertFrom-WinSecPublicHistoryRecord $records['Baseline']).PublicResult
    $ctx=New-WinSecUpdateFrameworkExportContext $p;$selection=Get-WinSecCLIFindingsExportSelection $ctx.State $ctx.Context
    function Get-WinSecFrameworkMappings {param($CheckId,$CriterionId,$Platform,$Frameworks);return}
    $report=New-WinSecFindingsMarkdown $selection -FrameworkId cis-controls
    Assert-WinSecUpdateFrameworkIntegration ($selection.ConfigurationAssessment.Controls[0].Value -eq 65 -and
        $report.Markdown.Contains('PENDING: no validated mapping') -and
        $report.Markdown.Contains('framework recommendations remain pending for those deviations') -and
        -not $report.Markdown.Contains('Framework-oriented manual guidance:') -and $script:artifactWrites -eq 0)
}
Test-WinSecUpdateFrameworkIntegration 'Re-export uses a revised mapping snapshot and hash without rewriting the recorded criterion or score' {
    $recordBefore=Get-WinSecPublicHistoryJson $records['Baseline'];$p=(ConvertFrom-WinSecPublicHistoryRecord $records['Baseline']).PublicResult
    $ctx=New-WinSecUpdateFrameworkExportContext $p;$selection=Get-WinSecCLIFindingsExportSelection $ctx.State $ctx.Context
    $original=New-WinSecFindingsMarkdown $selection -FrameworkId nist-csf
    $path=Join-Path $root 'config/frameworks/nist-csf.json'
    $fw=Copy-WinSecResultData $frameworks['nist-csf']
    $ref=@(@($fw.mappings|Where-Object checkId -CEQ WSA-SYS-003)[0].references|Where-Object {$_.criterionIds -ccontains 'WSA-WUP-BASE-002'})[0]
    $ref.recommendation='SYNTHETIC revised framework guidance; original assessment remains unchanged.'
    $script:revisedFrameworkJson=ConvertTo-Json $fw -Depth 24 -Compress
    $script:revisedFrameworkPath=$path;$script:revisedFrameworkHash=Get-WinSecReportTextHash $script:revisedFrameworkJson
    function Get-Content {
        [CmdletBinding()]param([string]$LiteralPath,[switch]$Raw,[string]$Encoding)
        if($LiteralPath -ceq $script:revisedFrameworkPath){return $script:revisedFrameworkJson}
        Microsoft.PowerShell.Management\Get-Content -LiteralPath $LiteralPath -Raw:$Raw -Encoding $Encoding
    }
    function Get-FileHash {
        [CmdletBinding()]param([Alias('Path')][string]$LiteralPath,[string]$Algorithm)
        if($LiteralPath -ceq $script:revisedFrameworkPath){return [pscustomobject]@{Hash=$script:revisedFrameworkHash}}
        Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm
    }
    $revised=New-WinSecFindingsMarkdown $selection -FrameworkId nist-csf
    Assert-WinSecUpdateFrameworkIntegration ($revised.Markdown.Contains($script:revisedFrameworkHash) -and
        $revised.Markdown.Contains((ConvertTo-WinSecMarkdownText $ref.recommendation)) -and
        -not $original.Markdown.Contains('SYNTHETIC revised') -and $selection.ConfigurationAssessment.Controls[0].Value -eq 65 -and
        $recordBefore -ceq (Get-WinSecPublicHistoryJson $records['Baseline']))
}
Test-WinSecUpdateFrameworkIntegration 'The CLI cancels framework selection without publishing or changing history' {
    $p=(ConvertFrom-WinSecPublicHistoryRecord $records['Automation']).PublicResult;$ctx=New-WinSecUpdateFrameworkExportContext $p
    $before=Get-WinSecPublicHistoryJson $ctx.Context.PublicScans
    function Show-WinSecExportFrameworkSelection {param($Selection);[pscustomobject]@{Confirmed=$false;FrameworkId=$null}}
    $result=Invoke-WinSecCLIFindingsExport $ctx.State $ctx.Context
    Assert-WinSecUpdateFrameworkIntegration ($null -eq $result -and $script:artifactWrites -eq 0 -and
        $ctx.Context.LastExportMessage -ceq 'Export cancelled.' -and $before -ceq (Get-WinSecPublicHistoryJson $ctx.Context.PublicScans))
}
Test-WinSecUpdateFrameworkIntegration 'The confirmed CLI export passes only the selected framework to the in-memory artifact writer' {
    $p=(ConvertFrom-WinSecPublicHistoryRecord $records['Automation']).PublicResult;$ctx=New-WinSecUpdateFrameworkExportContext $p
    $script:allowArtifact=$true
    function Show-WinSecExportFrameworkSelection {param($Selection);[pscustomobject]@{Confirmed=$true;FrameworkId='cis-controls'}}
    $null=Invoke-WinSecCLIFindingsExport $ctx.State $ctx.Context
    Assert-WinSecUpdateFrameworkIntegration ($script:artifactWrites -eq 1 -and $script:writtenReport.ScanId -ceq $p.ScanId -and
        $script:writtenReport.Markdown.Contains('CIS Controls / 7\.3') -and -not $script:writtenReport.Markdown.Contains('M1051'))
}
Test-WinSecUpdateFrameworkIntegration 'The removed CIS Benchmarks catalog cannot be selected for Windows Update export' {
    $p=(ConvertFrom-WinSecPublicHistoryRecord $records['Automation']).PublicResult;$ctx=New-WinSecUpdateFrameworkExportContext $p
    function Show-WinSecExportFrameworkSelection {param($Selection);[pscustomobject]@{Confirmed=$true;FrameworkId='cis-benchmarks'}}
    Assert-WinSecUpdateFrameworkIntegrationRejected {Invoke-WinSecCLIFindingsExport $ctx.State $ctx.Context}
    Assert-WinSecUpdateFrameworkIntegration ($script:artifactWrites -eq 0)
}
Write-Host ('Windows Update framework integration: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Windows Update framework integration failed.'}
