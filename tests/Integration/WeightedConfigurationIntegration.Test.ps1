# Scoring -> ResultModel -> public history -> CLI/Findings/report, entirely synthetic.
# Exercises generic weighted arithmetic through existing prerequisites, not a live Update scan.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/LayoutManager.ps1','src/UI/Components/Table.ps1','src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1',
    'src/UI/Screens/Findings.ps1','src/Services/FrameworkService.ps1','src/Core/FrameworkMappingEngine.ps1','src/Services/ReportService.ps1',
    'tests/Fixtures/WeightedConfiguration.ps1')){. (Join-Path $root $file)}
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
function Save-WinSecPublicHistory {throw 'Unexpected native history write.'}
function Save-WinSecEvidence {throw 'Unexpected native evidence write.'}
$script:passed=0;$script:failed=0
function Assert-WinSecWeightedIntegration {param([bool]$Value);if(-not $Value){throw 'Weighted integration assertion failed.'}}
function Test-WinSecWeightedIntegration {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
$f=New-WinSecWeightedConfigurationFixture;$r=Invoke-WinSecWeightedConfigurationFixture $f
$session=New-WinSecWeightedConfigurationSession $f $r
$record=New-WinSecPublicHistoryRecord $session
$recordJson=Get-WinSecPublicHistoryJson $record
$restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $recordJson)
$public=$restored.PublicResult
$state=New-WinSecNavigationState;$state.Screen='Findings';$state.SelectedDeviceId=$public.DeviceId;$state.FindingsScope='Control'
$key='{0}:{1}{2}:{3}' -f $public.DeviceId.Length,$public.DeviceId,$public.ScanId.Length,$public.ScanId
$ctx=[pscustomobject]@{ProjectRoot=$root;PublicScans=@{$key=$public};ActiveScanByDevice=@{};
    ActiveScanByScope=@{(Get-WinSecCLIScopeKey $public.DeviceId CONTROL WSA-SYS-001)=$public.ScanId}}
Test-WinSecWeightedIntegration 'Canonical public history preserves exact weights, score and original criteria without raw evidence' {
    $expected=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecWeightedIntegration ((Get-WinSecPublicHistoryJson $public) -ceq (Get-WinSecPublicHistoryJson $expected) -and
        $public.ConfigurationAssessment.Controls[0].Value -eq 65 -and
        ($public.ConfigurationAssessment.Controls[0].Criteria.Weight -join ',') -ceq '15,35,50' -and
        $recordJson -notmatch 'PRIVATE-WEIGHTED|SyntheticWindowsUpdate|DefenderStatus|"Evidence"' -and $null -eq $public.OverallScore)
}
Test-WinSecWeightedIntegration 'Historical weighted results never consult the current installed scoring policy' {
    function Get-WinSecConfigurationScoringPolicy {throw 'Unexpected policy read during historical reconstruction.'}
    $copy=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $recordJson)
    Assert-WinSecWeightedIntegration ($copy.PublicResult.ConfigurationAssessment.Controls[0].Value -eq 65)
}
Test-WinSecWeightedIntegration 'CLI and control table show the weighted value rather than the equal-criteria average' {
    $active=Get-WinSecCLIActiveAssessment $state $ctx
    $rows=@(Get-WinSecResultsControlRows -SectionKey SystemSecurity -NavigationState $state `
        -ControlResults $active.ControlResults -ConfigurationAssessment $active.ConfigurationAssessment)
    Assert-WinSecWeightedIntegration (@($rows|Where-Object {$_.CheckId -ceq 'WSA-SYS-001' -and $_.Score -ceq '65/100'}).Count -eq 1)
    $view=Get-WinSecSelectedFindings $state -ControlResults $active.ControlResults -Findings $active.Findings `
        -ScanId $active.ScanId -ConfigurationAssessment $active.ConfigurationAssessment
    Assert-WinSecWeightedIntegration ($view.CheckRows.Count -eq 3 -and
        @($view.CheckRows|Where-Object EvaluationStatus -CEQ FAIL).Count -eq 1)
}
foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
    Test-WinSecWeightedIntegration ('Markdown re-export retains the weighted score without re-evaluating history: '+$framework) {
        $selection=Get-WinSecCLIFindingsExportSelection $state $ctx
        $report=New-WinSecFindingsMarkdown $selection -FrameworkId $framework
        Assert-WinSecWeightedIntegration ($report.Markdown.Contains('65/100') -and $report.Markdown.Contains('1.2.0') -and
            $report.Markdown.Contains('Configuration checks') -and $report.Markdown.Contains('PASS') -and $report.Markdown.Contains('FAIL') -and
            $report.Markdown -notmatch 'PRIVATE-WEIGHTED|"Evidence"' -and (Get-WinSecPublicHistoryJson $record) -ceq $recordJson)
    }
}
foreach($version in @('1.0.0','1.1.0')) {
    Test-WinSecWeightedIntegration ('Legacy immutable records keep equal-weight results and their original schema: '+$version) {
        $legacy=New-WinSecWeightedConfigurationFixture
        foreach($rule in $legacy.Catalogs['WSA-SYS-001'].Catalog.Criteria){$rule.PSObject.Properties.Remove('Weight')}
        $legacy.Policy.Policy.methodologyVersion=$version;$legacy.Policy.Policy.controlMethod='PASS_CRITERIA_FRACTION'
        $result=Invoke-WinSecWeightedConfigurationFixture $legacy
        $oldSession=New-WinSecWeightedConfigurationSession $legacy $result
        $oldRecord=New-WinSecPublicHistoryRecord $oldSession;$before=Get-WinSecPublicHistoryJson $oldRecord
        $copy=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $before)
        $manifest=$copy.PublicResult.ConfigurationAssessment
        Assert-WinSecWeightedIntegration ($manifest.MethodologyVersion -ceq $version -and $manifest.Controls[0].Value -eq 66.67 -and
            $null -eq $manifest.Controls[0].Criteria[0].PSObject.Properties['Weight'] -and
            (Get-WinSecPublicHistoryJson $copy.Record) -ceq $before)
    }
}
Test-WinSecWeightedIntegration 'Unknown evidence survives history as NOT_SCORED with a legitimate evidence gap' {
    $unknown=New-WinSecWeightedConfigurationFixture @($true,$true,$true)
    $unknown.Audit.ControlResults[0].Evidence.SyntheticWindowsUpdate.Support=$null
    $result=Invoke-WinSecWeightedConfigurationFixture $unknown
    $s=New-WinSecWeightedConfigurationSession $unknown $result
    $stored=New-WinSecPublicHistoryRecord $s
    $copy=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $stored))
    Assert-WinSecWeightedIntegration ($null -eq $copy.PublicResult.ConfigurationAssessment.Controls[0].Value -and
        $copy.PublicResult.ConfigurationAssessment.Controls[0].Coverage -eq 66.67 -and
        @($copy.PublicResult.Findings|Where-Object Kind -CEQ EVIDENCE_GAP).Count -eq 1 -and
        @($copy.PublicResult.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
}
Test-WinSecWeightedIntegration 'Changing a weight in a stored record fails integrity validation' {
    $bad=ConvertFrom-WinSecStoredJson $recordJson;$bad.PublicResult.ConfigurationAssessment.Controls[0].Criteria[0].Weight=1
    $caught=$false;try{$null=ConvertFrom-WinSecPublicHistoryRecord $bad}catch{$caught=$true}
    Assert-WinSecWeightedIntegration $caught
}
Test-WinSecWeightedIntegration 'Mutating caller-owned catalogs cannot change an existing weighted session' {
    $f.Catalogs['WSA-SYS-001'].Catalog.Criteria[0].Weight=99
    Assert-WinSecWeightedIntegration ((Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult $session)) -ceq (Get-WinSecPublicHistoryJson $public))
}
Test-WinSecWeightedIntegration 'Installed Windows Update criteria do not grant execution permission' {
    $update=Get-WinSecAssessmentCatalog $root WSA-SYS-003 -Profile WSA-W11-24H2-PRO-DEF-BASE
    Assert-WinSecWeightedIntegration ($update.Catalog.Criteria.Count -eq 3 -and
        (($update.Catalog.Criteria.Weight -join '|') -ceq '15|35|50') -and
        (Test-WinSecCriteriaCatalog $update.Catalog).ReadyForScoring)
    $check=Get-WinSecRegisteredCheck (Get-WinSecCheckRegistry $root) WSA-SYS-003
    Assert-WinSecWeightedIntegration (-not $check.ExecutionEnabled -and -not $check.ExecutionReady -and
        $check.ImplementationStatus -ceq 'PENDING_VALIDATION')
}
Write-Host ('Weighted configuration integration: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Weighted configuration integration failed.'}
