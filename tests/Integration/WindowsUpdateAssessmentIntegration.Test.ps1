# Actual collector -> criteria -> weighted calculation -> public projection/history.
# All providers simulated. History roundtrips stay in memory; no execution permission changes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/LayoutManager.ps1','src/UI/Components/Table.ps1','src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1',
    'src/UI/Screens/Findings.ps1','src/Services/ReportService.ps1','src/Checks/System/Test-WindowsUpdate.ps1',
    'tests/Fixtures/WindowsUpdateMemory.ps1','tests/Fixtures/WindowsUpdateAssessment.ps1')){. (Join-Path $root $file)}
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
function Get-BitLockerVolume {throw 'Unexpected BitLocker query.'}
function Save-WinSecPublicHistory {throw 'Unexpected history write.'}
function Save-WinSecEvidence {throw 'Unexpected evidence write.'}
function Write-WinSecMarkdownArtifact {throw 'Unexpected report write.'}
$script:passed=0;$script:failed=0
function Assert-WinSecWUAssessmentIntegration {param([bool]$Value);if(-not $Value){throw 'Windows Update assessment integration assertion failed.'}}
function Assert-WinSecWUAssessmentRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecWUAssessmentIntegration $caught}
function Test-WinSecWUAssessmentIntegration {
    param([string]$Name,[scriptblock]$Action)
    Reset-WinSecWindowsUpdateFixture;Set-WinSecWindowsUpdateSupportedFixture
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-WinSecWUAssessmentIntegration 'Original collection produces legitimate patch guidance and immutable weighted public score' {
    $script:WU.VersionValues.UBR=9000
    $f=New-WinSecWindowsUpdateAssessmentFixture;$r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
    $session=New-WinSecWindowsUpdateAssessmentSession $f $r
    $public=ConvertTo-WinSecPublicScanResult $session
    $json=Get-WinSecPublicHistoryJson (New-WinSecPublicHistoryRecord $session)
    $copy=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $json)
    Assert-WinSecWUAssessmentIntegration ($public.ConfigurationAssessment.Controls[0].Value -eq 65 -and
        $public.Findings.Count -eq 1 -and $public.Findings[0].Guidance.CriterionId -ceq 'WSA-WUP-BASE-002' -and
        $public.Findings[0].Guidance.CatalogVersion -ceq '1.0.0+2026.10.24.1' -and $null -eq $public.OverallScore -and
        (Get-WinSecPublicHistoryJson $copy.PublicResult) -ceq (Get-WinSecPublicHistoryJson $public) -and
        $json -notmatch 'PRIVATE-WU|"Evidence"|PolicyRegistry|VersionRegistry|AutomationPolicy|NamedPolicy|WindowsUpdateReference|ObservedValue')
}
Test-WinSecWUAssessmentIntegration 'Current criteria/reference files and providers are never reopened when restoring a public result' {
    $f=New-WinSecWindowsUpdateAssessmentFixture;$r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
    $record=New-WinSecPublicHistoryRecord (New-WinSecWindowsUpdateAssessmentSession $f $r)
    function Get-WinSecWindowsUpdateReferenceCatalog {throw 'Unexpected reference reload.'}
    function Get-WinSecWindowsUpdateCriteriaTemplate {throw 'Unexpected criteria reload.'}
    function Get-WinSecConfigurationScoringPolicy {throw 'Unexpected scoring reload.'}
    function Get-CimInstance {throw 'Unexpected provider read.'}
    $copy=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    Assert-WinSecWUAssessmentIntegration ($copy.PublicResult.ConfigurationAssessment.Controls[0].Value -eq 100 -and -not $copy.PublicResult.ContainsRawEvidence)
}
Test-WinSecWUAssessmentIntegration 'Existing control and Findings consumers receive the actual three criterion states' {
    $script:WU.Services[0].StartMode='Disabled'
    $f=New-WinSecWindowsUpdateAssessmentFixture;$r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
    $public=ConvertTo-WinSecPublicScanResult (New-WinSecWindowsUpdateAssessmentSession $f $r)
    $state=New-WinSecNavigationState;$state.Screen='Findings';$state.SelectedDeviceId=$public.DeviceId;$state.FindingsScope='Control';$state.ControlIndex=2
    $key='{0}:{1}{2}:{3}' -f $public.DeviceId.Length,$public.DeviceId,$public.ScanId.Length,$public.ScanId
    $context=[pscustomobject]@{ProjectRoot=$root;PublicScans=@{$key=$public};ActiveScanByDevice=@{};
        ActiveScanByScope=@{(Get-WinSecCLIScopeKey $public.DeviceId CONTROL WSA-SYS-003)=$public.ScanId}}
    $active=Get-WinSecCLIActiveAssessment $state $context
    $rows=@(Get-WinSecResultsControlRows -SectionKey SystemSecurity -NavigationState $state -ControlResults $active.ControlResults -ConfigurationAssessment $active.ConfigurationAssessment)
    $view=Get-WinSecSelectedFindings $state -ControlResults $active.ControlResults -Findings $active.Findings -ScanId $active.ScanId -ConfigurationAssessment $active.ConfigurationAssessment
    Assert-WinSecWUAssessmentIntegration (@($rows|Where-Object {$_.CheckId -ceq 'WSA-SYS-003' -and $_.Score -ceq '85/100'}).Count -eq 1 -and $view.CheckRows.Count -eq 3)
    $selection=Get-WinSecCLIFindingsExportSelection $state $context
    foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
        $report=New-WinSecFindingsMarkdown $selection -FrameworkId $framework
        Assert-WinSecWUAssessmentIntegration ($report.Markdown.Contains((ConvertTo-WinSecMarkdownText 'WSA-WUP-BASE-001')) -and
            $report.Markdown.Contains('85/100') -and $report.Markdown -notmatch 'PRIVATE-WU|PolicyRegistry|NamedPolicy')
    }
}
foreach($fault in @('Service','Revision','Restart','Support','ReferenceDigest','CollectionStatus','SessionTime')) {
    Test-WinSecWUAssessmentIntegration ('Publication independently rejects a changed scored source: '+$fault) {
        $f=New-WinSecWindowsUpdateAssessmentFixture;$r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
        $session=New-WinSecWindowsUpdateAssessmentSession $f $r
        $null=ConvertTo-WinSecPublicScanResult $session # Prove the original is publishable first.
        $e=$session.ControlResults[0].Evidence
        switch($fault) {
            Service {$e.UpdateService.StartMode='DISABLED'};Revision {$e.VersionRegistry.UBR.Value=9000}
            Restart {$e.RestartInformation.Value=$true};Support {$e.Platform.OperatingSystemSKU=4}
            ReferenceDigest {$session.CriteriaSelections[0].EligibleCriteria[0].WindowsUpdateReference.ContentSha256='F'*64}
            CollectionStatus {$session.ControlResults[0].Status='ERROR'}
            SessionTime {$e.CollectedAtUTC='2026-10-25T12:00:00Z'}
        }
        Assert-WinSecWUAssessmentRejected {ConvertTo-WinSecPublicScanResult $session}
    }
}
Test-WinSecWUAssessmentIntegration 'A deviation cannot retain guidance after its original policy evidence changes' {
    $script:WU.Services[0].StartMode='Disabled'
    $f=New-WinSecWindowsUpdateAssessmentFixture;$r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
    $session=New-WinSecWindowsUpdateAssessmentSession $f $r;$null=ConvertTo-WinSecPublicScanResult $session
    $session.ConfigurationAssessment=$null # Guidance must independently validate even without a score.
    $session.ControlResults[0].Evidence.UpdateService.StartMode='MANUAL'
    Assert-WinSecWUAssessmentRejected {ConvertTo-WinSecPublicScanResult $session}
}
Test-WinSecWUAssessmentIntegration 'Caller catalog mutation cannot rewrite an existing session' {
    $f=New-WinSecWindowsUpdateAssessmentFixture;$r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
    $session=New-WinSecWindowsUpdateAssessmentSession $f $r;$before=Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult $session)
    $f.Catalogs['WSA-SYS-003'].Catalog.Criteria[0].WindowsUpdateReference.Catalog.ValidUntilUTC='2026-10-24T01:00:00Z'
    $f.Audit.ControlResults[0].Evidence.UpdateService.StartMode='DISABLED'
    Assert-WinSecWUAssessmentIntegration ($before -ceq (Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult $session)))
}
Test-WinSecWUAssessmentIntegration 'Installing criteria grants no production execution permission or automatic audit' {
    Reset-WinSecWindowsUpdateFixture
    $registry=Get-WinSecCheckRegistry $root;$check=Get-WinSecRegisteredCheck $registry WSA-SYS-003
    Assert-WinSecWUAssessmentRejected {Get-WinSecAuditImplementation $check $root}
    Assert-WinSecWUAssessmentIntegration (-not $check.ExecutionEnabled -and -not $check.ExecutionReady -and
        ($script:WU.IdentityReads+$script:WU.CimReads+$script:WU.KeyReads+$script:WU.VersionReads+$script:WU.RebootReads+$script:WU.NamedPolicyReads) -eq 0)
}
Write-Host ('Windows Update assessment integration: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Windows Update assessment integration failed.'}
