# Approved installed policy + synthetic evidence. No Windows queries or persistence.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$registry=Get-WinSecCheckRegistry $root
$policy=Get-WinSecConfigurationScoringPolicy $root
$script:passed=0;$script:failed=0
function Assert-WinSecConfig {param([bool]$Value);if(-not $Value){throw 'Configuration score assertion failed.'}}
function Assert-WinSecConfigRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecConfig $caught}
function New-WinSecConfigFixture {
    param([string]$Profile='WSA-W11-24H2-PRO-DEF-BASE',[bool[]]$Flags=@($true,$true,$false,$true),[string]$Mode='Normal')
    # Preserve regression coverage of the immutable four-rule historical policy.
    # The current eight-rule revision has its own scoring/pipeline suites.
    $snapshot=Get-WinSecBaseAssessmentCatalog $root 'WSA-SYS-001' -Profile $Profile
    $rule=$snapshot.Catalog.Criteria[0]
    $context=[pscustomobject]@{DeviceId='local:CONFIG-SYNTHETIC';ScanId='config-synthetic-1';OSFamily='Windows';
        OSRelease=$rule.Applicability.OSRelease;Edition=$rule.Applicability.Edition;Profile=$Profile}
    $control=[pscustomobject]@{DeviceId=$context.DeviceId;ScanId=$context.ScanId;CheckId='WSA-SYS-001';SectionKey='SystemSecurity';
        Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';Evidence=[pscustomobject]@{DeviceId=$context.DeviceId;ScanId=$context.ScanId;
        CheckId='WSA-SYS-001';CollectionSuccessful=$true;DefenderStatus=[pscustomobject]@{AMRunningMode=$Mode;AMServiceEnabled=$Flags[0];
            AntivirusEnabled=$Flags[1];RealTimeProtectionEnabled=$Flags[2];BehaviorMonitorEnabled=$Flags[3]};Secret='PRIVATE-CONFIG-EVIDENCE'}}
    $audit=[pscustomobject]@{DeviceId=$context.DeviceId;ScanId=$context.ScanId;CatalogVersion=$registry.CatalogVersion;ControlResults=@($control)}
    [pscustomobject]@{Context=$context;Audit=$audit;Catalogs=@{'WSA-SYS-001'=$snapshot}}
}
function Get-WinSecConfigFixtureResult {
    param($Fixture,[string]$ScopeType='CONTROL',[string]$ScopeKey='WSA-SYS-001')
    $assessment=Invoke-WinSecScanAssessment -AuditResult $Fixture.Audit -ProjectRoot $root -TargetContext $Fixture.Context -CatalogSnapshots $Fixture.Catalogs
    $summary=New-WinSecConfigurationAssessment -Audit $Fixture.Audit -Assessment $assessment -Context $Fixture.Context -Registry $registry `
        -Catalogs $Fixture.Catalogs -PolicySnapshot $policy -ScopeType $ScopeType -ScopeKey $ScopeKey -ProjectRoot $root
    [pscustomobject]@{Summary=$summary;Assessment=$assessment}
}
function Test-WinSecConfig {
    param([string]$Name,[scriptblock]$Action)
    try {$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch {$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
foreach($profile in @('WSA-W11-24H2-PRO-DEF-BASE','WSA-W11-25H2-ENT-DEF-BASE')) {
    Test-WinSecConfig ('Four approved criteria and independent installed profile: '+$profile) {
        $fixture=New-WinSecConfigFixture -Profile $profile;$result=Get-WinSecConfigFixtureResult $fixture
        Assert-WinSecConfig ($result.Summary.Controls.Count -eq 1 -and $result.Summary.Controls[0].Value -eq 75 -and
            $result.Summary.Controls[0].TotalCriteria -eq 4 -and $result.Summary.Controls[0].Coverage -eq 100 -and
            $result.Summary.Controls[0].Criteria[0].Profile -ceq $profile -and $result.Assessment.Findings.Count -eq 1)
        $text=ConvertTo-Json $result.Summary -Depth 30 -Compress
        Assert-WinSecConfig ($text -notmatch 'PRIVATE-CONFIG-EVIDENCE|DefenderStatus|ObservedValue|ExpectedValue|ReviewedBy|"Evidence"')
    }
}
foreach($spec in @(@{F=@($true,$true,$true,$true);V=100},@{F=@($true,$true,$false,$true);V=75},
    @{F=@($true,$false,$false,$true);V=50},@{F=@($false,$false,$false,$false);V=0})) {
    Test-WinSecConfig ('Gradual score from all four approved criteria: '+$spec.V) {
        $r=Get-WinSecConfigFixtureResult (New-WinSecConfigFixture -Flags $spec.F)
        Assert-WinSecConfig ($r.Summary.Controls[0].Value -eq $spec.V -and $r.Summary.Controls[0].Status -ceq 'COMPLETE')
    }
}
foreach($mode in @('Passive','EDR Block Mode','Unknown','')) {
    Test-WinSecConfig 'Nonactive or missing mode cannot turn disabled telemetry into scores or deviations' {
        $r=Get-WinSecConfigFixtureResult (New-WinSecConfigFixture -Mode $mode)
        Assert-WinSecConfig ($null -eq $r.Summary.Controls[0].Value -and $r.Summary.Controls[0].Status -ceq 'NOT_SCORED' -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
Test-WinSecConfig 'Section retains all three controls including disabled pending controls' {
    $r=Get-WinSecConfigFixtureResult (New-WinSecConfigFixture) SECTION SystemSecurity
    Assert-WinSecConfig ($r.Summary.Controls.Count -eq 3 -and $r.Summary.Controls[0].Value -eq 75 -and
        $null -eq $r.Summary.Sections[0].Value -and $r.Summary.Sections[0].CompleteControls -eq 1 -and
        $r.Summary.Sections[0].TotalControls -eq 3 -and $r.Summary.Sections[0].Coverage -eq 33.33)
}
Test-WinSecConfig 'A control scan never publishes a section result' {
    $r=Get-WinSecConfigFixtureResult (New-WinSecConfigFixture)
    Assert-WinSecConfig ($r.Summary.Sections.Count -eq 0 -and (Get-WinSecConfigurationScoreText $r.Summary SECTION SystemSecurity) -ceq 'NOT_SCORED')
}
foreach($mutation in @(
    {param($s);$s.Controls[0].Value=100}, {param($s);$s.Controls[0].Coverage=0},
    {param($s);$s.Controls[0].Criteria[0].Status='UNKNOWN'}, {param($s);$s.Controls[0].Criteria[0].SourceUrl='file:///private'},
    {param($s);$s.DeviceId='local:FOREIGN'}, {param($s);$s.Controls+=@($s.Controls[0])},
    {param($s);$s.Controls[0].Criteria+=@($s.Controls[0].Criteria[0])},
    {param($s);$s.Controls[0].Criteria[0]|Add-Member -NotePropertyName Evidence -NotePropertyValue 'PRIVATE-CONFIG-EVIDENCE'},
    {param($s);$s.MethodologyId=@()}, {param($s);$s.MethodologyVersion=@()}, {param($s);$s.SchemaVersion=@()},
    {param($s);$s.Controls[0].Permission=@()}, {param($s);$s.Controls[0].Criteria[0].SourceControlId='NOT_ASSIGNED'}
)) {
    Test-WinSecConfig 'Tampered totals, identity, duplicate criteria and raw fields fail closed' {
        $original=(Get-WinSecConfigFixtureResult (New-WinSecConfigFixture)).Summary
        $changed=Copy-WinSecResultData $original;& $mutation $changed
        Assert-WinSecConfigRejected {ConvertTo-WinSecPublicConfigurationAssessment $changed $original}
    }
}
Test-WinSecConfig 'Public session and history retain all criteria, original recommendations and exact score' {
    $fixture=New-WinSecConfigFixture;$r=Get-WinSecConfigFixtureResult $fixture
    $session=New-WinSecResultSession -DeviceId $fixture.Audit.DeviceId -ScanId $fixture.Audit.ScanId -ScopeType CONTROL -ScopeKey WSA-SYS-001 `
        -ControlResults $fixture.Audit.ControlResults -EvaluationResults $r.Assessment.EvaluationResults -CriteriaSelections $r.Assessment.CriteriaSelections `
        -Findings $r.Assessment.Findings -ConfigurationAssessment $r.Summary -ExpectedCheckIds @('WSA-SYS-001') -CatalogVersion $registry.CatalogVersion `
        -ExecutionStatus COMPLETED -StartedAtUTC '2026-10-21T00:00:00Z' -CompletedAtUTC '2026-10-21T00:01:00Z'
    $record=New-WinSecPublicHistoryRecord $session
    $decoded=ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record)
    $restored=ConvertFrom-WinSecPublicHistoryRecord $decoded
    Assert-WinSecConfig ($restored.PublicResult.ConfigurationAssessment.Controls[0].Value -eq 75 -and
        $restored.PublicResult.ConfigurationAssessment.Controls[0].Criteria.Count -eq 4 -and $null -eq $restored.PublicResult.OverallScore)
}
Test-WinSecConfig 'Section means weight controls equally and use original fractions' {
    $controls=@(foreach($count in @(3,4,2)) {
        $criteria=@(for($i=0;$i -lt $count;$i++){[pscustomobject]@{Status=if($i -eq 0){'FAIL'}else{'PASS'}}})
        [pscustomobject]@{Status='COMPLETE';Criteria=$criteria}
    })
    $totals=Get-WinSecConfigurationSectionTotals $controls
    Assert-WinSecConfig ($totals.Value -eq 63.89 -and $totals.Coverage -eq 100)
}
Test-WinSecConfig 'Getter-based or cross-device configuration data is rejected before scoring' {
    $fixture=New-WinSecConfigFixture;$fixture.Context.DeviceId='local:OTHER'
    Assert-WinSecConfigRejected {Get-WinSecConfigFixtureResult $fixture}
    $fixture=New-WinSecConfigFixture;$script:configGetterCalls=0
    $fixture.Audit|Add-Member -MemberType ScriptProperty -Name Extra -Value {$script:configGetterCalls++;throw 'PRIVATE-GETTER'}
    Assert-WinSecConfigRejected {Get-WinSecConfigFixtureResult $fixture}
    Assert-WinSecConfig ($script:configGetterCalls -eq 0)
}
Test-WinSecConfig 'A declared false prerequisite cannot be overridden by the scoring calculation' {
    $fixture=New-WinSecConfigFixture
    $assessment=Invoke-WinSecScanAssessment -AuditResult $fixture.Audit -ProjectRoot $root -TargetContext $fixture.Context `
        -CatalogSnapshots $fixture.Catalogs -DependencyEvidence @{'WSA-SYS-001'=@{'active-antivirus-mode'=$false}}
    $summary=New-WinSecConfigurationAssessment -Audit $fixture.Audit -Assessment $assessment -Context $fixture.Context -Registry $registry `
        -Catalogs $fixture.Catalogs -PolicySnapshot $policy -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ProjectRoot $root
    Assert-WinSecConfig ($null -eq $summary.Controls[0].Value -and $summary.Controls[0].Permission -ceq 'UNAVAILABLE')
}
Write-Host ('Configuration scoring: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Configuration scoring tests failed.'}
