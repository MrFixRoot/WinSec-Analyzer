# Real selection/evaluation/scoring/history, synthetic criterion exclusions and evidence only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
$registry=Get-WinSecCheckRegistry $root;$policy=Get-WinSecConfigurationScoringPolicy $root
$script:passed=0;$script:failed=0
function Assert-WinSecApplicability {param([bool]$Condition);if(-not $Condition){throw 'Configuration applicability assertion failed.'}}
function Assert-WinSecApplicabilityRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecApplicability $caught}
function New-WinSecApplicabilityFixture {
    $snapshot=Get-WinSecAssessmentCatalog $root WSA-SYS-001 -Profile WSA-W11-24H2-PRO-DEF-BASE
    $snapshot.Sha256='E'*64 # In-memory synthetic catalog, never installed.
    $context=[pscustomobject]@{DeviceId='local:APPLICABILITY';ScanId='applicability-1';OSFamily='Windows';
        OSRelease='Windows 11 10.0.26100';Edition='SKU:48';Profile='WSA-W11-24H2-PRO-DEF-BASE'}
    $collector=[pscustomobject]@{DeviceId=$context.DeviceId;ScanId=$context.ScanId;CheckId='WSA-SYS-001';SectionKey='SystemSecurity';
        Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';Evidence=[pscustomobject]@{DeviceId=$context.DeviceId;ScanId=$context.ScanId;
            CheckId='WSA-SYS-001';CollectionSuccessful=$true;DefenderStatus=[pscustomobject]@{AMRunningMode='Normal';
                AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$false;BehaviorMonitorEnabled=$true};
            ConfigurationModes=[pscustomobject]@{Pua='BLOCK';Cloud='ENABLED';Tamper='ENABLED';AsrVulnerableDriver='BLOCK'}}}
    [pscustomobject]@{Context=$context;Snapshot=$snapshot;Collector=$collector}
}
function Add-WinSecSyntheticExclusion {
    param($Fixture,[int]$Index=6)
    $Fixture.Snapshot.Catalog.Criteria[$Index]|Add-Member NotApplicableTargets @([pscustomobject]@{
        OSRelease=$Fixture.Context.OSRelease;Edition=$Fixture.Context.Edition;
        Reason='Synthetic unsupported feature on this exact build and SKU.';SourceUrl='https://example.invalid/synthetic-applicability'})
}
function Invoke-WinSecApplicabilityFixture {
    param($Fixture,[object]$Policy=$policy)
    $audit=[pscustomobject]@{DeviceId=$Fixture.Context.DeviceId;ScanId=$Fixture.Context.ScanId;CatalogVersion=$registry.CatalogVersion;ControlResults=@($Fixture.Collector)}
    $catalogs=@{'WSA-SYS-001'=$Fixture.Snapshot}
    $assessment=Invoke-WinSecScanAssessment -AuditResult $audit -ProjectRoot $root -TargetContext $Fixture.Context -CatalogSnapshots $catalogs
    $summary=New-WinSecConfigurationAssessment $audit $assessment $Fixture.Context $registry $catalogs $Policy CONTROL WSA-SYS-001 $root
    [pscustomobject]@{Audit=$audit;Assessment=$assessment;Summary=$summary}
}
function Test-WinSecApplicability {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-WinSecApplicability 'Six PASS, one FAIL and one verified exclusion yield 85.71 instead of NOT_SCORED' {
    $f=New-WinSecApplicabilityFixture;Add-WinSecSyntheticExclusion $f;$f.Collector.Evidence.ConfigurationModes.Tamper=$null
    $r=Invoke-WinSecApplicabilityFixture $f;$c=$r.Summary.Controls[0]
    Assert-WinSecApplicability ($c.Value -eq 85.71 -and $c.Coverage -eq 100 -and $c.TotalCriteria -eq 8 -and $c.EvaluatedCriteria -eq 7 -and
        $c.Criteria[6].Status -ceq 'NOT_APPLICABLE' -and $c.Criteria[6].ApplicabilityReason -like 'Synthetic*' -and $r.Assessment.Findings.Count -eq 1)
    $rows=@(Get-WinSecConfigurationRows $r.Summary CONTROL WSA-SYS-001)
    Assert-WinSecApplicability ($rows.Count -eq 8 -and $rows[6].ConfigurationPercent -ceq 'EXCLUDED' -and $rows[6].Description -like 'Synthetic*')
}
Test-WinSecApplicability 'Exclusion matching follows the existing case-insensitive platform contract' {
    $f=New-WinSecApplicabilityFixture;Add-WinSecSyntheticExclusion $f
    $f.Context.OSFamily='windows';$f.Context.OSRelease=$f.Context.OSRelease.ToLowerInvariant();$f.Context.Edition='sku:48'
    Assert-WinSecApplicability ((Invoke-WinSecApplicabilityFixture $f).Summary.Controls[0].Value -eq 85.71)
}
Test-WinSecApplicability 'A safe long applicability source retains the same 1024-character limit as other criterion sources' {
    $f=New-WinSecApplicabilityFixture;Add-WinSecSyntheticExclusion $f
    $f.Snapshot.Catalog.Criteria[6].NotApplicableTargets[0].SourceUrl='https://example.invalid/'+('a'*300)
    Assert-WinSecApplicability ((Invoke-WinSecApplicabilityFixture $f).Summary.Controls[0].Value -eq 85.71)
}
Test-WinSecApplicability 'Excluding a failed criterion neither fails nor counts it as PASS' {
    $f=New-WinSecApplicabilityFixture;Add-WinSecSyntheticExclusion $f 2;$r=Invoke-WinSecApplicabilityFixture $f
    Assert-WinSecApplicability ($r.Summary.Controls[0].Value -eq 100 -and $r.Assessment.Findings.Count -eq 0 -and
        $r.Assessment.EvaluationResults[0].PassedCriteria -eq 7 -and $r.Assessment.EvaluationResults[0].NotApplicableCriteria -eq 1)
}
Test-WinSecApplicability 'Missing telemetry without an explicit exclusion remains UNKNOWN and blocks the grade' {
    $f=New-WinSecApplicabilityFixture;$f.Collector.Evidence.ConfigurationModes.Tamper=$null;$r=Invoke-WinSecApplicabilityFixture $f
    Assert-WinSecApplicability ($null -eq $r.Summary.Controls[0].Value -and $r.Summary.Controls[0].Criteria[6].Status -ceq 'UNKNOWN')
}
foreach($field in @('OSRelease','Edition')) {
    Test-WinSecApplicability ('An exclusion for a different platform cannot hide missing telemetry: '+$field) {
        $f=New-WinSecApplicabilityFixture;Add-WinSecSyntheticExclusion $f
        $entry=$f.Snapshot.Catalog.Criteria[6].NotApplicableTargets[0]
        $entry.$field=if($field -ceq 'Edition'){'SKU:4'}else{'Windows 11 10.0.22631'}
        $f.Collector.Evidence.ConfigurationModes.Tamper=$null;$r=Invoke-WinSecApplicabilityFixture $f
        Assert-WinSecApplicability ($null -eq $r.Summary.Controls[0].Value -and $r.Summary.Controls[0].Criteria[6].Status -ceq 'UNKNOWN')
    }
}
Test-WinSecApplicability 'A wrong selected profile remains blocked rather than yielding a reduced grade' {
    $f=New-WinSecApplicabilityFixture;Add-WinSecSyntheticExclusion $f;$f.Context.OSRelease='Windows 11 10.0.22631'
    $r=Invoke-WinSecApplicabilityFixture $f
    Assert-WinSecApplicability ($null -eq $r.Summary.Controls[0].Value -and $r.Summary.Controls[0].Permission -ceq 'UNAVAILABLE')
}
Test-WinSecApplicability 'Only a verified excluded criterion can skip its own irrelevant prerequisite' {
    $f=New-WinSecApplicabilityFixture;Add-WinSecSyntheticExclusion $f
    $f.Snapshot.Catalog.Criteria[6].ActivationDependencies=@('synthetic-unsupported-feature')
    $r=Invoke-WinSecApplicabilityFixture $f
    Assert-WinSecApplicability ($r.Summary.Controls[0].Value -eq 85.71)
    $f.Snapshot.Catalog.Criteria[5].ActivationDependencies=@('synthetic-unsupported-feature')
    $r=Invoke-WinSecApplicabilityFixture $f
    Assert-WinSecApplicability ($null -eq $r.Summary.Controls[0].Value)
}
Test-WinSecApplicability 'All excluded criteria produce NOT_APPLICABLE without an invented 100 or zero' {
    $f=New-WinSecApplicabilityFixture;foreach($i in 0..7){Add-WinSecSyntheticExclusion $f $i}
    $r=Invoke-WinSecApplicabilityFixture $f
    Assert-WinSecApplicability ($null -eq $r.Summary.Controls[0].Value -and $r.Summary.Controls[0].Status -ceq 'NOT_APPLICABLE' -and
        (Get-WinSecConfigurationScoreText $r.Summary CONTROL WSA-SYS-001) -ceq 'NOT_APPLICABLE' -and $r.Assessment.Findings.Count -eq 0)
}
foreach($fault in @('Wildcard','Scalar','Duplicate','NoReason','UnsafeSource','ExtraField')) {
    Test-WinSecApplicability ('Malformed exclusion metadata fails closed: '+$fault) {
        $f=New-WinSecApplicabilityFixture;Add-WinSecSyntheticExclusion $f;$rule=$f.Snapshot.Catalog.Criteria[6];$entry=$rule.NotApplicableTargets[0]
        switch($fault){Wildcard {$entry.OSRelease='*'};Scalar {$rule.NotApplicableTargets=$entry};Duplicate {$rule.NotApplicableTargets+=@($entry)};
            NoReason {$entry.Reason=''};UnsafeSource {$entry.SourceUrl='file:///private'};ExtraField {$entry|Add-Member RawEvidence 'PRIVATE'}}
        Assert-WinSecApplicability (-not (Test-WinSecCriteriaCatalog $f.Snapshot.Catalog).ReadyForScoring)
        Assert-WinSecApplicability (-not (Test-WinSecEvaluationCriterion $rule).Valid)
    }
}
Test-WinSecApplicability 'Unapproved exclusion criteria cannot be released for scoring' {
    $f=New-WinSecApplicabilityFixture;Add-WinSecSyntheticExclusion $f;$f.Snapshot.Catalog.Criteria[6].Approved=$false
    Assert-WinSecApplicability (-not (Test-WinSecCriteriaCatalog $f.Snapshot.Catalog).ReadyForScoring)
    $r=Invoke-WinSecApplicabilityFixture $f;Assert-WinSecApplicability ($null -eq $r.Summary)
}
Test-WinSecApplicability 'Section denominator excludes only fully nonapplicable controls and uses original fractions' {
    $controls=@([pscustomobject]@{Status='COMPLETE';Criteria=@([pscustomobject]@{Status='PASS'},[pscustomobject]@{Status='FAIL'},[pscustomobject]@{Status='NOT_APPLICABLE'})},
        [pscustomobject]@{Status='NOT_APPLICABLE';Criteria=@([pscustomobject]@{Status='NOT_APPLICABLE'})})
    $r=Get-WinSecConfigurationSectionTotals $controls '1.1.0'
    Assert-WinSecApplicability ($r.Value -eq 50 -and $r.Coverage -eq 100 -and $r.TotalControls -eq 2)
    $controls[1].Status='NOT_SCORED';Assert-WinSecApplicability ($null -eq (Get-WinSecConfigurationSectionTotals $controls '1.1.0').Value)
}
Test-WinSecApplicability 'Legacy method 1.0 rejects exclusions and retains its original arithmetic' {
    $f=New-WinSecApplicabilityFixture;$legacy=Copy-WinSecResultData $policy;$legacy.Policy.methodologyVersion='1.0.0'
    $old=Invoke-WinSecApplicabilityFixture $f $legacy
    Assert-WinSecApplicability ($old.Summary.Controls[0].Value -eq 87.5 -and $old.Summary.MethodologyVersion -ceq '1.0.0')
    $changed=Copy-WinSecResultData $old.Summary;$changed.Controls[0].Criteria[6].Status='NOT_APPLICABLE'
    Assert-WinSecApplicabilityRejected {ConvertTo-WinSecPublicConfigurationAssessment $changed $changed}
}
Test-WinSecApplicability 'New exclusions survive canonical public history with reason and source and no raw evidence' {
    $f=New-WinSecApplicabilityFixture;Add-WinSecSyntheticExclusion $f;$r=Invoke-WinSecApplicabilityFixture $f
    $session=New-WinSecResultSession -DeviceId $f.Context.DeviceId -ScanId $f.Context.ScanId -ScopeType CONTROL -ScopeKey WSA-SYS-001 `
        -ControlResults @($f.Collector) -EvaluationResults $r.Assessment.EvaluationResults -CriteriaSelections $r.Assessment.CriteriaSelections `
        -Findings $r.Assessment.Findings -ConfigurationAssessment $r.Summary -ExpectedCheckIds @('WSA-SYS-001') -CatalogVersion $registry.CatalogVersion `
        -ExecutionStatus COMPLETED -StartedAtUTC '2026-10-22T00:00:00Z' -CompletedAtUTC '2026-10-22T00:01:00Z'
    $record=New-WinSecPublicHistoryRecord $session
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    Assert-WinSecApplicability ($restored.PublicResult.ConfigurationAssessment.Controls[0].Value -eq 85.71 -and
        $restored.PublicResult.ConfigurationAssessment.Controls[0].Criteria[6].ApplicabilitySourceUrl -ceq 'https://example.invalid/synthetic-applicability')
    $bad=Copy-WinSecResultData $r.Summary;$bad.Controls[0].Criteria[6].ApplicabilityReason='forged'
    Assert-WinSecApplicabilityRejected {Assert-WinSecConfigurationProvenance $session $bad}
}
Write-Host ('Configuration applicability: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Configuration applicability failed.'}
