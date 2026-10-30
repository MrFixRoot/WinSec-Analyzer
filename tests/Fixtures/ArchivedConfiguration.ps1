# Prepared archival compatibility fixture. Never changes coordinator/scoring flags.
# Exercises the retained historical model independently of the production workflow.
function New-WinSecArchivedExclusionFixture {
    param([string]$ProjectRoot)
    $registry=Get-WinSecCheckRegistry $ProjectRoot
    $snapshot=Get-WinSecAssessmentCatalog $ProjectRoot WSA-SYS-001 -Profile WSA-W11-24H2-PRO-DEF-BASE
    $snapshot=Copy-WinSecResultData $snapshot;$snapshot.Sha256='E'*64
    $id='local:hw1-'+('e'*64);$scan='archived-exclusion'
    $context=[pscustomobject]@{DeviceId=$id;ScanId=$scan;OSFamily='Windows';OSRelease='Windows 11 10.0.26100';Edition='SKU:48';Profile='WSA-W11-24H2-PRO-DEF-BASE'}
    $rule=$snapshot.Catalog.Criteria[6]
    $rule|Add-Member NotApplicableTargets @([pscustomobject]@{OSRelease=$context.OSRelease;Edition=$context.Edition;
        Reason='Synthetic unsupported feature on this exact build and SKU.';SourceUrl='https://example.invalid/synthetic-applicability'})
    $collector=[pscustomobject]@{DeviceId=$id;ScanId=$scan;CheckId='WSA-SYS-001';SectionKey='SystemSecurity';Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';
        TimestampUTC='2026-10-22T00:00:30Z';Evidence=[pscustomobject]@{DeviceId=$id;ScanId=$scan;CheckId='WSA-SYS-001';
            CollectedAtUTC='2026-10-22T00:00:30Z';CollectionSuccessful=$true;
            DefenderStatus=[pscustomobject]@{AMRunningMode='Normal';AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$false;BehaviorMonitorEnabled=$true};
            ConfigurationModes=[pscustomobject]@{Pua='BLOCK';Cloud='ENABLED';Tamper=$null;AsrVulnerableDriver='BLOCK'}}}
    $audit=[pscustomobject]@{DeviceId=$id;ScanId=$scan;CatalogVersion=$registry.CatalogVersion;ControlResults=@($collector)}
    $catalogs=@{'WSA-SYS-001'=$snapshot}
    $assessment=Invoke-WinSecScanAssessment -AuditResult $audit -ProjectRoot $ProjectRoot -TargetContext $context -CatalogSnapshots $catalogs
    $policy=Get-WinSecConfigurationScoringPolicy $ProjectRoot
    $summary=New-WinSecConfigurationAssessment $audit $assessment $context $registry $catalogs $policy CONTROL WSA-SYS-001 $ProjectRoot
    $session=New-WinSecResultSession -DeviceId $id -ScanId $scan -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ExpectedCheckIds @('WSA-SYS-001') `
        -ControlResults @($collector) -EvaluationResults $assessment.EvaluationResults -CriteriaSelections $assessment.CriteriaSelections `
        -Findings $assessment.Findings -ConfigurationAssessment $summary -CatalogVersion $registry.CatalogVersion -ExecutionStatus COMPLETED `
        -StartedAtUTC '2026-10-22T00:00:00Z' -CompletedAtUTC '2026-10-22T00:01:00Z'
    [pscustomobject]@{Session=$session;Report=(New-WinSecTechnicalReport $session WSA-SYS-001 SYNTHETIC SYNTHETIC);
        Source=[pscustomobject]@{CheckId='WSA-SYS-001';ScanId=$scan;ScopeType='CONTROL';ScopeKey='WSA-SYS-001';CompletedAtUTC=$session.CompletedAtUTC;
            Origin='RECORDS';PublicResult=(ConvertTo-WinSecPublicScanResult $session);CatalogVersion=$session.CatalogVersion;ExpectedCheckIds=@('WSA-SYS-001')}}
}
