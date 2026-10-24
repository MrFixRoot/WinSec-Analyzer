# Requires WindowsUpdateMemory providers, loaded AFTER product definitions.
# No permission/catalog enabling. Only the isolated score-policy copy is 1.2.0.
function New-WinSecWindowsUpdateAssessmentFixture {
    param([string]$Profile='WSA-W11-25H2-PRO-DEF-BASE')
    $project=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $registry=Get-WinSecCheckRegistry $project
    $snapshot=Get-WinSecAssessmentCatalog $project WSA-SYS-003 -Profile $Profile
    $scope=$snapshot.Catalog.Criteria[0].Applicability
    $raw=Test-WinSecWindowsUpdate -DeviceId $script:WU.DeviceId -ScanId wu-assessment-1 -CheckId WSA-SYS-003
    $raw.Evidence.CollectedAtUTC='2026-10-24T12:00:00Z'
    $control=ConvertTo-WinSecAuditRecord -RawResult $raw -Check (Get-WinSecRegisteredCheck $registry WSA-SYS-003) `
        -DeviceId $raw.DeviceId -ScanId $raw.ScanId
    $context=[pscustomobject]@{DeviceId=$raw.DeviceId;ScanId=$raw.ScanId;OSFamily=$scope.OSFamily;
        OSRelease=$scope.OSRelease;Edition=$scope.Edition;Profile=$Profile}
    $policy=Copy-WinSecResultData (Get-WinSecConfigurationScoringPolicy $project)
    $policy.Policy.methodologyVersion='1.2.0';$policy.Policy.controlMethod='WEIGHTED_PASS_CRITERIA_FRACTION';$policy.Sha256='E'*64
    [pscustomobject]@{Root=$project;Registry=$registry;Context=$context;Policy=$policy;Catalogs=@{'WSA-SYS-003'=$snapshot}
        Audit=[pscustomobject]@{DeviceId=$raw.DeviceId;ScanId=$raw.ScanId;CatalogVersion=$registry.CatalogVersion;ControlResults=@($control)}}
}
function Invoke-WinSecWindowsUpdateAssessmentFixture {
    param([object]$Fixture)
    $f=$Fixture
    $assessment=Invoke-WinSecScanAssessment -AuditResult $f.Audit -ProjectRoot $f.Root -TargetContext $f.Context -CatalogSnapshots $f.Catalogs
    $summary=New-WinSecConfigurationAssessment -Audit $f.Audit -Assessment $assessment -Context $f.Context -Registry $f.Registry `
        -Catalogs $f.Catalogs -PolicySnapshot $f.Policy -ScopeType CONTROL -ScopeKey WSA-SYS-003 -ProjectRoot $f.Root
    [pscustomobject]@{Assessment=$assessment;Summary=$summary}
}
function New-WinSecWindowsUpdateAssessmentSession {
    param([object]$Fixture,[object]$Result)
    $f=$Fixture;$r=$Result
    New-WinSecResultSession -DeviceId $f.Context.DeviceId -ScanId $f.Context.ScanId -ScopeType CONTROL -ScopeKey WSA-SYS-003 `
        -ExpectedCheckIds @('WSA-SYS-003') -ControlResults $f.Audit.ControlResults -EvaluationResults $r.Assessment.EvaluationResults `
        -CriteriaSelections $r.Assessment.CriteriaSelections -Findings $r.Assessment.Findings -ConfigurationAssessment $r.Summary `
        -CatalogVersion $f.Registry.CatalogVersion -ExecutionStatus COMPLETED `
        -StartedAtUTC '2026-10-24T11:59:00Z' -CompletedAtUTC '2026-10-24T12:01:00Z'
}
function Set-WinSecWindowsUpdateSupportedFixture {
    $script:WU.Systems[0].Version='10.0.26200';$script:WU.Systems[0].BuildNumber='26200'
    $script:WU.VersionValues.CurrentBuildNumber='26200'
}
