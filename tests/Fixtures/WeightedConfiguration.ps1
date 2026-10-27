# Synthetic criteria over an existing prerequisite path. No installed catalog or Windows reads.
# The 15/35/50 allocation exercises arithmetic, not operational Windows Update evaluation.
function New-WinSecWeightedConfigurationFixture {
    param([bool[]]$Flags=@($true,$false,$true))
    $project=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $registry=Get-WinSecCheckRegistry $project
    $template=Get-WinSecBaseAssessmentCatalog $project WSA-SYS-001 -Profile WSA-W11-24H2-PRO-DEF-BASE
    $catalog=Copy-WinSecResultData $template.Catalog
    $catalog.CatalogId='SYNTHETIC-WEIGHTED-ARITHMETIC';$catalog.CatalogVersion='0.1.0'
    $catalog.Criteria=@($catalog.Criteria|Select-Object -First 3)
    $names=@('Automatic installation','Security patches within policy deadline','Windows security support')
    $fields=@('Automation','Patches','Support');$weights=@(15,35,50)
    for($i=0;$i -lt 3;$i++) {
        $rule=$catalog.Criteria[$i];$id='SYNTH-WEIGHTED-'+('{0:D3}' -f ($i+1))
        $rule.CriterionId=$id;$rule.Name='Synthetic: '+$names[$i]
        $rule.EvidencePath='SyntheticWindowsUpdate.'+$fields[$i];$rule.ExpectedValue=$true
        $rule.Source.ControlId=$id;$rule.Source.Title='Synthetic weighted configuration fixture'
        $rule.Recommendation='Synthetic manual recommendation; not an installed Windows Update criterion.'
        $rule|Add-Member Weight $weights[$i]
    }
    $context=[pscustomobject]@{DeviceId='local:WEIGHTED-SYNTHETIC';ScanId='weighted-synthetic-1';OSFamily='Windows';
        OSRelease=$catalog.Criteria[0].Applicability.OSRelease;Edition=$catalog.Criteria[0].Applicability.Edition;
        Profile=$catalog.Criteria[0].Applicability.Profile}
    $collector=[pscustomobject]@{DeviceId=$context.DeviceId;ScanId=$context.ScanId;CheckId='WSA-SYS-001';SectionKey='SystemSecurity';
        Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';Evidence=[pscustomobject]@{DeviceId=$context.DeviceId;ScanId=$context.ScanId;
            CheckId='WSA-SYS-001';CollectionSuccessful=$true;DefenderStatus=[pscustomobject]@{AMRunningMode='Normal'};SyntheticWindowsUpdate=[pscustomobject]@{
                Automation=$Flags[0];Patches=$Flags[1];Support=$Flags[2]};Private='PRIVATE-WEIGHTED-EVIDENCE'}}
    $policy=Copy-WinSecResultData (Get-WinSecConfigurationScoringPolicy $project)
    $policy.Policy.methodologyVersion='1.2.0';$policy.Policy.controlMethod='WEIGHTED_PASS_CRITERIA_FRACTION';$policy.Sha256='E'*64
    [pscustomobject]@{Root=$project;Registry=$registry;Context=$context;Policy=$policy;
        Catalogs=@{'WSA-SYS-001'=[pscustomobject]@{Catalog=$catalog;Sha256=('D'*64)}};
        Audit=[pscustomobject]@{DeviceId=$context.DeviceId;ScanId=$context.ScanId;CatalogVersion=$registry.CatalogVersion;ControlResults=@($collector)}}
}
function Invoke-WinSecWeightedConfigurationFixture {
    param([object]$Fixture)
    $f=$Fixture
    $assessment=Invoke-WinSecScanAssessment -AuditResult $f.Audit -ProjectRoot $f.Root -TargetContext $f.Context -CatalogSnapshots $f.Catalogs
    $summary=New-WinSecConfigurationAssessment -Audit $f.Audit -Assessment $assessment -Context $f.Context -Registry $f.Registry `
        -Catalogs $f.Catalogs -PolicySnapshot $f.Policy -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ProjectRoot $f.Root
    [pscustomobject]@{Assessment=$assessment;Summary=$summary}
}
function New-WinSecWeightedConfigurationSession {
    param([object]$Fixture,[object]$Result)
    $f=$Fixture;$r=$Result
    New-WinSecResultSession -DeviceId $f.Context.DeviceId -ScanId $f.Context.ScanId -ScopeType CONTROL -ScopeKey WSA-SYS-001 `
        -ExpectedCheckIds @('WSA-SYS-001') -ControlResults $f.Audit.ControlResults -EvaluationResults $r.Assessment.EvaluationResults `
        -CriteriaSelections $r.Assessment.CriteriaSelections -Findings $r.Assessment.Findings -ConfigurationAssessment $r.Summary `
        -CatalogVersion $f.Registry.CatalogVersion -ExecutionStatus COMPLETED `
        -StartedAtUTC '2026-10-23T00:00:00Z' -CompletedAtUTC '2026-10-23T00:01:00Z'
}
