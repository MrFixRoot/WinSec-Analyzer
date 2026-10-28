# Versioned weighted arithmetic and provenance. All evidence is synthetic.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'tests/Fixtures/WeightedConfiguration.ps1')
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
$script:passed=0;$script:failed=0
function Assert-WinSecWeighted {param([bool]$Value);if(-not $Value){throw 'Weighted configuration assertion failed.'}}
function Assert-WinSecWeightedRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecWeighted $caught}
function Test-WinSecWeighted {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function Get-WinSecWeightedPolicyFixture {
    param([string]$Version,[string]$Method)
    $data=ConvertFrom-WinSecStoredJson (Microsoft.PowerShell.Management\Get-Content (Join-Path $root 'config/scoring.json') -Raw -Encoding UTF8)
    $data.configurationScoring.methodologyVersion=$Version;$data.configurationScoring.controlMethod=$Method
    $policyJson=ConvertTo-Json $data -Depth 32
    function Get-Content {
        [CmdletBinding()]param([string]$LiteralPath,[switch]$Raw,[string]$Encoding)
        if($LiteralPath -cne (Join-Path $root 'config/scoring.json')){throw 'Unexpected policy fixture read.'}
        return $policyJson
    }
    Get-WinSecConfigurationScoringPolicy $root
}
foreach($version in @('1.0.0','1.1.0','1.2.0')) {
    Test-WinSecWeighted ('Scoring policy reader accepts only the matching version/method pair: '+$version) {
        $method=if($version -ceq '1.2.0'){'WEIGHTED_PASS_CRITERIA_FRACTION'}else{'PASS_CRITERIA_FRACTION'}
        $p=Get-WinSecWeightedPolicyFixture $version $method
        Assert-WinSecWeighted ($p.Policy.methodologyVersion -ceq $version -and $p.Policy.controlMethod -ceq $method)
    }
}
Test-WinSecWeighted 'Mismatched or unknown scoring policy methods fail closed' {
    Assert-WinSecWeightedRejected {Get-WinSecWeightedPolicyFixture '1.2.0' 'PASS_CRITERIA_FRACTION'}
    Assert-WinSecWeightedRejected {Get-WinSecWeightedPolicyFixture '1.1.0' 'WEIGHTED_PASS_CRITERIA_FRACTION'}
    Assert-WinSecWeightedRejected {Get-WinSecWeightedPolicyFixture '9.0.0' 'WEIGHTED_PASS_CRITERIA_FRACTION'}
}
foreach($mask in 0..7) {
    Test-WinSecWeighted ('All 15/35/50 combinations use the approved point allocation: '+$mask) {
        $flags=@([bool]($mask -band 1),[bool]($mask -band 2),[bool]($mask -band 4))
        $expected=15*[int]$flags[0]+35*[int]$flags[1]+50*[int]$flags[2]
        $r=Invoke-WinSecWeightedConfigurationFixture (New-WinSecWeightedConfigurationFixture $flags)
        $control=$r.Summary.Controls[0]
        Assert-WinSecWeighted ($control.Value -eq $expected -and $control.Status -ceq 'COMPLETE' -and $control.Coverage -eq 100 -and
            ($control.Criteria.Weight -join ',') -ceq '15,35,50' -and $r.Summary.MethodologyVersion -ceq '1.2.0' -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq @($flags|Where-Object {-not $_}).Count)
    }
}
foreach($field in @('Automation','Patches','Support')) {
    Test-WinSecWeighted ('Unknown applicable evidence never contributes zero or allows a partial note: '+$field) {
        $f=New-WinSecWeightedConfigurationFixture @($true,$true,$true)
        $f.Audit.ControlResults[0].Evidence.SyntheticWindowsUpdate.$field=$null
        $r=Invoke-WinSecWeightedConfigurationFixture $f;$c=$r.Summary.Controls[0]
        Assert-WinSecWeighted ($null -eq $c.Value -and $c.Status -ceq 'NOT_SCORED' -and $c.Coverage -eq 66.67 -and
            @($c.Criteria|Where-Object Status -CEQ UNKNOWN).Count -eq 1 -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
Test-WinSecWeighted 'A verified exclusion removes its weight from the denominator without becoming PASS' {
    $f=New-WinSecWeightedConfigurationFixture @($true,$false,$false)
    $f.Catalogs['WSA-SYS-001'].Catalog.Criteria[2]|Add-Member NotApplicableTargets @([pscustomobject]@{
        OSRelease=$f.Context.OSRelease;Edition=$f.Context.Edition;Reason='Synthetic exclusion only.';SourceUrl='https://example.invalid/weighted-exclusion'})
    $r=Invoke-WinSecWeightedConfigurationFixture $f;$c=$r.Summary.Controls[0]
    Assert-WinSecWeighted ($c.Value -eq 30 -and $c.Coverage -eq 100 -and $c.EvaluatedCriteria -eq 2 -and
        $c.TotalCriteria -eq 3 -and $c.Criteria[2].Status -ceq 'NOT_APPLICABLE' -and $c.Criteria[2].Weight -eq 50)
}
Test-WinSecWeighted 'All excluded weighted criteria produce NOT_APPLICABLE without a numeric score' {
    $f=New-WinSecWeightedConfigurationFixture
    foreach($rule in $f.Catalogs['WSA-SYS-001'].Catalog.Criteria) {
        $rule|Add-Member NotApplicableTargets @([pscustomobject]@{OSRelease=$f.Context.OSRelease;Edition=$f.Context.Edition;
            Reason='Synthetic exclusion only.';SourceUrl='https://example.invalid/weighted-exclusion'})
    }
    $c=(Invoke-WinSecWeightedConfigurationFixture $f).Summary.Controls[0]
    Assert-WinSecWeighted ($null -eq $c.Value -and $null -eq $c.Coverage -and $c.Status -ceq 'NOT_APPLICABLE')
}
foreach($bad in @($null,$true,'15',0,-1,101,1.5,[double]15,@(15),[uint64]::MaxValue)) {
    Test-WinSecWeighted 'Malformed weight metadata is rejected by catalog and public manifest validation' {
        $f=New-WinSecWeightedConfigurationFixture;$f.Catalogs['WSA-SYS-001'].Catalog.Criteria[0].Weight=$bad
        Assert-WinSecWeighted (-not (Test-WinSecCriteriaCatalog $f.Catalogs['WSA-SYS-001'].Catalog).ReadyForScoring)
        Assert-WinSecWeightedRejected {Get-WinSecCriterionWeight $f.Catalogs['WSA-SYS-001'].Catalog.Criteria[0]}
        $r=Invoke-WinSecWeightedConfigurationFixture (New-WinSecWeightedConfigurationFixture)
        $r.Summary.Controls[0].Criteria[0].Weight=$bad
        Assert-WinSecWeightedRejected {ConvertTo-WinSecPublicConfigurationAssessment $r.Summary $r.Summary}
    }
}
Test-WinSecWeighted 'A legacy catalog defaults to equal unit weights only when no weight field is declared' {
    Assert-WinSecWeighted ((Get-WinSecCriterionWeight ([pscustomobject]@{CriterionId='fixture'})) -eq 1)
    Assert-WinSecWeightedRejected {Get-WinSecCriterionWeight ([pscustomobject]@{CriterionId='fixture'}) -Required}
    Assert-WinSecWeighted ((Get-WinSecCriterionWeight @{Weight=[uint32]35}) -eq 35)
}
Test-WinSecWeighted 'A getter cannot supply an approved weight' {
    $script:weightReads=0;$rule=[pscustomobject]@{}
    $rule|Add-Member -MemberType ScriptProperty -Name Weight -Value {$script:weightReads++;return 15}
    Assert-WinSecWeightedRejected {Get-WinSecCriterionWeight $rule}
    Assert-WinSecWeighted ($script:weightReads -eq 0)
}
Test-WinSecWeighted 'Missing recorded weights and wrong arithmetic fail closed' {
    $s=(Invoke-WinSecWeightedConfigurationFixture (New-WinSecWeightedConfigurationFixture)).Summary
    $bad=Copy-WinSecResultData $s;$bad.Controls[0].Criteria[0].PSObject.Properties.Remove('Weight')
    Assert-WinSecWeightedRejected {ConvertTo-WinSecPublicConfigurationAssessment $bad $s}
    $bad=Copy-WinSecResultData $s;$bad.Controls[0].Value=66.67
    Assert-WinSecWeightedRejected {ConvertTo-WinSecPublicConfigurationAssessment $bad $s}
}
Test-WinSecWeighted 'Legacy public schemas cannot be relabelled to smuggle weighted fields' {
    $s=(Invoke-WinSecWeightedConfigurationFixture (New-WinSecWeightedConfigurationFixture)).Summary
    foreach($version in @('1.0.0','1.1.0')) {
        $bad=Copy-WinSecResultData $s;$bad.MethodologyVersion=$version
        Assert-WinSecWeightedRejected {ConvertTo-WinSecPublicConfigurationAssessment $bad $bad}
    }
}
Test-WinSecWeighted 'A changed weight is rejected against its original criterion even after recomputing the score' {
    $f=New-WinSecWeightedConfigurationFixture;$r=Invoke-WinSecWeightedConfigurationFixture $f
    $session=New-WinSecWeightedConfigurationSession $f $r
    $bad=Copy-WinSecResultData $r.Summary;$bad.Controls[0].Criteria[0].Weight=16;$bad.Controls[0].Criteria[1].Weight=34
    $totals=Get-WinSecConfigurationControlTotals $bad.Controls[0] '1.2.0'
    foreach($p in $totals.PSObject.Properties){$bad.Controls[0].($p.Name)=$p.Value}
    $null=ConvertTo-WinSecPublicConfigurationAssessment $bad $bad
    Assert-WinSecWeightedRejected {Assert-WinSecConfigurationProvenance $session $bad}
}
Test-WinSecWeighted 'Section scores average control fractions equally rather than summing their criterion weights' {
    $controls=@([pscustomobject]@{Status='COMPLETE';Criteria=@([pscustomobject]@{Status='PASS';Weight=1})},
        [pscustomobject]@{Status='COMPLETE';Criteria=@([pscustomobject]@{Status='PASS';Weight=15},[pscustomobject]@{Status='FAIL';Weight=35},[pscustomobject]@{Status='PASS';Weight=50})},
        [pscustomobject]@{Status='COMPLETE';Criteria=@([pscustomobject]@{Status='FAIL';Weight=1})})
    $r=Get-WinSecConfigurationSectionTotals $controls '1.2.0'
    Assert-WinSecWeighted ($r.Value -eq 55 -and $r.Coverage -eq 100)
    $controls[2].Status='NOT_SCORED';Assert-WinSecWeighted ($null -eq (Get-WinSecConfigurationSectionTotals $controls '1.2.0').Value)
}
Test-WinSecWeighted 'Section means retain original fractions until the final rounding step' {
    $controls=@(foreach($length in @(3,4,2)) {[pscustomobject]@{Status='COMPLETE';Criteria=@(for($i=0;$i -lt $length;$i++){
        [pscustomobject]@{Status=if($i){'PASS'}else{'FAIL'};Weight=1}})}})
    Assert-WinSecWeighted ((Get-WinSecConfigurationSectionTotals $controls '1.2.0').Value -eq 63.89)
}
Test-WinSecWeighted 'Older arithmetic still ignores weights and does not silently adopt the new methodology' {
    $control=[pscustomobject]@{Permission='APPROVED';Criteria=@([pscustomobject]@{Status='PASS';Weight=15},
        [pscustomobject]@{Status='FAIL';Weight=35},[pscustomobject]@{Status='PASS';Weight=50})}
    foreach($version in @('1.0.0','1.1.0')){Assert-WinSecWeighted ((Get-WinSecConfigurationControlTotals $control $version).Value -eq 66.67)}
    $f=New-WinSecWeightedConfigurationFixture;$f.Policy.Policy.methodologyVersion='1.1.0';$f.Policy.Policy.controlMethod='PASS_CRITERIA_FRACTION'
    Assert-WinSecWeightedRejected {Invoke-WinSecWeightedConfigurationFixture $f}
}
Test-WinSecWeighted 'Legacy weighted methodology remains readable with eight validated controls and global scoring blocked' {
    $p=Get-WinSecConfigurationScoringPolicy $root;$registry=Get-WinSecCheckRegistry $root
    $rootPolicy=ConvertFrom-WinSecStoredJson (Get-Content (Join-Path $root 'config/scoring.json') -Raw -Encoding UTF8)
    $enabled=@($registry.Checks|Where-Object ExecutionEnabled)
    Assert-WinSecWeighted ($p.Policy.methodologyVersion -ceq '1.2.0' -and $p.Policy.controlMethod -ceq 'WEIGHTED_PASS_CRITERIA_FRACTION' -and -not $rootPolicy.enabled -and
        $rootPolicy.activationStatus -ceq 'PENDING_APPROVED_CRITERIA' -and
        (($enabled.CheckId|Sort-Object) -join '|') -ceq 'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-NET-005|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -and
        @($enabled|Where-Object {-not $_.ExecutionReady -or $_.ImplementationStatus -cne 'VALIDATED'}).Count -eq 0)
}
Write-Host ('Weighted configuration scoring: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Weighted configuration scoring tests failed.'}
