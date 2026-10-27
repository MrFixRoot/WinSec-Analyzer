# Actual policy and pure evaluation, synthetic Windows providers only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Checks/System/Test-WindowsUpdate.ps1')
. (Join-Path $root 'tests/Fixtures/WindowsUpdateMemory.ps1')
. (Join-Path $root 'tests/Fixtures/WindowsUpdateAssessment.ps1')
$script:strictReader=(Get-Command ConvertFrom-WinSecStoredJson).ScriptBlock
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
function Get-BitLockerVolume {throw 'Unexpected BitLocker query.'}
$script:passed=0;$script:failed=0
function Assert-WinSecWUCriteria {param([bool]$Value);if(-not $Value){throw 'Windows Update criteria assertion failed.'}}
function Assert-WinSecWUCriteriaRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecWUCriteria $caught}
function Test-WinSecWUCriteria {
    param([string]$Name,[scriptblock]$Action)
    Reset-WinSecWindowsUpdateFixture;Set-WinSecWindowsUpdateSupportedFixture
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-WinSecWUCriteria 'Installed approved three-rule policy preserves exact weights and pinned dated references' {
    $f=New-WinSecWindowsUpdateAssessmentFixture;$c=$f.Catalogs['WSA-SYS-003'].Catalog
    Assert-WinSecWUCriteria ((Test-WinSecCriteriaCatalog $c).ReadyForScoring -and ($c.Criteria.Weight -join '|') -ceq '15|35|50' -and
        $c.CatalogVersion -ceq '1.2.0+2026.10.24.1' -and
        (ConvertTo-WinSecWindowsUpdateReferenceUtc $c.Criteria[0].WindowsUpdateReference.Catalog.AsOfUTC).ToString('yyyy-MM-dd') -ceq '2026-10-24')
}
foreach($change in @(
    {$args[0].Criteria[0].Weight=16},{$args[0].Criteria[0].ExpectedValue=$false},
    {$args[0].Criteria[0].EvidencePath='EffectivePolicyVerified'},{$args[0].Criteria[0].Approved=$false},
    {$args[0].Criteria[0].ActivationDependencies=@('caller-assertion')},{$args[0].CheckId='WSA-SYS-001'},
    {$args[0].Criteria[1].CriterionId='WSA-WUP-BASE-001'}
)) {
    Test-WinSecWUCriteria 'Template loading rejects rules that differ from the approved policy' {
        $script:templateChange=$change
        function ConvertFrom-WinSecStoredJson {
            param([string]$Json)
            $data=& $script:strictReader $Json;$null=& $script:templateChange $data;return $data
        }
        Assert-WinSecWUCriteriaRejected {Get-WinSecWindowsUpdateCriteriaTemplate $root}
    }
}
Test-WinSecWUCriteria 'Three verified positives score 100 with installed weighted policy without mutating evidence' {
    $f=New-WinSecWindowsUpdateAssessmentFixture;$before=Get-WinSecPublicHistoryJson $f.Audit
    $reads=$script:WU.CimReads+$script:WU.NamedPolicyReads+$script:WU.KeyReads+$script:WU.VersionReads+$script:WU.RebootReads
    $r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
    Assert-WinSecWUCriteria ($r.Summary.Controls[0].Value -eq 100 -and $r.Summary.Controls[0].Status -ceq 'COMPLETE' -and
        $r.Assessment.Findings.Count -eq 0 -and ($r.Assessment.EvaluationResults[0].Evaluations.Status -join '|') -ceq 'PASS|PASS|PASS' -and
        $before -ceq (Get-WinSecPublicHistoryJson $f.Audit) -and
        $reads -eq ($script:WU.CimReads+$script:WU.NamedPolicyReads+$script:WU.KeyReads+$script:WU.VersionReads+$script:WU.RebootReads))
}
foreach($spec in @(@{Auto=$false;Patch=$true;Expected=85},@{Auto=$true;Patch=$false;Expected=65},@{Auto=$false;Patch=$false;Expected=50})) {
    Test-WinSecWUCriteria ('Approved independent weights produce '+$spec.Expected) {
        if(-not $spec.Auto){$script:WU.Services[0].StartMode='Disabled'}
        if(-not $spec.Patch){$script:WU.VersionValues.UBR=9000}
        $r=Invoke-WinSecWindowsUpdateAssessmentFixture (New-WinSecWindowsUpdateAssessmentFixture)
        Assert-WinSecWUCriteria ($r.Summary.Controls[0].Value -eq $spec.Expected -and $r.Summary.Controls[0].Coverage -eq 100 -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq @($r.Assessment.EvaluationResults[0].Evaluations|Where-Object Status -CEQ FAIL).Count)
    }
}
Test-WinSecWUCriteria 'The actual installed policy and hash reach the Windows Update assessment fixture' {
    $f=New-WinSecWindowsUpdateAssessmentFixture
    Assert-WinSecWUCriteria ($f.Policy.Sha256 -ceq (Get-FileHash (Join-Path $root 'config/scoring.json') -Algorithm SHA256).Hash -and
        $f.Policy.Policy.methodologyVersion -ceq '1.2.0' -and $f.Policy.Policy.controlMethod -ceq 'WEIGHTED_PASS_CRITERIA_FRACTION')
}
foreach($patched in @($true,$false)) {
    Test-WinSecWUCriteria 'Managed deadlines resolve automation without granting points for uninstalled patches' {
        $script:WU.MissingKeys=@('AutomaticUpdates','WindowsUpdate')
        $script:WU.NamedPolicies.AllowAutoUpdate.Managed=$true;$script:WU.NamedPolicies.AllowAutoUpdate.Value=5
        foreach($name in @('ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates')) {
            $script:WU.NamedPolicies[$name].Managed=$true;$script:WU.NamedPolicies[$name].Value=30
        }
        if(-not $patched){$script:WU.VersionValues.UBR=9000}
        $r=Invoke-WinSecWindowsUpdateAssessmentFixture (New-WinSecWindowsUpdateAssessmentFixture)
        $expected=if($patched){100}else{65}
        Assert-WinSecWUCriteria ($r.Summary.Controls[0].Value -eq $expected -and
            $r.Assessment.EvaluationResults[0].Evaluations[0].Status -ceq 'PASS' -and
            $r.Assessment.EvaluationResults[0].Evaluations[1].Status -ceq $(if($patched){'PASS'}else{'FAIL'}))
    }
}
Test-WinSecWUCriteria 'A partial deadline over manual updating remains unresolved in the complete score' {
    $script:WU.MissingKeys=@('AutomaticUpdates','WindowsUpdate')
    $script:WU.NamedPolicies.AllowAutoUpdate.Managed=$true;$script:WU.NamedPolicies.AllowAutoUpdate.Value=0
    $script:WU.NamedPolicies.ConfigureDeadlineForQualityUpdates.Managed=$true
    $r=Invoke-WinSecWindowsUpdateAssessmentFixture (New-WinSecWindowsUpdateAssessmentFixture)
    Assert-WinSecWUCriteria ($null -eq $r.Summary.Controls[0].Value -and
        ($r.Assessment.EvaluationResults[0].Evaluations.Status -join '|') -ceq 'UNKNOWN|PASS|PASS' -and
        @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
}
Test-WinSecWUCriteria 'Reviewed MDM precedence produces an automation failure rather than an invented GPO success' {
    $script:WU.NamedPolicies.IgnoreWindowsUpdateGroupPolicies.Managed=$true;$script:WU.NamedPolicies.IgnoreWindowsUpdateGroupPolicies.Value=1
    $script:WU.NamedPolicies.AllowAutoUpdate.Managed=$true;$script:WU.NamedPolicies.AllowAutoUpdate.Value=5
    $r=Invoke-WinSecWindowsUpdateAssessmentFixture (New-WinSecWindowsUpdateAssessmentFixture)
    Assert-WinSecWUCriteria ($r.Summary.Controls[0].Value -eq 85 -and
        ($r.Assessment.EvaluationResults[0].Evaluations.Status -join '|') -ceq 'FAIL|PASS|PASS')
}
foreach($fault in @('RevisionMissing','RevisionNewer','RestartPending','RestartUnknown','PolicyUnknown','PolicyConflict','Home','PlatformMismatch','CatalogExpired','BeforeCatalog','SupportBoundary')) {
    Test-WinSecWUCriteria ('Unresolved applicable criterion prevents the note without fake failure: '+$fault) {
        $f=New-WinSecWindowsUpdateAssessmentFixture;$e=$f.Audit.ControlResults[0].Evidence
        switch($fault) {
            RevisionMissing {$e.VersionRegistry.UBR.State='UNKNOWN';$e.VersionRegistry.UBR.Value=$null}
            RevisionNewer {$e.VersionRegistry.UBR.Value=99999}
            RestartPending {$e.RestartInformation.Value=$true}
            RestartUnknown {$e.RestartInformation.State='UNKNOWN';$e.RestartInformation.Value=$null}
            PolicyUnknown {$e.AutomationPolicy.AllowAutoUpdate.State='UNKNOWN'}
            PolicyConflict {$e.AutomationPolicy.AllowAutoUpdate.Managed=$true;$e.AutomationPolicy.AllowAutoUpdate.Value=0}
            Home {$e.Platform.OperatingSystemSKU=101;$f=New-WinSecWindowsUpdateAssessmentFixture -Profile WSA-W11-25H2-HOME-DEF-BASE
                $f.Audit.ControlResults[0].Evidence.Platform.OperatingSystemSKU=101}
            PlatformMismatch {$e.Platform.OperatingSystemSKU=4}
            CatalogExpired {$e.CollectedAtUTC='2026-10-31T00:00:00Z'}
            BeforeCatalog {$e.CollectedAtUTC='2026-10-23T23:59:59Z'}
            SupportBoundary {$ref=$f.Catalogs['WSA-SYS-003'].Catalog.Criteria[0].WindowsUpdateReference.Catalog
                $ref.Releases|Where-Object Release -CEQ 25H2|ForEach-Object {$_.Support[0].SupportEndsOn='2026-10-24'}
                foreach($rule in $f.Catalogs['WSA-SYS-003'].Catalog.Criteria){$rule.WindowsUpdateReference.Catalog=Copy-WinSecResultData $ref;$rule.WindowsUpdateReference.ContentSha256=Get-WinSecWindowsUpdateReferenceFingerprint $ref}}
        }
        $r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
        Assert-WinSecWUCriteria ($null -eq $r.Summary.Controls[0].Value -and $r.Summary.Controls[0].Status -ceq 'NOT_SCORED' -and
            @($r.Assessment.EvaluationResults[0].Evaluations|Where-Object Status -CEQ UNKNOWN).Count -gt 0 -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
Test-WinSecWUCriteria 'Verified end of support excludes patch weight and preserves the support deviation' {
    $script:WU.Systems[0].Version='10.0.26100';$script:WU.Systems[0].BuildNumber='26100';$script:WU.VersionValues.CurrentBuildNumber='26100'
    $r=Invoke-WinSecWindowsUpdateAssessmentFixture (New-WinSecWindowsUpdateAssessmentFixture WSA-W11-24H2-PRO-DEF-BASE)
    Assert-WinSecWUCriteria (($r.Assessment.EvaluationResults[0].Evaluations.Status -join '|') -ceq 'PASS|NOT_APPLICABLE|FAIL' -and
        $r.Summary.Controls[0].Value -eq 23.08 -and $r.Summary.Controls[0].Coverage -eq 100 -and
        @($r.Assessment.Findings|Where-Object {$_.Kind -ceq 'CONFIGURATION_DEVIATION' -and $_.CriterionId -ceq 'WSA-WUP-BASE-003'}).Count -eq 1)
}
Test-WinSecWUCriteria 'Previous policy keeps patch applicability unknown after support ended' {
    $script:WU.Systems[0].Version='10.0.22631';$script:WU.Systems[0].BuildNumber='22631';$script:WU.VersionValues.CurrentBuildNumber='22631'
    $f=New-WinSecWindowsUpdateAssessmentFixture WSA-W11-23H2-PRO-DEF-BASE
    $f.Catalogs['WSA-SYS-003'].Catalog.CatalogVersion='1.1.0+2026.10.24.1'
    foreach($rule in $f.Catalogs['WSA-SYS-003'].Catalog.Criteria){$rule.Source.Version='1.1.0+2026.10.24.1'}
    $r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
    Assert-WinSecWUCriteria (($r.Assessment.EvaluationResults[0].Evaluations.Status -join '|') -ceq 'PASS|UNKNOWN|FAIL' -and
        $null -eq $r.Summary.Controls[0].Value)
}
Test-WinSecWUCriteria 'Patch exclusion cannot compensate for unresolved automation after support ended' {
    $script:WU.Systems[0].Version='10.0.22631';$script:WU.Systems[0].BuildNumber='22631';$script:WU.VersionValues.CurrentBuildNumber='22631'
    $script:WU.NamedPolicyFailures=@('AllowAutoUpdate')
    $f=New-WinSecWindowsUpdateAssessmentFixture WSA-W11-23H2-PRO-DEF-BASE
    $f.Audit.ControlResults[0].Evidence.AutomationPolicy.AllowAutoUpdate.State='UNKNOWN'
    $r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
    Assert-WinSecWUCriteria (($r.Assessment.EvaluationResults[0].Evaluations.Status -join '|') -ceq 'UNKNOWN|NOT_APPLICABLE|FAIL' -and
        $null -eq $r.Summary.Controls[0].Value)
}
foreach($fault in @('Device','Scan','Check','Digest','Weight','Expected','Path','MissingReference','CollectedTime')) {
    Test-WinSecWUCriteria ('Foreign or changed provenance is rejected: '+$fault) {
        $f=New-WinSecWindowsUpdateAssessmentFixture;$e=$f.Audit.ControlResults[0].Evidence;$rule=$f.Catalogs['WSA-SYS-003'].Catalog.Criteria[0]
        switch($fault) {
            Device {$e.DeviceId='local:hw1-'+('b'*64)};Scan {$e.ScanId='other-scan'};Check {$e.CheckId='WSA-SYS-001'}
            Digest {$rule.WindowsUpdateReference.ContentSha256='F'*64};Weight {$rule.Weight=16};Expected {$rule.ExpectedValue=$false}
            Path {$rule.EvidencePath='EffectivePolicyVerified'};MissingReference {$rule.PSObject.Properties.Remove('WindowsUpdateReference')}
            CollectedTime {$e.CollectedAtUTC='not-UTC'}
        }
        Assert-WinSecWUCriteriaRejected {Invoke-WinSecWindowsUpdateAssessmentFixture $f}
    }
}
foreach($declared in @($true,$false,'true',$null,1)) {
    Test-WinSecWUCriteria 'A declaration never substitutes for observed local evidence or overrides an explicit denial' {
        $f=New-WinSecWindowsUpdateAssessmentFixture;$control=$f.Audit.ControlResults[0]
        $deps=Resolve-WinSecAssessmentDependencies $control @{'windows-update-local-evidence'=$declared}
        Assert-WinSecWUCriteria ($deps['windows-update-local-evidence'] -eq ($declared -is [bool] -and $declared))
        $control.Evidence.CollectionSuccessful=$false
        Assert-WinSecWUCriteria (-not (Resolve-WinSecAssessmentDependencies $control @{'windows-update-local-evidence'=$true})['windows-update-local-evidence'])
    }
}
Test-WinSecWUCriteria 'Caller verdict fields are ignored and missing raw policy cannot be promoted' {
    $f=New-WinSecWindowsUpdateAssessmentFixture;$e=$f.Audit.ControlResults[0].Evidence
    $e|Add-Member WindowsUpdate ([pscustomobject]@{Automation=$true;SecurityBaseline=$true;SecuritySupport=$true})
    $e.EffectivePolicyVerified=$true;$e.AutomationPolicy.AllowAutoUpdate.State='UNKNOWN'
    $r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
    Assert-WinSecWUCriteria ($null -eq $r.Summary.Controls[0].Value -and $r.Assessment.EvaluationResults[0].Evaluations[0].Status -ceq 'UNKNOWN')
}
foreach($field in @('Status','ObservedStatus','SectionKey','Scope','SchemaVersion')) {
    Test-WinSecWUCriteria ('Array-valued prerequisites are never interpreted as scalar approval: '+$field) {
        $f=New-WinSecWindowsUpdateAssessmentFixture;$control=$f.Audit.ControlResults[0]
        if($field -cin @('Scope','SchemaVersion')){$control.Evidence.$field=@($control.Evidence.$field,$control.Evidence.$field)}
        else {$control.$field=@($control.$field,$control.$field)}
        Assert-WinSecWUCriteria (-not (Resolve-WinSecAssessmentDependencies $control @{'windows-update-local-evidence'=$true})['windows-update-local-evidence'])
    }
}
Test-WinSecWUCriteria 'Profile discovery includes 101 exact Windows contexts and matches materialized hashes' {
    $options=@(Get-WinSecAssessmentProfileOptions $root @('WSA-SYS-003'))
    Assert-WinSecWUCriteria ($options.Count -eq 101 -and @($options.Profile|Sort-Object -Unique).Count -eq 101)
    foreach($p in @($options[0],$options[50],$options[100])) {
        $plan=Get-WinSecAssessmentProfilePlan $root @('WSA-SYS-003') $p.Profile
        Assert-WinSecWUCriteria ($p.Policies[0].CatalogSha256 -ceq $plan.Preview.Policies[0].CatalogSha256)
    }
}
Test-WinSecWUCriteria 'Installed individual scoring supports weights without enabling global scoring or the pending check' {
    $check=Get-WinSecRegisteredCheck (Get-WinSecCheckRegistry $root) WSA-SYS-003
    $global=ConvertFrom-WinSecStoredJson (Get-Content (Join-Path $root 'config/scoring.json') -Raw)
    Assert-WinSecWUCriteria (-not $check.ExecutionEnabled -and -not $check.ExecutionReady -and $check.ImplementationStatus -ceq 'PENDING_VALIDATION' -and
        -not $global.enabled -and $global.activationStatus -ceq 'PENDING_APPROVED_CRITERIA' -and
        $global.configurationScoring.methodologyVersion -ceq '1.2.0' -and $global.configurationScoring.controlMethod -ceq 'WEIGHTED_PASS_CRITERIA_FRACTION')
}
Write-Host ('Windows Update criteria: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Windows Update criteria tests failed.'}
