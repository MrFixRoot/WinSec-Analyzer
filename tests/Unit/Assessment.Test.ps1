# Synthetic policies and evidence only. No Windows queries, writes or real approval.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$script:productionCatalog=Get-WinSecAssessmentCatalog $root 'WSA-SYS-001'
$script:catalogReader=(Get-Command Get-WinSecAssessmentCatalog).ScriptBlock
$script:passed=0;$script:failed=0
function Assert-WinSecAssessment {param([bool]$Value);if(-not $Value){throw 'Assessment assertion failed.'}}
function Get-WinSecAssessmentCatalog {param($ProjectRoot,$CheckId);if($CheckId -ceq 'WSA-SYS-001'){Copy-WinSecResultData $script:snapshot}}
function New-WinSecAssessmentTestSession {
    param($Assessment)
    New-WinSecResultSession -DeviceId $script:audit.DeviceId -ScanId $script:audit.ScanId `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ControlResults $script:audit.ControlResults `
        -EvaluationResults $Assessment.EvaluationResults -CriteriaSelections $Assessment.CriteriaSelections -Findings $Assessment.Findings `
        -ExpectedCheckIds @('WSA-SYS-001') -ExecutionStatus COMPLETED -CatalogVersion '0.9.0' `
        -StartedAtUTC '2026-10-16T00:00:00Z' -CompletedAtUTC '2026-10-16T00:01:00Z'
}
function Invoke-WinSecAssessmentFixture {
    Invoke-WinSecScanAssessment $script:audit $root -TargetContext $script:context -DependencyEvidence $script:dependencies
}
function Test-WinSecAssessment {
    param([string]$Name,[scriptblock]$Action)
    $device='local:ASSESSMENT-SYNTHETIC';$scan='assessment-synthetic-1'
    $script:audit=[pscustomobject]@{DeviceId=$device;ScanId=$scan;ControlResults=@([pscustomobject]@{
        DeviceId=$device;ScanId=$scan;CheckId='WSA-SYS-001';SectionKey='SystemSecurity';Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';
        Evidence=[pscustomobject]@{DeviceId=$device;ScanId=$scan;CheckId='WSA-SYS-001';CollectionSuccessful=$true;
            DefenderStatus=@{AMRunningMode='Normal';RealTimeProtectionEnabled=$false};Secret='PRIVATE-ASSESSMENT-EVIDENCE'}})}
    $script:context=[pscustomobject]@{DeviceId=$device;ScanId=$scan;OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='TEST';Profile='TEST'}
    $catalog=Copy-WinSecResultData $script:productionCatalog.Catalog
    $catalog.CatalogId='SYNTHETIC-LOCAL-POLICY';$catalog.CatalogVersion='test-1';$catalog.Status='APPROVED';$catalog.ScoringEnabled=$false
    $catalog|Add-Member -NotePropertyName EvaluationEnabled -NotePropertyValue $true
    $rule=Copy-WinSecResultData $catalog.Criteria[2]
    $rule.Name='SYNTHETIC real-time protection policy';$rule.Approved=$true
    $rule.Source=[pscustomobject]@{Framework='LOCAL_POLICY';Version='test-1';ControlId='SYNTHETIC-DEF-001';
        Title='SYNTHETIC policy, not a real security baseline';Url='https://example.invalid/synthetic-policy'}
    $rule.Recommendation='SYNTHETIC: Review the intended real-time protection setting manually.'
    $rule.Verification=[pscustomobject]@{Status='VERIFIED';ReviewedBy='SYNTHETIC REVIEWER';ReviewedAtUTC='2026-10-16T00:00:00Z'}
    $rule.Applicability=[pscustomobject]@{OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='TEST';Profile='TEST'}
    $catalog.Criteria=@($rule);$catalog.ReviewOnly=@()
    $script:snapshot=[pscustomobject]@{Catalog=$catalog;Sha256=('A'*64)}
    $script:dependencies=@{'WSA-SYS-001'=@{'active-antivirus-mode'=$true}}
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-WinSecAssessment 'Approved applicable synthetic criteria produce a deviation and manual guidance without a score' {
    $result=Invoke-WinSecAssessmentFixture
    Assert-WinSecAssessment ($result.CriteriaSelections[0].Status -ceq 'READY' -and $result.EvaluationResults[0].Status -ceq 'FAIL')
    Assert-WinSecAssessment ($result.CriteriaSelections[0].EvaluationEligible -ceq $true -and
        $result.CriteriaSelections[0].ScoringEligible -ceq $false -and -not (Test-WinSecCriteriaCatalog $script:snapshot.Catalog).ReadyForScoring)
    $public=ConvertTo-WinSecPublicScanResult (New-WinSecAssessmentTestSession $result)
    Assert-WinSecAssessment ($public.Findings.Count -eq 1 -and $public.Findings[0].Kind -ceq 'CONFIGURATION_DEVIATION' -and
        $public.Findings[0].Guidance.CatalogVersion -ceq 'test-1' -and $public.OverallScore -eq $null -and $public.OverallStatus -ceq 'NOT_SCORED')
    Assert-WinSecAssessment ((Get-WinSecPublicHistoryJson $public) -notmatch 'PRIVATE-ASSESSMENT-EVIDENCE|ObservedValue|ExpectedValue|ReviewedBy')
}
Test-WinSecAssessment 'Evaluation-only approval cannot authorize numeric scoring or legacy scoring selection' {
    $r=Invoke-WinSecAssessmentFixture
    $scoringSelection=Get-WinSecApplicableCriteria -Catalog $script:snapshot.Catalog -TargetContext $script:context `
        -ControlResult $script:audit.ControlResults[0] -ProjectRoot $root -DependencyEvidence $script:dependencies['WSA-SYS-001']
    Assert-WinSecAssessment ($scoringSelection.Status -ceq 'DRAFT_BLOCKED' -and $scoringSelection.ScoringEligible -ceq $false)
    . (Join-Path $root 'src/Core/ScoreEngine.ps1')
    $authorization=Test-WinSecScoreAuthorization -Evaluation $r.EvaluationResults[0] -CriteriaSelection $r.CriteriaSelections[0] `
        -CollectorResult $script:audit.ControlResults[0]
    Assert-WinSecAssessment (-not $authorization.Authorized)
}
Test-WinSecAssessment 'Real JSON reader preserves approved UTC timestamps across PowerShell versions' {
    $script:approvedJson=ConvertTo-Json $script:snapshot.Catalog -Depth 40
    function Assert-WinSecDeviceRemovalPath {param($ProjectRoot,$Path)}
    function Get-Item {[CmdletBinding()]param($LiteralPath,[switch]$Force);[pscustomobject]@{PSIsContainer=$false;Length=100}}
    function Get-FileHash {[CmdletBinding()]param($LiteralPath,$Algorithm);[pscustomobject]@{Hash=('A'*64)}}
    function Get-Content {[CmdletBinding()]param($LiteralPath,[switch]$Raw,$Encoding);$script:approvedJson}
    $read=& $script:catalogReader $root 'WSA-SYS-001'
    Assert-WinSecAssessment ($read.Catalog.Criteria[0].Verification.ReviewedAtUTC -is [string] -and
        (Test-WinSecCriteriaCatalog $read.Catalog).ReadyForEvaluation -and
        -not (Test-WinSecCriteriaCatalog $read.Catalog).ReadyForScoring)
}
Test-WinSecAssessment 'Satisfied criteria produce no configuration deviation' {
    $script:audit.ControlResults[0].Evidence.DefenderStatus.RealTimeProtectionEnabled=$true
    $r=Invoke-WinSecAssessmentFixture
    Assert-WinSecAssessment ($r.EvaluationResults[0].Status -ceq 'PASS' -and $r.Findings.Count -eq 0)
}
Test-WinSecAssessment 'Actual production draft yields a pending catalog diagnostic without guidance' {
    $script:snapshot=Copy-WinSecResultData $script:productionCatalog
    $r=Invoke-WinSecAssessmentFixture
    Assert-WinSecAssessment ($r.CriteriaSelections[0].Status -ceq 'DRAFT_BLOCKED' -and $r.EvaluationResults[0].Status -ceq 'NOT_EVALUATED' -and
        $r.Findings.Count -eq 1 -and $r.Findings[0].Kind -ceq 'CATALOG_NOT_READY' -and $null -eq $r.Findings[0].Guidance)
}
foreach($mutation in @(
    { $script:snapshot.Catalog.Criteria[0].Approved=$false },
    { $script:snapshot.Catalog.Criteria[0].Verification.Status='PENDING' },
    { $script:snapshot.Catalog.EvaluationEnabled='true' },
    { $script:snapshot.Catalog.EvaluationEnabled=$false },
    { $script:snapshot.Catalog.Status='DRAFT_UNAPPROVED' },
    { $script:context.Edition='OTHER' },
    { $script:dependencies=@{}; $script:audit.ControlResults[0].Evidence.DefenderStatus.AMRunningMode=$null },
    { $script:dependencies['WSA-SYS-001']['active-antivirus-mode']='true' }
)) {
    Test-WinSecAssessment 'Unapproved, inapplicable or unproven criteria never become deviations' {
        $null=& $mutation;$r=Invoke-WinSecAssessmentFixture
        Assert-WinSecAssessment (@($r.Findings|Where-Object Kind -EQ CONFIGURATION_DEVIATION).Count -eq 0 -and
            @($r.Findings|Where-Object {$null -ne $_.Guidance}).Count -eq 0)
    }
}
Test-WinSecAssessment 'Missing target scope is unresolved and cannot grade a device' {
    $r=Invoke-WinSecScanAssessment $script:audit $root
    Assert-WinSecAssessment ($r.CriteriaSelections[0].Status -cne 'READY' -and $r.EvaluationResults[0].Status -ceq 'NOT_EVALUATED')
}
Test-WinSecAssessment 'Missing evidence remains UNKNOWN and never receives guidance' {
    $script:audit.ControlResults[0].Evidence.DefenderStatus.RealTimeProtectionEnabled=$null
    $r=Invoke-WinSecAssessmentFixture
    Assert-WinSecAssessment ($r.EvaluationResults[0].Status -ceq 'UNKNOWN' -and
        @($r.Findings|Where-Object Kind -EQ EVIDENCE_GAP).Count -eq 1 -and $null -eq $r.Findings[0].Guidance)
}
Test-WinSecAssessment 'Observed collector ERROR is preserved instead of evaluated as a configuration failure' {
    $script:audit.ControlResults[0].ObservedStatus='ERROR';$r=Invoke-WinSecAssessmentFixture
    Assert-WinSecAssessment ($r.EvaluationResults[0].Status -ceq 'UNKNOWN' -and
        @($r.Findings|Where-Object Kind -EQ COLLECTION_ERROR).Count -eq 1 -and
        @($r.Findings|Where-Object Kind -EQ CONFIGURATION_DEVIATION).Count -eq 0)
}
Test-WinSecAssessment 'Foreign context and control identities abort' {
    $script:context.DeviceId='local:OTHER';$caught=$false
    try{$null=Invoke-WinSecAssessmentFixture}catch{$caught=$true}
    Assert-WinSecAssessment $caught
}
Test-WinSecAssessment 'Unselected controls do not generate evaluations or diagnostics' {
    $script:audit.ControlResults[0].Status='NOT_SELECTED';$r=Invoke-WinSecAssessmentFixture
    Assert-WinSecAssessment ($r.EvaluationResults.Count -eq 0 -and $r.Findings.Count -eq 0)
}
Test-WinSecAssessment 'Versioned public guidance survives history JSON without retaining raw data' {
    $session=New-WinSecAssessmentTestSession (Invoke-WinSecAssessmentFixture)
    $record=New-WinSecPublicHistoryRecord $session
    $roundtrip=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    Assert-WinSecAssessment ($roundtrip.PublicResult.Findings[0].Guidance.Recommendation -ceq $script:snapshot.Catalog.Criteria[0].Recommendation)
    Assert-WinSecAssessment ($roundtrip.PublicResult.Findings[0].Guidance.CatalogSha256 -ceq ('A'*64) -and
        (Get-WinSecPublicHistoryJson $roundtrip.PublicResult) -notmatch 'PRIVATE-ASSESSMENT-EVIDENCE')
}
Test-WinSecAssessment 'Editing the current catalog cannot rewrite a previously projected recommendation' {
    $session=New-WinSecAssessmentTestSession (Invoke-WinSecAssessmentFixture)
    $public=ConvertTo-WinSecPublicScanResult $session
    $before=$public.Findings[0].Guidance.Recommendation
    $script:snapshot.Catalog.Criteria[0].Recommendation='Changed current policy'
    Assert-WinSecAssessment ($public.Findings[0].Guidance.Recommendation -ceq $before)
}
foreach($change in @(
    {param($f);$f.Guidance|Add-Member -NotePropertyName Evidence -NotePropertyValue 'PRIVATE'},
    {param($f);$f.Guidance.CheckId='WSA-SYS-002'},
    {param($f);$f.Guidance.ReferenceUrl='https://user:secret@example.invalid'},
    {param($f);$f.Guidance.Profile='PENDING_SELECTION'},
    {param($f);$f.Guidance.Recommendation='Forged recommendation'},
    {param($f);$f.Guidance.CatalogVersion='forged-version'},
    {param($f);$f.Guidance.VerifiedAtUTC='2025-01-01T00:00:00.0000000Z'},
    {param($f);$f.EvaluationStatus='UNKNOWN'},
    {param($f);$f.Guidance.VerifiedAtUTC='2999-01-01T00:00:00Z'}
)) {
    Test-WinSecAssessment 'Malformed guidance cannot enter a public projection' {
        $session=New-WinSecAssessmentTestSession (Invoke-WinSecAssessmentFixture)
        $null=& $change $session.Findings[0];$caught=$false
        try{$null=ConvertTo-WinSecPublicScanResult $session}catch{$caught=$true}
        Assert-WinSecAssessment $caught
    }
}
Test-WinSecAssessment 'Runtime Normal confirms its own prerequisite without an external assertion' {
    $script:dependencies=@{}
    $r=Invoke-WinSecAssessmentFixture
    Assert-WinSecAssessment ($r.CriteriaSelections[0].EvaluationEligible -ceq $true -and
        $r.Findings[0].Kind -ceq 'CONFIGURATION_DEVIATION' -and $r.Findings[0].Guidance.CriterionId -ceq $script:snapshot.Catalog.Criteria[0].CriterionId)
    Assert-WinSecAssessment ((Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult (New-WinSecAssessmentTestSession $r))) -notmatch
        'AMRunningMode|active-antivirus-mode|PRIVATE-ASSESSMENT-EVIDENCE')
}
foreach ($mode in @('Passive','EDR Block Mode','SxS Passive Mode','Hybrid','Disabled','UNKNOWN','Normal ',
    "Normal`n",$null,$true,1,@('Normal'),@{Mode='Normal'})) {
    Test-WinSecAssessment 'Nonactive, missing or malformed runtime mode cannot be overridden by an external true' {
        $script:audit.ControlResults[0].Evidence.DefenderStatus.AMRunningMode=$mode
        $r=Invoke-WinSecAssessmentFixture
        Assert-WinSecAssessment ($r.CriteriaSelections[0].Status -cne 'READY' -and
            $r.EvaluationResults[0].Status -ceq 'NOT_EVALUATED' -and
            @($r.Findings|Where-Object Kind -EQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
Test-WinSecAssessment 'Case differences in a recognized runtime mode do not change its meaning' {
    $script:audit.ControlResults[0].Evidence.DefenderStatus.AMRunningMode='normal'
    $script:dependencies=@{}
    Assert-WinSecAssessment ((Invoke-WinSecAssessmentFixture).CriteriaSelections[0].Status -ceq 'READY')
}
foreach ($declaration in @($false,'true',$null,1)) {
    Test-WinSecAssessment 'Explicit false or malformed prerequisite declarations are never upgraded' {
        $script:dependencies['WSA-SYS-001']['active-antivirus-mode']=$declaration
        $r=Invoke-WinSecAssessmentFixture
        Assert-WinSecAssessment ($r.CriteriaSelections[0].Status -cne 'READY' -and
            @($r.Findings|Where-Object Kind -EQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
Test-WinSecAssessment 'Other prerequisites still require independent confirmation' {
    $script:snapshot.Catalog.Criteria[0].ActivationDependencies=@('active-antivirus-mode','privacy-review','network-connectivity')
    $script:dependencies=@{}
    Assert-WinSecAssessment ((Invoke-WinSecAssessmentFixture).CriteriaSelections[0].Status -cne 'READY')
    $script:dependencies=@{'WSA-SYS-001'=@{'privacy-review'=$true;'network-connectivity'=$false}}
    Assert-WinSecAssessment ((Invoke-WinSecAssessmentFixture).CriteriaSelections[0].Status -cne 'READY')
    $script:dependencies['WSA-SYS-001']['network-connectivity']=$true
    Assert-WinSecAssessment ((Invoke-WinSecAssessmentFixture).CriteriaSelections[0].Status -ceq 'READY')
}
Test-WinSecAssessment 'Resolving dependencies isolates caller data and returns no telemetry' {
    $declared=@{'privacy-review'=$false}
    $before=Get-WinSecPublicHistoryJson $script:audit
    $r=Resolve-WinSecAssessmentDependencies $script:audit.ControlResults[0] $declared
    Assert-WinSecAssessment ($r['active-antivirus-mode'] -is [bool] -and $r['active-antivirus-mode'] -ceq $true -and
        $r['privacy-review'] -ceq $false -and $r.Count -eq 2 -and $declared.Count -eq 1 -and
        (Get-WinSecPublicHistoryJson $script:audit) -ceq $before)
    $r['privacy-review']=$true
    Assert-WinSecAssessment ($declared['privacy-review'] -ceq $false)
}
foreach ($successful in @($false,'true',$null,1,@($true))) {
    Test-WinSecAssessment 'Unconfirmed collection cannot prove the runtime prerequisite' {
        $script:audit.ControlResults[0].Evidence.CollectionSuccessful=$successful
        $r=Resolve-WinSecAssessmentDependencies $script:audit.ControlResults[0]
        Assert-WinSecAssessment ($r['active-antivirus-mode'] -ceq $false)
    }
}
foreach ($field in @('CheckId','DeviceId','ScanId')) {
    Test-WinSecAssessment 'Foreign evidence identity aborts prerequisite resolution and assessment' {
        $script:audit.ControlResults[0].Evidence.$field='foreign-identity'
        $caught=$false
        try { $null=Invoke-WinSecAssessmentFixture } catch { $caught=$true }
        Assert-WinSecAssessment $caught
    }
    Test-WinSecAssessment 'Missing evidence identity never proves the prerequisite' {
        $script:audit.ControlResults[0].Evidence.PSObject.Properties.Remove($field)
        $r=Resolve-WinSecAssessmentDependencies $script:audit.ControlResults[0]
        Assert-WinSecAssessment ($r['active-antivirus-mode'] -ceq $false)
    }
}
Test-WinSecAssessment 'Technical and unselected collection states cannot prove an active mode' {
    foreach ($status in @('ERROR','UNKNOWN','NOT_APPLICABLE','NOT_SELECTED')) {
        $control=Copy-WinSecResultData $script:audit.ControlResults[0];$control.ObservedStatus=$status
        Assert-WinSecAssessment ((Resolve-WinSecAssessmentDependencies $control)['active-antivirus-mode'] -ceq $false)
        $control.Status=$status;$control.ObservedStatus=$null
        Assert-WinSecAssessment ((Resolve-WinSecAssessmentDependencies $control)['active-antivirus-mode'] -ceq $false)
    }
}
Test-WinSecAssessment 'Enabled service or real-time telemetry cannot substitute for the actual running mode' {
    $control=$script:audit.ControlResults[0]
    $control.Evidence.DefenderStatus=@{RealTimeProtectionEnabled=$true;AMServiceEnabled=$true;AntivirusEnabled=$true}
    Assert-WinSecAssessment ((Resolve-WinSecAssessmentDependencies $control)['active-antivirus-mode'] -ceq $false)
}
Test-WinSecAssessment 'The runtime prerequisite does not assume every protection is enabled' {
    $script:audit.ControlResults[0].Evidence.DefenderStatus.AntivirusEnabled=$false
    $r=Resolve-WinSecAssessmentDependencies $script:audit.ControlResults[0]
    Assert-WinSecAssessment ($r['active-antivirus-mode'] -ceq $true -and $r.Count -eq 1)
}
Test-WinSecAssessment 'Other controls do not inherit Defender runtime eligibility' {
    $control=$script:audit.ControlResults[0];$control.CheckId='WSA-SYS-002'
    $r=Resolve-WinSecAssessmentDependencies $control @{'other-required-review'=$false}
    Assert-WinSecAssessment ($r.Count -eq 1 -and -not $r.Contains('active-antivirus-mode') -and $r['other-required-review'] -ceq $false)
}
Test-WinSecAssessment 'Array identities cannot exploit collection comparison semantics' {
    foreach ($field in @('CheckId','DeviceId','ScanId')) {
        foreach ($value in @(@(),@($script:audit.ControlResults[0].Evidence.$field),$true,1,'')) {
            $control=Copy-WinSecResultData $script:audit.ControlResults[0];$control.Evidence.$field=$value
            $caught=$false
            try { $null=Resolve-WinSecAssessmentDependencies $control } catch { $caught=$true }
            Assert-WinSecAssessment $caught
        }
    }
}
Test-WinSecAssessment 'Only scalar informational collection states can prove the prerequisite' {
    foreach ($field in @('Status','ObservedStatus')) {
        foreach ($value in @(@(),@('INFORMATIONAL'),$true,1)) {
            $control=Copy-WinSecResultData $script:audit.ControlResults[0];$control.$field=$value
            Assert-WinSecAssessment ((Resolve-WinSecAssessmentDependencies $control)['active-antivirus-mode'] -ceq $false)
        }
    }
}
Test-WinSecAssessment 'Missing evidence leaves the prerequisite unconfirmed' {
    $control=$script:audit.ControlResults[0];$control.Evidence=$null
    Assert-WinSecAssessment ((Resolve-WinSecAssessmentDependencies $control)['active-antivirus-mode'] -ceq $false)
}
Test-WinSecAssessment 'Calculated telemetry is rejected without executing its getter' {
    $script:getterCalls=0
    $control=$script:audit.ControlResults[0]
    $control.Evidence.DefenderStatus=[pscustomobject]@{}
    $control.Evidence.DefenderStatus|Add-Member -MemberType ScriptProperty -Name AMRunningMode -Value {$script:getterCalls++;'Normal'}
    $caught=$false
    try { $null=Resolve-WinSecAssessmentDependencies $control } catch { $caught=$true }
    Assert-WinSecAssessment ($caught -and $script:getterCalls -eq 0)
}
Write-Host ('Assessment: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Assessment unit tests failed.'}
