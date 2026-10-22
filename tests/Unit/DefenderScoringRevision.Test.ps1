# Real revision/normalization/evaluator with synthetic values. No Windows queries or writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Checks/Defender/Test-Defender.ps1')
. (Join-Path $root 'src/Services/FrameworkService.ps1')
. (Join-Path $root 'src/Core/FrameworkMappingEngine.ps1')
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
$script:passed=0;$script:failed=0
$snapshot=Get-WinSecAssessmentCatalog $root WSA-SYS-001 -Profile WSA-W11-24H2-PRO-DEF-BASE
$context=[pscustomobject]@{DeviceId='local:REVISION';ScanId='revision-1';OSFamily='Windows';OSRelease='Windows 11 10.0.26100';Edition='SKU:48';Profile='WSA-W11-24H2-PRO-DEF-BASE'}
function Assert-WinSecRevision {param([bool]$Value);if(-not $Value){throw 'Defender scoring revision assertion failed.'}}
function Test-WinSecRevision {
    param([string]$Name,[scriptblock]$Action)
    $script:status=[pscustomobject]@{IsTamperProtected=$true};$script:prefs=[pscustomobject]@{MAPSReporting=[uint32]2};$script:pua=[pscustomobject]@{Mode='BLOCK'}
    $script:asr=[pscustomobject]@{Available=$true;Complete=$true;Rules=@([pscustomobject]@{RuleId='56a863a9-875e-4185-98a7-b882c64b5ce5';Mode='BLOCK'})}
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function Get-WinSecRevisionResult {
    param([string]$Id)
    $modes=Get-WinSecDefenderConfigurationModes $script:status $script:prefs $script:pua $script:asr
    $rule=@($snapshot.Catalog.Criteria|Where-Object CriterionId -CEQ $Id)[0]
    Invoke-WinSecCriterionEvaluation -Criterion $rule -Evidence ([pscustomobject]@{ConfigurationModes=$modes}) `
        -TargetContext $context -DeviceId $context.DeviceId -ScanId $context.ScanId -CheckId WSA-SYS-001
}
Test-WinSecRevision 'All 101 exact profile previews use revision 0.3 and original baseline files remain unchanged' {
    $options=@(Get-WinSecAssessmentProfileOptions $root @('WSA-SYS-001'))
    Assert-WinSecRevision ($options.Count -eq 101 -and @($options|Where-Object {$_.Policies[0].CatalogVersion -cne '0.3.0'}).Count -eq 0 -and
        $snapshot.Catalog.Criteria.Count -eq 8 -and (Test-WinSecCriteriaCatalog $snapshot.Catalog).ReadyForScoring)
    Assert-WinSecRevision ((Get-WinSecBaseAssessmentCatalog $root WSA-SYS-001 -Profile WSA-W11-24H2-PRO-DEF-BASE).Sha256 -ceq '12F3BAC36CFCBAE46FFC890FC5AD50F6721096EB4E1E8446BAA4DBB28712BC6E')
}
foreach($mode in @('BLOCK','AUDIT','DISABLED','UNKNOWN')) {
    Test-WinSecRevision ('PUA requires blocking, without failing unknown telemetry: '+$mode) {
        $script:pua.Mode=$mode;$r=Get-WinSecRevisionResult WSA-DEF-ADD-001
        $expected=if($mode -ceq 'BLOCK'){'PASS'}elseif($mode -ceq 'UNKNOWN'){'UNKNOWN'}else{'FAIL'}
        Assert-WinSecRevision ($r.Status -ceq $expected)
    }
}
foreach($value in @(0,[uint32]1,[uint32]2,'Basic','Advanced',$true,$null)) {
    Test-WinSecRevision ('Cloud preference normalization is type safe: '+[string]$value) {
        $script:prefs.MAPSReporting=$value;$r=Get-WinSecRevisionResult WSA-DEF-ADD-002
        $expected=if($value -is [bool] -or $null -eq $value){'UNKNOWN'}elseif([string]$value -ceq '0'){'FAIL'}else{'PASS'}
        Assert-WinSecRevision ($r.Status -ceq $expected)
    }
}
foreach($value in @($true,$false,$null,'false')) {
    Test-WinSecRevision 'Tamper grading uses reported Boolean state and never fabricates support' {
        $script:status.IsTamperProtected=$value;$r=Get-WinSecRevisionResult WSA-DEF-ADD-003
        $expected=if($value -isnot [bool]){'UNKNOWN'}elseif($value){'PASS'}else{'FAIL'}
        Assert-WinSecRevision ($r.Status -ceq $expected)
    }
}
foreach($mode in @('BLOCK','AUDIT','WARN','DISABLED','NOT_CONFIGURED','UNKNOWN')) {
    Test-WinSecRevision ('Only the selected standard ASR rule is graded: '+$mode) {
        $script:asr.Rules[0].Mode=$mode;$r=Get-WinSecRevisionResult WSA-DEF-ADD-004
        $expected=if($mode -ceq 'BLOCK'){'PASS'}elseif($mode -ceq 'UNKNOWN'){'UNKNOWN'}else{'FAIL'}
        Assert-WinSecRevision ($r.Status -ceq $expected)
    }
}
Test-WinSecRevision 'Absent required ASR rule fails only a complete inventory; incomplete/unavailable are UNKNOWN' {
    $script:asr.Rules=@();Assert-WinSecRevision ((Get-WinSecRevisionResult WSA-DEF-ADD-004).Status -ceq 'FAIL')
    $script:asr.Complete=$false;Assert-WinSecRevision ((Get-WinSecRevisionResult WSA-DEF-ADD-004).Status -ceq 'UNKNOWN')
    $script:asr.Available=$false;Assert-WinSecRevision ((Get-WinSecRevisionResult WSA-DEF-ADD-004).Status -ceq 'UNKNOWN')
}
Test-WinSecRevision 'The revision fingerprint binds baseline, added criteria and exact profile' {
    $first=Get-WinSecDefenderRevisionFingerprint ('A'*64) ('B'*64) $context.Profile
    Assert-WinSecRevision ($first -cne (Get-WinSecDefenderRevisionFingerprint ('A'*64) ('C'*64) $context.Profile) -and
        $first -cne (Get-WinSecDefenderRevisionFingerprint ('A'*64) ('B'*64) 'WSA-W11-25H2-ENT-DEF-BASE'))
}
foreach($framework in (Get-WinSecFrameworkCatalog).Frameworks) {
    Test-WinSecRevision ('Singleton criterion mappings retain their type and reject scalars/foreign criteria: '+$framework.frameworkId) {
        $doc=Copy-WinSecResultData $framework
        $reference=$doc.mappings[0].references[-1]
        $doc.mappings[0].references=@($reference)
        $reference.criterionIds=@('WSA-DEF-ADD-004')
        Assert-WinSecRevision (@(Get-WinSecFrameworkMappings WSA-SYS-001 @($doc) Windows WSA-DEF-ADD-004).Count -eq 1)
        Assert-WinSecRevision (@(Get-WinSecFrameworkMappings WSA-SYS-001 @($doc) Windows WSA-DEF-ADD-001).Count -eq 0)
        $reference.criterionIds='WSA-DEF-ADD-004'
        Assert-WinSecRevision (@(Get-WinSecFrameworkMappings WSA-SYS-001 @($doc) Windows WSA-DEF-ADD-004).Count -eq 0)
    }
}
Test-WinSecRevision 'Dictionary mappings preserve singleton arrays and reject scalar mappings too' {
    $reference=@{id='10.5';criterionIds=@('WSA-DEF-ADD-004')}
    $doc=@{frameworkId='cis-controls';frameworkVersion='8.1';enabled=$true;mappingRules=@{};
        mappings=@(@{checkId='WSA-SYS-001';references=@($reference)})}
    Assert-WinSecRevision (@(Get-WinSecFrameworkMappings WSA-SYS-001 @($doc) Windows WSA-DEF-ADD-004).Count -eq 1)
    $reference.criterionIds='WSA-DEF-ADD-004'
    Assert-WinSecRevision (@(Get-WinSecFrameworkMappings WSA-SYS-001 @($doc) Windows WSA-DEF-ADD-004).Count -eq 0)
}
Write-Host ('Defender scoring revision: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Defender scoring revision failed.'}
