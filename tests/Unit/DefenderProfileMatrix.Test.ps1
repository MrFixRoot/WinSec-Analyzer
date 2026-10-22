# Matriz y evaluación con evidencia sintética; sin Windows ni almacenamiento.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$script:passed=0;$script:failed=0
function Assert-WinSecMatrix {param([bool]$Value);if(-not $Value){throw 'Defender matrix assertion failed.'}}
function Test-WinSecMatrix {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
function Assert-WinSecMatrixRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecMatrix $caught}
function Get-CimInstance {throw 'Unexpected Windows query in profile matrix test.'}
function Get-MpComputerStatus {throw 'Unexpected Defender query in profile matrix test.'}
function Get-MpPreference {throw 'Unexpected Defender query in profile matrix test.'}
$definitions=@(Get-WinSecInstalledAssessmentProfiles -ProjectRoot $root)
$builds=@{'21H2'=22000;'22H2'=22621;'23H2'=22631;'24H2'=26100;'25H2'=26200;'26H1'=28000;'26H2'=26300}
$skus=@{'HOME'=101;'HOME-N'=98;'HOME-SL'=100;'HOME-CHINA'=99;'PRO'=48;'PRO-N'=49;'PRO-WORKSTATION'=161;
    'PRO-WORKSTATION-N'=162;'PRO-EDU'=164;'PRO-EDU-N'=165;'ENT'=4;'ENT-N'=27;'EDU'=121;'EDU-N'=122;
    'ENT-LTSC'=125;'ENT-LTSC-N'=126;'IOT-ENT-LTSC'=191}
Test-WinSecMatrix 'Exactly 101 unique reviewed combinations preserve the first two profile identities' {
    Assert-WinSecMatrix ($definitions.Count -eq 101 -and @($definitions.Profile|Sort-Object -Unique).Count -eq 101 -and
        $definitions[0].Profile -ceq 'WSA-W11-24H2-PRO-DEF-BASE' -and $definitions[1].Profile -ceq 'WSA-W11-25H2-ENT-DEF-BASE')
    foreach($edition in $skus.Keys){
        $expected=if($edition -match 'LTSC'){1}else{7}
        Assert-WinSecMatrix (@($definitions|Where-Object Edition -CEQ ('SKU:'+$skus[$edition])).Count -eq $expected)
    }
}
foreach($definition in $definitions) {
    Test-WinSecMatrix ('Exact SKU/build and eight approved evaluable criteria: '+$definition.Profile) {
        $match=[regex]::Match($definition.Profile,'\AWSA-W11-(2[1-6]H[12])-(.+)-DEF-BASE\z')
        $release=$match.Groups[1].Value;$edition=$match.Groups[2].Value
        $snapshot=Get-WinSecAssessmentCatalog $root WSA-SYS-001 -Profile $definition.Profile
        Assert-WinSecMatrix ($definition.OSRelease -ceq ('Windows 11 10.0.'+$builds[$release]) -and
            $definition.Edition -ceq ('SKU:'+$skus[$edition]) -and $snapshot.Catalog.Criteria.Count -eq 8)
        $context=[pscustomobject]@{DeviceId='local:MATRIX';ScanId='matrix-1';OSFamily='Windows';OSRelease=$definition.OSRelease;
            Edition=$definition.Edition;Profile=$definition.Profile}
        $control=[pscustomobject]@{DeviceId=$context.DeviceId;ScanId=$context.ScanId;CheckId='WSA-SYS-001';SectionKey='SystemSecurity';
            Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';Evidence=[pscustomobject]@{DeviceId=$context.DeviceId;ScanId=$context.ScanId;
                CheckId='WSA-SYS-001';CollectionSuccessful=$true;DefenderStatus=[pscustomobject]@{AMRunningMode='Normal';AMServiceEnabled=$true;
                    AntivirusEnabled=$true;RealTimeProtectionEnabled=$false;BehaviorMonitorEnabled=$true};ConfigurationModes=[pscustomobject]@{Pua='BLOCK';Cloud='ENABLED';Tamper='ENABLED';AsrVulnerableDriver='BLOCK'}}}
        $selection=Get-WinSecApplicableCriteria -Catalog $snapshot.Catalog -TargetContext $context -ControlResult $control -ProjectRoot $root `
            -DependencyEvidence (Resolve-WinSecAssessmentDependencies $control) -ForEvaluation
        $evaluation=Invoke-WinSecControlEvaluation -ControlResult $control -Criteria $selection.EligibleCriteria -TargetContext $context
        Assert-WinSecMatrix ($selection.Status -ceq 'READY' -and @($evaluation.Evaluations|Where-Object Status -CEQ PASS).Count -eq 7 -and
            @($evaluation.Evaluations|Where-Object Status -CEQ FAIL).Count -eq 1)
        if($null -eq $definition.FileName){
            Assert-WinSecMatrix ($snapshot.Catalog.CatalogVersion -ceq '0.3.0' -and
                $snapshot.Sha256 -ceq (Get-WinSecDefenderRevisionFingerprint (Get-WinSecDefenderProfileFingerprint $definition.MatrixSha256 $definition.TemplateSha256 $definition.Profile) (Get-WinSecDefenderCriteriaRevision $root).Sha256 $definition.Profile))
        }
        $context.Edition='SKU:65535'
        $blocked=Get-WinSecApplicableCriteria -Catalog $snapshot.Catalog -TargetContext $context -ControlResult $control -ProjectRoot $root `
            -DependencyEvidence (Resolve-WinSecAssessmentDependencies $control) -ForEvaluation
        Assert-WinSecMatrix ($blocked.Status -cne 'READY' -and $blocked.EligibleCriteria.Count -eq 0)
    }
}
Test-WinSecMatrix 'Original catalog bytes and independent expanded objects remain immutable' {
    $a=Get-WinSecBaseAssessmentCatalog $root WSA-SYS-001 -Profile WSA-W11-24H2-PRO-DEF-BASE
    $b=Get-WinSecBaseAssessmentCatalog $root WSA-SYS-001 -Profile WSA-W11-25H2-ENT-DEF-BASE
    Assert-WinSecMatrix ($a.Sha256 -ceq '12F3BAC36CFCBAE46FFC890FC5AD50F6721096EB4E1E8446BAA4DBB28712BC6E' -and
        $b.Sha256 -ceq '8A6DE7C2B198926923E5A0E033C175BFF1ACB8F7447D4999DD8522273AE6DEF2')
    $first=Get-WinSecAssessmentCatalog $root WSA-SYS-001 -Profile WSA-W11-23H2-PRO-DEF-BASE
    $first.Catalog.Criteria[0].ExpectedValue=$false
    $next=Get-WinSecAssessmentCatalog $root WSA-SYS-001 -Profile WSA-W11-23H2-PRO-DEF-BASE
    Assert-WinSecMatrix ($next.Catalog.Criteria[0].ExpectedValue -ceq $true -and $next.Sha256 -ceq $first.Sha256)
}
foreach($profile in @('WSA-W11-21H2-ENT-LTSC-DEF-BASE','WSA-W11-26H2-IOT-ENT-LTSC-DEF-BASE',
    'WSA-W11-26H1-IOT-ENT-LTSC-N-DEF-BASE','WSA-W11-27H2-PRO-DEF-BASE','../defender','WSA-W11-24H2-UNKNOWN-DEF-BASE')) {
    Test-WinSecMatrix ('Unreviewed combinations and paths fail closed: '+$profile) {
        Assert-WinSecMatrixRejected {Get-WinSecAssessmentCatalog $root WSA-SYS-001 -Profile $profile}
    }
}
$script:matrixJson=Get-Content (Join-Path $root 'config/criteria/profiles/defender-windows11-matrix.json') -Raw -Encoding UTF8
$originalJson=$script:matrixJson
function Get-Content {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Raw,[string]$Encoding)
    if($LiteralPath -like '*defender-windows11-matrix.json'){return $script:matrixJson}
    Microsoft.PowerShell.Management\Get-Content @PSBoundParameters
}
foreach($mutation in @(
    {param($m);$m.SchemaVersion='0'}, {param($m);$m.Status='DRAFT'}, {param($m);$m.Releases+=@($m.Releases[0])},
    {param($m);$m.Releases[0].Build=0}, {param($m);$m.Releases[1].Build=$m.Releases[0].Build},
    {param($m);$m.Editions[1].Sku=$m.Editions[0].Sku}, {param($m);$m.Editions[0].Releases+=@('UNKNOWN')},
    {param($m);$m.Editions[-1].Releases=@('21H2')}, {param($m);$m.Sources=@('https://example.invalid/unreviewed')},
    {param($m);$m.ReviewedAtUTC='invalid'}, {param($m);$m|Add-Member Extra 'unexpected'},
    {param($m);$m.TemplateSha256=('F'*64)}
)) {
    Test-WinSecMatrix 'Invalid matrix or changed template cannot release an expanded catalog' {
        $m=ConvertFrom-WinSecStoredJson $originalJson;$null=& $mutation $m
        $script:matrixJson=ConvertTo-Json $m -Depth 20 -Compress
        Assert-WinSecMatrixRejected {Get-WinSecAssessmentCatalog $root WSA-SYS-001 -Profile WSA-W11-23H2-PRO-DEF-BASE}
        $script:matrixJson=$originalJson
    }
}
Test-WinSecMatrix 'Duplicate JSON keys are rejected before profile discovery' {
    $script:matrixJson='{"SchemaVersion":"1.0.0","SchemaVersion":"1.0.0"}'
    Assert-WinSecMatrixRejected {Get-WinSecInstalledAssessmentProfiles -ProjectRoot $root}
    $script:matrixJson=$originalJson
}
[Console]::WriteLine(('Defender profile matrix: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Defender profile matrix tests failed.'}
