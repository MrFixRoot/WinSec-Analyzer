# Synthetic categorical data only: no Windows providers or filesystem writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ResultModel.ps1')
$script:passed=0;$script:failed=0
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Assert-WinSecDefenderReview {param([bool]$Value);if(-not $Value){throw 'Defender review assertion failed.'}}
function New-WinSecReviewCollector {
    [pscustomobject]@{CheckId='WSA-SYS-001';DeviceId='local:review-test';ScanId='review-test-1';SectionKey='SystemSecurity';Status='INFORMATIONAL';
        Evidence=[pscustomobject]@{CheckId='WSA-SYS-001';DeviceId='local:review-test';ScanId='review-test-1';CollectionSuccessful=$true;
            PUAProtectionAssessment=[pscustomobject]@{Mode='BLOCK'};DefenderPreferences=[pscustomobject]@{MAPSReporting=2};
            DefenderStatus=[pscustomobject]@{IsTamperProtected=$true};
            AttackSurfaceReduction=[pscustomobject]@{Available=$true;Complete=$true;Rules=@()};PrivatePaths=@('PRIVATE-DEFENDER-REVIEW')}}
}
function Test-WinSecDefenderReview {
    param([string]$Name,[scriptblock]$Action)
    $script:collector=New-WinSecReviewCollector
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
foreach($mode in @('BLOCK','AUDIT','DISABLED','UNKNOWN')) {
    Test-WinSecDefenderReview ('PUA mode is informational: '+$mode) {
        $collector.Evidence.PUAProtectionAssessment.Mode=$mode
        $items=@(New-WinSecDefenderReviewItems $collector)
        Assert-WinSecDefenderReview ($items.Count -eq 4 -and $items[0].DefenderSetting.Mode -ceq $mode -and $items[0].Type -ceq 'REVIEW_ONLY')
    }
}
foreach($value in @(0,1,2,[uint32]0,[uint32]1,[uint32]2,'Basic','Advanced','Disabled',3,$true,$null)) {
    Test-WinSecDefenderReview ('Cloud telemetry is categorized without inferring connectivity: '+[string]$value) {
        $collector.Evidence.DefenderPreferences.MAPSReporting=$value
        $expected=if($value -is [bool] -or $null -eq $value -or $value -ceq 3){'UNKNOWN'}elseif([string]$value -cin @('0','Disabled')){'DISABLED'}else{'ENABLED'}
        $items=@(New-WinSecDefenderReviewItems $collector)
        Assert-WinSecDefenderReview ($items[1].DefenderSetting.Mode -ceq $expected)
    }
}
foreach($value in @($true,$false,'false',1,$null)) {
    Test-WinSecDefenderReview 'Tamper protection accepts observed booleans only' {
        $collector.Evidence.DefenderStatus.IsTamperProtected=$value
        $expected=if($value -isnot [bool]){'UNKNOWN'}elseif($value){'ENABLED'}else{'DISABLED'}
        $items=@(New-WinSecDefenderReviewItems $collector)
        Assert-WinSecDefenderReview ($items[2].DefenderSetting.Mode -ceq $expected)
    }
}
foreach($mode in @('BLOCK','AUDIT','WARN','DISABLED','NOT_CONFIGURED','UNKNOWN')) {
    Test-WinSecDefenderReview ('ASR modes are inventory rather than approved deviations: '+$mode) {
        $collector.Evidence.AttackSurfaceReduction.Rules=@([pscustomobject]@{RuleId='56a863a9-875e-4185-98a7-b882c64b5ce5';Mode=$mode;RawAction='PRIVATE-DEFENDER-REVIEW'})
        $items=@(New-WinSecDefenderReviewItems $collector)
        Assert-WinSecDefenderReview ($items.Count -eq 5 -and $items[4].DefenderSetting.Mode -ceq $mode -and
            $items[4].Type -ceq 'REVIEW_ONLY' -and (ConvertTo-Json $items -Depth 15) -notmatch 'PRIVATE-DEFENDER-REVIEW|RawAction|ScoringEligible|PASS|FAIL')
    }
}
Test-WinSecDefenderReview 'Incomplete ASR cannot claim aligned modes; empty complete inventory does not invent disabled rules' {
    $items=@(New-WinSecDefenderReviewItems $collector)
    Assert-WinSecDefenderReview ($items.Count -eq 4 -and $items[3].DefenderSetting.InventoryState -ceq 'COMPLETE')
    $collector.Evidence.AttackSurfaceReduction.Complete=$false
    $collector.Evidence.AttackSurfaceReduction.Rules=@([pscustomobject]@{RuleId='56a863a9-875e-4185-98a7-b882c64b5ce5';Mode='BLOCK'})
    $items=@(New-WinSecDefenderReviewItems $collector)
    Assert-WinSecDefenderReview ($items[4].Status -ceq 'UNKNOWN' -and $items[4].DefenderSetting.Mode -ceq 'UNKNOWN')
    $collector.Evidence.AttackSurfaceReduction=$null
    $items=@(New-WinSecDefenderReviewItems $collector)
    Assert-WinSecDefenderReview ($items[3].Status -ceq 'UNKNOWN' -and $items[3].DefenderSetting.InventoryState -ceq 'UNAVAILABLE')
}
foreach($kind in @('Device','Scan','RawField','InvalidMode','ScoredStatus','ForeignCheck','NonScalar')) {
    Test-WinSecDefenderReview ('Invalid public observations reject: '+$kind) {
        $item=@(New-WinSecDefenderReviewItems $collector)[0]
        switch($kind){Device {$item.DeviceId='local:other'};Scan {$item.ScanId='other'};RawField {$item.DefenderSetting|Add-Member RawAction 'PRIVATE'};
            InvalidMode {$item.DefenderSetting.Mode='PASS'};ScoredStatus {$item.Status='FAIL'};ForeignCheck {$item.CheckId='WSA-SYS-002'};NonScalar {$item.Type=@('REVIEW_ONLY')}}
        $caught=$false;try{$null=ConvertTo-WinSecDefenderReviewItem $item $collector}catch{$caught=$true}
        Assert-WinSecDefenderReview $caught
    }
}
Test-WinSecDefenderReview 'Collection failure and unselected controls create no observations; foreign evidence rejects' {
    $collector.Status='ERROR';Assert-WinSecDefenderReview (@(New-WinSecDefenderReviewItems $collector).Count -eq 0)
    $collector.Status='NOT_SELECTED';Assert-WinSecDefenderReview (@(New-WinSecDefenderReviewItems $collector).Count -eq 0)
    $collector.Status='INFORMATIONAL';$collector.Evidence.DeviceId='local:other'
    $caught=$false;try{$null=New-WinSecDefenderReviewItems $collector}catch{$caught=$true};Assert-WinSecDefenderReview $caught
}
foreach($fault in @('InvalidGuid','Duplicate','Overflow')) {
    Test-WinSecDefenderReview ('Invalid ASR data cannot publish even partial reviews: '+$fault) {
        $rule=[pscustomobject]@{RuleId='56a863a9-875e-4185-98a7-b882c64b5ce5';Mode='BLOCK'}
        $collector.Evidence.AttackSurfaceReduction.Rules=@($rule)
        switch($fault){InvalidGuid {$rule.RuleId='PRIVATE-INVALID-GUID'};Duplicate {$collector.Evidence.AttackSurfaceReduction.Rules+=Copy-WinSecResultData $rule};
            Overflow {$collector.Evidence.AttackSurfaceReduction.Rules=@(1..129|ForEach-Object {$rule})}}
        $published=New-Object 'System.Collections.Generic.List[object]';$caught=$false
        try{New-WinSecDefenderReviewItems $collector|ForEach-Object {$published.Add($_)}}catch{$caught=$true}
        Assert-WinSecDefenderReview ($caught -and $published.Count -eq 0)
    }
}
Test-WinSecDefenderReview 'Additional numeric criteria reflect the explicit D-051 approval and preserve ASR inventory' {
    . (Join-Path $root 'src/Services/CriteriaService.ps1')
    $draft=Get-Content (Join-Path $root 'config/criteria/defender-additional.json') -Raw|ConvertFrom-Json
    foreach($rule in $draft.Criteria){if($rule.Verification.ReviewedAtUTC -is [datetime]){$rule.Verification.ReviewedAtUTC=$rule.Verification.ReviewedAtUTC.ToString('o')}}
    $validation=Test-WinSecCriteriaCatalog $draft
    Assert-WinSecDefenderReview ($validation.Valid -and $validation.ReadyForEvaluation -and $validation.ReadyForScoring -and
        $draft.Criteria.Count -eq 4 -and @($draft.Criteria|Where-Object Approved -EQ $true).Count -eq 4 -and
        $draft.ReviewOnly[0].Assessment -ceq 'REVIEW_ONLY')
}
Test-WinSecDefenderReview 'Public projection retains only typed settings and reconstructs an unchanged review snapshot' {
    $items=@(New-WinSecDefenderReviewItems $collector)
    $session=New-WinSecResultSession -DeviceId $collector.DeviceId -ScanId $collector.ScanId -ControlResults @($collector) -ReviewItems $items
    $public=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecDefenderReview ($public.ReviewItems.Count -eq 4 -and (ConvertTo-Json $public -Depth 20) -notmatch 'PRIVATE-DEFENDER-REVIEW|"Evidence"|RawAction' -and
        $null -eq $public.OverallScore -and $public.OverallStatus -ceq 'NOT_SCORED')
    $public.ReviewItems[0].DefenderSetting.Mode='DISABLED'
    Assert-WinSecDefenderReview ($session.ReviewItems[0].DefenderSetting.Mode -ceq 'BLOCK')
}
Write-Host ('Defender review: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Defender review tests failed.'}
