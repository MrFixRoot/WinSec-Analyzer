# Pure diagnostic contract tests. All collection providers are synthetic; no writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/Checks/System/Test-WindowsUpdate.ps1',
    'tests/Fixtures/WindowsUpdateMemory.ps1','tests/Fixtures/WindowsUpdateAssessment.ps1')) {. (Join-Path $root $file)}
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
function Get-BitLockerVolume {throw 'Unexpected BitLocker query.'}
function Save-WinSecPublicHistory {throw 'Unexpected history write.'}
function Save-WinSecEvidence {throw 'Unexpected evidence write.'}
Reset-WinSecWindowsUpdateFixture;Set-WinSecWindowsUpdateSupportedFixture
$fixture=New-WinSecWindowsUpdateAssessmentFixture
$assessment=Invoke-WinSecWindowsUpdateAssessmentFixture $fixture
$baselineControl=Copy-WinSecResultData $fixture.Audit.ControlResults[0]
$baselineSelection=Copy-WinSecResultData $assessment.Assessment.CriteriaSelections[0]
$script:passed=0;$script:failed=0
function Assert-WinSecUpdateReview {param([bool]$Value);if(-not $Value){throw 'Windows Update review assertion failed.'}}
function Assert-WinSecUpdateReviewRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecUpdateReview $caught}
function Test-WinSecUpdateReview {
    param([string]$Name,[scriptblock]$Action)
    $control=Copy-WinSecResultData $baselineControl;$selection=Copy-WinSecResultData $baselineSelection
    $before=ConvertTo-Json $script:WU -Depth 12 -Compress
    try {
        $null=& $Action
        Assert-WinSecUpdateReview ($before -ceq (ConvertTo-Json $script:WU -Depth 12 -Compress))
        $script:passed++;Write-Host ('[PASS] '+$Name)
    } catch {$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-WinSecUpdateReview 'Only three typed explanations and pinned source metadata leave the original evidence' {
    $before=Get-WinSecPublicHistoryJson $control
    $control.Evidence|Add-Member PrivateSecret 'PRIVATE-UPDATE-REVIEW'
    $items=@(New-WinSecWindowsUpdateReviewItems $control $selection)
    $rows=@(ConvertTo-WinSecWindowsUpdateReviewRows $items)
    $json=Get-WinSecPublicHistoryJson $items
    Assert-WinSecUpdateReview ($items.Count -eq 3 -and $rows.Count -eq 3 -and
        $items[0].WindowsUpdateSetting.State -ceq 'AUTOMATIC' -and
        $items[1].WindowsUpdateSetting.Reason -ceq 'REVIEWED_OS_BASELINE_COMPLETED' -and
        $items[2].WindowsUpdateSetting.State -ceq 'SUPPORTED' -and
        $items[0].WindowsUpdateSetting.ReferenceSha256 -ceq $selection.EligibleCriteria[0].WindowsUpdateReference.Sha256 -and
        @($rows|Where-Object {$_.ConfigurationPercent -ceq 'N/A' -and $_.Kind -ceq 'REVIEW_ONLY'}).Count -eq 3 -and
        $json -notmatch 'PRIVATE|Evidence|PolicyRegistry|VersionRegistry|AutomationPolicy|ObservedValue|SourceUrl')
    $control.Evidence.PSObject.Properties.Remove('PrivateSecret')
    Assert-WinSecUpdateReview ($before -ceq (Get-WinSecPublicHistoryJson $control))
}
foreach($fault in @('Disabled','Revision','RestartPending','RestartUnknown','NewerRevision','MissingPolicy','ConflictingPolicy')) {
    Test-WinSecUpdateReview ('Diagnostics reflect the original collector state: '+$fault) {
        $id='WSA-WUP-BASE-002';$state='UNKNOWN'
        switch($fault) {
            Disabled {$control.Evidence.UpdateService.StartMode='DISABLED';$id='WSA-WUP-BASE-001';$state='NOT_AUTOMATIC';$reason='UPDATE_SERVICE_DISABLED'}
            Revision {$control.Evidence.VersionRegistry.UBR.Value=9000;$state='MISSING';$reason='REVIEWED_BASELINE_OVERDUE'}
            RestartPending {$control.Evidence.RestartInformation.Value=$true;$reason='UPDATE_COMPLETION_UNVERIFIED'}
            RestartUnknown {$control.Evidence.RestartInformation.State='UNKNOWN';$control.Evidence.RestartInformation.Value=$null;$reason='UPDATE_COMPLETION_UNVERIFIED'}
            NewerRevision {$control.Evidence.VersionRegistry.UBR.Value=99999;$reason='NEWER_REVISION_NOT_REVIEWED'}
            MissingPolicy {$control.Evidence.AutomationPolicy.AllowAutoUpdate.State='UNKNOWN';$id='WSA-WUP-BASE-001';$reason='POLICY_SOURCES_UNVERIFIED'}
            ConflictingPolicy {$control.Evidence.AutomationPolicy.AllowAutoUpdate.Managed=$true;$control.Evidence.AutomationPolicy.AllowAutoUpdate.Value=5;
                $id='WSA-WUP-BASE-001';$reason='GROUP_POLICY_MDM_CONFLICT'}
        }
        $items=@(New-WinSecWindowsUpdateReviewItems $control $selection)
        $s=@($items|Where-Object {$_.WindowsUpdateSetting.CriterionId -ceq $id})[0].WindowsUpdateSetting
        Assert-WinSecUpdateReview ($items.Count -eq 3 -and $s.State -ceq $state -and $s.Reason -ceq $reason)
    }
}
foreach($case in @(@('2026-10-23T12:00:00Z','CATALOG_NOT_YET_VALID'),@('2026-10-31T00:00:00Z','CATALOG_EXPIRED'))) {
    Test-WinSecUpdateReview ('Reference freshness is recorded without upgrading unknown states: '+$case[1]) {
        $control.Evidence.CollectedAtUTC=$case[0]
        $items=@(New-WinSecWindowsUpdateReviewItems $control $selection)
        Assert-WinSecUpdateReview (@($items|Where-Object {$_.Status -ceq 'UNKNOWN' -and $_.WindowsUpdateSetting.Reason -ceq $case[1]}).Count -eq 3)
    }
}
foreach($fault in @('ForeignDevice','ForeignScan','ForeignCheck','WrongStatus','WrongType','WrongSchema','WrongReason','WrongState',
    'ExtraRawField','MixedExtension','ArrayState','BadDigest','BadVersion','LongReferenceWindow','WrongFreshness','WrongId','BeforeSession','ContradictoryCriterion','ScriptProperty')) {
    Test-WinSecUpdateReview ('Public diagnostic validation rejects: '+$fault) {
        $item=@(New-WinSecWindowsUpdateReviewItems $control $selection)[0]
        $owner=Copy-WinSecResultData $control
        switch($fault) {
            ForeignDevice {$item.DeviceId='local:hw1-'+('b'*64)};ForeignScan {$item.ScanId='foreign'};ForeignCheck {$item.CheckId='WSA-SYS-001'}
            WrongStatus {$item.Status='FAIL'};WrongType {$item.Type='CRITERION_RESULT'};WrongSchema {$item.WindowsUpdateSetting.SchemaVersion='2.0.0'}
            WrongReason {$item.WindowsUpdateSetting.Reason='PRIVATE-UPDATE-REVIEW'};WrongState {$item.WindowsUpdateSetting.State='SUPPORTED'}
            ExtraRawField {$item.WindowsUpdateSetting|Add-Member RawEvidence 'PRIVATE-UPDATE-REVIEW'}
            MixedExtension {$item|Add-Member BitLockerSetting ([pscustomobject]@{})};ArrayState {$item.WindowsUpdateSetting.State=@('AUTOMATIC')}
            BadDigest {$item.WindowsUpdateSetting.ReferenceSha256='bad'};BadVersion {$item.WindowsUpdateSetting.ReferenceVersion='PRIVATE'}
            LongReferenceWindow {$item.WindowsUpdateSetting.ReferenceValidUntilUTC='2026-11-01T00:00:00Z'}
            WrongFreshness {$item.WindowsUpdateSetting.EvaluatedAtUTC='2026-11-01T00:00:00Z'};WrongId {$item.ReviewId='forged'}
            BeforeSession {$owner|Add-Member StartedAtUTC '2026-10-25T00:00:00Z'}
            ContradictoryCriterion {$owner|Add-Member ConfigurationAssessment ([pscustomobject]@{Controls=@([pscustomobject]@{
                CheckId='WSA-SYS-003';Criteria=@([pscustomobject]@{CriterionId='WSA-WUP-BASE-001';Status='FAIL'})})})}
            ScriptProperty {$item.WindowsUpdateSetting.PSObject.Properties.Remove('State');$script:reviewGetterRuns=0;
                $item.WindowsUpdateSetting|Add-Member ScriptProperty State {$script:reviewGetterRuns++;throw 'PRIVATE'}}
        }
        Assert-WinSecUpdateReviewRejected {ConvertTo-WinSecWindowsUpdateReviewItem $item $owner}
        if($fault -ceq 'ScriptProperty'){Assert-WinSecUpdateReview ($script:reviewGetterRuns -eq 0)}
    }
}
foreach($fault in @('ForeignEvidence','ForeignSelection','MissingRule','DuplicateRule','UnapprovedRule','ReferenceDigest')) {
    Test-WinSecUpdateReview ('No partial diagnostics escape an invalid source: '+$fault) {
        switch($fault) {
            ForeignEvidence {$control.Evidence.ScanId='foreign'};ForeignSelection {$selection.ScanId='foreign'}
            MissingRule {$selection.EligibleCriteria=@($selection.EligibleCriteria|Select-Object -First 2)}
            DuplicateRule {$selection.EligibleCriteria+=@($selection.EligibleCriteria[0])}
            UnapprovedRule {$selection.EligibleCriteria[0].Verification.Status='PENDING'}
            ReferenceDigest {$selection.EligibleCriteria[0].WindowsUpdateReference.ContentSha256='F'*64}
        }
        $published=New-Object 'System.Collections.Generic.List[object]'
        Assert-WinSecUpdateReviewRejected {New-WinSecWindowsUpdateReviewItems $control $selection|ForEach-Object {$published.Add($_)}}
        Assert-WinSecUpdateReview ($published.Count -eq 0)
    }
}
Test-WinSecUpdateReview 'Failed, unselected or unapproved collection does not create diagnostic rows' {
    foreach($status in @('ERROR','NOT_SELECTED','UNKNOWN')) {
        $control.Status=$status;Assert-WinSecUpdateReview (@(New-WinSecWindowsUpdateReviewItems $control $selection).Count -eq 0)
    }
    $control.Status='INFORMATIONAL';$selection.Status='PENDING'
    Assert-WinSecUpdateReview (@(New-WinSecWindowsUpdateReviewItems $control $selection).Count -eq 0)
}
Write-Host ('Windows Update review model: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Windows Update review model tests failed.'}
