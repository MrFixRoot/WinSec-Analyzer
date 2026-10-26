# Real coordinator conversion, public history, CLI, Findings and Markdown, with synthetic providers.
# No native scan, execution permission changes or persistent artifacts.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/TerminalRenderer.ps1','src/UI/Core/LayoutManager.ps1','src/UI/Core/KeyboardController.ps1',
    'src/UI/Components/Table.ps1','src/UI/Components/Banner.ps1','src/UI/Components/KeyboardHelp.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1','src/Services/ReportService.ps1',
    'src/Checks/System/Test-WindowsUpdate.ps1','tests/Fixtures/WindowsUpdateMemory.ps1','tests/Fixtures/WindowsUpdateAssessment.ps1')) {
    . (Join-Path $root $file)
}
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
function Get-BitLockerVolume {throw 'Unexpected BitLocker query.'}
function Save-WinSecPublicHistory {throw 'Unexpected history write.'}
function Save-WinSecEvidence {throw 'Unexpected evidence write.'}
function Write-WinSecMarkdownArtifact {throw 'Unexpected report write.'}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
$script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
$script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=40}
$script:passed=0;$script:failed=0
function Assert-WinSecUpdateReviewIntegration {param([bool]$Value);if(-not $Value){throw 'Windows Update review integration assertion failed.'}}
function Assert-WinSecUpdateReviewIntegrationRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecUpdateReviewIntegration $caught}
function Test-WinSecUpdateReviewIntegration {
    param([string]$Name,[scriptblock]$Action)
    $session=Copy-WinSecResultData $baselineSession
    $before=ConvertTo-Json $script:WU -Depth 12 -Compress
    try {
        $null=& $Action
        Assert-WinSecUpdateReviewIntegration ($before -ceq (ConvertTo-Json $script:WU -Depth 12 -Compress))
        $script:passed++;[Console]::WriteLine('[PASS] '+$Name)
    } catch {$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
function New-WinSecUpdateReviewContext {
    param([object]$Public)
    $key='{0}:{1}{2}:{3}' -f $Public.DeviceId.Length,$Public.DeviceId,$Public.ScanId.Length,$Public.ScanId
    $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$Public.DeviceId;$state.ControlIndex=2
    $state=Set-WinSecNavigationScreen $state Findings;$state.FindingsScope='Control'
    [pscustomobject]@{State=$state;Context=[pscustomobject]@{ProjectRoot=$root;Version='0.9.0';PublicScans=@{$key=$Public};ActiveScanByDevice=@{};
        ActiveScanByScope=@{(Get-WinSecCLIScopeKey $Public.DeviceId CONTROL WSA-SYS-003)=$Public.ScanId}}}
}
Reset-WinSecWindowsUpdateFixture;Set-WinSecWindowsUpdateSupportedFixture
$f=New-WinSecWindowsUpdateAssessmentFixture;$r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
# Exercise the actual coordinator-to-session wiring without invoking a scan.
$audit=Copy-WinSecResultData $f.Audit
$audit|Add-Member ComputerName 'SYNTHETIC-UPDATE';$audit|Add-Member StartedAtUTC '2026-10-24T11:59:00Z'
$audit|Add-Member CompletedAtUTC '2026-10-24T12:01:00Z';$audit|Add-Member ExecutionStatus COMPLETED
$assessment=Copy-WinSecResultData $r.Assessment;$assessment|Add-Member ConfigurationAssessment $r.Summary
$baselineSession=ConvertTo-WinSecCoordinatedSession $audit -ScopeType CONTROL -ScopeKey WSA-SYS-003 -Assessment $assessment
$baselineRecord=New-WinSecPublicHistoryRecord $baselineSession
Test-WinSecUpdateReviewIntegration 'Coordinator conversion publishes three independently verified observations without raw policy data' {
    $p=ConvertTo-WinSecPublicScanResult $session
    $json=Get-WinSecPublicHistoryJson $p
    Assert-WinSecUpdateReviewIntegration ($p.ReviewItems.Count -eq 3 -and $p.ConfigurationAssessment.Controls[0].Value -eq 100 -and
        $p.Findings.Count -eq 0 -and $null -eq $p.OverallScore -and
        $json -notmatch 'PRIVATE|"Evidence"|PolicyRegistry|VersionRegistry|AutomationPolicy|WindowsUpdateReference|NamedPolicy')
}
Test-WinSecUpdateReviewIntegration 'History restore and re-export do not reopen providers, criteria or servicing references' {
    function Get-CimInstance {throw 'Unexpected Windows query.'}
    function Get-WinSecWindowsUpdateReferenceCatalog {throw 'Unexpected reference reload.'}
    function Get-WinSecWindowsUpdateCriteriaTemplate {throw 'Unexpected criteria reload.'}
    function Get-WinSecConfigurationScoringPolicy {throw 'Unexpected scoring reload.'}
    $copy=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $baselineRecord))
    $ctx=New-WinSecUpdateReviewContext $copy.PublicResult
    $selection=Get-WinSecCLIFindingsExportSelection $ctx.State $ctx.Context
    $report=New-WinSecFindingsMarkdown $selection -FrameworkId nist-csf
    Assert-WinSecUpdateReviewIntegration ((Get-WinSecPublicHistoryJson $copy.PublicResult) -ceq (Get-WinSecPublicHistoryJson $baselineRecord.PublicResult) -and
        $report.Markdown.Contains((ConvertTo-WinSecMarkdownText 'REVIEWED_OS_BASELINE_COMPLETED')) -and $report.Markdown.Contains('reference window UTC'))
}
Test-WinSecUpdateReviewIntegration 'Findings enriches the three existing criteria without duplicate review rows or scores' {
    $p=ConvertTo-WinSecPublicScanResult $session;$ctx=New-WinSecUpdateReviewContext $p
    $a=Get-WinSecCLIActiveAssessment $ctx.State $ctx.Context
    $v=Get-WinSecSelectedFindings $ctx.State -ControlResults $a.ControlResults -Findings $a.Findings -ReviewItems $a.ReviewItems `
        -ScanId $a.ScanId -ConfigurationAssessment $a.ConfigurationAssessment
    Assert-WinSecUpdateReviewIntegration ($v.CheckRows.Count -eq 3 -and $v.Rows.Count -eq 3 -and $v.Score -ceq '100/100' -and
        $v.Rows[0].DisplayId -ceq '01' -and $v.Rows[1].Finding.Contains('no restart is pending') -and
        $v.Rows[1].Description.Contains('REVIEWED_OS_BASELINE_COMPLETED') -and $v.Rows[1].ConfigurationPercent -ceq '100%')
    $back=Invoke-WinSecNavigationAction $ctx.State Back
    Assert-WinSecUpdateReviewIntegration ($back.Screen -ceq 'Section' -and $back.ControlIndex -eq 2)
}
foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
    Test-WinSecUpdateReviewIntegration ('Markdown preserves table order, diagnostic reasons and reviewed source metadata: '+$framework) {
        $p=ConvertTo-WinSecPublicScanResult $session;$ctx=New-WinSecUpdateReviewContext $p
        $selection=Get-WinSecCLIFindingsExportSelection $ctx.State $ctx.Context
        $before=Get-WinSecPublicHistoryJson $selection
        $report=New-WinSecFindingsMarkdown $selection -FrameworkId $framework
        $markdown=$report.Markdown;$rows=$markdown -split "`n"
        Assert-WinSecUpdateReviewIntegration ($markdown.Contains('| ID | Control | Configuration | State | Configuration % |') -and
            $markdown.Contains('AUTOMATIC') -and $markdown.Contains((ConvertTo-WinSecMarkdownText 'REVIEWED_OS_BASELINE_COMPLETED')) -and
            $markdown.Contains((ConvertTo-WinSecMarkdownText 'WITHIN_REVIEWED_SUPPORT_PERIOD')) -and
            $markdown.Contains($p.ReviewItems[0].WindowsUpdateSetting.ReferenceSha256) -and $markdown.Contains('not every applicable update') -and
            $markdown.Contains('pending individual review') -and $before -ceq (Get-WinSecPublicHistoryJson $selection))
        for($i=0;$i -lt $rows.Count;$i++) {
            if(-not $rows[$i].StartsWith('|')){continue}
            if($i -eq 0 -or -not $rows[$i-1].StartsWith('|')){Assert-WinSecUpdateReviewIntegration ($i -gt 0 -and [string]::IsNullOrWhiteSpace($rows[$i-1]))}
            if($i+1 -eq $rows.Count -or -not $rows[$i+1].StartsWith('|')){Assert-WinSecUpdateReviewIntegration ($i+1 -lt $rows.Count -and [string]::IsNullOrWhiteSpace($rows[$i+1]))}
        }
        if($null -ne (Get-Command ConvertFrom-Markdown -CommandType Cmdlet -ErrorAction SilentlyContinue)) {
            $html=(ConvertFrom-Markdown -InputObject $markdown).Html
            Assert-WinSecUpdateReviewIntegration ([regex]::Matches($html,'<table>').Count -eq 3 -and $html.Contains('<td>REVIEWED_OS_BASELINE_COMPLETED</td>'))
        }
    }
}
foreach($size in @(@(120,40),@(80,26),@(40,20),@(16,5),@(120,40))) {
    Test-WinSecUpdateReviewIntegration ('Diagnostic Findings stays within resized terminal '+($size -join 'x')) {
        $p=ConvertTo-WinSecPublicScanResult $session;$ctx=New-WinSecUpdateReviewContext $p
        $script:terminal=[pscustomobject]@{Width=$size[0];ContentWidth=($size[0]-1);Height=$size[1]}
        Show-WinSecCLICurrentScreen $ctx.State $ctx.Context
        Assert-WinSecUpdateReviewIntegration (@($script:lines|Where-Object {$_.Length -gt $size[0]}).Count -eq 0)
    }
}
foreach($fault in @('AllowedReason','SourceDigest','ReferenceWindow','CollectionTime','MissingEvidence')) {
    Test-WinSecUpdateReviewIntegration ('Publication reproduces the diagnostic source independently: '+$fault) {
        $s=$session.ReviewItems[0].WindowsUpdateSetting
        switch($fault) {
            AllowedReason {$s.Reason='MANAGED_POLICY_RESOLVED'};SourceDigest {$s.ReferenceSha256='F'*64}
            ReferenceWindow {$s.ReferenceAsOfUTC='2026-10-23T00:00:00Z';$s.ReferenceValidUntilUTC='2026-10-30T00:00:00Z'}
            CollectionTime {$s.EvaluatedAtUTC='2026-10-24T11:59:30Z'};MissingEvidence {$session.ControlResults[0].Evidence=$null}
        }
        Assert-WinSecUpdateReviewIntegrationRejected {ConvertTo-WinSecPublicScanResult $session}
    }
}
foreach($fault in @('Foreign','RawField','Duplicate','StateContradiction','OutsideSession')) {
    Test-WinSecUpdateReviewIntegration ('History rejects inconsistent diagnostic data even with a recomputed digest: '+$fault) {
        $record=Copy-WinSecResultData $baselineRecord;$item=$record.PublicResult.ReviewItems[0]
        switch($fault) {
            Foreign {$item.ScanId='foreign'};RawField {$item.WindowsUpdateSetting|Add-Member Evidence 'PRIVATE'}
            Duplicate {$record.PublicResult.ReviewItems+=@($item)}
            StateContradiction {$item.WindowsUpdateSetting.State='NOT_AUTOMATIC';$item.WindowsUpdateSetting.Reason='GROUP_POLICY_RESOLVED'}
            OutsideSession {$item.WindowsUpdateSetting.EvaluatedAtUTC='2026-10-24T13:00:00Z'}
        }
        $record.ContentSha256=Get-WinSecPublicHistoryDigest $record
        Assert-WinSecUpdateReviewIntegrationRejected {ConvertFrom-WinSecPublicHistoryRecord $record}
    }
}
Test-WinSecUpdateReviewIntegration 'The CLI and direct Findings reject a diagnostic state that contradicts the recorded criterion' {
    $p=Copy-WinSecResultData $baselineRecord.PublicResult;$p.ReviewItems[0].WindowsUpdateSetting.State='NOT_AUTOMATIC'
    $ctx=New-WinSecUpdateReviewContext $p
    Assert-WinSecUpdateReviewIntegrationRejected {Get-WinSecCLIActiveAssessment $ctx.State $ctx.Context}
    Assert-WinSecUpdateReviewIntegrationRejected {Get-WinSecSelectedFindings $ctx.State -ControlResults $p.ControlResults -Findings $p.Findings `
        -ReviewItems $p.ReviewItems -ScanId $p.ScanId -ConfigurationAssessment $p.ConfigurationAssessment}
}
Test-WinSecUpdateReviewIntegration 'Older public results without the optional diagnostic extension remain unchanged' {
    $session.ReviewItems=@()
    $record=New-WinSecPublicHistoryRecord $session;$json=Get-WinSecPublicHistoryJson $record
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $json)
    Assert-WinSecUpdateReviewIntegration ($restored.PublicResult.ReviewItems.Count -eq 0 -and
        $json -ceq (Get-WinSecPublicHistoryJson $restored.Record) -and $restored.PublicResult.ConfigurationAssessment.Controls[0].Value -eq 100)
}
Test-WinSecUpdateReviewIntegration 'Diagnostic publication remains a copy and cannot rewrite its session' {
    $public=ConvertTo-WinSecPublicScanResult $session;$before=Get-WinSecPublicHistoryJson $session
    $public.ReviewItems[0].WindowsUpdateSetting.Reason='MANAGED_POLICY_RESOLVED'
    Assert-WinSecUpdateReviewIntegration ($before -ceq (Get-WinSecPublicHistoryJson $session))
}
# A new synthetic collection proves unresolved applicable evidence stays unscored.
Reset-WinSecWindowsUpdateFixture;Set-WinSecWindowsUpdateSupportedFixture;$script:WU.RebootValue=$true
$f=New-WinSecWindowsUpdateAssessmentFixture;$r=Invoke-WinSecWindowsUpdateAssessmentFixture $f
$baselineSession=New-WinSecWindowsUpdateAssessmentSession $f $r
Test-WinSecUpdateReviewIntegration 'An unresolved restart is explained in Findings, history and Markdown without a false deviation or score' {
    $record=New-WinSecPublicHistoryRecord $session
    $p=(ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))).PublicResult
    $ctx=New-WinSecUpdateReviewContext $p;$selection=Get-WinSecCLIFindingsExportSelection $ctx.State $ctx.Context
    $report=New-WinSecFindingsMarkdown $selection -FrameworkId nist-csf
    Assert-WinSecUpdateReviewIntegration ($null -eq $p.ConfigurationAssessment.Controls[0].Value -and
        $p.ReviewItems[1].Status -ceq 'UNKNOWN' -and $p.ReviewItems[1].WindowsUpdateSetting.Reason -ceq 'UPDATE_COMPLETION_UNVERIFIED' -and
        @($p.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0 -and
        $report.Markdown.Contains((ConvertTo-WinSecMarkdownText 'UPDATE_COMPLETION_UNVERIFIED')) -and $report.Markdown.Contains('NOT_SCORED'))
}
[Console]::WriteLine(('Windows Update review integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Windows Update review integration failed.'}
