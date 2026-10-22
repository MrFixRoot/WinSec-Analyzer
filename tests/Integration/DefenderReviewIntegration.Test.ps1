# Real Defender/coordinator/public history/CLI/UI/Markdown; all Windows and I/O synthetic.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/TerminalRenderer.ps1','src/UI/Core/LayoutManager.ps1','src/UI/Core/KeyboardController.ps1',
    'src/UI/Components/Table.ps1','src/UI/Components/Banner.ps1','src/UI/Components/KeyboardHelp.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1',
    'src/Services/FrameworkService.ps1','src/Core/FrameworkMappingEngine.ps1','src/Services/ReportService.ps1')){. (Join-Path $root $file)}
function Get-CimInstance {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    if($ClassName -ceq 'Win32_ComputerSystemProduct'){return [pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}}
    if($ClassName -ceq 'Win32_OperatingSystem'){return [pscustomobject]@{Caption='Microsoft Windows 11';Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=48;ProductType=1}}
    throw 'Unexpected synthetic CIM class.'
}
function Get-MpComputerStatus {
    [CmdletBinding()]param()
    $script:reads++
    [pscustomobject]@{AMRunningMode='Normal';AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$script:realtime;BehaviorMonitorEnabled=$true;IsTamperProtected=($script:additionalHealthy -and $script:badCriterion -cne 'TAMPER')}
}
function Get-MpPreference {
    [CmdletBinding()]param()
    [pscustomobject]@{PUAProtection=if($script:additionalHealthy -and $script:badCriterion -cne 'PUA'){1}else{0};
        MAPSReporting=if($script:badCriterion -ceq 'UNKNOWN_CLOUD'){$null}elseif($script:additionalHealthy -and $script:badCriterion -cne 'CLOUD'){2}else{0};ExclusionPath=@('C:\PRIVATE-REVIEW-INTEGRATION');
        AttackSurfaceReductionRules_Ids=@('56a863a9-875e-4185-98a7-b882c64b5ce5','9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
            'e6db77e5-3df2-4cf1-b95a-636979351e5b','d4f940ab-401b-4efc-aadc-ad5f3c50688a');
        AttackSurfaceReductionRules_Actions=@($(if($script:badCriterion -ceq 'ASR'){2}else{1}),2,6,0)}
}
function Save-WinSecPublicHistory {throw 'Unexpected history write.'}
function Save-WinSecEvidence {throw 'Unexpected evidence write.'}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
$script:passed=0;$script:failed=0;$script:reads=0;$script:realtime=$false;$script:additionalHealthy=$false;$script:badCriterion=''
$script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55}
$script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
function Assert-WinSecReviewIntegration {param([bool]$Value);if(-not $Value){throw 'Defender review integration assertion failed.'}}
function Test-WinSecReviewIntegration {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
$coordinator=New-WinSecScanCoordinator
$target=New-WinSecLocalTarget
$coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
$coordinator.AssessmentEnabled=$true;$coordinator.PublicHistoryEnabled=$false
$public=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -DeviceId $target.DeviceId -ScanId 'defender-review-integration' `
    -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction {$true}
$key='{0}:{1}{2}:{3}' -f $public.DeviceId.Length,$public.DeviceId,$public.ScanId.Length,$public.ScanId
$ctx=[pscustomobject]@{ProjectRoot=$root;Version='0.9.0';PublicScans=@{$key=$public};ActiveScanByDevice=@{};
    ActiveScanByScope=@{(Get-WinSecCLIScopeKey $public.DeviceId CONTROL WSA-SYS-001)=$public.ScanId};ScanCoordinator=$coordinator;Devices=@($target)}
$state=New-WinSecNavigationState;$state.Screen='Findings';$state.FindingsScope='Control';$state.SelectedDeviceId=$public.DeviceId
Test-WinSecReviewIntegration 'The real collector grades the selected baseline and preserves the remaining ASR inventory' {
    Assert-WinSecReviewIntegration ($script:reads -eq 1 -and $public.ReviewItems.Count -eq 8 -and $public.Findings.Count -eq 4 -and
        $public.ConfigurationAssessment.Controls[0].Value -eq 50 -and $public.ConfigurationAssessment.Controls[0].Criteria.Count -eq 8)
    $rules=@($public.ReviewItems|Where-Object {$_.DefenderSetting.Topic -ceq 'ASR' -and $_.DefenderSetting.SettingId -cne 'INVENTORY'})
    Assert-WinSecReviewIntegration (($rules.DefenderSetting.Mode -join ',') -ceq 'BLOCK,AUDIT,WARN,DISABLED' -and
        (ConvertTo-Json $public -Depth 40) -notmatch 'PRIVATE-REVIEW-INTEGRATION|RawAction|ExclusionPath|"Evidence"')
}
Test-WinSecReviewIntegration 'Canonical public history roundtrip preserves inventory and its original session without Windows reads' {
    $session=($coordinator.Sessions.Values|Select-Object -First 1).Session
    $record=New-WinSecPublicHistoryRecord $session
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    $expected=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecReviewIntegration ((Get-WinSecPublicHistoryJson $restored.PublicResult) -ceq (Get-WinSecPublicHistoryJson $expected) -and
        (Get-WinSecPublicHistoryJson $restored.PublicResult.ReviewItems) -ceq (Get-WinSecPublicHistoryJson $public.ReviewItems) -and $script:reads -eq 1)
    # All subsequent UI/export cases consume only the reconstructed public history.
    $ctx.PublicScans[$key]=Copy-WinSecResultData $restored.PublicResult
}
Test-WinSecReviewIntegration 'Findings routes observations separately and includes them in scrolling without false deviations' {
    $active=Get-WinSecCLIActiveAssessment $state $ctx
    $view=Get-WinSecSelectedFindings $state -ControlResults $active.ControlResults -Findings $active.Findings -ScanId $active.ScanId -ReviewItems $active.ReviewItems -ConfigurationAssessment $active.ConfigurationAssessment
    $counts=Get-WinSecCLINavigationCounts $state $ctx
    Show-WinSecCLICurrentScreen $state $ctx
    Assert-WinSecReviewIntegration ($view.Findings.Count -eq 4 -and $view.ReviewItems.Count -eq 8 -and $view.CheckRows.Count -eq 8 -and $counts.FindingCount -eq 12 -and
        ($script:lines -join '|').Contains('PASS') -and ($script:lines -join '|').Contains('FAIL') -and $script:reads -eq 1)
    foreach($row in $view.Rows|Where-Object {$_.Kind -ceq 'CRITERION_RESULT'}) {
        Assert-WinSecReviewIntegration ($row.ControlCode -ceq ($row.CheckId+' / '+$row.CriterionId) -and
            ($script:lines -join '|').Contains($row.ControlCode))
    }
    $state.ControlIndex=1
    $other=Get-WinSecCLIActiveAssessment $state $ctx
    Assert-WinSecReviewIntegration (@($other.ReviewItems).Count -eq 0)
    $state.ControlIndex=0
}
foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
    Test-WinSecReviewIntegration ('Markdown re-exports only public inventory and the existing approved finding: '+$framework) {
        $selection=Get-WinSecCLIFindingsExportSelection $state $ctx
        $report=New-WinSecFindingsMarkdown $selection -FrameworkId $framework
        Assert-WinSecReviewIntegration ($report.Markdown.Contains('Defender observations') -and $report.Markdown.Contains('BLOCK') -and
            $report.Markdown.Contains('9e6c4e1f') -and $report.Markdown.Contains('excluded from scoring') -and
            $report.Markdown.Contains('50/100') -and $report.Markdown.Contains('Configuration checks') -and $report.Markdown.Contains('Framework-oriented manual guidance:') -and
            $report.Markdown -notmatch 'PRIVATE-REVIEW-INTEGRATION|RawAction|ExclusionPath|"Evidence"' -and $script:reads -eq 1)
        $markdownLines=@($report.Markdown -split '\r?\n')
        for($i=0;$i -lt $markdownLines.Count;$i++) {
            if(-not $markdownLines[$i].StartsWith('|')){continue}
            if($i -eq 0 -or -not $markdownLines[$i-1].StartsWith('|')) {
                Assert-WinSecReviewIntegration ($i -gt 0 -and [string]::IsNullOrWhiteSpace($markdownLines[$i-1]))
            }
            if($i+1 -eq $markdownLines.Count -or -not $markdownLines[$i+1].StartsWith('|')) {
                Assert-WinSecReviewIntegration ($i+1 -lt $markdownLines.Count -and [string]::IsNullOrWhiteSpace($markdownLines[$i+1]))
            }
        }
        # The built-in PS7 Markdown renderer verifies actual table structure.
        # PS5.1 exercises the same table boundaries without an extra dependency.
        if($null -ne (Get-Command ConvertFrom-Markdown -CommandType Cmdlet -ErrorAction SilentlyContinue)) {
            $html=(ConvertFrom-Markdown -InputObject $report.Markdown).Html
            $tables=[regex]::Matches($html,'<table>[\s\S]*?</table>')
            Assert-WinSecReviewIntegration ($tables.Count -eq 3 -and
                [regex]::Matches($tables[0].Value,'<tr>').Count -eq 9 -and
                -not $tables[0].Value.Contains('Percentages describe'))
        }
    }
}
foreach($size in @(@(80,26),@(40,20),@(16,5))) {
    Test-WinSecReviewIntegration ('Review rows and the last ASR item fit terminal '+($size -join 'x')) {
        $script:terminal=[pscustomobject]@{Width=$size[0];ContentWidth=($size[0]-1);Height=$size[1]};$state.FindingsOffset=8
        Show-WinSecCLICurrentScreen $state $ctx
        Assert-WinSecReviewIntegration (@($script:lines|Where-Object {$_.Length -gt $size[0]}).Count -eq 0 -and
            $state.FindingsOffset -eq 8 -and $script:reads -eq 1)
    }
}
foreach($fault in @('Device','Scan','Scope','Raw','Duplicate')) {
    Test-WinSecReviewIntegration ('Export rejects a forged observation before publishing Markdown: '+$fault) {
        $selection=Get-WinSecCLIFindingsExportSelection $state $ctx
        switch($fault){Device {$selection.ReviewItems[0].DeviceId='local:another'};Scan {$selection.ReviewItems[0].ScanId='another'};
            Scope {$selection.ScopeKey='WSA-SYS-002'};Raw {$selection.ReviewItems[0].DefenderSetting|Add-Member RawAction 'PRIVATE'};
            Duplicate {$selection.ReviewItems+=Copy-WinSecResultData $selection.ReviewItems[0]}}
        $caught=$false;try{$null=New-WinSecFindingsMarkdown $selection -FrameworkId nist-csf}catch{$caught=$true}
        Assert-WinSecReviewIntegration ($caught -and $script:reads -eq 1)
    }
}
Test-WinSecReviewIntegration 'Cancelling a fresh operation cannot collect or publish new review observations' {
    $cancelled=New-WinSecScanCoordinator;$cancelled.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $result=Invoke-WinSecCoordinatedScan -Coordinator $cancelled -DeviceId $target.DeviceId -ScanId 'review-cancelled' `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction {$false}
    Assert-WinSecReviewIntegration ($null -eq $result -and $cancelled.Sessions.Count -eq 0 -and $script:reads -eq 1)
}
Test-WinSecReviewIntegration 'A scan with no approved deviations can export observations without inventing a failed control' {
    $script:realtime=$true;$script:additionalHealthy=$true
    $fresh=New-WinSecScanCoordinator;$fresh.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)};$fresh.AssessmentEnabled=$true
    $p=Invoke-WinSecCoordinatedScan -Coordinator $fresh -DeviceId $target.DeviceId -ScanId 'review-only-export' `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction {$true}
    $sessionKey='{0}:{1}{2}:{3}' -f $p.DeviceId.Length,$p.DeviceId,$p.ScanId.Length,$p.ScanId
    $freshCtx=[pscustomobject]@{ProjectRoot=$root;PublicScans=@{$sessionKey=$p};ActiveScanByDevice=@{};
        ActiveScanByScope=@{(Get-WinSecCLIScopeKey $p.DeviceId CONTROL WSA-SYS-001)=$p.ScanId}}
    $selection=Get-WinSecCLIFindingsExportSelection $state $freshCtx
    $report=New-WinSecFindingsMarkdown $selection -FrameworkId nist-csf
    Assert-WinSecReviewIntegration ($p.Findings.Count -eq 0 -and $selection.Findings.Count -eq 0 -and $selection.ReviewItems.Count -eq 8 -and
        $p.ConfigurationAssessment.Controls[0].Value -eq 100 -and $report.Markdown.Contains('No verified configuration deviations') -and
        $report.Markdown.Contains('Defender observations') -and $report.Markdown.Contains('Configuration checks') -and
        $report.Markdown -notmatch 'Criteria: PENDING_APPROVED_CRITERIA' -and $script:reads -eq 2)
}
foreach($fault in @('Device','Scan','Raw','Duplicate')) {
    Test-WinSecReviewIntegration ('CLI refuses a forged cached observation before drawing: '+$fault) {
        $bad=[pscustomobject]@{PublicScans=(Copy-WinSecResultData $ctx.PublicScans);ActiveScanByDevice=@{};
            ActiveScanByScope=(Copy-WinSecResultData $ctx.ActiveScanByScope);Version='0.9.0'}
        $item=$bad.PublicScans[$key].ReviewItems[0]
        switch($fault){Device {$item.DeviceId='local:other'};Scan {$item.ScanId='other'};
            Raw {$item.DefenderSetting|Add-Member RawEvidence 'PRIVATE'};Duplicate {$bad.PublicScans[$key].ReviewItems+=Copy-WinSecResultData $item}}
        $before=$script:lines -join '|';$reads=$script:reads;$caught=$false
        try{Show-WinSecCLICurrentScreen $state $bad}catch{$caught=$true}
        Assert-WinSecReviewIntegration ($caught -and $before -ceq ($script:lines -join '|') -and $script:reads -eq $reads)
    }
}
foreach($spec in @(@{Topic='PUA';Id='WSA-DEF-ADD-001'},@{Topic='CLOUD';Id='WSA-DEF-ADD-002'},
    @{Topic='TAMPER';Id='WSA-DEF-ADD-003'},@{Topic='ASR';Id='WSA-DEF-ADD-004'})) {
    Test-WinSecReviewIntegration ('Each new group contributes independently to the score and framework guidance: '+$spec.Topic) {
        $script:badCriterion=$spec.Topic;$script:realtime=$true;$script:additionalHealthy=$true
        $fresh=New-WinSecScanCoordinator;$fresh.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)};$fresh.AssessmentEnabled=$true
        $p=Invoke-WinSecCoordinatedScan -Coordinator $fresh -DeviceId $target.DeviceId -ScanId ('score-'+$spec.Topic) `
            -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction {$true}
        Assert-WinSecReviewIntegration ($p.ConfigurationAssessment.Controls[0].Value -eq 87.5 -and $p.Findings.Count -eq 1 -and
            $p.Findings[0].Guidance.CriterionId -ceq $spec.Id)
        $sessionKey='{0}:{1}{2}:{3}' -f $p.DeviceId.Length,$p.DeviceId,$p.ScanId.Length,$p.ScanId
        $exportContext=[pscustomobject]@{ProjectRoot=$root;PublicScans=@{$sessionKey=$p};ActiveScanByDevice=@{};
            ActiveScanByScope=@{(Get-WinSecCLIScopeKey $p.DeviceId CONTROL WSA-SYS-001)=$p.ScanId}}
        $selection=Get-WinSecCLIFindingsExportSelection $state $exportContext
        foreach($fw in @('cis-controls','nist-csf','mitre-attack')) {
            $report=New-WinSecFindingsMarkdown $selection -FrameworkId $fw
            if($spec.Topic -ceq 'ASR') {
                $expectedReference=switch($fw){'cis-controls' {'10.5'};'nist-csf' {'PR.PS-05'};'mitre-attack' {'T1068'}}
                if(-not $report.Markdown.Contains('reference: '+(ConvertTo-WinSecMarkdownText $expectedReference))){throw ('Missing ASR mapping: '+$fw)}
            }
            Assert-WinSecReviewIntegration ($report.Markdown.Contains('87.5/100') -and $report.Markdown.Contains('Framework-oriented manual guidance:') -and
                $report.Markdown.Contains('Configuration checks') -and $report.Markdown.Contains('PASS') -and $report.Markdown.Contains('FAIL'))
        }
        $script:badCriterion=''
    }
}
Test-WinSecReviewIntegration 'Missing added telemetry is UNKNOWN and never becomes a false failure or numeric score' {
    $script:badCriterion='UNKNOWN_CLOUD';$script:realtime=$true;$script:additionalHealthy=$true
    $fresh=New-WinSecScanCoordinator;$fresh.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)};$fresh.AssessmentEnabled=$true
    $p=Invoke-WinSecCoordinatedScan -Coordinator $fresh -DeviceId $target.DeviceId -ScanId 'unknown-added-criterion' `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction {$true}
    $control=$p.ConfigurationAssessment.Controls[0]
    Assert-WinSecReviewIntegration ($null -eq $control.Value -and $control.Coverage -eq 87.5 -and
        @($control.Criteria|Where-Object {$_.CriterionId -ceq 'WSA-DEF-ADD-002' -and $_.Status -ceq 'UNKNOWN'}).Count -eq 1 -and
        @($p.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
    $script:badCriterion=''
}
function Get-FileHash {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Algorithm='SHA256')
    if($script:changedRevision -and $LiteralPath -like '*defender-additional.json'){return [pscustomobject]@{Hash=('F'*64)}}
    Microsoft.PowerShell.Utility\Get-FileHash @PSBoundParameters
}
Test-WinSecReviewIntegration 'Changing the approved additional catalog during confirmation aborts before any collection' {
    $before=$script:reads;$script:changedRevision=$false
    $fresh=New-WinSecScanCoordinator;$fresh.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)};$fresh.AssessmentEnabled=$true
    $caught=$false
    try{$null=Invoke-WinSecCoordinatedScan -Coordinator $fresh -DeviceId $target.DeviceId -ScanId 'revision-race' `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction {$script:changedRevision=$true;return $true}}
    catch{$caught=$true}finally{$script:changedRevision=$false}
    Assert-WinSecReviewIntegration ($caught -and $script:reads -eq $before -and $fresh.Sessions.Count -eq 0)
}
[Console]::WriteLine(('Defender review integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Defender review integration failed.'}
