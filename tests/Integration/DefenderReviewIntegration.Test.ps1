# Real Defender/coordinator/public history/CLI/UI/Markdown; all Windows and I/O synthetic.
[CmdletBinding()]
param([string]$CasePattern='*')
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/TerminalRenderer.ps1','src/UI/Core/LayoutManager.ps1','src/UI/Core/KeyboardController.ps1',
    'src/UI/Components/Table.ps1','src/UI/Components/Banner.ps1','src/UI/Components/KeyboardHelp.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1',
    'src/Services/FrameworkService.ps1','src/Core/FrameworkMappingEngine.ps1','src/Services/ReportService.ps1')){. (Join-Path $root $file)}
. (Join-Path $PSScriptRoot '../Fixtures/FrameworkMemory.ps1')
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
    $preferences=[pscustomobject]@{PUAProtection=if($script:additionalHealthy -and $script:badCriterion -cne 'PUA'){1}else{0};
        MAPSReporting=if($script:badCriterion -ceq 'UNKNOWN_CLOUD'){$null}elseif($script:additionalHealthy -and $script:badCriterion -cne 'CLOUD'){2}else{0};ExclusionPath=@('C:\PRIVATE-REVIEW-INTEGRATION');
        AttackSurfaceReductionRules_Ids=@('56a863a9-875e-4185-98a7-b882c64b5ce5','9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
            'e6db77e5-3df2-4cf1-b95a-636979351e5b','d4f940ab-401b-4efc-aadc-ad5f3c50688a');
        AttackSurfaceReductionRules_Actions=@($(if($script:badCriterion -ceq 'ASR'){2}else{1}),
            $(if($script:additionalHealthy){1}else{2}),$(if($script:additionalHealthy){1}else{6}),$(if($script:additionalHealthy){1}else{0}))}
    switch($script:asrShape) {
        'NULL_PAIR' {$preferences.AttackSurfaceReductionRules_Ids=$null;$preferences.AttackSurfaceReductionRules_Actions=$null}
        'MISSING' {$preferences.PSObject.Properties.Remove('AttackSurfaceReductionRules_Actions')}
        'NULL_IDS' {$preferences.AttackSurfaceReductionRules_Ids=$null}
        'NULL_ACTIONS' {$preferences.AttackSurfaceReductionRules_Actions=$null}
        'NULL_ENTRIES' {$preferences.AttackSurfaceReductionRules_Ids=@($null);$preferences.AttackSurfaceReductionRules_Actions=@($null)}
    }
    return $preferences
}
function Save-WinSecPublicHistory {throw 'Unexpected history write.'}
function Save-WinSecEvidence {throw 'Unexpected evidence write.'}
function Import-WinSecDeviceInventory {param($ProjectRoot);[pscustomobject]@{schemaVersion='1.2.0';targets=@(New-WinSecLocalTarget);removedDeviceHashes=@()}}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
$script:passed=0;$script:failed=0;$script:reads=0;$script:realtime=$false;$script:additionalHealthy=$false;$script:badCriterion=''
$script:asrShape='NORMAL'
$script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55}
$script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
function Assert-WinSecReviewIntegration {param([bool]$Value);if(-not $Value){throw 'Defender review integration assertion failed.'}}
function Test-WinSecReviewIntegration {
    param([string]$Name,[scriptblock]$Action)
    if($Name -notlike $CasePattern){return}
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
Reset-WinSecFrameworkMemory
function New-WinSecReviewContext {
    param([string]$Id='defender-review-integration',[scriptblock]$ConfirmAction={$true})
    $coordinator=New-WinSecScanCoordinator -ProjectRoot $root;$target=New-WinSecLocalTarget
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)};$coordinator.TechnicalReportsEnabled=$true;$coordinator.AssessmentEnabled=$true
    $p=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -DeviceId $target.DeviceId -ScanId $Id -ScopeType CONTROL -ScopeKey WSA-SYS-001 `
        -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction $ConfirmAction
    $c=[pscustomobject]@{ProjectRoot=$root;Version='0.9.0';PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};
        ScanCoordinator=$coordinator;Devices=@($target);FrameworkWorkflowEnabled=$true;LocalDeviceId=$target.DeviceId}
    if($null -ne $p){Add-WinSecFrameworkMemoryPublic $c $p}
    $c
}
function New-WinSecReviewState {
    param($Context)
    $s=New-WinSecNavigationState;$s.Screen='Findings';$s.FindingsScope='Control';$s.SelectedDeviceId=$Context.Devices[0].DeviceId;$s
}
function Assert-WinSecReviewRejected {
    param([scriptblock]$Action)
    $caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecReviewIntegration $caught
}
$ctx=New-WinSecReviewContext;$state=New-WinSecReviewState $ctx
$public=@($ctx.PublicScans.Values)[0];$key=@($ctx.PublicScans.Keys)[0];$target=$ctx.Devices[0]
Test-WinSecReviewIntegration 'Production collector preserves complete ASR inventory in technical readings without grading the scan' {
    $r=Read-WinSecTechnicalReport $root $public.DeviceId $public.ScanId WSA-SYS-001
    $rules=@($r.Rows|Where-Object SettingId -CLike 'AttackSurfaceReduction.Rules.*.Mode')
    Assert-WinSecReviewIntegration ($script:reads -eq 1 -and $null -eq $public.ConfigurationAssessment -and $public.Findings.Count -eq 4 -and
        $rules.Count -eq 4 -and (($rules.Value|Sort-Object) -join ',') -ceq 'AUDIT,BLOCK,DISABLED,WARN' -and
        (Get-WinSecPublicHistoryJson $r) -notmatch 'PRIVATE-REVIEW-INTEGRATION|ExclusionPath|"Evidence"' -and
        (Get-WinSecPublicHistoryJson $public) -notmatch 'PRIVATE-REVIEW-INTEGRATION|RawAction|ExclusionPath|"Evidence"')
    $expected=@{
        '56a863a9-875e-4185-98a7-b882c64b5ce5'=@('BLOCK','1');'9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'=@('AUDIT','2');
        'e6db77e5-3df2-4cf1-b95a-636979351e5b'=@('WARN','6');'d4f940ab-401b-4efc-aadc-ad5f3c50688a'=@('DISABLED','0')}
    foreach($id in $expected.Keys) {
        $mode=@($r.Rows|Where-Object SettingId -CEQ ('AttackSurfaceReduction.Rules.'+$id+'.Mode'))
        $code=@($r.Rows|Where-Object SettingId -CEQ ('AttackSurfaceReduction.Rules.'+$id+'.RawAction'))
        Assert-WinSecReviewIntegration ($mode.Count -eq 1 -and $code.Count -eq 1 -and $mode[0].Value -ceq $expected[$id][0] -and $code[0].Value -ceq $expected[$id][1])
    }
}
Test-WinSecReviewIntegration 'Canonical history roundtrip preserves its original session; saved technical readings remain independently readable' {
    $session=(@($ctx.ScanCoordinator.Sessions.Values)[0]).Session;$record=New-WinSecPublicHistoryRecord $session
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    Assert-WinSecReviewIntegration ((Get-WinSecPublicHistoryJson $restored.PublicResult) -ceq (Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult $session)) -and $script:reads -eq 1)
    $ctx.PublicScans[$key]=Copy-WinSecResultData $restored.PublicResult
    # Force F through the saved artifact reader rather than its in-memory cache.
    $ctx.ScanCoordinator.TechnicalSnapshots.Clear()
}
Test-WinSecReviewIntegration 'Findings displays only warnings, retaining ASR context and real navigation counts' {
    $a=Open-WinSecFrameworkMemoryView $state $ctx
    $count=Get-WinSecCLINavigationCounts $state $ctx;Show-WinSecCLICurrentScreen $state $ctx
    Assert-WinSecReviewIntegration ($a.Rows.Count -eq 8 -and $count.FindingCount -eq $a.Rows.Count -and $a.UnknownReadingCount -gt 0 -and
        ($script:lines -join '|').Contains('WARNING') -and ($script:lines -join '|') -notmatch 'CONFIGURATION %|/100' -and $script:reads -eq 1)
    $state.ControlIndex=1;$other=Open-WinSecFrameworkMemoryView $state $ctx
    Assert-WinSecReviewIntegration ($other.Rows.Count -eq 0 -and $other.Sources.Count -eq 0)
    $state.ControlIndex=0;$null=Open-WinSecFrameworkMemoryView $state $ctx
}
foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
    Test-WinSecReviewIntegration ('Markdown exports exactly the frozen warning rows and table boundaries: '+$framework) {
        $a=Open-WinSecFrameworkMemoryView $state $ctx $framework;$frozen=Get-WinSecPublicHistoryJson $a
        $null=Invoke-WinSecCLIFindingsExport $state $ctx;$e=$script:frameworkExports[$script:frameworkExports.Count-1];$text=$e.Markdown
        Assert-WinSecReviewIntegration ($e.Analysis.AnalysisId -ceq $a.AnalysisId -and $e.Analysis.FrameworkId -ceq $framework -and
            (Get-WinSecPublicHistoryJson $e.Analysis.Rows) -ceq (Get-WinSecPublicHistoryJson $a.Rows) -and
            $text.Contains('## Source scans') -and $text.Contains('## Coverage') -and $text.Contains('Manual recommendation:') -and
            $text -notmatch 'PRIVATE-REVIEW-INTEGRATION|RawAction|ExclusionPath|"Evidence"|/100|Configuration %' -and
            $script:reads -eq 1 -and $frozen -ceq (Get-WinSecPublicHistoryJson $ctx.FrameworkFindings))
        foreach($row in $a.Rows) {
            $values=@($row.Id,($row.CheckId+' / '+$row.CriterionId),$row.Title,$row.State,$row.Observed)
            $prefix='| '+((@($values|ForEach-Object {ConvertTo-WinSecTechnicalCell $_})) -join ' | ')+' |'
            Assert-WinSecReviewIntegration ($text.Contains($prefix) -and $row.References.Count -gt 0)
        }
        $lines=@($text -split '\r?\n')
        for($i=0;$i -lt $lines.Count;$i++) {
            if(-not $lines[$i].StartsWith('|')){continue}
            if($i -eq 0 -or -not $lines[$i-1].StartsWith('|')){Assert-WinSecReviewIntegration ($i -gt 0 -and [string]::IsNullOrWhiteSpace($lines[$i-1]))}
            if($i+1 -eq $lines.Count -or -not $lines[$i+1].StartsWith('|')){Assert-WinSecReviewIntegration ($i+1 -lt $lines.Count -and [string]::IsNullOrWhiteSpace($lines[$i+1]))}
        }
        if($null -ne (Get-Command ConvertFrom-Markdown -CommandType Cmdlet -ErrorAction SilentlyContinue)) {
            $html=(ConvertFrom-Markdown -InputObject $text).Html;$tables=[regex]::Matches($html,'<table>[\s\S]*?</table>')
            Assert-WinSecReviewIntegration ($tables.Count -eq 2 -and [regex]::Matches($tables[1].Value,'<tr>').Count -eq ($a.Rows.Count+1))
        }
    }
}
foreach($size in @(@(80,26),@(40,20),@(16,5))) {
    Test-WinSecReviewIntegration ('Frozen Findings and last warning fit terminal '+($size -join 'x')) {
        $script:terminal=[pscustomobject]@{Width=$size[0];ContentWidth=($size[0]-1);Height=$size[1]};$state.FindingsOffset=7
        $before=Get-WinSecPublicHistoryJson $ctx.FrameworkFindings;Show-WinSecCLICurrentScreen $state $ctx
        Assert-WinSecReviewIntegration (@($script:lines|Where-Object {$_.Length -gt $size[0]}).Count -eq 0 -and
            $state.FindingsOffset -eq 7 -and $script:reads -eq 1 -and $before -ceq (Get-WinSecPublicHistoryJson $ctx.FrameworkFindings))
    }
}
foreach($fault in @('Device','Scan','Scope','Raw','Duplicate')) {
    Test-WinSecReviewIntegration ('Export rejects forged frozen observations before publication: '+$fault) {
        $bad=Copy-WinSecResultData $ctx.FrameworkFindings
        switch($fault){Device {$bad.DeviceId='local:other'};Scan {$bad.Rows[0].ScanId='another'};Scope {$bad.ScopeKey='WSA-SYS-002'};
            Raw {$bad.Rows[0]|Add-Member RawAction PRIVATE};Duplicate {$bad.Rows+=Copy-WinSecResultData $bad.Rows[0]}}
        $bad.ContentSha256=Get-WinSecFrameworkAnalysisDigest $bad
        $count=$script:frameworkExports.Count
        $saved=$ctx.FrameworkFindings;$ctx.FrameworkFindings=$bad
        try{Assert-WinSecReviewRejected {Invoke-WinSecCLIFindingsExport $state $ctx}}
        finally{$ctx.FrameworkFindings=$saved}
        Assert-WinSecReviewIntegration ($count -eq $script:frameworkExports.Count -and $script:reads -eq 1)
    }
}
Test-WinSecReviewIntegration 'Cancelling a fresh scan cannot collect or publish any new observations' {
    $cancelled=New-WinSecReviewContext review-cancelled -ConfirmAction {$false}
    Assert-WinSecReviewIntegration ($cancelled.PublicScans.Count -eq 0 -and $cancelled.ScanCoordinator.Sessions.Count -eq 0 -and $script:reads -eq 1)
}
Test-WinSecReviewIntegration 'A healthy scan exports zero warnings while technical observations and limited coverage remain accessible' {
    $script:realtime=$true;$script:additionalHealthy=$true;$fresh=New-WinSecReviewContext review-only-export;$s=New-WinSecReviewState $fresh
    $a=Open-WinSecFrameworkMemoryView $s $fresh;$null=Invoke-WinSecCLIFindingsExport $s $fresh
    Assert-WinSecReviewIntegration ($a.Rows.Count -eq 0 -and $a.ReadingCount -gt 80 -and $a.UnknownReadingCount -gt 0 -and
        $script:frameworkExports[$script:frameworkExports.Count-1].Markdown.Contains('No warnings does not prove full framework coverage') -and $script:reads -eq 2)
}
foreach($fault in @('Device','Scan','Raw','Duplicate')) {
    Test-WinSecReviewIntegration ('F refuses forged cached public observations before replacing the frozen view: '+$fault) {
        $bad=Copy-WinSecResultData $ctx.PublicScans[$key];$saved=$ctx.PublicScans[$key]
        switch($fault){Device {$bad.ControlResults[0].DeviceId='local:other'};Scan {$bad.ControlResults[0].ScanId='other'};
            Raw {$bad.ControlResults[0]|Add-Member RawEvidence PRIVATE};Duplicate {$bad.ControlResults+=Copy-WinSecResultData $bad.ControlResults[0]}}
        $ctx.PublicScans[$key]=$bad;$before=$script:lines -join '|';$reads=$script:reads;$view=Get-WinSecPublicHistoryJson $ctx.FrameworkFindings
        try{Assert-WinSecReviewRejected {Open-WinSecFrameworkMemoryView $state $ctx}}
        finally{$ctx.PublicScans[$key]=$saved}
        Assert-WinSecReviewIntegration ($before -ceq ($script:lines -join '|') -and $script:reads -eq $reads -and $view -ceq (Get-WinSecPublicHistoryJson $ctx.FrameworkFindings))
    }
}
foreach($spec in @(@{Topic='PUA';Id='WSA-DEF-ADD-001'},@{Topic='CLOUD';Id='WSA-DEF-ADD-002'},
    @{Topic='TAMPER';Id='WSA-DEF-ADD-003'},@{Topic='ASR';Id='WSA-DEF-ADD-004'})) {
    Test-WinSecReviewIntegration ('Each added protection contributes independently to qualitative findings and framework guidance: '+$spec.Topic) {
        $script:badCriterion=$spec.Topic;$script:realtime=$true;$script:additionalHealthy=$true
        $fresh=New-WinSecReviewContext ('protection-'+$spec.Topic);$s=New-WinSecReviewState $fresh
        foreach($fw in @('cis-controls','nist-csf','mitre-attack')) {
            $a=Open-WinSecFrameworkMemoryView $s $fresh $fw;$null=Invoke-WinSecCLIFindingsExport $s $fresh
            $expectedCount=if($spec.Topic -ceq 'ASR'){2}else{1}
            Assert-WinSecReviewIntegration ($a.Rows.Count -eq $expectedCount -and @($a.Rows|Where-Object CriterionId -CEQ $spec.Id).Count -eq 1 -and
                @($a.Rows|Where-Object {$_.CriterionId -cnotin @($spec.Id,'WSA-DEF-BASE-001')}).Count -eq 0)
            if($spec.Topic -ceq 'ASR') {
                $expected=switch($fw){cis-controls {'10.5'};nist-csf {'PR.PS-05'};mitre-attack {'T1068'}}
                Assert-WinSecReviewIntegration (@($a.Rows|Where-Object CriterionId -CEQ $spec.Id)[0].References.ReferenceId -ccontains $expected)
            }
            Assert-WinSecReviewIntegration ($script:frameworkExports[$script:frameworkExports.Count-1].Markdown -notmatch '/100|CONFIGURATION %')
        }
        $script:badCriterion=''
    }
}
Test-WinSecReviewIntegration 'Unavailable cloud telemetry remains UNKNOWN and never becomes a false failure or score' {
    $script:badCriterion='UNKNOWN_CLOUD';$script:realtime=$true;$script:additionalHealthy=$true
    $fresh=New-WinSecReviewContext unknown-added-criterion;$s=New-WinSecReviewState $fresh;$a=Open-WinSecFrameworkMemoryView $s $fresh
    $r=Read-WinSecTechnicalReport $root $s.SelectedDeviceId unknown-added-criterion WSA-SYS-001
    Assert-WinSecReviewIntegration ($a.Rows.Count -eq 0 -and $a.UnknownReadingCount -gt 0 -and
        @($r.Rows|Where-Object {$_.SettingId -ceq 'ConfigurationModes.Cloud' -and $_.State -ceq 'UNKNOWN'}).Count -eq 1)
    $script:badCriterion=''
}
Test-WinSecReviewIntegration 'Present null ASR pair is explicitly not configured and survives history, Findings and all exports' {
    $script:asrShape='NULL_PAIR';$script:realtime=$true;$script:additionalHealthy=$true;$original=Get-WinSecPublicHistoryJson $ctx.PublicScans[$key]
    try {
        $fresh=New-WinSecReviewContext null-asr-pair;$s=New-WinSecReviewState $fresh
        $session=(@($fresh.ScanCoordinator.Sessions.Values)[0]).Session;$record=New-WinSecPublicHistoryRecord $session
        $saved=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
        Assert-WinSecReviewIntegration ((Get-WinSecPublicHistoryJson $saved.PublicResult) -ceq (Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult $session)))
        $r=Read-WinSecTechnicalReport $root $s.SelectedDeviceId null-asr-pair WSA-SYS-001
        Assert-WinSecReviewIntegration (@($r.Rows|Where-Object {$_.SettingId -ceq 'AttackSurfaceReduction.Complete' -and $_.Value -ceq $true}).Count -eq 1 -and
            @($r.Rows|Where-Object {$_.SettingId -ceq 'ConfigurationModes.AsrVulnerableDriver' -and $_.Value -ceq 'NOT_CONFIGURED'}).Count -eq 1)
        foreach($fw in @('cis-controls','nist-csf','mitre-attack')) {
            $a=Open-WinSecFrameworkMemoryView $s $fresh $fw;$null=Invoke-WinSecCLIFindingsExport $s $fresh
            Assert-WinSecReviewIntegration ($a.Rows.Count -eq 1 -and $a.Rows[0].CriterionId -ceq 'WSA-DEF-ADD-004' -and
                $script:frameworkExports[$script:frameworkExports.Count-1].Markdown -notmatch '/100|PRIVATE|RawAction|ExclusionPath')
        }
        Assert-WinSecReviewIntegration ($original -ceq (Get-WinSecPublicHistoryJson $ctx.PublicScans[$key]))
    } finally {$script:asrShape='NORMAL'}
}
foreach($shape in @('MISSING','NULL_IDS','NULL_ACTIONS','NULL_ENTRIES')) {
    Test-WinSecReviewIntegration ('Malformed ASR telemetry stays UNKNOWN with explicit gaps and no invented deviation: '+$shape) {
        $script:asrShape=$shape;$script:realtime=$true;$script:additionalHealthy=$true
        try {
            $fresh=New-WinSecReviewContext ('asr-'+$shape);$s=New-WinSecReviewState $fresh;$a=Open-WinSecFrameworkMemoryView $s $fresh
            $r=Read-WinSecTechnicalReport $root $s.SelectedDeviceId ('asr-'+$shape) WSA-SYS-001
            Assert-WinSecReviewIntegration ($a.Rows.Count -eq 0 -and $a.UnknownReadingCount -gt 0 -and
                @($r.Rows|Where-Object {$_.SettingId -ceq 'ConfigurationModes.AsrVulnerableDriver' -and $_.State -ceq 'UNKNOWN'}).Count -eq 1)
        } finally {$script:asrShape='NORMAL'}
    }
}
function Get-FileHash {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Algorithm='SHA256')
    if($script:changedRevision -and $LiteralPath -like '*defender-additional.json'){return [pscustomobject]@{Hash=('F'*64)}}
    Microsoft.PowerShell.Utility\Get-FileHash @PSBoundParameters
}
Test-WinSecReviewIntegration 'Changing the approved additional catalog during confirmation aborts before collection' {
    $before=$script:reads;$script:changedRevision=$false
    try{Assert-WinSecReviewRejected {New-WinSecReviewContext revision-race -ConfirmAction {$script:changedRevision=$true;return $true}}}
    finally{$script:changedRevision=$false}
    Assert-WinSecReviewIntegration ($script:reads -eq $before)
}
[Console]::WriteLine(('Defender review integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Defender review integration failed.'}
