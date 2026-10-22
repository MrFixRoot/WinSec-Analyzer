# Real coordinator/Defender/evaluation/score/history/UI/report; synthetic Windows, keyboard and I/O.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/TerminalRenderer.ps1','src/UI/Core/LayoutManager.ps1','src/UI/Core/KeyboardController.ps1','src/UI/Core/ResizeHandler.ps1',
    'src/UI/Components/Table.ps1','src/UI/Components/Banner.ps1','src/UI/Components/KeyboardHelp.ps1','src/UI/Screens/MainMenu.ps1',
    'src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1','src/UI/Screens/ScanConfirmation.ps1','src/UI/Screens/AssessmentProfileSelection.ps1','src/UI/Screens/ExportFrameworkSelection.ps1',
    'src/Services/FrameworkService.ps1','src/Core/FrameworkMappingEngine.ps1','src/Services/ReportService.ps1','src/Services/ExportService.ps1')){. (Join-Path $root $file)}
$script:registry=Get-WinSecCheckRegistry $root
$script:policyReader=(Get-Command Get-WinSecConfigurationScoringPolicy).ScriptBlock
$script:passed=0;$script:failed=0
function Assert-WinSecConfigIntegration {param([bool]$Value);if(-not $Value){throw 'Configuration integration assertion failed.'}}
function Get-CimInstance {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    if($ClassName -ceq 'Win32_ComputerSystemProduct'){return [pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}}
    if($ClassName -ceq 'Win32_OperatingSystem'){$script:osReads++;return [pscustomobject]@{Caption='Microsoft Windows 11';Version=$script:osVersion;
        BuildNumber=($script:osVersion.Split('.')[2]);OperatingSystemSKU=$script:sku;ProductType=1}}
    throw 'Synthetic CIM query unavailable.'
}
function Get-MpComputerStatus {
    [CmdletBinding()]param()
    $script:reads++
    $script:metrics.Reads++
    if($script:collectionError){throw 'PRIVATE-CONFIG-COLLECTION'}
    [pscustomobject]@{AMRunningMode=$script:mode;AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$script:realtime;BehaviorMonitorEnabled=$true}
}
function Get-MpPreference {
    [CmdletBinding()]param()
    [pscustomobject]@{PUAProtection=1;AttackSurfaceReductionRules_Ids=@();AttackSurfaceReductionRules_Actions=@();ExclusionPath=@('C:\PRIVATE-CONFIG-RAW')}
}
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $copy=Copy-WinSecResultData $script:registry
    $check=$copy.Checks|Where-Object CheckId -CEQ WSA-SYS-001
    $check.ExecutionEnabled=$true;$check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'
    $copy
}
function Get-WinSecConfigurationScoringPolicy {
    param($ProjectRoot)
    $snapshot=& $script:policyReader $ProjectRoot
    if($script:changedPolicy){$snapshot.Sha256=('F'*64)}
    $snapshot
}
function Get-FileHash {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Algorithm='SHA256')
    if($script:changedMatrix -and $LiteralPath -like '*defender-windows11-matrix.json'){return [pscustomobject]@{Hash=('F'*64)}}
    Microsoft.PowerShell.Utility\Get-FileHash @PSBoundParameters
}
function Save-WinSecPublicHistory {
    param($ProjectRoot,$Session)
    if($script:store.ContainsKey($Session.ScanId)){throw 'Immutable test history conflict.'}
    $script:store[$Session.ScanId]=Get-WinSecPublicHistoryJson (New-WinSecPublicHistoryRecord $Session)
}
function Import-WinSecDeviceInventory {param($ProjectRoot);[pscustomobject]@{schemaVersion='1.2.0';targets=@(New-WinSecLocalTarget);removedDeviceHashes=@()}}
function Open-WinSecDeviceInventoryStore {
    param($ProjectRoot)
    $lease=[pscustomobject]@{};$lease|Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
    [pscustomobject]@{Lock=$lease}
}
function Read-WinSecPublicHistoryArtifacts {param($ProjectRoot,$Devices,[ref]$TotalBytes);foreach($json in $script:store.Values){ConvertFrom-WinSecStoredJson $json}}
function Write-WinSecMarkdownArtifact {
    param($ProjectRoot,$Report)
    $script:reports.Add((Copy-WinSecResultData $Report))
    [pscustomobject]@{RelativePath='reports/exports/synthetic/report.md'}
}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if($script:keys.Count){return $script:keys.Dequeue()}
    [pscustomobject]@{VirtualKeyCode=13;Character='';ControlKeyState=0;KeyDown=$true}
}
function New-WinSecConfigIntegrationContext {
    $coordinator=New-WinSecScanCoordinator
    $device=New-WinSecLocalTarget
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($device)}
    $coordinator.AssessmentEnabled=$true;$coordinator.PublicHistoryEnabled=$true
    [pscustomobject]@{ProjectRoot=$root;Version='0.9.0';Devices=@($device);ScanCoordinator=$coordinator;
        PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LastScanMessage=''}
}
function Invoke-WinSecConfigIntegrationScan {
    param($Context,[string]$Profile='WSA-W11-24H2-PRO-DEF-BASE',[string]$Id='config-integration-1',[string]$ScopeType='CONTROL',[string]$ScopeKey='WSA-SYS-001',[scriptblock]$ConfirmAction={$true})
    Invoke-WinSecCoordinatedScan -Coordinator $Context.ScanCoordinator -DeviceId $Context.Devices[0].DeviceId -ScanId $Id `
        -ScopeType $ScopeType -ScopeKey $ScopeKey -AssessmentProfile $Profile -ConfirmAction $ConfirmAction
}
function Test-WinSecConfigIntegration {
    param([string]$Name,[scriptblock]$Action)
    $script:reads=0;$script:osReads=0;$script:realtime=$false;$script:mode='Normal';$script:collectionError=$false;$script:changedPolicy=$false
    $script:metrics=[pscustomobject]@{Reads=0}
    $script:changedMatrix=$false
    $script:osVersion='10.0.26100';$script:sku=48;$script:store=@{}
    $script:reports=New-Object 'System.Collections.Generic.List[object]';$script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    $script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55}
    try {$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch {$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
Test-WinSecConfigIntegration 'Initialization and installed profile discovery never collect Windows security information' {
    $ctx=New-WinSecConfigIntegrationContext;$options=@(Get-WinSecAssessmentProfileOptions $root @('WSA-SYS-001'))
    Assert-WinSecConfigIntegration ($options.Count -eq 101 -and $script:reads -eq 0 -and $script:osReads -eq 0 -and $script:store.Count -eq 0)
}
foreach($spec in @(@{P='WSA-W11-24H2-PRO-DEF-BASE';V='10.0.26100';S=48},@{P='WSA-W11-25H2-ENT-DEF-BASE';V='10.0.26200';S=4},
    @{P='WSA-W11-23H2-PRO-DEF-BASE';V='10.0.22631';S=48},@{P='WSA-W11-21H2-HOME-DEF-BASE';V='10.0.22000';S=101},
    @{P='WSA-W11-26H2-PRO-WORKSTATION-N-DEF-BASE';V='10.0.26300';S=162},
    @{P='WSA-W11-24H2-IOT-ENT-LTSC-DEF-BASE';V='10.0.26100';S=191},@{P='WSA-W11-26H1-EDU-N-DEF-BASE';V='10.0.28000';S=122})) {
    Test-WinSecConfigIntegration ('Confirmed real pipeline produces and persists 75 without a global score: '+$spec.P) {
        $script:osVersion=$spec.V;$script:sku=$spec.S;$ctx=New-WinSecConfigIntegrationContext
        $public=Invoke-WinSecConfigIntegrationScan $ctx -Profile $spec.P
        Assert-WinSecConfigIntegration ($script:reads -eq 1 -and $public.ConfigurationAssessment.Controls[0].Value -eq 75 -and
            $public.ConfigurationAssessment.Controls[0].Criteria.Count -eq 4 -and $public.Findings.Count -eq 1 -and $script:store.Count -eq 1 -and $null -eq $public.OverallScore)
    }
}
Test-WinSecConfigIntegration 'A section preserves pending BitLocker and Update rather than inventing a section score' {
    $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx -ScopeType SECTION -ScopeKey SystemSecurity
    Assert-WinSecConfigIntegration ($p.ConfigurationAssessment.Controls.Count -eq 3 -and $null -eq $p.ConfigurationAssessment.Sections[0].Value -and
        $p.ConfigurationAssessment.Sections[0].Coverage -eq 33.33 -and $p.ConfigurationAssessment.Controls[0].Value -eq 75)
}
Test-WinSecConfigIntegration 'Restart and Findings render the original score; all three available mappings export without rewriting it' {
    $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx
    $restart=New-WinSecConfigIntegrationContext;Restore-WinSecPublicHistory $restart
    $state=New-WinSecNavigationState;$state.Screen='Findings';$state.SelectedDeviceId=$ctx.Devices[0].DeviceId;$state.FindingsScope='Control'
    $snapshot=ConvertTo-Json $restart.PublicScans -Depth 40 -Compress
    Show-WinSecCLICurrentScreen $state $restart
    Assert-WinSecConfigIntegration (($script:lines -join '|').Contains('75/100') -and ($script:lines -join '|').Contains('MISCONFIGURED'))
    foreach($index in @(0,1,2)) {
        for($i=0;$i -lt $index;$i++){$script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=40;Character='';ControlKeyState=0;KeyDown=$true})}
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';ControlKeyState=0;KeyDown=$true})
        $null=Invoke-WinSecCLIFindingsExport $state $restart
        $report=$script:reports[$script:reports.Count-1].Markdown
        Assert-WinSecConfigIntegration ($report.Contains('75/100') -and $report.Contains('Framework-oriented manual guidance:') -and
            $report -notmatch 'PRIVATE-CONFIG-RAW|ObservedValue|ExpectedValue|"Evidence"')
    }
    Assert-WinSecConfigIntegration ($script:reports.Count -eq 3 -and $script:reads -eq 1 -and $snapshot -ceq (ConvertTo-Json $restart.PublicScans -Depth 40 -Compress))
}
Test-WinSecConfigIntegration 'Cancellation before collection and scoring-policy changes require another confirmation' {
    $ctx=New-WinSecConfigIntegrationContext
    $p=Invoke-WinSecConfigIntegrationScan $ctx -ConfirmAction {$false}
    Assert-WinSecConfigIntegration ($null -eq $p -and $script:reads -eq 0 -and $script:store.Count -eq 0)
    $caught=$false;try {$null=Invoke-WinSecConfigIntegrationScan $ctx -ConfirmAction {$script:changedPolicy=$true;$true}}catch {$caught=$true}
    Assert-WinSecConfigIntegration ($caught -and $script:reads -eq 0 -and $script:store.Count -eq 0)
}
foreach($kind in @('Passive','WrongEdition','UnknownTelemetry','CollectionError')) {
    Test-WinSecConfigIntegration ('Incomplete or inapplicable evidence never becomes a numeric security failure: '+$kind) {
        switch($kind){Passive {$script:mode='Passive'};WrongEdition {$script:sku=4};UnknownTelemetry {$script:realtime=$null};CollectionError {$script:collectionError=$true}}
        $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx
        Assert-WinSecConfigIntegration ($null -eq $p.ConfigurationAssessment.Controls[0].Value -and
            @($p.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
Test-WinSecConfigIntegration 'A later all-pass rescan keeps the earlier 75 and records all four satisfied criteria' {
    $ctx=New-WinSecConfigIntegrationContext;$first=Invoke-WinSecConfigIntegrationScan $ctx
    $before=$script:store['config-integration-1'];$script:realtime=$true
    $second=Invoke-WinSecConfigIntegrationScan $ctx -Id 'config-integration-2'
    Assert-WinSecConfigIntegration ($second.ConfigurationAssessment.Controls[0].Value -eq 100 -and $second.Findings.Count -eq 0 -and
        $second.ConfigurationAssessment.Controls[0].Criteria.Count -eq 4 -and $before -ceq $script:store['config-integration-1'])
}
Test-WinSecConfigIntegration 'Expanded profile history restores the original 23H2 Pro criteria version and exports without raw evidence' {
    $script:osVersion='10.0.22631';$ctx=New-WinSecConfigIntegrationContext
    $p=Invoke-WinSecConfigIntegrationScan $ctx -Profile 'WSA-W11-23H2-PRO-DEF-BASE'
    $saved=$script:store['config-integration-1'];$restart=New-WinSecConfigIntegrationContext;Restore-WinSecPublicHistory $restart
    $state=New-WinSecNavigationState;$state.Screen='Findings';$state.FindingsScope='Control';$state.SelectedDeviceId=$p.DeviceId
    $selection=Get-WinSecCLIFindingsExportSelection $state $restart
    $report=New-WinSecFindingsMarkdown $selection -FrameworkId cis-controls
    Assert-WinSecConfigIntegration ($selection.ConfigurationAssessment.Controls[0].Value -eq 75 -and
        $selection.ConfigurationAssessment.Controls[0].Criteria[0].CatalogVersion -ceq '0.2.0' -and
        $report.Markdown.Contains('75/100') -and $saved -ceq $script:store['config-integration-1'] -and
        $saved -notmatch 'DefenderStatus|PRIVATE-CONFIG|ExpectedValue|ReviewedBy')
}
Test-WinSecConfigIntegration 'The real scan confirmation displays and binds the configuration method before any collection' {
    $ctx=New-WinSecConfigIntegrationContext
    $p=Invoke-WinSecConfigIntegrationScan $ctx -ConfirmAction {
        param($request)
        Assert-WinSecConfigIntegration ($script:reads -eq 0 -and $script:osReads -eq 0 -and $null -ne $request.ConfigurationScoring)
        $confirmed=Show-WinSecScanConfirmation $request
        Assert-WinSecConfigIntegration (($script:lines -join '|').Contains('WSA_CONTROL_CRITERIA_MEAN') -and
            ($script:lines -join '|').Contains($request.ConfigurationScoring.PolicySha256))
        return $confirmed
    }
    Assert-WinSecConfigIntegration ($p.ConfigurationAssessment.Controls[0].Value -eq 75 -and $script:reads -eq 1)
}
Test-WinSecConfigIntegration 'Criterion-specific exports do not apply behavior references to a real-time-only finding' {
    $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx
    $ctx=New-WinSecConfigIntegrationContext
    Restore-WinSecPublicHistory $ctx
    $state=New-WinSecNavigationState;$state.Screen='Findings';$state.FindingsScope='Control';$state.SelectedDeviceId=$p.DeviceId
    $selection=Get-WinSecCLIFindingsExportSelection $state $ctx
    foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
        $report=New-WinSecFindingsMarkdown $selection -FrameworkId $framework
        Assert-WinSecConfigIntegration ($report.Markdown -notmatch '10\.7|DE\.CM-09' -and
            $report.Markdown.Contains('75/100') -and $report.Markdown.Contains('Framework-oriented manual guidance:'))
    }
}
Test-WinSecConfigIntegration 'A control export from section history preserves the source scope and rejects conflicting criterion provenance' {
    $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx -ScopeType SECTION -ScopeKey SystemSecurity
    $ctx=New-WinSecConfigIntegrationContext;Restore-WinSecPublicHistory $ctx
    $state=New-WinSecNavigationState;$state.Screen='Findings';$state.FindingsScope='Control';$state.SelectedDeviceId=$p.DeviceId
    $selection=Get-WinSecCLIFindingsExportSelection $state $ctx
    $report=New-WinSecFindingsMarkdown $selection -FrameworkId nist-csf
    Assert-WinSecConfigIntegration ($selection.SourceScopeType -ceq 'SECTION' -and $selection.ScopeType -ceq 'CONTROL' -and $report.Markdown.Contains('75/100'))
    $selection.ConfigurationAssessment.Controls[0].Criteria[2].Recommendation='Conflicting historical recommendation'
    $caught=$false;try{$null=New-WinSecFindingsMarkdown $selection -FrameworkId nist-csf}catch{$caught=$true}
    Assert-WinSecConfigIntegration $caught
}
Test-WinSecConfigIntegration 'The interactive CLI selects an installed profile, confirms, publishes and displays the 75 control score' {
    $ctx=New-WinSecConfigIntegrationContext;$state=New-WinSecNavigationState
    $state.Screen='Section';$state.SelectedDeviceId=$ctx.Devices[0].DeviceId
    foreach($code in @(40,13,13)){$script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$code;Character='';ControlKeyState=0;KeyDown=$true})}
    $p=Invoke-WinSecCLILocalRescan -State $state -Context $ctx
    Assert-WinSecConfigIntegration ($p.ConfigurationAssessment.Controls[0].Value -eq 75 -and $ctx.PublicScans.Count -eq 1 -and
        $ctx.LastScanMessage.Contains('75/100') -and $script:reads -eq 1 -and $script:keys.Count -eq 0)
    Show-WinSecCLICurrentScreen $state $ctx
    Assert-WinSecConfigIntegration (($script:lines -join '|').Contains('75/100'))
    $saved=ConvertTo-Json $ctx.PublicScans -Depth 40 -Compress
    foreach($size in @(@(80,26),@(40,20),@(16,5))) {
        $script:terminal=[pscustomobject]@{Width=$size[0];ContentWidth=($size[0]-1);Height=$size[1]}
        Show-WinSecCLICurrentScreen $state $ctx
        Assert-WinSecConfigIntegration (@($script:lines|Where-Object {$_.Length -gt $size[0]}).Count -eq 0 -and
            $script:reads -eq 1 -and $saved -ceq (ConvertTo-Json $ctx.PublicScans -Depth 40 -Compress))
    }
}
Test-WinSecConfigIntegration 'Native validation helper prepares safely, rejects an unapproved hash and collects only after a matching synthetic approval' {
    $helper=Join-Path $root 'tests/Integration/Invoke-DefenderNativeValidation.ps1'
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    Assert-WinSecConfigIntegration ($script:reads -eq 0 -and $plan.Request.ReadOnly -ceq $true -and $plan.Request.Checks.Count -eq 1)
    $caught=$false
    try {$null=. $helper -OperationId $plan.Request.OperationId -ApprovedRequestHash ('0'*64)}catch {$caught=$true}
    Assert-WinSecConfigIntegration ($caught -and $script:reads -eq 0 -and $script:store.Count -eq 0)
    $result=(. $helper -OperationId $plan.Request.OperationId -ApprovedRequestHash $plan.RequestHash)|ConvertFrom-Json
    Assert-WinSecConfigIntegration ($result.ConfigurationScore -eq 75 -and $script:metrics.Reads -eq 1 -and $script:store.Count -eq 0 -and
        $result.ApplicabilityDiagnostics.Count -eq 0 -and $result.RawEvidencePersisted -ceq $false -and $result.PublicHistoryPersisted -ceq $false -and $result.WindowsChanges -ceq $false)
}
Test-WinSecConfigIntegration 'A changed profile matrix during confirmation aborts before Windows reads or publication' {
    $ctx=New-WinSecConfigIntegrationContext;$caught=$false
    try{$null=Invoke-WinSecConfigIntegrationScan $ctx -Profile 'WSA-W11-23H2-PRO-DEF-BASE' -ConfirmAction {$script:changedMatrix=$true;return $true}}
    catch{$caught=$true}
    Assert-WinSecConfigIntegration ($caught -and $script:reads -eq 0 -and $script:osReads -eq 0 -and $script:store.Count -eq 0 -and $ctx.ScanCoordinator.Sessions.Count -eq 0)
}
Test-WinSecConfigIntegration 'A native-validation fixture using a mismatched profile reports scope mismatch without a score or persistence' {
    $script:osVersion='10.0.22631'
    $helper=Join-Path $root 'tests/Integration/Invoke-DefenderNativeValidation.ps1'
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    $result=(. $helper -OperationId $plan.Request.OperationId -ApprovedRequestHash $plan.RequestHash)|ConvertFrom-Json
    Assert-WinSecConfigIntegration ($result.ExecutionStatus -ceq 'COMPLETED' -and $null -eq $result.ConfigurationScore -and
        $result.ConfigurationStatus -ceq 'NOT_SCORED' -and $result.ApplicabilityDiagnostics.Count -eq 1 -and
        $result.ApplicabilityDiagnostics[0] -ceq 'WINDOWS_SCOPE_MISMATCH' -and $script:metrics.Reads -eq 1 -and $script:store.Count -eq 0)
}
[Console]::WriteLine(('Configuration integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Configuration assessment integration failed.'}
