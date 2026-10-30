# Production qualitative coordinator/Defender/history/F/P; synthetic Windows, keyboard and I/O.
[CmdletBinding()]
param([string]$CasePattern='*')
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/TerminalRenderer.ps1','src/UI/Core/LayoutManager.ps1','src/UI/Core/KeyboardController.ps1','src/UI/Core/ResizeHandler.ps1',
    'src/UI/Components/Table.ps1','src/UI/Components/Banner.ps1','src/UI/Components/KeyboardHelp.ps1','src/UI/Screens/MainMenu.ps1',
    'src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1','src/UI/Screens/ScanConfirmation.ps1','src/UI/Screens/AssessmentProfileSelection.ps1','src/UI/Screens/ExportFrameworkSelection.ps1',
    'src/Services/FrameworkService.ps1','src/Core/FrameworkMappingEngine.ps1','src/Services/ReportService.ps1','src/Services/ExportService.ps1')){. (Join-Path $root $file)}
$script:registry=Get-WinSecCheckRegistry $root
. (Join-Path $PSScriptRoot '../Fixtures/FrameworkMemory.ps1')
# Other System Security providers are explicitly unavailable in this fixture.
# The real catalog still authorizes all three; missing readings stay partial.
function Open-WinSecConfigUnavailablePolicy {param($SubKey,$Name,$CancellationAction);throw 'Synthetic policy provider unavailable.'}
foreach($name in @('Open-WinSecWindowsUpdatePolicyKey','Open-WinSecWindowsUpdateVersionKey',
    'Get-WinSecWindowsUpdateRebootRequired','Read-WinSecWindowsUpdateNamedPolicy')) {
    Set-Alias $name Open-WinSecConfigUnavailablePolicy -Scope Script
}
$script:passed=0;$script:failed=0
function Assert-WinSecConfigIntegration {param([bool]$Value,[string]$Message='Configuration integration assertion failed.');if(-not $Value){throw $Message}}
function Get-CimInstance {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    if($ClassName -ceq 'Win32_ComputerSystemProduct'){return [pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}}
    if($ClassName -ceq 'Win32_OperatingSystem' -and
        ($Property -join ',') -ceq 'Caption,Version,BuildNumber,OperatingSystemSKU,ProductType'){$script:osReads++;return [pscustomobject]@{Caption='Microsoft Windows 11';Version=$script:osVersion;
        BuildNumber=($script:osVersion.Split('.')[2]);OperatingSystemSKU=$script:sku;ProductType=1}}
    throw 'Synthetic CIM query unavailable.'
}
function Get-MpComputerStatus {
    [CmdletBinding()]param()
    $script:reads++
    $script:metrics.Reads++
    if($script:collectionError){throw 'PRIVATE-CONFIG-COLLECTION'}
    [pscustomobject]@{AMRunningMode=$script:mode;AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$script:realtime;BehaviorMonitorEnabled=$true;IsTamperProtected=$true}
}
function Get-MpPreference {
    [CmdletBinding()]param()
    [pscustomobject]@{PUAProtection=1;MAPSReporting=2;AttackSurfaceReductionRules_Ids=@('56a863a9-875e-4185-98a7-b882c64b5ce5');AttackSurfaceReductionRules_Actions=@(1);ExclusionPath=@('C:\PRIVATE-CONFIG-RAW')}
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
    $coordinator.AssessmentEnabled=$true;$coordinator.PublicHistoryEnabled=$true;$coordinator.TechnicalReportsEnabled=$true
    [pscustomobject]@{ProjectRoot=$root;Version='0.9.0';Devices=@($device);ScanCoordinator=$coordinator;
        PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LastScanMessage='';
        FrameworkWorkflowEnabled=$true;LocalDeviceId=$device.DeviceId}
}
function Invoke-WinSecConfigIntegrationScan {
    param($Context,[string]$Profile='WSA-W11-24H2-PRO-DEF-BASE',[string]$Id='config-integration-1',[string]$ScopeType='CONTROL',[string]$ScopeKey='WSA-SYS-001',[scriptblock]$ConfirmAction={$true})
    $p=Invoke-WinSecCoordinatedScan -Coordinator $Context.ScanCoordinator -DeviceId $Context.Devices[0].DeviceId -ScanId $Id `
        -ScopeType $ScopeType -ScopeKey $ScopeKey -AssessmentProfile $Profile -ConfirmAction $ConfirmAction
    if($null -ne $p){Add-WinSecFrameworkMemoryPublic $Context $p}
    $p
}
function Test-WinSecConfigIntegration {
    param([string]$Name,[scriptblock]$Action)
    if($Name -notlike $CasePattern){return}
    $script:reads=0;$script:osReads=0;$script:realtime=$false;$script:mode='Normal';$script:collectionError=$false;$script:changedPolicy=$false
    $script:metrics=[pscustomobject]@{Reads=0}
    $script:changedMatrix=$false
    $script:osVersion='10.0.26100';$script:sku=48;$script:store=@{}
    $script:reports=New-Object 'System.Collections.Generic.List[object]';$script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    $script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55}
    Reset-WinSecFrameworkMemory
    try {$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch {$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
function New-WinSecConfigState {
    param($Context,[string]$Screen='Findings',[string]$Scope='Control')
    $s=New-WinSecNavigationState;$s.Screen=$Screen;$s.FindingsScope=$Scope;$s.SelectedDeviceId=$Context.Devices[0].DeviceId;$s
}
function Assert-WinSecConfigRejected {
    param([scriptblock]$Action)
    $caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecConfigIntegration $caught
}
Test-WinSecConfigIntegration 'Initialization and installed profile discovery never collect Windows security information' {
    $ctx=New-WinSecConfigIntegrationContext;$options=@(Get-WinSecAssessmentProfileOptions $root @('WSA-SYS-001'))
    Assert-WinSecConfigIntegration ($options.Count -eq 101 -and $script:reads -eq 0 -and $script:osReads -eq 0 -and $script:store.Count -eq 0)
}
foreach($spec in @(@{P='WSA-W11-24H2-PRO-DEF-BASE';V='10.0.26100';S=48},@{P='WSA-W11-25H2-ENT-DEF-BASE';V='10.0.26200';S=4},
    @{P='WSA-W11-23H2-PRO-DEF-BASE';V='10.0.22631';S=48},@{P='WSA-W11-21H2-HOME-DEF-BASE';V='10.0.22000';S=101},
    @{P='WSA-W11-26H2-PRO-WORKSTATION-N-DEF-BASE';V='10.0.26300';S=162},
    @{P='WSA-W11-24H2-IOT-ENT-LTSC-DEF-BASE';V='10.0.26100';S=191},@{P='WSA-W11-26H1-EDU-N-DEF-BASE';V='10.0.28000';S=122})) {
    Test-WinSecConfigIntegration ('Confirmed pipeline persists observed platform without ratings: '+$spec.P) {
        $script:osVersion=$spec.V;$script:sku=$spec.S;$ctx=New-WinSecConfigIntegrationContext
        $p=Invoke-WinSecConfigIntegrationScan $ctx -Profile $spec.P
        $r=Read-WinSecTechnicalReport $root $p.DeviceId $p.ScanId WSA-SYS-001
        Assert-WinSecConfigIntegration ($script:reads -eq 1 -and $null -eq $p.ConfigurationAssessment -and $null -eq $p.OverallScore -and
            $p.Findings.Count -eq 1 -and $p.Findings[0].Guidance.CriterionId -ceq 'WSA-DEF-BASE-003' -and $script:store.Count -eq 1 -and $r.Rows.Count -gt 80 -and
            $r.ObservedOSRelease -ceq ('Windows 11 '+$spec.V) -and $r.ObservedEdition -ceq ('SKU:'+$spec.S)) `
            ('Unexpected projection: '+(Get-WinSecPublicHistoryJson ([pscustomobject]@{Reads=$script:reads;Assessment=$p.ConfigurationAssessment;Score=$p.OverallScore;Findings=$p.Findings;Stored=$script:store.Count;Rows=$r.Rows.Count;Release=$r.ObservedOSRelease;Edition=$r.ObservedEdition})))
        $a=Open-WinSecFrameworkMemoryView (New-WinSecConfigState $ctx) $ctx
        Assert-WinSecConfigIntegration (@($a.Rows|Where-Object SettingId -CEQ 'DefenderStatus.RealTimeProtectionEnabled').Count -eq 1)
    }
}
Test-WinSecConfigIntegration 'A section authorizes all three real checks and preserves unavailable sibling readings as partial' {
    $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx -ScopeType SECTION -ScopeKey SystemSecurity
    $rows=@(Get-WinSecWorkflowControlRows (New-WinSecConfigState $ctx Section) $ctx)
    Assert-WinSecConfigIntegration ($p.ExecutionStatus -cin @('COMPLETED','COMPLETED_WITH_ERRORS') -and $null -eq $p.ConfigurationAssessment -and
        $rows.Count -eq 3 -and $rows[0].Status -ceq 'COMPLETE' -and @($rows|Where-Object Status -CEQ PARTIAL).Count -eq 2 -and
        $script:technicalMemory.Count -eq 3) ('Unexpected partial section: '+(Get-WinSecPublicHistoryJson ([pscustomobject]@{
            Execution=$p.ExecutionStatus;Assessment=$p.ConfigurationAssessment;Rows=$rows;Saved=$script:technicalMemory.Count})))
}
Test-WinSecConfigIntegration 'Restart, Findings and all frameworks reuse immutable history and saved readings without ratings' {
    $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx
    $restart=New-WinSecConfigIntegrationContext;Restore-WinSecPublicHistory $restart
    $s=New-WinSecConfigState $restart;$saved=Get-WinSecPublicHistoryJson $restart.PublicScans
    foreach($fw in @('nist-csf','cis-controls','mitre-attack')) {
        $a=Open-WinSecFrameworkMemoryView $s $restart $fw
        Show-WinSecCLICurrentScreen $s $restart
        $null=Invoke-WinSecCLIFindingsExport $s $restart
        $e=$script:frameworkExports[$script:frameworkExports.Count-1]
        Assert-WinSecConfigIntegration ($e.Analysis.AnalysisId -ceq $a.AnalysisId -and $e.Analysis.FrameworkId -ceq $fw -and
            $e.Analysis.Sources[0].Origin -ceq 'RECORDS' -and $e.Markdown -notmatch 'PRIVATE-CONFIG|/100|ConfigurationPercent|"Evidence"')
    }
    Assert-WinSecConfigIntegration ($script:frameworkExports.Count -eq 3 -and $script:reads -eq 1 -and
        $saved -ceq (Get-WinSecPublicHistoryJson $restart.PublicScans))
}
Test-WinSecConfigIntegration 'Cancellation and changed active storage policy reject before collection or publication' {
    $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx -ConfirmAction {$false}
    Assert-WinSecConfigIntegration ($null -eq $p -and $script:reads -eq 0 -and $script:store.Count -eq 0)
    Assert-WinSecConfigRejected {Invoke-WinSecConfigIntegrationScan $ctx -ConfirmAction {
        param($request);$request.TechnicalReports.PolicySha256='F'*64;return $true
    }}
    Assert-WinSecConfigIntegration ($script:reads -eq 0 -and $script:store.Count -eq 0)
}
foreach($kind in @('Passive','WrongEdition','UnknownTelemetry','CollectionError')) {
    Test-WinSecConfigIntegration ('Incomplete or inapplicable data never become a numeric security failure: '+$kind) {
        switch($kind){Passive {$script:mode='Passive'};WrongEdition {$script:sku=4};UnknownTelemetry {$script:realtime=$null};CollectionError {$script:collectionError=$true}}
        $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx
        $a=Open-WinSecFrameworkMemoryView (New-WinSecConfigState $ctx) $ctx
        Assert-WinSecConfigIntegration ($null -eq $p.ConfigurationAssessment -and @($p.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0 -and
            @($a.Rows|Where-Object State -CNE WARNING).Count -eq 0)
        if($kind -cin @('UnknownTelemetry','CollectionError')) {
            Assert-WinSecConfigIntegration (@($a.Rows|Where-Object SettingId -CEQ 'DefenderStatus.RealTimeProtectionEnabled').Count -eq 0 -and $a.UnknownReadingCount -gt 0)
        }
        if($kind -ceq 'Passive'){Assert-WinSecConfigIntegration (@($a.Rows|Where-Object SettingId -CEQ 'DefenderStatus.AMRunningMode').Count -eq 1)}
    }
}
Test-WinSecConfigIntegration 'A healthy rescan removes its warning without rewriting the earlier reading or history' {
    $ctx=New-WinSecConfigIntegrationContext;$first=Invoke-WinSecConfigIntegrationScan $ctx
    $saved=$script:store[$first.ScanId];$technical=$script:technicalMemory.Values|Select-Object -First 1;$script:realtime=$true
    $next=Invoke-WinSecConfigIntegrationScan $ctx -Id config-integration-2
    $a=Open-WinSecFrameworkMemoryView (New-WinSecConfigState $ctx) $ctx
    Assert-WinSecConfigIntegration ($a.Rows.Count -eq 0 -and $a.Sources[0].ScanId -ceq $next.ScanId -and
        $saved -ceq $script:store[$first.ScanId] -and $script:technicalMemory.Values -ccontains $technical -and $null -eq $next.ConfigurationAssessment)
}
Test-WinSecConfigIntegration 'Restored 23H2 history retains original source profile and version without private evidence' {
    $script:osVersion='10.0.22631';$ctx=New-WinSecConfigIntegrationContext
    $p=Invoke-WinSecConfigIntegrationScan $ctx -Profile WSA-W11-23H2-PRO-DEF-BASE
    $saved=$script:store[$p.ScanId];$restart=New-WinSecConfigIntegrationContext;Restore-WinSecPublicHistory $restart
    $r=Read-WinSecTechnicalReport $root $p.DeviceId $p.ScanId WSA-SYS-001
    $a=Open-WinSecFrameworkMemoryView (New-WinSecConfigState $restart) $restart cis-controls
    Assert-WinSecConfigIntegration ($r.Profile -ceq 'WSA-W11-23H2-PRO-DEF-BASE' -and $r.ObservedOSRelease -ceq 'Windows 11 10.0.22631' -and
        $a.Sources[0].ScanId -ceq $p.ScanId -and $saved -ceq $script:store[$p.ScanId] -and $saved -notmatch 'DefenderStatus|PRIVATE-CONFIG|ExpectedValue|ReviewedBy')
}
Test-WinSecConfigIntegration 'Real confirmation binds framework mode and technical policy before any collection' {
    $ctx=New-WinSecConfigIntegrationContext
    $p=Invoke-WinSecConfigIntegrationScan $ctx -ConfirmAction {
        param($request)
        Assert-WinSecConfigIntegration ($script:reads -eq 0 -and $script:osReads -eq 0 -and $null -eq $request.ConfigurationScoring -and
            $request.AssessmentMode -ceq 'FRAMEWORK_REVIEW' -and $request.TechnicalReports.PolicySha256 -match '^[A-F0-9]{64}$')
        Show-WinSecScanConfirmation $request
    }
    Assert-WinSecConfigIntegration ($null -eq $p.ConfigurationAssessment -and $script:reads -eq 1 -and ($script:lines -join '|') -notmatch 'WSA_CONTROL_CRITERIA_MEAN|/100')
}
Test-WinSecConfigIntegration 'Real-time-only warnings retain criterion-specific references in all framework exports' {
    $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx;$s=New-WinSecConfigState $ctx
    foreach($fw in @('cis-controls','nist-csf','mitre-attack')) {
        $a=Open-WinSecFrameworkMemoryView $s $ctx $fw;$null=Invoke-WinSecCLIFindingsExport $s $ctx
        $r=$script:frameworkExports[$script:frameworkExports.Count-1]
        Assert-WinSecConfigIntegration ($a.Rows.Count -eq 2 -and @($a.Rows|Where-Object CriterionId -CNotIn @('WSA-DEF-BASE-002','WSA-DEF-BASE-003')).Count -eq 0 -and
            $r.Markdown -notmatch '10\.7|DE\\\.CM\\-09|/100' -and $a.Rows[0].References.Count -gt 0)
    }
}
Test-WinSecConfigIntegration 'Control Findings from section history preserve source scope and reject changed recommendations' {
    $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx -ScopeType SECTION -ScopeKey SystemSecurity
    $restart=New-WinSecConfigIntegrationContext;Restore-WinSecPublicHistory $restart;$s=New-WinSecConfigState $restart
    $a=Open-WinSecFrameworkMemoryView $s $restart
    Assert-WinSecConfigIntegration ($a.ScopeType -ceq 'CONTROL' -and $a.Sources[0].ScopeType -ceq 'SECTION' -and $a.Sources[0].ScanId -ceq $p.ScanId)
    $restart.FrameworkFindings.Rows[0].Recommendation='Conflicting historical recommendation'
    Assert-WinSecConfigRejected {Invoke-WinSecCLIFindingsExport $s $restart}
    Assert-WinSecConfigIntegration ($script:frameworkExports.Count -eq 0)
}
Test-WinSecConfigIntegration 'Interactive profile selection, confirmation, publication and small terminals retain the qualitative control view' {
    $ctx=New-WinSecConfigIntegrationContext;$s=New-WinSecConfigState $ctx Section
    $editions=@((Get-WinSecDefenderProfileMatrix $root).Matrix.Editions|Sort-Object Name|ForEach-Object {$_.Name})
    for($i=0;$i -le [array]::IndexOf($editions,'Pro');$i++){$script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=40;Character='';ControlKeyState=0;KeyDown=$true})}
    foreach($code in @(13,40,40,40,13,13)){$script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$code;Character='';ControlKeyState=0;KeyDown=$true})}
    $p=Invoke-WinSecCLILocalRescan $s $ctx
    Assert-WinSecConfigIntegration ($null -ne $p -and $null -eq $p.ConfigurationAssessment -and $ctx.PublicScans.Count -eq 1 -and $script:reads -eq 1 -and $script:keys.Count -eq 0)
    $saved=Get-WinSecPublicHistoryJson $ctx.PublicScans
    foreach($size in @(@(120,55),@(80,26),@(40,20),@(16,5))) {
        $script:terminal=[pscustomobject]@{Width=$size[0];ContentWidth=($size[0]-1);Height=$size[1]};Show-WinSecCLICurrentScreen $s $ctx
        Assert-WinSecConfigIntegration (@($script:lines|Where-Object {$_.Length -gt $size[0]}).Count -eq 0 -and
            ($script:lines -join '|') -notmatch 'SCORE|/100' -and $script:reads -eq 1 -and $saved -ceq (Get-WinSecPublicHistoryJson $ctx.PublicScans))
    }
}
Test-WinSecConfigIntegration 'Restored completion stays on its own control while cursor moves and Escape returns from Findings' {
    $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx
    $restart=New-WinSecConfigIntegrationContext;Restore-WinSecPublicHistory $restart;$s=New-WinSecConfigState $restart Section
    $before=Get-WinSecPublicHistoryJson @($restart.PublicScans,$script:store)
    foreach($index in @(0,1,2,0)) {
        while($s.ControlIndex -ne $index){$null=Invoke-WinSecNavigationAction $s MoveDown -ControlCount 3}
        $rows=@(Get-WinSecWorkflowControlRows $s $restart)
        Assert-WinSecConfigIntegration ($rows[0].Status -ceq 'COMPLETE' -and $rows[0].Mode -ceq 'RECORDS' -and $rows[1].Status -ceq 'PENDING')
        Show-WinSecCLICurrentScreen $s $restart
    }
    $s.ControlIndex=1;$null=Invoke-WinSecNavigationAction $s ShowFindings -ControlCount 3
    $a=Open-WinSecFrameworkMemoryView $s $restart;Assert-WinSecConfigIntegration ($a.Rows.Count -eq 0 -and $a.Sources.Count -eq 0)
    $null=Invoke-WinSecNavigationAction $s Back;Assert-WinSecConfigIntegration ($s.Screen -ceq 'Section')
    $s.ControlIndex=0;$null=Invoke-WinSecNavigationAction $s ShowFindings -ControlCount 3
    $a=Open-WinSecFrameworkMemoryView $s $restart
    Assert-WinSecConfigIntegration ($a.Rows.Count -eq 2 -and $a.Sources[0].ScanId -ceq $p.ScanId -and $script:reads -eq 1 -and
        $before -ceq (Get-WinSecPublicHistoryJson @($restart.PublicScans,$script:store)))
}
Test-WinSecConfigIntegration 'A control rescan changes only its row while section session and sibling source IDs remain immutable' {
    $ctx=New-WinSecConfigIntegrationContext;$section=Invoke-WinSecConfigIntegrationScan $ctx -ScopeType SECTION -ScopeKey SystemSecurity -Id section-original
    $saved=$script:store[$section.ScanId];$script:realtime=$true;$control=Invoke-WinSecConfigIntegrationScan $ctx -Id control-later
    $restart=New-WinSecConfigIntegrationContext;Restore-WinSecPublicHistory $restart;$s=New-WinSecConfigState $restart Section
    $views=@(Get-WinSecCLIControlViews $s $restart)
    Assert-WinSecConfigIntegration ($views[0].ScanId -ceq $control.ScanId -and $views[1].ScanId -ceq $section.ScanId -and $saved -ceq $script:store[$section.ScanId])
    $a=Open-WinSecFrameworkMemoryView $s $restart
    Assert-WinSecConfigIntegration ($a.Sources.Count -eq 1 -and $a.Rows.Count -eq 0 -and $script:reads -eq 2)
}
foreach($field in @('DeviceId','ScanId','ScopeKey')) {
    Test-WinSecConfigIntegration ('Presentation rejects conflicting source identity before publishing rows: '+$field) {
        $ctx=New-WinSecConfigIntegrationContext;$p=Invoke-WinSecConfigIntegrationScan $ctx;$s=New-WinSecConfigState $ctx Section
        $views=@(Get-WinSecCLIControlViews $s $ctx);$views[0].$field=if($field -ceq 'DeviceId'){'local:another'}elseif($field -ceq 'ScanId'){'another-scan'}else{'WSA-SYS-002'}
        $published=New-Object 'Collections.Generic.List[object]'
        Assert-WinSecConfigRejected {Get-WinSecResultsControlRows SystemSecurity $s -ControlViews $views|ForEach-Object{$published.Add($_)}}
        Assert-WinSecConfigIntegration ($published.Count -eq 0 -and $script:reads -eq 1)
    }
}
Test-WinSecConfigIntegration 'Validation helper uses only synthetic providers after matching approval and never persists' {
    $helper=Join-Path $root 'tests/Integration/Invoke-DefenderNativeValidation.ps1'
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    Assert-WinSecConfigIntegration ($script:reads -eq 0 -and $plan.Request.ReadOnly -ceq $true -and $plan.Request.Checks.Count -eq 1)
    Assert-WinSecConfigRejected {. $helper -OperationId $plan.Request.OperationId -ApprovedRequestHash ('0'*64)}
    $result=(. $helper -OperationId $plan.Request.OperationId -ApprovedRequestHash $plan.RequestHash)|ConvertFrom-Json
    Assert-WinSecConfigIntegration ($result.AssessmentMode -ceq 'FRAMEWORK_REVIEW' -and $script:metrics.Reads -eq 1 -and $result.InMemoryReports -eq 3 -and
        $result.ApplicabilityDiagnostics.Count -eq 0 -and $script:store.Count -eq 0 -and -not $result.RawEvidencePersisted -and -not $result.PublicHistoryPersisted -and -not $result.WindowsChanges)
}
Test-WinSecConfigIntegration 'Changed profile matrix during confirmation aborts before Windows reads or publication' {
    $ctx=New-WinSecConfigIntegrationContext
    Assert-WinSecConfigRejected {Invoke-WinSecConfigIntegrationScan $ctx -Profile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction {$script:changedMatrix=$true;return $true}}
    Assert-WinSecConfigIntegration ($script:reads -eq 0 -and $script:osReads -eq 0 -and $script:store.Count -eq 0 -and $ctx.ScanCoordinator.Sessions.Count -eq 0)
}
Test-WinSecConfigIntegration 'Synthetic validation with mismatched selected profile retains observed platform and explicit diagnostics' {
    $script:osVersion='10.0.22631';$helper=Join-Path $root 'tests/Integration/Invoke-DefenderNativeValidation.ps1'
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    $r=(. $helper -OperationId $plan.Request.OperationId -ApprovedRequestHash $plan.RequestHash)|ConvertFrom-Json
    Assert-WinSecConfigIntegration ($r.ExecutionStatus -ceq 'COMPLETED' -and $r.AssessmentMode -ceq 'FRAMEWORK_REVIEW' -and
        $r.ApplicabilityDiagnostics -ccontains 'WINDOWS_SCOPE_MISMATCH' -and $script:metrics.Reads -eq 1 -and $script:store.Count -eq 0)
}
# Archive compatibility is exercised with prepared synthetic criteria, not by
# enabling scores in a new coordinator scan or changing any production flag.
. (Join-Path $PSScriptRoot '../Fixtures/ArchivedConfiguration.ps1')
Test-WinSecConfigIntegration 'Archived explicit exclusions survive history and framework export without grading new scans' {
    $legacy=New-WinSecArchivedExclusionFixture $root
    $record=New-WinSecPublicHistoryRecord $legacy.Session
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    Assert-WinSecConfigIntegration ($restored.PublicResult.ConfigurationAssessment.Controls[0].Criteria[6].Status -ceq 'NOT_APPLICABLE')
    foreach($fw in @('nist-csf','cis-controls','mitre-attack')) {
        $a=New-WinSecFrameworkAnalysis -ProjectRoot $root -DeviceId $legacy.Session.DeviceId -DeviceName SYNTHETIC -ScopeType CONTROL -ScopeKey WSA-SYS-001 `
            -FrameworkId $fw -Sources @($legacy.Source) -Reports @($legacy.Report)
        $text=New-WinSecFrameworkMarkdown $a
        Assert-WinSecConfigIntegration (@($a.Rows|Where-Object CriterionId -CEQ 'WSA-DEF-ADD-003').Count -eq 0 -and $text -notmatch '/100' -and $script:reads -eq 0)
    }
}
Test-WinSecConfigIntegration 'A new qualitative scan never rewrites archived exclusions or their original denominator' {
    $legacy=New-WinSecArchivedExclusionFixture $root;$record=New-WinSecPublicHistoryRecord $legacy.Session;$saved=Get-WinSecPublicHistoryJson $record
    $ctx=New-WinSecConfigIntegrationContext;$next=Invoke-WinSecConfigIntegrationScan $ctx
    Assert-WinSecConfigIntegration ($null -eq $next.ConfigurationAssessment -and $saved -ceq (Get-WinSecPublicHistoryJson $record) -and
        $legacy.Session.ConfigurationAssessment.Controls[0].Criteria[6].Status -ceq 'NOT_APPLICABLE')
    $bad=Copy-WinSecResultData $legacy.Session.ConfigurationAssessment;$bad.Controls[0].Criteria[6].ApplicabilityReason='forged'
    Assert-WinSecConfigRejected {Assert-WinSecConfigurationProvenance $legacy.Session $bad}
}
Test-WinSecConfigIntegration 'An operation following archived exclusions still requires its own confirmation' {
    $legacy=New-WinSecArchivedExclusionFixture $root;$ctx=New-WinSecConfigIntegrationContext
    $r=Invoke-WinSecConfigIntegrationScan $ctx -ConfirmAction {$false}
    Assert-WinSecConfigIntegration ($null -eq $r -and $script:reads -eq 0 -and $script:osReads -eq 0 -and $script:store.Count -eq 0 -and $ctx.ScanCoordinator.Sessions.Count -eq 0)
}
[Console]::WriteLine(('Configuration integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Configuration assessment integration failed.'}
