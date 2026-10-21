# Real Defender/coordinator/evaluation/findings/history/UI/export pipeline.
# Only synthetic policies, Windows queries, keyboard/terminal and storage boundaries.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/KeyboardController.ps1','src/UI/Core/ResizeHandler.ps1','src/UI/Core/TerminalRenderer.ps1',
    'src/UI/Core/LayoutManager.ps1','src/UI/Components/Banner.ps1','src/UI/Components/Table.ps1','src/UI/Components/KeyboardHelp.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1',
    'src/Services/ReportService.ps1','src/Services/ExportService.ps1')){. (Join-Path $root $file)}
$script:catalog=Get-WinSecCheckRegistry -ProjectRoot $root
$script:draft=Get-WinSecAssessmentCatalog $root WSA-SYS-001
if(@($script:catalog.Checks|Where-Object ExecutionEnabled).Count){throw 'Production checks must stay disabled.'}
$script:passed=0;$script:failed=0
function Assert-WinSecAssessmentIntegration {param([bool]$Value);if(-not $Value){throw 'Assessment integration assertion failed.'}}
function Get-CimInstance {
    [CmdletBinding()]
    param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    if($Namespace -ceq 'root/cimv2' -and $ClassName -ceq 'Win32_ComputerSystemProduct'){
        return [pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}
    }
    throw 'Synthetic Defender CIM unavailable.'
}
function Get-MpComputerStatus {
    [CmdletBinding()]param()
    $script:reads++
    if($script:changePolicyDuringRead){
        $script:policy.Catalog.CatalogVersion='changed-during-read'
        $script:policy.Catalog.Criteria[0].Recommendation='CHANGED DURING COLLECTION'
    }
    if($script:collectionError){throw 'PRIVATE-ASSESSMENT-COLLECTION-ERROR'}
    [pscustomobject]@{AMRunningMode='Normal';AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$script:realTime}
}
function Get-MpPreference {
    [CmdletBinding()]param()
    [pscustomobject]@{PUAProtection=1;AttackSurfaceReductionRules_Ids=@();AttackSurfaceReductionRules_Actions=@();
        ExclusionPath=@('C:\PRIVATE-ASSESSMENT-RAW-PATH')}
}
function Import-WinSecDeviceInventory {param($ProjectRoot);[pscustomobject]@{schemaVersion='1.2.0';targets=@(New-WinSecLocalTarget);removedDeviceHashes=@()}}
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $copy=Copy-WinSecResultData $script:catalog
    $check=$copy.Checks|Where-Object CheckId -CEQ WSA-SYS-001
    $check.ExecutionEnabled=$true;$check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'
    $copy
}
function Get-WinSecAssessmentCatalog {param($ProjectRoot,$CheckId);$script:catalogReads++;if($CheckId -ceq 'WSA-SYS-001'){Copy-WinSecResultData $script:policy}}
function Save-WinSecPublicHistory {
    param($ProjectRoot,$Session)
    if($script:store.ContainsKey($Session.ScanId)){throw 'Immutable history conflict.'}
    $script:store[$Session.ScanId]=Get-WinSecPublicHistoryJson (New-WinSecPublicHistoryRecord $Session)
}
function Open-WinSecDeviceInventoryStore {
    param($ProjectRoot)
    $lease=[pscustomobject]@{};$lease|Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
    [pscustomobject]@{Lock=$lease}
}
function Read-WinSecPublicHistoryArtifacts {
    param($ProjectRoot,$Devices,[ref]$TotalBytes)
    foreach($json in $script:store.Values){ConvertFrom-WinSecStoredJson $json}
}
function Write-WinSecMarkdownArtifact {
    param($ProjectRoot,$Report)
    $script:exports.Add((Copy-WinSecResultData $Report));[pscustomobject]@{DeviceId=$Report.DeviceId;ScanId=$Report.ScanId;Status='SYNTHETIC_EXPORT'}
}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
function New-WinSecAssessmentIntegrationContext {
    $coordinator=New-WinSecScanCoordinator
    $device=New-WinSecLocalTarget
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($device)}
    $coordinator.PublicHistoryEnabled=$true;$coordinator.AssessmentEnabled=$true
    [pscustomobject]@{ProjectRoot=$root;Version='0.9.0';Devices=@($device);ScanCoordinator=$coordinator;
        PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LastScanMessage=''}
}
function Invoke-WinSecAssessmentIntegrationScan {
    param([string]$ScanId='assessment-integration-1')
    $id=$script:context.Devices[0].DeviceId
    $os=[pscustomobject]@{DeviceId=$id;ScanId=$ScanId;OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='TEST';Profile='TEST'}
    Invoke-WinSecCoordinatedScan -Coordinator $script:context.ScanCoordinator -DeviceId $id -ScanId $ScanId `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -TargetContext $os `
        -DependencyEvidence @{'WSA-SYS-001'=@{'active-antivirus-mode'=$true}} -ConfirmAction {$true}
}
function Test-WinSecAssessmentIntegration {
    param([string]$Name,[scriptblock]$Action)
    $script:reads=0;$script:catalogReads=0;$script:realTime=$false;$script:collectionError=$false
    $script:changePolicyDuringRead=$false
    $script:store=@{};$script:exports=New-Object 'System.Collections.Generic.List[object]'
    $script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55}
    $catalog=Copy-WinSecResultData $script:draft.Catalog
    $catalog.CatalogId='SYNTHETIC-APPROVED-POLICY';$catalog.CatalogVersion='test-1';$catalog.Status='APPROVED';$catalog.ScoringEnabled=$false
    $catalog|Add-Member -NotePropertyName EvaluationEnabled -NotePropertyValue $true
    $rule=Copy-WinSecResultData $catalog.Criteria[2];$rule.Approved=$true
    $rule.Name='SYNTHETIC real-time protection policy'
    $rule.Recommendation='SYNTHETIC: Review real-time protection manually.'
    $rule.Source=[pscustomobject]@{Framework='LOCAL_POLICY';Version='test-1';ControlId='SYNTHETIC-RT-001';
        Title='SYNTHETIC test policy';Url='https://example.invalid/synthetic-policy'}
    $rule.Verification=[pscustomobject]@{Status='VERIFIED';ReviewedBy='SYNTHETIC';ReviewedAtUTC='2026-10-16T00:00:00Z'}
    $rule.Applicability=[pscustomobject]@{OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='TEST';Profile='TEST'}
    $catalog.Criteria=@($rule);$catalog.ReviewOnly=@()
    $script:policy=[pscustomobject]@{Catalog=$catalog;Sha256=('B'*64)}
    $script:context=New-WinSecAssessmentIntegrationContext
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
Test-WinSecAssessmentIntegration 'Initialization never reads Defender or evaluates a catalog' {
    Assert-WinSecAssessmentIntegration ($script:reads -eq 0 -and $script:catalogReads -eq 0 -and $script:store.Count -eq 0)
}
Test-WinSecAssessmentIntegration 'Confirmed Defender reaches evaluation, findings and public history without scoring' {
    $p=Invoke-WinSecAssessmentIntegrationScan
    Assert-WinSecAssessmentIntegration ($script:reads -eq 1 -and $p.Findings.Count -eq 1 -and
        $p.Findings[0].Kind -ceq 'CONFIGURATION_DEVIATION' -and $p.Findings[0].EvaluationStatus -ceq 'FAIL' -and
        $p.Findings[0].Guidance.CatalogVersion -ceq 'test-1' -and $p.OverallScore -eq $null -and $p.OverallStatus -ceq 'NOT_SCORED')
    Assert-WinSecAssessmentIntegration ($script:store.Count -eq 1 -and
        ($script:store.Values -join '|') -notmatch 'PRIVATE-ASSESSMENT-RAW-PATH|DefenderPreferences|ObservedValue|ExpectedValue')
}
Test-WinSecAssessmentIntegration 'Restart, F navigation, Findings and Markdown retain the original recommendation' {
    $p=Invoke-WinSecAssessmentIntegrationScan
    $script:policy.Catalog.Criteria[0].Recommendation='CHANGED CURRENT POLICY'
    $restart=New-WinSecAssessmentIntegrationContext;Restore-WinSecPublicHistory $restart
    $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$restart.Devices[0].DeviceId
    $key=[pscustomobject]@{VirtualKeyCode=70;Character='F';ControlKeyState=0;KeyDown=$true}
    $action=ConvertTo-WinSecKeyboardAction -KeyInfo $key -Screen Section
    $null=Invoke-WinSecNavigationAction -State $state -Action $action -Devices $restart.Devices -ControlCount 3
    Show-WinSecCLICurrentScreen $state $restart
    $rendered=$script:lines -join '|'
    Assert-WinSecAssessmentIntegration ($state.Screen -ceq 'Findings' -and $state.FindingsScope -ceq 'Control' -and
        $rendered -match 'SYNTHETIC real-time protection policy' -and $rendered -match 'Review real-time protection manually' -and
        $rendered -notmatch 'CHANGED CURRENT POLICY|PRIVATE-ASSESSMENT-RAW-PATH')
    $selection=Get-WinSecCLIFindingsExportSelection $state $restart
    $null=Export-WinSecFindingsMarkdown $root $selection
    $text=$script:exports[0].Markdown
    Assert-WinSecAssessmentIntegration ($text.Contains((ConvertTo-WinSecMarkdownText 'SYNTHETIC-RT-001')) -and
        $text.Contains((ConvertTo-WinSecMarkdownText 'test-1')) -and
        $text.Contains((ConvertTo-WinSecMarkdownText 'SYNTHETIC: Review real-time protection manually.')) -and $text -match 'NOT_SCORED' -and
        $text -notmatch 'CHANGED CURRENT POLICY|PRIVATE-ASSESSMENT-RAW-PATH|ObservedValue|ExpectedValue')
    Assert-WinSecAssessmentIntegration ($script:reads -eq 1 -and $script:store.Count -eq 1)
}
Test-WinSecAssessmentIntegration 'Guidance fits resized terminals without collecting again' {
    $p=Invoke-WinSecAssessmentIntegrationScan
    $restart=New-WinSecAssessmentIntegrationContext;Restore-WinSecPublicHistory $restart
    $state=New-WinSecNavigationState;$state.Screen='Findings';$state.SelectedDeviceId=$restart.Devices[0].DeviceId;$state.FindingsScope='Control'
    foreach($size in @(@{W=120;H=55},@{W=80;H=26},@{W=40;H=20})){
        $script:terminal=[pscustomobject]@{Width=$size.W;ContentWidth=$size.W-1;Height=$size.H}
        Show-WinSecCLICurrentScreen $state $restart
        Assert-WinSecAssessmentIntegration ($script:lines.Count -le $size.H -and
            @($script:lines|Where-Object {$_.Length -gt ($size.W-1)}).Count -eq 0 -and
            ($script:lines -join '|') -notmatch 'PRIVATE-ASSESSMENT-RAW-PATH')
    }
    Assert-WinSecAssessmentIntegration ($script:reads -eq 1 -and $script:store.Count -eq 1)
}
Test-WinSecAssessmentIntegration 'Production draft produces an honest pending diagnostic, not a misconfiguration' {
    $script:policy=Copy-WinSecResultData $script:draft
    $p=Invoke-WinSecAssessmentIntegrationScan
    Assert-WinSecAssessmentIntegration ($p.Findings.Count -eq 1 -and $p.Findings[0].Kind -ceq 'CATALOG_NOT_READY' -and
        $p.Findings[0].EvaluationStatus -ceq 'NOT_EVALUATED' -and $null -eq $p.Findings[0].Guidance)
}
Test-WinSecAssessmentIntegration 'Unknown telemetry and technical errors never become configuration deviations' {
    $script:collectionError=$true;$p=Invoke-WinSecAssessmentIntegrationScan
    Assert-WinSecAssessmentIntegration ($p.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS' -and
        @($p.Findings|Where-Object Kind -EQ CONFIGURATION_DEVIATION).Count -eq 0 -and
        @($p.Findings|Where-Object Kind -EQ COLLECTION_ERROR).Count -eq 1)
}
Test-WinSecAssessmentIntegration 'Cancellation and changed evaluation mode prevent collection and publication' {
    $id=$script:context.Devices[0].DeviceId
    $cancel=Invoke-WinSecCoordinatedScan $script:context.ScanCoordinator -DeviceId $id `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction {$false}
    Assert-WinSecAssessmentIntegration ($null -eq $cancel -and $script:reads -eq 0 -and $script:catalogReads -eq 0)
    $caught=$false
    try{$null=Invoke-WinSecCoordinatedScan $script:context.ScanCoordinator -DeviceId $id `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction {$script:context.ScanCoordinator.AssessmentEnabled=$false;$true}}
    catch{$caught=$true}
    Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:store.Count -eq 0)
}
Test-WinSecAssessmentIntegration 'Catalog changes during collection cannot change the original evaluation policy' {
    $script:changePolicyDuringRead=$true
    $p=Invoke-WinSecAssessmentIntegrationScan
    Assert-WinSecAssessmentIntegration ($script:catalogReads -eq 1 -and $p.Findings[0].Guidance.CatalogVersion -ceq 'test-1' -and
        $p.Findings[0].Guidance.Recommendation -notmatch 'CHANGED DURING COLLECTION')
}
Test-WinSecAssessmentIntegration 'Foreign target context is rejected before Defender reads' {
    $caught=$false
    try{$null=Invoke-WinSecCoordinatedScan $script:context.ScanCoordinator -ScanId 'scan-foreign' `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction {$true} `
        -TargetContext ([pscustomobject]@{DeviceId='local:FOREIGN';ScanId='scan-foreign'})}
    catch{$caught=$true}
    Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:store.Count -eq 0)
}
[Console]::WriteLine(('Assessment integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Assessment integration failed.'}
