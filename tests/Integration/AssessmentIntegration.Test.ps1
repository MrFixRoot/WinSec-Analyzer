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
    'src/UI/Screens/ScanConfirmation.ps1','src/UI/Screens/AssessmentProfileSelection.ps1',
    'src/Services/ReportService.ps1','src/Services/ExportService.ps1')){. (Join-Path $root $file)}
$script:catalog=Get-WinSecCheckRegistry -ProjectRoot $root
$script:draft=Get-WinSecAssessmentCatalog $root WSA-SYS-001
function Get-WinSecInstalledAssessmentProfiles { @() } # Production profiles are covered separately.
$enabled=@($script:catalog.Checks|Where-Object ExecutionEnabled)
if($enabled.Count -ne 8 -or (($enabled.CheckId | Sort-Object) -join '|') -cne 'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-NET-005|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -or
    @($enabled | Where-Object {-not $_.ExecutionReady -or $_.ImplementationStatus -cne 'VALIDATED'}).Count -ne 0){
    throw 'Only validated System Security, Firewall, SMBv1, Remote Desktop, Open Ports and Network Configuration controls may be enabled in production.'
}
$script:passed=0;$script:failed=0
function Assert-WinSecAssessmentIntegration {param([bool]$Value);if(-not $Value){throw 'Assessment integration assertion failed.'}}
function Get-CimInstance {
    [CmdletBinding()]
    param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    if($Namespace -ceq 'root/cimv2' -and $ClassName -ceq 'Win32_ComputerSystemProduct'){
        return [pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}
    }
    if($Namespace -ceq 'root/cimv2' -and $ClassName -ceq 'Win32_OperatingSystem'){
        $script:osReads++
        return [pscustomobject]@{Caption='Microsoft Windows 11 Pro';Version='10.0.26100';BuildNumber='26100';
            OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}
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
    [pscustomobject]@{AMRunningMode=$script:runningMode;AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$script:realTime}
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
    foreach($item in $copy.Checks){$item.ExecutionEnabled=$false;$item.ExecutionReady=$false}
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
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$script:allLines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if($script:pickerKeys.Count -eq 0){throw 'Synthetic profile/scan key queue exhausted.'}
    $key=$script:pickerKeys.Dequeue()
    if($null -ne $key.Hook){$null=& $key.Hook}
    return $key
}
function Add-WinSecAssessmentPickerKey {
    param([int]$Code,[string]$Character='',[scriptblock]$Hook)
    $script:pickerKeys.Enqueue([pscustomobject]@{VirtualKeyCode=$Code;Character=$Character;KeyDown=$true;ControlKeyState=0;Hook=$Hook})
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
    param([string]$ScanId='assessment-integration-1',
        [string]$ScopeType='CONTROL',[string]$ScopeKey='WSA-SYS-001',[switch]$UseCollectedDependencies)
    $id=$script:context.Devices[0].DeviceId
    $os=[pscustomobject]@{DeviceId=$id;ScanId=$ScanId;OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='TEST';Profile='TEST'}
    $arguments=@{}
    if (-not $UseCollectedDependencies) { $arguments.DependencyEvidence=@{'WSA-SYS-001'=@{'active-antivirus-mode'=$true}} }
    Invoke-WinSecCoordinatedScan @arguments -Coordinator $script:context.ScanCoordinator -DeviceId $id -ScanId $ScanId `
        -ScopeType $ScopeType -ScopeKey $ScopeKey -TargetContext $os -ConfirmAction {$true}
}
function Test-WinSecAssessmentIntegration {
    param([string]$Name,[scriptblock]$Action)
    $script:reads=0;$script:catalogReads=0;$script:realTime=$false;$script:collectionError=$false
    $script:runningMode='Normal'
    $script:changePolicyDuringRead=$false
    $script:osReads=0;$script:pickerKeys=New-Object 'System.Collections.Generic.Queue[object]'
    $script:allLines=New-Object 'System.Collections.Generic.List[string]'
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
function Invoke-WinSecAssessmentProfileIntegrationScan {
    param([string]$ScanId='profile-integration-1',[string]$ScopeType='CONTROL',[string]$ScopeKey='WSA-SYS-001',
        [scriptblock]$ConfirmAction={param($request);$script:profileRequest=Copy-WinSecResultData $request;$true})
    $id=$script:context.Devices[0].DeviceId
    $os=[pscustomobject]@{DeviceId=$id;ScanId=$ScanId;OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='TEST';Profile='UNRESOLVED'}
    $p=Invoke-WinSecCoordinatedScan -Coordinator $script:context.ScanCoordinator -DeviceId $id -ScanId $ScanId `
        -ScopeType $ScopeType -ScopeKey $ScopeKey -AssessmentProfile TEST -TargetContext $os -ConfirmAction $ConfirmAction
    Assert-WinSecAssessmentIntegration ($os.Profile -ceq 'UNRESOLVED')
    return $p
}
function Invoke-WinSecAssessmentPickerIntegrationScan {
    param([string]$Screen='Devices')
    if($script:policy.Catalog.Status -ceq 'APPROVED'){
        $script:policy.Catalog.Criteria[0].Applicability.OSRelease='Windows 11 10.0.26100'
        $script:policy.Catalog.Criteria[0].Applicability.Edition='SKU:48'
    }
    $script:pickerState=New-WinSecNavigationState
    $script:pickerState.Screen=$Screen;$script:pickerState.SelectedDeviceId=$script:context.Devices[0].DeviceId
    Invoke-WinSecCLILocalRescan -State $script:pickerState -Context $script:context
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
foreach ($scope in @(@{Type='DEVICE';Key='ALL'},@{Type='SECTION';Key='SystemSecurity'},@{Type='CONTROL';Key='WSA-SYS-001'})) {
    Test-WinSecAssessmentIntegration ('Actual collected mode supports approved synthetic evaluation without external flags: '+$scope.Type) {
        $p=Invoke-WinSecAssessmentIntegrationScan -ScopeType $scope.Type -ScopeKey $scope.Key -UseCollectedDependencies
        Assert-WinSecAssessmentIntegration ($script:reads -eq 1 -and $p.ScopeType -ceq $scope.Type -and
            $p.Findings[0].Kind -ceq 'CONFIGURATION_DEVIATION' -and $null -ne $p.Findings[0].Guidance -and
            $p.OverallStatus -ceq 'NOT_SCORED' -and $script:store.Count -eq 1)
        Assert-WinSecAssessmentIntegration (($script:store.Values -join '|') -notmatch
            'AMRunningMode|active-antivirus-mode|PRIVATE-ASSESSMENT-RAW-PATH')
    }
}
foreach ($mode in @('Passive','EDR Block Mode','Disabled',$null)) {
    Test-WinSecAssessmentIntegration 'An external true cannot turn nonactive or unknown Defender telemetry into a deviation' {
        $script:runningMode=$mode
        $p=Invoke-WinSecAssessmentIntegrationScan
        Assert-WinSecAssessmentIntegration ($script:reads -eq 1 -and $script:store.Count -eq 1 -and
            $p.Findings[0].Kind -ceq 'CATALOG_NOT_READY' -and $p.Findings[0].EvaluationStatus -ceq 'NOT_EVALUATED' -and
            @($p.Findings|Where-Object Kind -EQ CONFIGURATION_DEVIATION).Count -eq 0 -and
            @($p.Findings|Where-Object {$null -ne $_.Guidance}).Count -eq 0)
    }
}
Test-WinSecAssessmentIntegration 'A later passive scan cannot rewrite an earlier finding or its export recommendation' {
    $first=Invoke-WinSecAssessmentIntegrationScan -ScanId 'normal-first' -UseCollectedDependencies
    $originalJson=$script:store['normal-first']
    $script:runningMode='Passive'
    $second=Invoke-WinSecAssessmentIntegrationScan -ScanId 'passive-later' -UseCollectedDependencies
    Assert-WinSecAssessmentIntegration ($script:store.Count -eq 2 -and $script:store['normal-first'] -ceq $originalJson -and
        $first.Findings[0].Kind -ceq 'CONFIGURATION_DEVIATION' -and $second.Findings[0].Kind -ceq 'CATALOG_NOT_READY')
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $originalJson)
    $selection=[pscustomobject]@{DeviceId=$first.DeviceId;ScanId=$first.ScanId;SourceScopeType='CONTROL';
        SourceScopeKey='WSA-SYS-001';ScopeType='CONTROL';ScopeKey='WSA-SYS-001';CatalogVersion=$first.CatalogVersion;
        Findings=@([pscustomobject]@{FindingId=$first.Findings[0].FindingId;CheckId='WSA-SYS-001';DeviceId=$first.DeviceId;
            ScanId=$first.ScanId;Kind='CONFIGURATION_DEVIATION';EvaluationStatus='FAIL';Guidance=$restored.PublicResult.Findings[0].Guidance})}
    $null=Export-WinSecFindingsMarkdown $root $selection
    Assert-WinSecAssessmentIntegration ($script:exports[0].Markdown.Contains((ConvertTo-WinSecMarkdownText 'SYNTHETIC: Review real-time protection manually.')) -and
        $script:reads -eq 2 -and $script:store['normal-first'] -ceq $originalJson)
}
foreach($scope in @(@{Type='DEVICE';Key='ALL'},@{Type='SECTION';Key='SystemSecurity'},@{Type='CONTROL';Key='WSA-SYS-001'})){
    Test-WinSecAssessmentIntegration ('Explicit approved profile reaches guidance through confirmation: '+$scope.Type) {
        $p=Invoke-WinSecAssessmentProfileIntegrationScan -ScopeType $scope.Type -ScopeKey $scope.Key
        Assert-WinSecAssessmentIntegration ($script:profileRequest.EvaluationProfile.Profile -ceq 'TEST' -and
            $script:profileRequest.EvaluationProfile.Policies[0].CatalogSha256 -ceq ('B'*64) -and $script:catalogReads -eq 2 -and
            $p.Findings[0].Guidance.Profile -ceq 'TEST' -and $p.Findings[0].Kind -ceq 'CONFIGURATION_DEVIATION' -and
            $p.OverallStatus -ceq 'NOT_SCORED' -and $script:store.Count -eq 1)
        $loaded=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $script:store[$p.ScanId])
        Assert-WinSecAssessmentIntegration ($loaded.PublicResult.Findings[0].Guidance.Profile -ceq 'TEST')
    }
}
Test-WinSecAssessmentIntegration 'Explicit profile binds the automatically collected OS context without guessing a policy' {
    function Get-CimInstance {
        [CmdletBinding()]param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
        if($ClassName -ceq 'Win32_ComputerSystemProduct'){return [pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}}
        if($ClassName -ceq 'Win32_OperatingSystem'){return [pscustomobject]@{Caption='Microsoft Windows 11 Pro';Version='10.0.26100';
            BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}}
        throw 'Unexpected synthetic CIM class.'
    }
    $script:policy.Catalog.Criteria[0].Applicability.OSRelease='Windows 11 10.0.26100'
    $script:policy.Catalog.Criteria[0].Applicability.Edition='SKU:48'
    $p=Invoke-WinSecCoordinatedScan $script:context.ScanCoordinator -ScanId 'profile-native-context' `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile TEST -ConfirmAction {$true}
    Assert-WinSecAssessmentIntegration ($p.Findings[0].Kind -ceq 'CONFIGURATION_DEVIATION' -and
        $p.Findings[0].Guidance.OSRelease -ceq 'Windows 11 10.0.26100' -and $p.Findings[0].Guidance.Profile -ceq 'TEST')
}
Test-WinSecAssessmentIntegration 'Cancelling a profile-bound rescan preserves the earlier history and reads no new telemetry' {
    $first=Invoke-WinSecAssessmentProfileIntegrationScan
    $second=Invoke-WinSecAssessmentProfileIntegrationScan -ScanId 'cancelled-profile' -ConfirmAction {$false}
    Assert-WinSecAssessmentIntegration ($null -eq $second -and $script:reads -eq 1 -and $script:store.Count -eq 1 -and
        $script:context.ScanCoordinator.Sessions.Count -eq 1 -and $null -ne $first)
}
Test-WinSecAssessmentIntegration 'The production draft cannot be selected as an approved profile' {
    $script:policy=Copy-WinSecResultData $script:draft;$caught=$false;$script:profileConfirmCalls=0
    try{$null=Invoke-WinSecAssessmentProfileIntegrationScan -ConfirmAction {$script:profileConfirmCalls++;$true}}catch{$caught=$true}
    Assert-WinSecAssessmentIntegration ($caught -and $script:profileConfirmCalls -eq 0 -and $script:reads -eq 0 -and $script:store.Count -eq 0)
}
foreach($change in @(
    {$script:policy.Catalog.CatalogVersion='changed-at-confirmation';$script:policy.Sha256=('C'*64)},
    {$script:policy.Catalog.Criteria[0].Approved=$false},
    {$script:policy.Catalog.Criteria[0].Applicability.Profile='OTHER'}
)){
    Test-WinSecAssessmentIntegration 'Policy changes while confirming invalidate the requested evaluation before collection' {
        $caught=$false
        try{$null=Invoke-WinSecAssessmentProfileIntegrationScan -ConfirmAction {$null=& $change;$true}}catch{$caught=$true}
        Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:store.Count -eq 0 -and
            $script:context.ScanCoordinator.Sessions.Count -eq 0)
    }
}
Test-WinSecAssessmentIntegration 'A modified profile preview cannot authorize collection' {
    $caught=$false
    try{$null=Invoke-WinSecAssessmentProfileIntegrationScan -ConfirmAction {param($r);$r.EvaluationProfile.Profile='OTHER';$true}}catch{$caught=$true}
    Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:store.Count -eq 0)
}
Test-WinSecAssessmentIntegration 'The profile policy is frozen before telemetry collection' {
    $script:changePolicyDuringRead=$true
    $p=Invoke-WinSecAssessmentProfileIntegrationScan
    Assert-WinSecAssessmentIntegration ($p.Findings[0].Guidance.CatalogVersion -ceq 'test-1' -and
        $p.Findings[0].Guidance.Recommendation -notmatch 'CHANGED DURING COLLECTION' -and $script:catalogReads -eq 2)
}
Test-WinSecAssessmentIntegration 'An explicit profile never overrides a conflicting supplied context' {
    $caught=$false;$id=$script:context.Devices[0].DeviceId
    try{$null=Invoke-WinSecCoordinatedScan $script:context.ScanCoordinator -ScanId 'profile-conflict' `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile TEST -ConfirmAction {$true} `
        -TargetContext ([pscustomobject]@{DeviceId=$id;ScanId='profile-conflict';Profile='OTHER'})}catch{$caught=$true}
    Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:catalogReads -eq 0)
}
Test-WinSecAssessmentIntegration 'Selecting a profile does not bypass runtime OS applicability' {
    $script:policy.Catalog.Criteria[0].Applicability.OSRelease='Windows 11 OTHER'
    $p=Invoke-WinSecAssessmentProfileIntegrationScan
    Assert-WinSecAssessmentIntegration ($p.Findings[0].Kind -ceq 'CATALOG_NOT_READY' -and
        @($p.Findings|Where-Object Kind -EQ CONFIGURATION_DEVIATION).Count -eq 0 -and $p.OverallStatus -ceq 'NOT_SCORED')
}
Test-WinSecAssessmentIntegration 'A selected profile is not remembered or inferred for the next operation' {
    $first=Invoke-WinSecAssessmentProfileIntegrationScan
    $id=$script:context.Devices[0].DeviceId
    $os=[pscustomobject]@{DeviceId=$id;ScanId='without-profile';OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='TEST';Profile='UNRESOLVED'}
    $second=Invoke-WinSecCoordinatedScan $script:context.ScanCoordinator -ScanId 'without-profile' `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -TargetContext $os -ConfirmAction {$true}
    Assert-WinSecAssessmentIntegration ($first.Findings[0].Kind -ceq 'CONFIGURATION_DEVIATION' -and
        $second.Findings[0].Kind -ceq 'CATALOG_NOT_READY' -and $script:store.Count -eq 2)
}
foreach($field in @('DeviceId','ScanId')){
    Test-WinSecAssessmentIntegration 'Profile context identity requires scalar device and scan identifiers before collection' {
        $id=$script:context.Devices[0].DeviceId
        $os=[pscustomobject]@{DeviceId=$id;ScanId='profile-array-identity';OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='TEST';Profile='UNRESOLVED'}
        $os.$field=@();$caught=$false
        try{$null=Invoke-WinSecCoordinatedScan $script:context.ScanCoordinator -ScanId 'profile-array-identity' `
            -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile TEST -TargetContext $os -ConfirmAction {$true}}catch{$caught=$true}
        Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:catalogReads -eq 0 -and $script:store.Count -eq 0)
    }
}
foreach($screen in @('Devices','MainMenu','Section')){
    Test-WinSecAssessmentIntegration ('CLI picker and final confirmation reach approved evaluation and history: '+$screen) {
        $script:context|Add-Member -NotePropertyName LocalSystemInfo -NotePropertyValue ([pscustomobject]@{
            DeviceId=$script:context.Devices[0].DeviceId;Label='Pro 24H2 | build: 26100'})
        Add-WinSecAssessmentPickerKey 40
        Add-WinSecAssessmentPickerKey 13
        Add-WinSecAssessmentPickerKey 13 -Hook {Assert-WinSecAssessmentIntegration ($script:reads -eq 0 -and $script:osReads -eq 0)}
        Add-WinSecAssessmentPickerKey 13 -Hook {Assert-WinSecAssessmentIntegration ($script:reads -eq 0 -and $script:osReads -eq 0)}
        $p=Invoke-WinSecAssessmentPickerIntegrationScan $screen
        Assert-WinSecAssessmentIntegration ($p.Findings[0].Guidance.Profile -ceq 'TEST' -and $p.OverallStatus -ceq 'NOT_SCORED' -and
            $script:reads -eq 1 -and $script:osReads -eq 1 -and $script:store.Count -eq 1 -and $script:pickerKeys.Count -eq 0 -and
            $script:context.PublicScans.Count -eq 1)
        $text=$script:allLines -join '|'
        Assert-WinSecAssessmentIntegration ($text.Contains('ASSESSMENT PROFILE') -and $text.Contains('CONFIRM SCAN') -and
            $text.Contains('Evaluation profile: TEST') -and $text.Contains('Current OS: Pro 24H2 | build: 26100') -and
            $text -notmatch 'PRIVATE-ASSESSMENT-RAW-PATH' -and ($script:store.Values -join '|') -notmatch 'LocalSystemInfo|Current OS:')
    }
}
foreach($where in @('picker','confirmation')){
    Test-WinSecAssessmentIntegration 'Cancelling either modal collects nothing and preserves the public state' {
        if($where -ceq 'confirmation'){Add-WinSecAssessmentPickerKey 40;Add-WinSecAssessmentPickerKey 13;Add-WinSecAssessmentPickerKey 13}
        Add-WinSecAssessmentPickerKey 27
        $p=Invoke-WinSecAssessmentPickerIntegrationScan
        Assert-WinSecAssessmentIntegration ($null -eq $p -and $script:reads -eq 0 -and $script:osReads -eq 0 -and
            $script:store.Count -eq 0 -and $script:context.PublicScans.Count -eq 0 -and $script:context.ScanCoordinator.Sessions.Count -eq 0)
    }
}
Test-WinSecAssessmentIntegration 'Collection-only choice cannot silently use an available approved profile' {
    Add-WinSecAssessmentPickerKey 13;Add-WinSecAssessmentPickerKey 13
    $p=Invoke-WinSecAssessmentPickerIntegrationScan
    Assert-WinSecAssessmentIntegration ($p.Findings[0].Kind -ceq 'CATALOG_NOT_READY' -and
        @($p.Findings|Where-Object {$null -ne $_.Guidance}).Count -eq 0 -and
        ($script:allLines -join '|').Contains('Collection only') -and $p.OverallStatus -ceq 'NOT_SCORED')
}
Test-WinSecAssessmentIntegration 'The real draft offers collection only without pretending to have an approved profile' {
    $script:policy=Copy-WinSecResultData $script:draft
    Add-WinSecAssessmentPickerKey 13;Add-WinSecAssessmentPickerKey 13
    $p=Invoke-WinSecAssessmentPickerIntegrationScan
    Assert-WinSecAssessmentIntegration ($p.Findings[0].Kind -ceq 'CATALOG_NOT_READY' -and
        ($script:allLines -join '|').Contains('No approved profile is available') -and
        @($p.Findings|Where-Object Kind -EQ CONFIGURATION_DEVIATION).Count -eq 0)
}
Test-WinSecAssessmentIntegration 'Policy changes after it was offered invalidate selection before telemetry collection' {
    Add-WinSecAssessmentPickerKey 40
    Add-WinSecAssessmentPickerKey 13
    Add-WinSecAssessmentPickerKey 13 -Hook {$script:policy.Catalog.CatalogVersion='changed-in-picker';$script:policy.Sha256=('C'*64)}
    $caught=$false;try{$null=Invoke-WinSecAssessmentPickerIntegrationScan}catch{$caught=$true}
    Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:osReads -eq 0 -and $script:store.Count -eq 0)
}
Test-WinSecAssessmentIntegration 'Revoked approval while choosing a profile cannot reach scan confirmation or collection' {
    Add-WinSecAssessmentPickerKey 40
    Add-WinSecAssessmentPickerKey 13
    Add-WinSecAssessmentPickerKey 13 -Hook {$script:policy.Catalog.Criteria[0].Approved=$false}
    $caught=$false;try{$null=Invoke-WinSecAssessmentPickerIntegrationScan}catch{$caught=$true}
    Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:osReads -eq 0 -and $script:store.Count -eq 0)
}
Test-WinSecAssessmentIntegration 'Navigation changed in the picker cannot scan the earlier selection' {
    Add-WinSecAssessmentPickerKey 40
    Add-WinSecAssessmentPickerKey 13
    Add-WinSecAssessmentPickerKey 13 -Hook {$script:pickerState.Screen='MainMenu'}
    $caught=$false;try{$null=Invoke-WinSecAssessmentPickerIntegrationScan}catch{$caught=$true}
    Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:store.Count -eq 0)
}
Test-WinSecAssessmentIntegration 'The picker cannot return metadata for a policy it was not offered' {
    function Show-WinSecAssessmentProfileSelection {
        param($Request,$Profiles)
        $forged=Copy-WinSecResultData $Profiles[0];$forged.Policies[0].CatalogSha256=('F'*64)
        [pscustomobject]@{Confirmed=$true;Selection=$forged}
    }
    $caught=$false;try{$null=Invoke-WinSecAssessmentPickerIntegrationScan}catch{$caught=$true}
    Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:osReads -eq 0 -and $script:store.Count -eq 0)
}
Test-WinSecAssessmentIntegration 'The next rescan asks again and a collection-only result cannot rewrite prior guidance' {
    Add-WinSecAssessmentPickerKey 40;Add-WinSecAssessmentPickerKey 13;Add-WinSecAssessmentPickerKey 13;Add-WinSecAssessmentPickerKey 13
    $first=Invoke-WinSecAssessmentPickerIntegrationScan;$saved=$script:store[$first.ScanId]
    Add-WinSecAssessmentPickerKey 13;Add-WinSecAssessmentPickerKey 13
    $second=Invoke-WinSecAssessmentPickerIntegrationScan
    Assert-WinSecAssessmentIntegration ($script:reads -eq 2 -and $script:store.Count -eq 2 -and
        $script:store[$first.ScanId] -ceq $saved -and $first.Findings[0].Guidance.Profile -ceq 'TEST' -and
        $second.Findings[0].Kind -ceq 'CATALOG_NOT_READY' -and ($script:allLines -join '|').Contains('CONFIRM RESCAN'))
}
Test-WinSecAssessmentIntegration 'An empty executable selection skips the picker and cannot start an audit' {
    function Get-WinSecCheckRegistry {
        param($ProjectRoot)
        $copy=Copy-WinSecResultData $script:catalog
        foreach($check in $copy.Checks){$check.ExecutionEnabled=$false;$check.ExecutionReady=$false}
        $copy
    }
    Add-WinSecAssessmentPickerKey 27
    $p=Invoke-WinSecAssessmentPickerIntegrationScan
    Assert-WinSecAssessmentIntegration ($null -eq $p -and $script:reads -eq 0 -and $script:osReads -eq 0 -and
        ($script:allLines -join '|').Contains('NO_EXECUTABLE_CHECKS') -and
        -not ($script:allLines -join '|').Contains('ASSESSMENT PROFILE'))
}
Test-WinSecAssessmentIntegration 'Cancelling profile selection preserves an existing CLI assessment and immutable history' {
    Add-WinSecAssessmentPickerKey 40;Add-WinSecAssessmentPickerKey 13;Add-WinSecAssessmentPickerKey 13;Add-WinSecAssessmentPickerKey 13
    $first=Invoke-WinSecAssessmentPickerIntegrationScan;$saved=$script:store[$first.ScanId]
    $publicBefore=Get-WinSecPublicHistoryJson $script:context.PublicScans
    Add-WinSecAssessmentPickerKey 27
    $cancelled=Invoke-WinSecAssessmentPickerIntegrationScan
    Assert-WinSecAssessmentIntegration ($null -eq $cancelled -and $script:reads -eq 1 -and $script:osReads -eq 1 -and
        $script:store.Count -eq 1 -and $script:store[$first.ScanId] -ceq $saved -and
        (Get-WinSecPublicHistoryJson $script:context.PublicScans) -ceq $publicBefore)
}
foreach($invalid in @('textual','multiple','cancelled-with-selection')){
    Test-WinSecAssessmentIntegration 'Malformed picker decisions cannot reach scan confirmation or publication' {
        function Show-WinSecAssessmentProfileSelection {
            param($Request,$Profiles)
            switch($invalid){
                'textual' {[pscustomobject]@{Confirmed='true';Selection=$null}}
                'multiple' {[pscustomobject]@{Confirmed=$true;Selection=$null};[pscustomobject]@{Confirmed=$true;Selection=$null}}
                'cancelled-with-selection' {[pscustomobject]@{Confirmed=$false;Selection=$Profiles[0]}}
            }
        }
        $caught=$false;try{$null=Invoke-WinSecAssessmentPickerIntegrationScan}catch{$caught=$true}
        Assert-WinSecAssessmentIntegration ($caught -and $script:reads -eq 0 -and $script:osReads -eq 0 -and $script:store.Count -eq 0)
    }
}
[Console]::WriteLine(('Assessment integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Assessment integration failed.'}
