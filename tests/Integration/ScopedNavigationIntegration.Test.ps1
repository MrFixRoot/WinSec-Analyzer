# Full keyboard/navigation -> CLI -> coordinator -> synthetic collectors.
# Real UI rendering, public models and in-memory history. No startup/storage.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1',
    'src/UI/Core/TerminalRenderer.ps1','src/UI/Core/LayoutManager.ps1','src/UI/Core/KeyboardController.ps1',
    'src/UI/Core/NavigationController.ps1','src/UI/Core/ResizeHandler.ps1','src/UI/Components/Banner.ps1',
    'src/UI/Components/Table.ps1','src/UI/Components/KeyboardHelp.ps1','src/UI/Screens/MainMenu.ps1',
    'src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1','src/UI/Screens/Devices.ps1','src/UI/Screens/ScanConfirmation.ps1')){. (Join-Path $root $file)}
$script:catalog=Get-WinSecCheckRegistry -ProjectRoot $root
$enabled=@($script:catalog.Checks|Where-Object ExecutionEnabled)
if($enabled.Count -ne 8 -or (($enabled.CheckId | Sort-Object) -join '|') -cne 'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-NET-005|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -or
    @($enabled | Where-Object {-not $_.ExecutionReady -or $_.ImplementationStatus -cne 'VALIDATED'}).Count -ne 0){
    throw 'Only validated System Security, Firewall, SMBv1, Remote Desktop, Open Ports and Network Configuration controls may be enabled in production.'
}
$script:passed=0;$script:failed=0
function Get-CimInstance {[pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}}
function Assert-WinSecNavigationScan {param([bool]$Condition);if(-not $Condition){throw 'Scoped navigation assertion failed.'}}
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $registry=Copy-WinSecResultData -Value $script:catalog
    foreach($check in $registry.Checks){$check.ExecutionEnabled=$false;$check.ExecutionReady=$false;if($check.CheckId -cin @('WSA-SYS-001','WSA-SYS-002','WSA-NET-001') -and $check.CheckId -cne $script:disabledCheck){
        $check.ExecutionEnabled=$true;$check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'
    }}
    return $registry
}
function Import-WinSecAuditDependencies {param([switch]$SkipScoring);Assert-WinSecNavigationScan ([bool]$SkipScoring)}
function Invoke-WinSecAuditCheck {
    param($Check,$DeviceId,$ScanId)
    $script:collected.Add($Check.CheckId)
    New-WinSecAuditRecord -Check $Check -DeviceId $DeviceId -ScanId $ScanId -Status INFORMATIONAL `
        -ObservedStatus INFORMATIONAL -Evidence @{Secret='SCOPED-NAV-PRIVATE'}
}
function Assert-WinSecEvidenceProtection {throw 'Unexpected storage.'}
function Get-WinSecEvidenceStorageRoot {throw 'Unexpected storage.'}
function Save-WinSecCoordinatedEvidence {throw 'Unexpected storage.'}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    $key=$script:keys.Dequeue()
    if($key -is [scriptblock]){$null=& $key;return [pscustomobject]@{Character='';VirtualKeyCode=13;ControlKeyState=0;KeyDown=$true}}
    return $key
}
function Add-WinSecNavigationKey {
    param([int]$Code=13,[string]$Character='')
    $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$Code;Character=$Character;ControlKeyState=0;KeyDown=$true})
}
function Invoke-WinSecNavigationKey {
    param([int]$Code,[string]$Character='')
    $event=[pscustomobject]@{VirtualKeyCode=$Code;Character=$Character;ControlKeyState=0;KeyDown=$true}
    if (Invoke-WinSecCLIBackNavigation -KeyInfo $event -State $script:state) { return }
    $action=ConvertTo-WinSecKeyboardAction -KeyInfo $event -Screen $script:state.Screen -EnableRescan
    $counts=Get-WinSecCLINavigationCounts -State $script:state -Context $script:context -Action $action
    $null=Invoke-WinSecNavigationAction -State $script:state -Action $action -Devices $script:context.Devices `
        -SectionCount $counts.SectionCount -ControlCount $counts.ControlCount -FindingCount $counts.FindingCount
}
function Test-WinSecScopedNavigation {
    param([string]$Name,[scriptblock]$Action)
    $script:disabledCheck=$null
    $script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]';$script:collected=New-Object 'System.Collections.Generic.List[string]'
    $script:terminal=[pscustomobject]@{Width=100;ContentWidth=99;Height=40}
    $target=New-WinSecLocalTarget
    $script:state=New-WinSecNavigationState
    $script:state.Screen='Devices';$script:state.SelectedDeviceId=$target.DeviceId;$script:state.SelectedDeviceName=$target.Hostname
    $script:context=[pscustomobject]@{Version='0.9.0';Devices=@($target);ScanCoordinator=New-WinSecScanCoordinator;
        ActiveScanByDevice=@{};ActiveScanByScope=@{};PublicScans=@{};ScanId='';SectionResults=@();ControlResults=@();Findings=@();LastScanMessage=''}
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)
        [Console]::WriteLine(('Terminal {0}x{1}; rendered rows {2}; maximum width {3}' -f $script:terminal.Width,$script:terminal.Height,
            $script:lines.Count,(@($script:lines|ForEach-Object{$_.Length})|Measure-Object -Maximum).Maximum))}
}
Test-WinSecScopedNavigation 'R resolves DEVICE, SECTION and CONTROL through real keyboard and navigation' {
    Invoke-WinSecNavigationKey 82 R
    Assert-WinSecNavigationScan ($script:state.PendingScope -ceq 'Device')
    Invoke-WinSecNavigationKey 13
    Assert-WinSecNavigationScan ($script:state.Screen -ceq 'MainMenu')
    Invoke-WinSecNavigationKey 82 R
    Assert-WinSecNavigationScan ($script:state.PendingScope -ceq 'Section' -and
        (Get-WinSecCLIScanScope $script:state).ScopeKey -ceq 'SystemSecurity')
    Invoke-WinSecNavigationKey 13
    Assert-WinSecNavigationScan ($script:state.Screen -ceq 'Section')
    Invoke-WinSecNavigationKey 82 R
    Assert-WinSecNavigationScan ($script:state.PendingScope -ceq 'Control' -and
        (Get-WinSecCLIScanScope $script:state).ScopeKey -ceq 'WSA-SYS-001' -and $script:collected.Count -eq 0)
    $script:state.PendingCommand=$null
    Invoke-WinSecNavigationKey 13
    Assert-WinSecNavigationScan ($script:state.Screen -ceq 'Section')
    Invoke-WinSecNavigationKey 70 F
    Assert-WinSecNavigationScan ($script:state.Screen -ceq 'Findings' -and $script:state.FindingsScope -ceq 'Control')
    Invoke-WinSecNavigationKey 82 R
    Assert-WinSecNavigationScan ($null -eq $script:state.PendingCommand -and $script:collected.Count -eq 0)
}
Test-WinSecScopedNavigation 'Partial scans append separate sessions and never replace the device assessment' {
    Add-WinSecNavigationKey
    $full=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context
    $deviceId=$script:state.SelectedDeviceId
    $fullJson=ConvertTo-Json -InputObject $full -Depth 20 -Compress
    Invoke-WinSecNavigationKey 13
    Add-WinSecNavigationKey
    $section=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context
    Invoke-WinSecNavigationKey 70 F
    Assert-WinSecNavigationScan ($section.ScopeType -ceq 'SECTION' -and
        (Get-WinSecCLIActiveAssessment $script:state $script:context).ScanId -ceq $section.ScanId)
    Invoke-WinSecNavigationKey 27
    Show-WinSecCLICurrentScreen -State $script:state -Context $script:context
    Assert-WinSecNavigationScan (($script:lines -join '|') -match '\[R\] Rescan Section' -and $script:collected.Count -eq 5)
    Invoke-WinSecNavigationKey 13
    Add-WinSecNavigationKey
    $control=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context
    Show-WinSecCLICurrentScreen -State $script:state -Context $script:context
    Assert-WinSecNavigationScan (($script:lines -join '|') -match '\[R\] Rescan Control' -and $script:collected.Count -eq 6)
    Invoke-WinSecNavigationKey 70 F
    Assert-WinSecNavigationScan ($control.ScopeType -ceq 'CONTROL' -and $control.ScopeKey -ceq 'WSA-SYS-001' -and
        @($control.ControlResults|Where-Object{$_.Status -cne 'NOT_SELECTED'}).Count -eq 1 -and
        (Get-WinSecCLIActiveAssessment $script:state $script:context).ScanId -ceq $control.ScanId)
    Show-WinSecCLICurrentScreen -State $script:state -Context $script:context
    Assert-WinSecNavigationScan (($script:lines -join '|') -notmatch '\[R\]' -and $script:collected.Count -eq 6)
    Invoke-WinSecNavigationKey 27
    # The controls screen presents the selected control's exact session when
    # available; this does not replace the independently stored section scan.
    Assert-WinSecNavigationScan ((Get-WinSecCLIActiveAssessment $script:state $script:context).ScanId -ceq $control.ScanId)
    $sectionView=[pscustomobject]@{Screen='Findings';FindingsScope='Section';SelectedDeviceId=$deviceId;SectionIndex=$script:state.SectionIndex;ControlIndex=0}
    Assert-WinSecNavigationScan ((Get-WinSecCLIActiveAssessment $sectionView $script:context).ScanId -ceq $section.ScanId)
    Invoke-WinSecNavigationKey 27
    $read=Get-WinSecCLIActiveAssessment $script:state $script:context
    Assert-WinSecNavigationScan ($read.ScanId -ceq $full.ScanId -and $script:context.ActiveScanByDevice[$deviceId] -ceq $full.ScanId -and
        $script:context.PublicScans.Count -eq 3 -and $script:context.ScanCoordinator.Sessions.Count -eq 3 -and
        $fullJson -ceq (ConvertTo-Json -InputObject $full -Depth 20 -Compress) -and
        (ConvertTo-Json -InputObject $script:context.PublicScans -Depth 20) -notmatch 'SCOPED-NAV-PRIVATE|"Evidence"')
}
Test-WinSecScopedNavigation 'A first section scan works without a device scan and retains an empty device dashboard' {
    Invoke-WinSecNavigationKey 13
    Add-WinSecNavigationKey
    $partial=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context
    Invoke-WinSecNavigationKey 70 F
    Assert-WinSecNavigationScan ((Get-WinSecCLIActiveAssessment $script:state $script:context).ScanId -ceq $partial.ScanId -and
        $script:context.ActiveScanByDevice.Count -eq 0)
    Invoke-WinSecNavigationKey 27
    Assert-WinSecNavigationScan ((Get-WinSecCLIActiveAssessment $script:state $script:context).ScanId -ceq '')
}
Test-WinSecScopedNavigation 'Cancellation leaves navigation caches full sessions and scope selections unchanged' {
    Invoke-WinSecNavigationKey 13
    Add-WinSecNavigationKey
    $null=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context
    $before=ConvertTo-Json -InputObject @($script:state,
        ($script:context|Select-Object * -ExcludeProperty LastScanMessage,LastDeviceMessage)) -Depth 30 -Compress
    $calls=$script:collected.Count
    Add-WinSecNavigationKey -Code 27
    $result=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context
    Assert-WinSecNavigationScan ($null -eq $result -and $calls -eq $script:collected.Count -and
        $before -ceq (ConvertTo-Json -InputObject @($script:state,
            ($script:context|Select-Object * -ExcludeProperty LastScanMessage,LastDeviceMessage)) -Depth 30 -Compress) -and
        $script:context.LastScanMessage -ceq 'Scan cancelled. Previous results were preserved.')
}
Test-WinSecScopedNavigation 'Changing control selection inside confirmation aborts before collection' {
    Invoke-WinSecNavigationKey 13;Invoke-WinSecNavigationKey 13
    $script:keys.Enqueue({$script:state.ControlIndex=1})
    $caught=$false
    try{$null=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context}catch{$caught=$true}
    Assert-WinSecNavigationScan ($caught -and $script:collected.Count -eq 0 -and
        $script:context.PublicScans.Count -eq 0 -and $script:context.ActiveScanByScope.Count -eq 0)
}
Test-WinSecScopedNavigation 'Disabled control remains unavailable and cannot run even by direct request' {
    Invoke-WinSecNavigationKey 13;Invoke-WinSecNavigationKey 13;$script:state.ControlIndex=2
    $presentation=Get-WinSecCLIScanPresentation $script:state $script:context
    $caught=$false
    try{$null=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context}catch{$caught=$true}
    Assert-WinSecNavigationScan (-not $presentation.EnableRescan -and $caught -and $script:collected.Count -eq 0)
}
foreach($size in @(@{W=120;H=45},@{W=80;H=26},@{W=40;H=20})){
    Test-WinSecScopedNavigation ('Scoped shortcuts render and navigate without audits at width '+$size.W) {
        $script:terminal=[pscustomobject]@{Width=$size.W;ContentWidth=$size.W-1;Height=$size.H}
        Invoke-WinSecNavigationKey 13
        Show-WinSecCLICurrentScreen -State $script:state -Context $script:context
        Assert-WinSecNavigationScan (($script:lines -join '|') -match '\[R\] Scan Section' -and
            $script:lines.Count -le $size.H -and @($script:lines|Where-Object{$_.Length -gt ($size.W-1)}).Count -eq 0)
        Invoke-WinSecNavigationKey 13
        Show-WinSecCLICurrentScreen -State $script:state -Context $script:context
        Assert-WinSecNavigationScan (($script:lines -join '|') -match '\[R\] Scan Control' -and
            $script:lines.Count -le $size.H -and @($script:lines|Where-Object{$_.Length -gt ($size.W-1)}).Count -eq 0 -and
            $script:collected.Count -eq 0)
    }
}
Test-WinSecScopedNavigation 'Disabled control retains contextual Rescan history without authorizing execution' {
    Invoke-WinSecNavigationKey 13;Invoke-WinSecNavigationKey 13;Add-WinSecNavigationKey
    $result=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context
    $script:disabledCheck='WSA-SYS-001'
    $presentation=Get-WinSecCLIScanPresentation $script:state $script:context
    $calls=$script:collected.Count;$caught=$false
    try{$null=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context}catch{$caught=$true}
    Assert-WinSecNavigationScan ($presentation.ScanAction -ceq 'Rescan' -and -not $presentation.EnableRescan -and
        $caught -and $script:collected.Count -eq $calls -and $script:context.ScanCoordinator.Sessions.Count -eq 1 -and
        $result.ScopeType -ceq 'CONTROL')
}
Test-WinSecScopedNavigation 'A partial session cannot masquerade as the device assessment through a forged device map' {
    Invoke-WinSecNavigationKey 13
    Add-WinSecNavigationKey
    $partial=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context
    $script:context.ActiveScanByDevice[$partial.DeviceId]=$partial.ScanId
    $caught=$false
    try{$null=Get-WinSecCLIActiveAssessment $script:state $script:context}catch{$caught=$true}
    Assert-WinSecNavigationScan $caught
}
Test-WinSecScopedNavigation 'A forged scoped selection cannot read a different scope even with a valid session ID' {
    Add-WinSecNavigationKey
    $full=Invoke-WinSecCLILocalRescan -State $script:state -Context $script:context
    Invoke-WinSecNavigationKey 13;Invoke-WinSecNavigationKey 13
    $script:context.ActiveScanByScope[(Get-WinSecCLIScopeKey $full.DeviceId SECTION SystemSecurity)]=$full.ScanId
    $caught=$false
    try{$null=Get-WinSecCLIActiveAssessment $script:state $script:context}catch{$caught=$true}
    Assert-WinSecNavigationScan $caught
}
[Console]::WriteLine('Passed: '+$script:passed)
[Console]::WriteLine('Failed: '+$script:failed)
if($script:failed -gt 0){throw "$script:failed scoped navigation integration test(s) failed."}
