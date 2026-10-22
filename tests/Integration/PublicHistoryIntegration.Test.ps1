# CLI, teclado, confirmaciones, coordinador e historial reales; I/O y colectores en memoria.
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/TerminalRenderer.ps1',
    'src/UI/Core/LayoutManager.ps1','src/UI/Core/KeyboardController.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/ResizeHandler.ps1','src/UI/Components/Banner.ps1','src/UI/Components/Table.ps1','src/UI/Components/KeyboardHelp.ps1',
    'src/UI/Screens/Devices.ps1','src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1',
    'src/UI/Screens/ScanConfirmation.ps1','src/UI/Screens/ScanProgress.ps1','src/UI/Screens/DeviceName.ps1')){. (Join-Path $root $file)}
$script:catalog=Get-WinSecCheckRegistry -ProjectRoot $root
$enabled=@($script:catalog.Checks|Where-Object ExecutionEnabled)
if($enabled.Count -ne 1 -or $enabled[0].CheckId -cne 'WSA-SYS-001' -or -not $enabled[0].ExecutionReady){throw 'Only validated Defender may be enabled in production.'}
. (Join-Path $PSScriptRoot '../Fixtures/DeviceInventoryMemoryStore.ps1')
# La fixture bloquea auditorías por defecto; esta integración usa el motor real
# con Import-WinSecAuditDependencies e Invoke-WinSecAuditCheck simulados abajo.
. (Join-Path $root 'src/Core/AuditEngine.ps1')
$script:passed=0;$script:failed=0
function Assert-WinSecHistoryIntegration {param([bool]$Value);if(-not $Value){throw 'History integration assertion failed.'}}
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $registry=Copy-WinSecResultData $script:catalog
    foreach($check in $registry.Checks){if($check.CheckId -cin @('WSA-SYS-001','WSA-SYS-002','WSA-NET-001')){
        $check.ExecutionEnabled=$true;$check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'
    }}
    return $registry
}
function Import-WinSecAuditDependencies {param([switch]$SkipScoring);Assert-WinSecHistoryIntegration ([bool]$SkipScoring)}
function Invoke-WinSecAuditCheck {
    param($Check,$DeviceId,$ScanId)
    $script:collected.Add($Check.CheckId)
    New-WinSecAuditRecord -Check $Check -DeviceId $DeviceId -ScanId $ScanId -Status INFORMATIONAL -ObservedStatus INFORMATIONAL -Evidence @{Secret='PRIVATE-PERSISTENT-HISTORY'}
}
function Write-WinSecPublicHistoryArtifact {
    param($ProjectRoot,$Record)
    if($script:failHistory){throw 'PRIVATE-PERSISTENT-HISTORY'}
    $key=Get-WinSecScanSessionKey $Record.DeviceId $Record.ScanId
    if($script:stored.ContainsKey($key)){throw 'Immutable history conflict.'}
    $script:stored[$key]=Get-WinSecPublicHistoryJson (ConvertFrom-WinSecPublicHistoryRecord $Record).Record
}
function Read-WinSecPublicHistoryArtifacts {
    param($ProjectRoot,$Devices,[ref]$TotalBytes)
    if($null -ne $TotalBytes){$TotalBytes.Value=0;foreach($json in $script:stored.Values){$TotalBytes.Value+=[Text.Encoding]::UTF8.GetByteCount($json)}}
    foreach($json in $script:stored.Values){ConvertFrom-WinSecStoredJson $json}
}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
function Add-WinSecHistoryKey {
    param([int]$Code=13,[string]$Character='')
    $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$Code;Character=$Character;ControlKeyState=0;KeyDown=$true})
}
function Read-WinSecResizeAwareKey {param($ResizeState,$RenderAction);if(-not $script:keys.Count){throw 'Synthetic keyboard exhausted.'};$script:keys.Dequeue()}
function Read-WinSecPendingKey { return $null }
function New-WinSecHistoryIntegrationContext {
    $devices=@(foreach($device in (Import-WinSecDeviceInventory $root).targets){ConvertTo-WinSecRegisteredTarget $device})
    $coordinator=New-WinSecScanCoordinator
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=$devices}
    $coordinator.RequireDeviceInventory=$true;$coordinator.PublicHistoryEnabled=$true
    [pscustomobject]@{ProjectRoot=$root;Version='0.9.0';Devices=$devices;ScanCoordinator=$coordinator;PublicScans=@{};
        ActiveScanByDevice=@{};ActiveScanByScope=@{};SectionResults=@();ControlResults=@();Findings=@();ScanId='';LastScanMessage='';LastDeviceMessage=''}
}
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1'),[ref]$tokens,[ref]$errors)
$branches=@($ast.FindAll({param($node);$node -is [System.Management.Automation.Language.IfStatementAst] -and
    $node.Clauses[0].Item1.Extent.Text -ceq '$navigationState.PendingCommand -eq ''Rescan'''},$true))
if($errors.Count -or $branches.Count -ne 1){throw 'Expected one real rescan handler.'}
$script:handler=[scriptblock]::Create($branches[0].Extent.Text)
function Invoke-WinSecHistoryIntegrationScan {
    param([int]$Confirm=13,[string]$Character='')
    $event=[pscustomobject]@{VirtualKeyCode=82;Character='R';ControlKeyState=0;KeyDown=$true}
    $eligible=Test-WinSecCLIRescanEligibility $script:state $script:context.Devices $script:context.ScanCoordinator
    $action=ConvertTo-WinSecKeyboardAction -KeyInfo $event -Screen $script:state.Screen -EnableRescan:$eligible
    $null=Invoke-WinSecNavigationAction -State $script:state -Action $action -Devices $script:context.Devices -SectionCount 5 -ControlCount 3
    Add-WinSecHistoryKey $Confirm $Character
    $navigationState=$script:state;$context=$script:context
    & $script:handler
}
function Test-WinSecHistoryIntegration {
    param([string]$Name,[scriptblock]$Action)
    Reset-WinSecInventoryMemoryStore;$script:inventoryMemory.LocalId='local:hw1-'+('b'*64)
    $null=Register-WinSecLocalDevice $root
    $script:stored=@{};$script:failHistory=$false;$script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    $script:collected=New-Object 'System.Collections.Generic.List[string]';$script:lines=New-Object 'System.Collections.Generic.List[string]'
    $script:fragment=New-Object Text.StringBuilder;$script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=45}
    $script:context=New-WinSecHistoryIntegrationContext
    Restore-WinSecPublicHistory $script:context
    $script:state=New-WinSecNavigationState;$script:state.DeviceIndex=1
    try{$null=& $Action;Assert-WinSecHistoryIntegration ($script:inventoryMemory.UnexpectedWrites -eq 0 -and -not $script:inventoryMemory.LeaseHeld);
        $script:passed++;[Console]::WriteLine('[PASS] '+$Name)}catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
Test-WinSecHistoryIntegration 'First start and empty history do not audit or claim a previous scan' {
    Show-WinSecCLICurrentScreen $script:state $script:context
    Assert-WinSecHistoryIntegration ($script:context.HistoryReady -and $script:context.PublicScans.Count -eq 0 -and
        $script:collected.Count -eq 0 -and $script:stored.Count -eq 0 -and ($script:lines -join '|') -match 'No saved scan')
}
Test-WinSecHistoryIntegration 'F2 changes the label with Enter confirmation and a restart preserves it' {
    $event=[pscustomobject]@{VirtualKeyCode=113;Character='';ControlKeyState=0;KeyDown=$true}
    $action=ConvertTo-WinSecKeyboardAction -KeyInfo $event -Screen Devices
    $null=Invoke-WinSecNavigationAction $script:state $action -Devices $script:context.Devices
    Assert-WinSecHistoryIntegration ($script:state.PendingCommand -ceq 'RenameDevice')
    foreach($character in 'Laboratorio'.ToCharArray()){Add-WinSecHistoryKey 0 ([string]$character)}
    Add-WinSecHistoryKey;Add-WinSecHistoryKey
    $null=Invoke-WinSecCLIDeviceRename $script:state $script:context
    $restart=New-WinSecHistoryIntegrationContext;Restore-WinSecPublicHistory $restart
    Assert-WinSecHistoryIntegration ($restart.Devices.Count -eq 2 -and $restart.Devices[1].DisplayName -ceq 'Laboratorio' -and
        $restart.Devices[1].DeviceId -ceq $script:inventoryMemory.LocalId -and $script:collected.Count -eq 0 -and $script:stored.Count -eq 0)
}
foreach($cancel in @(@{Code=27;Char=''},@{Code=78;Char='N'})){
    Test-WinSecHistoryIntegration 'Name cancellation preserves the inventory and never scans' {
        foreach($character in 'Cancelado'.ToCharArray()){Add-WinSecHistoryKey 0 ([string]$character)}
        Add-WinSecHistoryKey;Add-WinSecHistoryKey $cancel.Code $cancel.Char
        $before=$script:inventoryMemory.Json
        $null=Invoke-WinSecCLIDeviceRename $script:state $script:context
        Assert-WinSecHistoryIntegration ($script:inventoryMemory.Json -ceq $before -and $script:collected.Count -eq 0)
    }
}
Test-WinSecHistoryIntegration 'Confirmed device section and control scans persist separately and survive restart' {
    Invoke-WinSecHistoryIntegrationScan
    Assert-WinSecHistoryIntegration ($script:stored.Count -eq 1 -and $script:context.ScanCoordinator.Sessions.Count -eq 1 -and $script:state.PendingCommand -eq $null)
    $device=$script:inventoryMemory.LocalId;$full=$script:context.ActiveScanByDevice[$device]
    $script:state.Screen='MainMenu';$script:state.SelectedDeviceId=$device
    Invoke-WinSecHistoryIntegrationScan
    $script:state.Screen='Section'
    Invoke-WinSecHistoryIntegrationScan
    $old=($script:stored.Values|Sort-Object)-join '|'
    $alias=Set-WinSecDeviceDisplayName $root $device 'Nuevo nombre' (Get-WinSecDeviceInventoryFingerprint $root)
    $restart=New-WinSecHistoryIntegrationContext;Restore-WinSecPublicHistory $restart
    Assert-WinSecHistoryIntegration ($restart.PublicScans.Count -eq 3 -and $restart.ActiveScanByDevice[$device] -ceq $full -and
        $restart.ActiveScanByScope.Count -eq 3 -and $restart.Devices[1].DisplayName -ceq $alias.DisplayName -and
        $old -ceq (($script:stored.Values|Sort-Object)-join '|') -and $old -notmatch 'PRIVATE-PERSISTENT-HISTORY|"Evidence"')
    foreach($spec in @(@('DEVICE','ALL'),@('SECTION','SystemSecurity'),@('CONTROL','WSA-SYS-001'))){
        Assert-WinSecHistoryIntegration ((Get-WinSecScanAction $restart.ScanCoordinator $device $spec[0] $spec[1]) -ceq 'Rescan')
    }
}
Test-WinSecHistoryIntegration 'Cancelled scan preserves persistent and active results without collection' {
    Invoke-WinSecHistoryIntegrationScan
    $before=ConvertTo-Json $script:context -Depth 40 -Compress;$calls=$script:collected.Count
    Invoke-WinSecHistoryIntegrationScan -Confirm 78 -Character N
    Assert-WinSecHistoryIntegration ($script:stored.Count -eq 1 -and $calls -eq $script:collected.Count -and
        $before -ceq (ConvertTo-Json $script:context -Depth 40 -Compress))
}
Test-WinSecHistoryIntegration 'Storage failure does not publish a new session or leak diagnostics' {
    Invoke-WinSecHistoryIntegrationScan;$script:failHistory=$true
    $scans=$script:context.PublicScans.Count
    Invoke-WinSecHistoryIntegrationScan
    Assert-WinSecHistoryIntegration ($script:stored.Count -eq 1 -and $script:context.PublicScans.Count -eq $scans -and
        $script:context.ScanCoordinator.Sessions.Count -eq 1 -and $script:context.LastScanMessage -match 'failed or was rejected' -and
        $script:context.LastScanMessage -notmatch 'PRIVATE-PERSISTENT-HISTORY' -and $null -eq $script:state.PendingCommand)
}
Test-WinSecHistoryIntegration 'Corrupt history aborts loading and blocks collection before confirmation' {
    $script:stored.bad='{"SchemaVersion":"unknown"}'
    $restart=New-WinSecHistoryIntegrationContext;$caught=$false
    try{Restore-WinSecPublicHistory $restart}catch{$caught=$true;$restart.ScanCoordinator.HistoryLoadFailed=$true}
    Assert-WinSecHistoryIntegration ($caught -and $restart.PublicScans.Count -eq 0 -and
        -not (Test-WinSecCLIRescanEligibility $script:state $restart.Devices $restart.ScanCoordinator))
    $caught=$false;try{Invoke-WinSecCoordinatedScan -Coordinator $restart.ScanCoordinator -DeviceId $script:inventoryMemory.LocalId -ConfirmAction {throw 'Unexpected confirmation'}}catch{$caught=$true}
    Assert-WinSecHistoryIntegration ($caught -and $script:collected.Count -eq 0 -and $restart.ScanCoordinator.Sessions.Count -eq 0)
}
foreach($size in @(@{W=120;H=45},@{W=80;H=26},@{W=40;H=22})){
    Test-WinSecHistoryIntegration ('Device names hardware code and history fit terminal '+$size.W) {
        Invoke-WinSecHistoryIntegrationScan
        Assert-WinSecHistoryIntegration ($script:stored.Count -eq 1 -and $script:collected.Count -gt 0)
        $script:terminal=[pscustomobject]@{Width=$size.W;ContentWidth=$size.W-1;Height=$size.H}
        $calls=$script:collected.Count
        Show-WinSecCLICurrentScreen $script:state $script:context
        Assert-WinSecHistoryIntegration ($script:lines.Count -le $size.H -and @($script:lines|Where-Object{$_.Length -gt ($size.W-1)}).Count -eq 0 -and
            $calls -eq $script:collected.Count -and ($script:lines -join '|') -notmatch 'PRIVATE-PERSISTENT-HISTORY|\d+/100')
        if($size.W -ge 120){Assert-WinSecHistoryIntegration (($script:lines -join '|') -match 'Hardware ID')}
    }
}
Test-WinSecHistoryIntegration 'A history mode changed during confirmation aborts before collection' {
    $caught=$false
    try{Invoke-WinSecCoordinatedScan -Coordinator $script:context.ScanCoordinator -DeviceId $script:inventoryMemory.LocalId -ConfirmAction {
        param($Request);$script:context.ScanCoordinator.PublicHistoryEnabled=$false;return $true
    }}catch{$caught=$true}
    Assert-WinSecHistoryIntegration ($caught -and $script:collected.Count -eq 0 -and $script:stored.Count -eq 0 -and $script:context.ScanCoordinator.Sessions.Count -eq 0)
}
Test-WinSecHistoryIntegration 'String coordination flags cannot enable persistence or authorize an operation' {
    $script:context.ScanCoordinator.PublicHistoryEnabled='True';$caught=$false
    try{Invoke-WinSecCoordinatedScan -Coordinator $script:context.ScanCoordinator -DeviceId $script:inventoryMemory.LocalId -ConfirmAction {$true}}catch{$caught=$true}
    Assert-WinSecHistoryIntegration ($caught -and $script:collected.Count -eq 0 -and $script:stored.Count -eq 0)
}
[Console]::WriteLine('Passed: '+$script:passed+'; Failed: '+$script:failed)
if($script:failed){throw 'Public history integration tests failed.'}
