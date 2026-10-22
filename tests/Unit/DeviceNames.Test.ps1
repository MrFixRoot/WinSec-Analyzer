# Identidad y nombres en memoria. Ningún hostname ni archivo real se modifica.
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1')
. (Join-Path $root 'src/UI/Screens/Devices.ps1')
. (Join-Path $root 'src/UI/Core/NavigationController.ps1')
. (Join-Path $PSScriptRoot '../Fixtures/DeviceInventoryMemoryStore.ps1')
$script:passed=0;$script:failed=0
function Assert-WinSecNames {param([bool]$Value);if(-not $Value){throw 'Device name assertion failed.'}}
function Assert-WinSecNamesReject {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecNames $caught}
function Test-WinSecNames {
    param([string]$Name,[scriptblock]$Action)
    Reset-WinSecInventoryMemoryStore
    $script:inventoryMemory.LocalId='local:hw1-'+('a'*64)
    $null=Register-WinSecLocalDevice $root
    try{$null=& $Action;Assert-WinSecNames (-not $script:inventoryMemory.LeaseHeld -and $script:inventoryMemory.UnexpectedWrites -eq 0);
        $script:passed++;Write-Host "[PASS] $Name"}catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function Set-WinSecTestName {param($Name);Set-WinSecDeviceDisplayName $root $script:inventoryMemory.LocalId $Name (Get-WinSecDeviceInventoryFingerprint $root)}
Test-WinSecNames 'First registration uses the OS name and hardware identity' {
    $inventory=Import-WinSecDeviceInventory $root
    Assert-WinSecNames ($inventory.schemaVersion -ceq '1.2.0' -and $inventory.targets[1].DisplayName -ceq 'CURRENT-FIXTURE' -and $inventory.targets.Count -eq 2)
}
Test-WinSecNames 'Alias supports spaces and accents and preserves identity permissions and other devices' {
    $before=Import-WinSecDeviceInventory $root;$old=ConvertTo-Json $before.targets[0] -Depth 8 -Compress
    $null=Set-WinSecTestName 'Equipo de recepción'
    $saved=Import-WinSecDeviceInventory $root
    Assert-WinSecNames ($saved.targets[1].DisplayName -ceq 'Equipo de recepción' -and
        $saved.targets[1].DeviceId -ceq $before.targets[1].DeviceId -and $saved.targets[1].Hostname -ceq 'CURRENT-FIXTURE' -and
        $saved.targets[1].Enabled -ceq $before.targets[1].Enabled -and $saved.targets.Count -eq 2 -and
        $old -ceq (ConvertTo-Json $saved.targets[0] -Depth 8 -Compress))
}
Test-WinSecNames 'Restart and OS rename retain the alias without duplicating hardware' {
    $null=Set-WinSecTestName 'Servidor de pruebas'
    $writes=$script:inventoryMemory.Saves;$null=Register-WinSecLocalDevice $root
    Assert-WinSecNames ($script:inventoryMemory.Saves -eq $writes)
    $script:inventoryMemory.LocalHostname='NEW-OS-NAME';$null=Register-WinSecLocalDevice $root
    $saved=Import-WinSecDeviceInventory $root
    Assert-WinSecNames ($saved.targets.Count -eq 2 -and $saved.targets[1].DisplayName -ceq 'Servidor de pruebas' -and $saved.targets[1].Hostname -ceq 'NEW-OS-NAME')
}
Test-WinSecNames 'Default first OS label also survives a later OS rename' {
    $script:inventoryMemory.LocalHostname='NEW-OS-NAME';$null=Register-WinSecLocalDevice $root
    Assert-WinSecNames ((Import-WinSecDeviceInventory $root).targets[1].DisplayName -ceq 'CURRENT-FIXTURE')
}
foreach($bad in @('', ' ', ' leading', "Bad`nName", "Bad$([char]27)", "Bad$([char]0x202e)", ('x'*254), @('Alias'), 12)){
    Test-WinSecNames 'Invalid or unsafe names reject without saving' {
        $json=$script:inventoryMemory.Json;$writes=$script:inventoryMemory.Saves
        Assert-WinSecNamesReject {Set-WinSecTestName $bad}
        Assert-WinSecNames ($json -ceq $script:inventoryMemory.Json -and $writes -eq $script:inventoryMemory.Saves)
    }
}
Test-WinSecNames 'Stale edits and failed writes preserve the previous inventory' {
    $stamp=Get-WinSecDeviceInventoryFingerprint $root;$null=Set-WinSecTestName 'Newer name'
    Assert-WinSecNamesReject {Set-WinSecDeviceDisplayName $root $script:inventoryMemory.LocalId 'Stale name' $stamp}
    $before=$script:inventoryMemory.Json;$script:inventoryMemory.FailSave=$true
    Assert-WinSecNamesReject {Set-WinSecTestName 'Failed name'}
    Assert-WinSecNames ($before -ceq $script:inventoryMemory.Json)
}
Test-WinSecNames 'Display rows use alias and separate full hardware code without trusting scores' {
    $null=Set-WinSecTestName 'Equipo de pruebas'
    $rows=@(Get-WinSecDeviceRows -Devices @((Import-WinSecDeviceInventory $root).targets))
    Assert-WinSecNames ($rows[1].Device -ceq 'Equipo de pruebas' -and $rows[1].Hostname -ceq 'CURRENT-FIXTURE' -and
        $rows[1].HardwareId -ceq ('hw1-'+('a'*64)) -and $rows[0].HardwareId -ceq 'Not recorded' -and $rows[1].Score -ceq 'NOT_SCORED')
}
Test-WinSecNames 'CLI cancellation preserves names selection and cached sessions' {
    function Show-WinSecDeviceNameEditor {param($Request);return $null}
    $state=New-WinSecNavigationState;$state.DeviceIndex=1
    $context=[pscustomobject]@{ProjectRoot=$root;Devices=@((Import-WinSecDeviceInventory $root).targets);PublicScans=@{test='unchanged'};LastDeviceMessage=''}
    $before=ConvertTo-Json @($state,$context) -Depth 12 -Compress;$json=$script:inventoryMemory.Json
    $null=Invoke-WinSecCLIDeviceRename $state $context
    Assert-WinSecNames ($json -ceq $script:inventoryMemory.Json -and $before -ceq (ConvertTo-Json @($state,$context) -Depth 12 -Compress))
}
Test-WinSecNames 'CLI approved rename preserves session keys and refreshes navigation labels' {
    function Show-WinSecDeviceNameEditor {param($Request);[pscustomobject]@{DeviceId=$Request.DeviceId;DisplayName='Mi equipo'}}
    $state=New-WinSecNavigationState;$state.DeviceIndex=1;$state.SelectedDeviceId=$script:inventoryMemory.LocalId
    $context=[pscustomobject]@{ProjectRoot=$root;Devices=@((Import-WinSecDeviceInventory $root).targets);PublicScans=@{test='unchanged'};LastDeviceMessage=''}
    $null=Invoke-WinSecCLIDeviceRename $state $context
    Assert-WinSecNames ($state.SelectedDeviceName -ceq 'Mi equipo' -and $context.Devices[1].DisplayName -ceq 'Mi equipo' -and $context.PublicScans.test -ceq 'unchanged')
}
Test-WinSecNames 'Selection changes during name confirmation abort without touching inventory' {
    $state=New-WinSecNavigationState;$state.DeviceIndex=1
    $context=[pscustomobject]@{ProjectRoot=$root;Devices=@((Import-WinSecDeviceInventory $root).targets);LastDeviceMessage=''}
    $script:nameChangingState=$state
    function Show-WinSecDeviceNameEditor {param($Request);$script:nameChangingState.DeviceIndex=0;[pscustomobject]@{DeviceId=$Request.DeviceId;DisplayName='Wrong selection'}}
    $json=$script:inventoryMemory.Json
    Assert-WinSecNamesReject {Invoke-WinSecCLIDeviceRename $state $context}
    Assert-WinSecNames ($json -ceq $script:inventoryMemory.Json)
}
Test-WinSecNames 'Display names do not merge different hardware identities' {
    $null=Set-WinSecTestName 'Fleet device'
    $null=Set-WinSecDeviceDisplayName $root 'local:OLD-FIXTURE' 'Fleet device' (Get-WinSecDeviceInventoryFingerprint $root)
    $saved=Import-WinSecDeviceInventory $root
    Assert-WinSecNames ($saved.targets.Count -eq 2 -and $saved.targets[0].DisplayName -ceq $saved.targets[1].DisplayName -and
        $saved.targets[0].DeviceId -cne $saved.targets[1].DeviceId -and $saved.targets[0].Enabled -ceq $false)
}
Test-WinSecNames 'Editor reloads a newer persisted name before requesting confirmation' {
    $state=New-WinSecNavigationState;$state.DeviceIndex=1
    $context=[pscustomobject]@{ProjectRoot=$root;Devices=@((Import-WinSecDeviceInventory $root).targets);LastDeviceMessage=''}
    $null=Set-WinSecTestName 'Changed in another instance'
    $script:previewedName=''
    function Show-WinSecDeviceNameEditor {param($Request);$script:previewedName=$Request.DisplayName;return $null}
    $json=$script:inventoryMemory.Json
    $null=Invoke-WinSecCLIDeviceRename $state $context
    Assert-WinSecNames ($script:previewedName -ceq 'Changed in another instance' -and $json -ceq $script:inventoryMemory.Json)
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if($script:failed){throw 'Device name tests failed.'}
