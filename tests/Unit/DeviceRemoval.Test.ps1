# In-memory inventory and synthetic sessions; no physical deletion or audit.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Services/DeviceManagementService.ps1')
. (Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1')
. (Join-Path $root 'src/UI/Core/NavigationController.ps1')
. (Join-Path $root 'src/UI/Core/KeyboardController.ps1')
. (Join-Path $root 'src/UI/Screens/DeviceRemovalConfirmation.ps1')
$script:realDialog=(Get-Command Show-WinSecDeviceRemovalConfirmation).ScriptBlock
. (Join-Path $PSScriptRoot '../Fixtures/DeviceInventoryMemoryStore.ps1')
$script:passed=0; $script:failed=0
function Assert-WinSecRemoval { param([bool]$Condition) if (-not $Condition) { throw 'Removal assertion failed.' } }
function Test-WinSecRemovalCase {
    param([string]$Name,[scriptblock]$Action)
    Reset-WinSecInventoryMemoryStore
    $null=Register-WinSecLocalDevice -ProjectRoot $root
    $script:devices=@((Import-WinSecDeviceInventory -ProjectRoot $root).targets)
    $script:coordinator=New-WinSecScanCoordinator -ProjectRoot $root
    foreach ($device in $script:devices) {
        $id=$device.DeviceId; $key=Get-WinSecScanSessionKey $id 'scan-1'
        $script:coordinator.Sessions[$key]=[pscustomobject]@{DeviceId=$id; ScanId='scan-1'}
    }
    $script:dialogAnswer=$true
    $script:dialogAction=$null
    try {
        $null=& $Action
        Assert-WinSecRemoval (-not $script:inventoryMemory.LeaseHeld -and $script:inventoryMemory.UnexpectedWrites -eq 0 -and
            $script:inventoryMemory.Audits -eq 0 -and -not [IO.Directory]::Exists($script:inventoryMemoryRoot))
        $script:passed++; Write-Host "[PASS] $Name"
    }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}
function Invoke-WinSecRemovalFixture {
    param([scriptblock]$Confirm={ $true },[string]$DeviceId='local:OLD-FIXTURE')
    Remove-WinSecManagedDevice -ProjectRoot $root -DeviceId $DeviceId -Coordinator $script:coordinator -Devices $script:devices -ConfirmAction $Confirm
}
function Assert-WinSecRemovalThrows {
    param([scriptblock]$Action)
    $caught=$false
    try { $null=& $Action } catch { $caught=$true }
    Assert-WinSecRemoval $caught
}
Test-WinSecRemovalCase 'No confirmation handler rejects before mutation' {
    $before=$script:inventoryMemory.Json
    Assert-WinSecRemovalThrows { Remove-WinSecManagedDevice -ProjectRoot $root -DeviceId 'local:OLD-FIXTURE' -Coordinator $script:coordinator -Devices $script:devices }
    Assert-WinSecRemoval ($script:inventoryMemory.Json -ceq $before -and $script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'Cancellation preserves inventory sessions and write count' {
    $before=$script:inventoryMemory.Json; $writes=$script:inventoryMemory.Saves
    $result=Invoke-WinSecRemovalFixture -Confirm { $false }
    Assert-WinSecRemoval ($null -eq $result -and $script:inventoryMemory.Json -ceq $before -and
        $script:inventoryMemory.Saves -eq $writes -and $script:coordinator.Sessions.Count -eq 2)
}
foreach ($handler in @({ }, { 'yes' }, { $true; $true }, { throw 'PRIVATE-REMOVAL-DETAIL' })) {
    Test-WinSecRemovalCase 'Missing ambiguous or failed consent cannot delete' {
        $before=$script:inventoryMemory.Json
        Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -Confirm $handler }
        Assert-WinSecRemoval ($script:inventoryMemory.Json -ceq $before -and $script:coordinator.Sessions.Count -eq 2)
    }
}
Test-WinSecRemovalCase 'Preview includes the exact device history count and re-registration behavior' {
    $null=Invoke-WinSecRemovalFixture -Confirm {
        param($request)
        Assert-WinSecRemoval ($request.Operation -ceq 'DELETE_DEVICE' -and $request.DeviceId -ceq 'local:OLD-FIXTURE' -and
            $request.MemoryScanCount -eq 1 -and $request.StoredFileCount -eq 0 -and -not $request.RegistersAgainOnStartup)
        return $false
    }
}
Test-WinSecRemovalCase 'Confirmed deletion preserves other device metadata and sessions' {
    $before=ConvertTo-Json -InputObject $script:devices[1] -Depth 8 -Compress
    $result=Invoke-WinSecRemovalFixture
    $saved=Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecRemoval ($result.Status -ceq 'REMOVED' -and $saved.schemaVersion -ceq '1.1.0' -and $saved.targets.Count -eq 1 -and
        (ConvertTo-Json -InputObject $saved.targets[0] -Depth 8 -Compress) -ceq $before -and $script:coordinator.Sessions.Count -eq 1)
    Assert-WinSecRemoval (Test-WinSecDeviceInventoryRemoval $saved 'local:old-fixture')
}
Test-WinSecRemovalCase 'The current device re-registers empty without reviving other removed devices' {
    $null=Invoke-WinSecRemovalFixture
    $script:devices=@((Import-WinSecDeviceInventory -ProjectRoot $root).targets)
    $null=Invoke-WinSecRemovalFixture -DeviceId 'local:CURRENT-FIXTURE'
    $registered=Register-WinSecLocalDevice -ProjectRoot $root
    $saved=Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecRemoval ($registered.Created -and $saved.targets.Count -eq 1 -and $script:coordinator.Sessions.Count -eq 0 -and
        -not (Test-WinSecDeviceInventoryRemoval $saved 'local:CURRENT-FIXTURE') -and (Test-WinSecDeviceInventoryRemoval $saved 'local:OLD-FIXTURE'))
}
Test-WinSecRemovalCase 'Changed confirmation previews reject without deleting' {
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -Confirm { param($r) $r.DeviceId='local:OTHER'; $true } }
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'New sessions during confirmation require a fresh confirmation' {
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -Confirm {
        $script:coordinator.Sessions['local:OLD-FIXTURE|scan-2']=[pscustomobject]@{DeviceId='local:OLD-FIXTURE'; ScanId='scan-2'}
        $true
    } }
    Assert-WinSecRemoval ((Import-WinSecDeviceInventory -ProjectRoot $root).targets.Count -eq 2)
}
Test-WinSecRemovalCase 'Inventory mutation during confirmation cannot reuse consent' {
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -Confirm {
        $changed=ConvertFrom-WinSecDeviceInventoryJson $script:inventoryMemory.Json
        $changed.targets[0].Hostname='CHANGED-FIXTURE'
        $script:inventoryMemory.Json=ConvertTo-Json -InputObject $changed -Depth 8
        $true
    } }
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'Busy storage cannot delete or drop sessions' {
    $script:inventoryMemory.Busy=$true
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture }
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'A failed commit reports incomplete and retains a row for a confirmed retry' {
    $script:inventoryMemory.FailSave=$true
    $result=Invoke-WinSecRemovalFixture
    Assert-WinSecRemoval ($result.Status -ceq 'INCOMPLETE' -and $script:coordinator.Sessions.Count -eq 1 -and
        (Import-WinSecDeviceInventory -ProjectRoot $root).targets.Count -eq 2)
    $script:inventoryMemory.FailSave=$false
    Assert-WinSecRemoval ((Invoke-WinSecRemovalFixture).Status -ceq 'REMOVED')
}
Test-WinSecRemovalCase 'Traversal and unknown identifiers cannot delete' {
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -DeviceId '../other' }
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -DeviceId 'local:NOT-REGISTERED' }
}
Test-WinSecRemovalCase 'Inconsistent session ownership fails closed' {
    $script:coordinator.Sessions['local:OLD-FIXTURE|scan-1'].DeviceId='local:OTHER'
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture }
}
Test-WinSecRemovalCase 'A foreign session payload cannot be deleted under another device key' {
    $script:coordinator.Sessions['local:OLD-FIXTURE|scan-1'] | Add-Member -NotePropertyName Session -NotePropertyValue (
        [pscustomobject]@{DeviceId='local:OTHER'; ScanId='scan-1'})
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture }
    Assert-WinSecRemoval ((Import-WinSecDeviceInventory $root).targets.Count -eq 2)
}
Test-WinSecRemovalCase 'An explicit configured device can be removed without editing its catalog' {
    $script:devices+= [pscustomobject]@{DeviceId='remote:CONFIG-FIXTURE'; Hostname='CONFIG-FIXTURE'; Mode='REMOTE'; Enabled=$false}
    $result=Invoke-WinSecRemovalFixture -DeviceId 'remote:CONFIG-FIXTURE'
    Assert-WinSecRemoval ($result.Status -ceq 'REMOVED' -and
        (Test-WinSecDeviceInventoryRemoval (Import-WinSecDeviceInventory -ProjectRoot $root) 'remote:CONFIG-FIXTURE'))
}
Test-WinSecRemovalCase 'Removal metadata rejects duplicate hashes invalid types and active/removed conflicts' {
    $hash=Get-WinSecDeviceInventoryIdentityHash 'local:OLD-FIXTURE'
    foreach ($doc in @(
        [pscustomobject]@{schemaVersion='1.1.0'; targets=@(); removedDeviceHashes=@($hash,$hash)},
        [pscustomobject]@{schemaVersion='1.1.0'; targets=@(); removedDeviceHashes=@('invalid')},
        [pscustomobject]@{schemaVersion='1.1.0'; targets=@(); removedDeviceHashes=$hash},
        [pscustomobject]@{schemaVersion='1.1.0'; targets=@($script:devices[0]); removedDeviceHashes=@($hash)}
    )) { Assert-WinSecRemovalThrows { ConvertFrom-WinSecDeviceInventoryJson (ConvertTo-Json -InputObject $doc -Depth 8) } }
}
Test-WinSecRemovalCase 'Delete/Supr only requests deletion from a nonempty Devices screen' {
    $key=[pscustomobject]@{KeyDown=$true; Character=[char]0; VirtualKeyCode=46; ControlKeyState=0}
    Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $key -Screen Devices).Action -ceq 'DeleteDevice')
    Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $key -Screen MainMenu).Action -ceq 'None')
    foreach ($modifier in @(1,2,4,8)) {
        $key.ControlKeyState=$modifier
        Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $key -Screen Devices).Action -ceq 'None')
    }
    $key.ControlKeyState=0; $key.KeyDown=$false
    Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $key -Screen Devices).Action -ceq 'None')
    $letter=[pscustomobject]@{KeyDown=$true; Character='D'; VirtualKeyCode=68; ControlKeyState=0}
    Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $letter -Screen Devices).Action -ceq 'None')
    $letter.Character='d'
    Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $letter -Screen Devices).Action -ceq 'None')
    $state=New-WinSecNavigationState
    $null=Invoke-WinSecNavigationAction -State $state -Action DeleteDevice -Devices @()
    Assert-WinSecRemoval ($null -eq $state.PendingCommand)
    $null=Invoke-WinSecNavigationAction -State $state -Action DeleteDevice -Devices $script:devices
    Assert-WinSecRemoval ($state.PendingCommand -ceq 'DeleteDevice' -and $script:coordinator.Sessions.Count -eq 2)
}
function Show-WinSecDeviceRemovalConfirmation {
    param($Request)
    if ($null -ne $script:dialogAction) { return (& $script:dialogAction) }
    return $script:dialogAnswer
}
function New-WinSecRemovalCLIContext {
    $context=[pscustomobject]@{ProjectRoot=$root; Devices=$script:devices; ScanCoordinator=$script:coordinator;
        PublicScans=@{}; ActiveScanByDevice=@{}; SectionResults=@(); ControlResults=@(); Findings=@(); ScanId='scan-1'; LastDeviceMessage=''}
    foreach ($device in $script:devices) {
        $id=$device.DeviceId
        $context.PublicScans[(Get-WinSecScanSessionKey $id 'scan-1')]=[pscustomobject]@{DeviceId=$id; ScanId='scan-1'}
        $context.ActiveScanByDevice[$id]='scan-1'
        $context.Findings+= [pscustomobject]@{DeviceId=$id; ScanId='scan-1'; FindingId='synthetic'}
    }
    return $context
}
Test-WinSecRemovalCase 'CLI cancellation preserves row navigation public scans and findings' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $before=ConvertTo-Json -InputObject $context -Depth 15 -Compress
    $script:dialogAnswer=$false
    $result=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    Assert-WinSecRemoval ($null -eq $result -and $before -ceq (ConvertTo-Json -InputObject $context -Depth 15 -Compress) -and
        $state.DeviceIndex -eq 0 -and $state.History.Count -eq 0)
}
Test-WinSecRemovalCase 'CLI removes only selected rows maps findings and navigation references' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $null=$state.History.Add([pscustomobject]@{SelectedDeviceId='local:OLD-FIXTURE'})
    $result=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    Assert-WinSecRemoval ($result.Status -ceq 'REMOVED' -and $context.Devices.Count -eq 1 -and
        $context.Devices[0].DeviceId -ceq 'local:CURRENT-FIXTURE' -and $context.PublicScans.Count -eq 1 -and
        $context.ActiveScanByDevice.Count -eq 1 -and $context.Findings.Count -eq 1 -and
        $context.Findings[0].DeviceId -ceq 'local:CURRENT-FIXTURE' -and $context.ScanId -ceq 'scan-1' -and $state.History.Count -eq 0)
}
Test-WinSecRemovalCase 'Deleting the last row leaves an empty Devices screen without registering implicitly' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $null=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    $null=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    Assert-WinSecRemoval ($context.Devices.Count -eq 0 -and $context.PublicScans.Count -eq 0 -and
        $context.ActiveScanByDevice.Count -eq 0 -and $context.ScanId -ceq '' -and $state.DeviceIndex -eq 0 -and
        $null -eq $state.SelectedDeviceId -and (Import-WinSecDeviceInventory -ProjectRoot $root).targets.Count -eq 0)
}
Test-WinSecRemovalCase 'CLI rejects ambiguous legacy data and corrupt public ownership before confirmation' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $context.Findings=@([pscustomobject]@{FindingId='unowned'})
    Assert-WinSecRemovalThrows { Invoke-WinSecCLIDeviceRemoval -State $state -Context $context }
    $context=New-WinSecRemovalCLIContext
    $context.PublicScans['local:OLD-FIXTURE|scan-1'].DeviceId='local:OTHER'
    Assert-WinSecRemovalThrows { Invoke-WinSecCLIDeviceRemoval -State $state -Context $context }
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'CLI incomplete deletion keeps the row but invalidates the selected cached results' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $script:inventoryMemory.FailSave=$true
    $result=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    Assert-WinSecRemoval ($result.Status -ceq 'INCOMPLETE' -and $context.Devices.Count -eq 2 -and $context.PublicScans.Count -eq 1 -and
        $context.LastDeviceMessage -match 'incomplete' -and $context.ActiveScanByDevice.Count -eq 1)
}
Test-WinSecRemovalCase 'A changing public view invalidates CLI consent before any deletion' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $script:changingContext=$context
    $script:dialogAction={
        $script:changingContext.PublicScans['local:OLD-FIXTURE|scan-2']=[pscustomobject]@{DeviceId='local:OLD-FIXTURE'; ScanId='scan-2'}
        return $true
    }
    Assert-WinSecRemovalThrows { Invoke-WinSecCLIDeviceRemoval -State $state -Context $context }
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2 -and (Import-WinSecDeviceInventory $root).targets.Count -eq 2)
}
Test-WinSecRemovalCase 'A hash table key named Keys cannot hide inconsistent session ownership' {
    $script:coordinator.Sessions['Keys']=@()
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture }
    $script:coordinator.Sessions.Remove('Keys')
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $context.PublicScans['Keys']=@()
    Assert-WinSecRemovalThrows { Invoke-WinSecCLIDeviceRemoval -State $state -Context $context }
    Assert-WinSecRemoval ((Import-WinSecDeviceInventory $root).targets.Count -eq 2 -and $script:coordinator.Sessions.Count -eq 2)
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if ($script:failed -gt 0) { throw 'Device removal unit tests failed.' }
