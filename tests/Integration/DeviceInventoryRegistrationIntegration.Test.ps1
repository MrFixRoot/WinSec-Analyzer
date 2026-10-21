# Multiple simulated starts/devices through real registration, import and CLI.
# The shared fixture replaces physical reads, leases and atomic commit only.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/TargetRegistry.ps1')
. (Join-Path $root 'src/Core/DeviceInventory.ps1')
. (Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1')
. (Join-Path $PSScriptRoot '../Fixtures/DeviceInventoryMemoryStore.ps1')
$script:passed = 0
$script:failed = 0

function Assert-WinSecRegistrationIntegration {
    param([bool]$Condition)
    if (-not $Condition) { throw 'Registration integration assertion failed.' }
}
function Test-WinSecRegistrationIntegrationCase {
    param([string]$Name, [scriptblock]$Action)
    Reset-WinSecInventoryMemoryStore -Json '{"schemaVersion":"1.0.0","targets":[]}' -Exists $false
    try {
        $null = & $Action
        Assert-WinSecRegistrationIntegration (-not $script:inventoryMemory.LeaseHeld -and
            $script:inventoryMemory.Audits -eq 0 -and $script:inventoryMemory.UnexpectedWrites -eq 0)
        Assert-WinSecRegistrationIntegration (-not [IO.Directory]::Exists($script:inventoryMemoryRoot))
        $script:passed++; Write-Host "[PASS] $Name"
    }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}
function Get-WinSecRegistrationFixtureDevices {
    $inventory = Import-WinSecDeviceInventory -ProjectRoot $root
    return Get-WinSecCLIDevices -ProjectRoot $root -Devices $inventory.targets
}

Test-WinSecRegistrationIntegrationCase 'First start and restart retain one unscored CLI device' {
    $first = Register-WinSecLocalDevice -ProjectRoot $root
    $beforeRestart = $script:inventoryMemory.Json
    $restart = Register-WinSecLocalDevice -ProjectRoot $root
    $devices = @(Get-WinSecRegistrationFixtureDevices)
    Assert-WinSecRegistrationIntegration ($first.Created -ceq $true -and $restart.Created -ceq $false -and
        $devices.Count -eq 1 -and $script:inventoryMemory.Json -ceq $beforeRestart -and $script:inventoryMemory.Saves -eq 1)
    Assert-WinSecRegistrationIntegration ($null -eq $devices[0].Score -and $devices[0].Status -ceq 'PENDING' -and
        [string]::IsNullOrEmpty($devices[0].ScanId))
}
Test-WinSecRegistrationIntegrationCase 'A different local device appends without replacing previous inventory' {
    $first = Register-WinSecLocalDevice -ProjectRoot $root
    $firstMetadata = ConvertTo-Json -InputObject (Import-WinSecDeviceInventory -ProjectRoot $root).targets[0] -Depth 8 -Compress
    $script:inventoryMemory.LocalId = 'local:SECOND-FIXTURE'
    $script:inventoryMemory.LocalHostname = 'SECOND-FIXTURE'
    $second = Register-WinSecLocalDevice -ProjectRoot $root
    $saved = Import-WinSecDeviceInventory -ProjectRoot $root
    $devices = @(Get-WinSecRegistrationFixtureDevices)
    Assert-WinSecRegistrationIntegration ($second.Created -ceq $true -and $saved.targets.Count -eq 2 -and $devices.Count -eq 2)
    Assert-WinSecRegistrationIntegration ((ConvertTo-Json -InputObject $saved.targets[0] -Depth 8 -Compress) -ceq $firstMetadata)
    Assert-WinSecRegistrationIntegration ($devices[0].DeviceId -cne $devices[1].DeviceId)
}
Test-WinSecRegistrationIntegrationCase 'Returning to the first device does not duplicate either device' {
    $null = Register-WinSecLocalDevice -ProjectRoot $root
    $script:inventoryMemory.LocalId = 'local:SECOND-FIXTURE'
    $script:inventoryMemory.LocalHostname = 'SECOND-FIXTURE'
    $null = Register-WinSecLocalDevice -ProjectRoot $root
    $script:inventoryMemory.LocalId = 'local:CURRENT-FIXTURE'
    $script:inventoryMemory.LocalHostname = 'CURRENT-FIXTURE'
    $returned = Register-WinSecLocalDevice -ProjectRoot $root
    Assert-WinSecRegistrationIntegration ($returned.Created -ceq $false -and
        @(Get-WinSecRegistrationFixtureDevices).Count -eq 2 -and $script:inventoryMemory.Saves -eq 2)
}
Test-WinSecRegistrationIntegrationCase 'Registration alone does not populate scans or findings in the CLI' {
    $null = Register-WinSecLocalDevice -ProjectRoot $root
    $devices = @(Get-WinSecRegistrationFixtureDevices)
    $state = [pscustomobject]@{Screen='MainMenu'; SelectedDeviceId=$devices[0].DeviceId}
    $context = [pscustomobject]@{Devices=$devices; PublicScans=@{}; ActiveScanByDevice=@{}}
    $assessment = Get-WinSecCLIActiveAssessment -State $state -Context $context
    Assert-WinSecRegistrationIntegration ($assessment.OverallStatus -ceq 'PENDING' -and $null -eq $assessment.OverallScore -and
        @($assessment.ControlResults).Count -eq 0 -and @($assessment.Findings).Count -eq 0 -and
        $context.PublicScans.Count -eq 0 -and $context.ActiveScanByDevice.Count -eq 0)
}
Test-WinSecRegistrationIntegrationCase 'A failed append leaves the first device available without fake success' {
    $null = Register-WinSecLocalDevice -ProjectRoot $root
    $before = $script:inventoryMemory.Json
    $script:inventoryMemory.LocalId = 'local:SECOND-FIXTURE'
    $script:inventoryMemory.LocalHostname = 'SECOND-FIXTURE'
    $script:inventoryMemory.FailSave = $true
    $published = $null
    $caught = $false
    try { $published = Register-WinSecLocalDevice -ProjectRoot $root } catch { $caught = $true }
    $devices = @(Get-WinSecRegistrationFixtureDevices)
    Assert-WinSecRegistrationIntegration ($caught -and $null -eq $published -and $devices.Count -eq 1 -and
        $devices[0].DeviceId -ceq 'local:CURRENT-FIXTURE' -and $script:inventoryMemory.Json -ceq $before)
}
Test-WinSecRegistrationIntegrationCase 'Existing disabled devices keep their saved state after another append' {
    Reset-WinSecInventoryMemoryStore
    $null = Register-WinSecLocalDevice -ProjectRoot $root
    $devices = @(Get-WinSecRegistrationFixtureDevices)
    $old = @($devices | Where-Object { $_.DeviceId -ceq 'local:OLD-FIXTURE' })
    Assert-WinSecRegistrationIntegration ($old.Count -eq 1 -and $old[0].Enabled -ceq $false -and
        $null -eq $old[0].Score -and [string]::IsNullOrEmpty($old[0].ScanId))
}

Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if ($script:failed -gt 0) { throw "$script:failed registration integration test(s) failed." }
