# Real inventory decoder, registry and CLI with storage reads simulated in memory.
# No files/directories are created; registration tests can only reuse records.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/TargetRegistry.ps1')
. (Join-Path $root 'src/Core/DeviceInventory.ps1')
. (Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1')
$script:virtualRoot = Join-Path ([IO.Path]::GetTempPath()) ('WinSec-NoStorage-' + [guid]::NewGuid().ToString('N'))
$script:virtualPath = Join-Path $script:virtualRoot 'data/devices.json'
if ([IO.Directory]::Exists($script:virtualRoot)) { throw 'The in-memory fixture must have no storage directory.' }
$script:passed = 0
$script:failed = 0

function Get-WinSecDeviceInventoryPath { param($ProjectRoot) return $script:virtualPath }
function Test-Path {
    [CmdletBinding()]
    param($LiteralPath, $Path, $PathType)
    if ($LiteralPath -ceq $script:virtualPath) { return $script:inventoryExists }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
function Get-Item {
    [CmdletBinding()]
    param($LiteralPath, [switch]$Force)
    if ($LiteralPath -ceq $script:virtualPath) {
        $length = [Text.Encoding]::UTF8.GetByteCount($script:inventoryJson)
        if ($null -ne $script:lengthOverride) { $length = $script:lengthOverride }
        return [pscustomobject]@{Length=$length}
    }
    Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
}
function Get-Content {
    [CmdletBinding()]
    param($LiteralPath, [switch]$Raw, $Encoding)
    if ($LiteralPath -ceq $script:virtualPath) { $script:readCalls++; return $script:inventoryJson }
    Microsoft.PowerShell.Management\Get-Content @PSBoundParameters
}
function New-Item { $script:writeCalls++; throw 'Unexpected fixture write.' }
function Set-Content { $script:writeCalls++; throw 'Unexpected fixture write.' }
function Add-Content { $script:writeCalls++; throw 'Unexpected fixture write.' }
function Out-File { $script:writeCalls++; throw 'Unexpected fixture write.' }
function Remove-Item { $script:writeCalls++; throw 'Unexpected fixture write.' }
function Invoke-WinSecAudit { $script:auditCalls++; throw 'Unexpected audit.' }

function Assert-WinSecInventoryIntegration {
    param([bool]$Condition)
    if (-not $Condition) { throw 'Inventory integration assertion failed.' }
}
function Test-WinSecInventoryIntegrationCase {
    param([string]$Name, [scriptblock]$Action)
    $script:inventoryExists = $true
    $script:inventoryJson = '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:CURRENT-FIXTURE","Hostname":"CURRENT-FIXTURE","Mode":"LOCAL","Enabled":false,"Description":"Synthetic device","RegisteredAtUtc":"2026-10-20T12:34:56Z"},{"DeviceId":"local:OLD-FIXTURE","Hostname":"OLD-FIXTURE","Mode":"LOCAL","Enabled":true}]}'
    $script:lengthOverride = $null
    $script:readCalls = 0
    $script:writeCalls = 0
    $script:auditCalls = 0
    try {
        $null = & $Action
        Assert-WinSecInventoryIntegration ($script:writeCalls -eq 0 -and $script:auditCalls -eq 0)
        Assert-WinSecInventoryIntegration (-not [IO.Directory]::Exists($script:virtualRoot))
        $script:passed++
        Write-Host "[PASS] $Name"
    }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}

Test-WinSecInventoryIntegrationCase 'Missing inventory is a read-only empty first-run state' {
    $script:inventoryExists = $false
    $inventory = Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecInventoryIntegration ($inventory.targets.Count -eq 0 -and $script:readCalls -eq 0)
}
Test-WinSecInventoryIntegrationCase 'Import preserves historical devices and saved enablement' {
    $inventory = Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecInventoryIntegration ($inventory.targets.Count -eq 2 -and
        $inventory.targets[0].Enabled -ceq $false -and $inventory.targets[1].Enabled -ceq $true)
}
Test-WinSecInventoryIntegrationCase 'Repeated imports keep independent objects and do not alter storage' {
    $before = $script:inventoryJson
    $first = Import-WinSecDeviceInventory -ProjectRoot $root
    $first.targets[0].Enabled = $true
    $second = Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecInventoryIntegration ($second.targets.Count -eq 2 -and
        $second.targets[0].Enabled -ceq $false -and $script:inventoryJson -ceq $before)
}
Test-WinSecInventoryIntegrationCase 'Validated inventory reaches CLI devices without scores or scan results' {
    $inventory = Import-WinSecDeviceInventory -ProjectRoot $root
    $devices = @(Get-WinSecCLIDevices -ProjectRoot $root -Devices $inventory.targets)
    Assert-WinSecInventoryIntegration ($devices.Count -eq 2)
    foreach ($device in $devices) {
        Assert-WinSecInventoryIntegration ($null -eq $device.Score -and $device.Status -ceq 'PENDING' -and
            [string]::IsNullOrEmpty($device.ScanId) -and $device.LastScan -ceq 'Never')
    }
    $state = [pscustomobject]@{Screen='MainMenu'; SelectedDeviceId='local:CURRENT-FIXTURE'}
    $context = [pscustomobject]@{Devices=$devices; PublicScans=@{}; ActiveScanByDevice=@{}}
    $assessment = Get-WinSecCLIActiveAssessment -State $state -Context $context
    Assert-WinSecInventoryIntegration ($assessment.OverallStatus -ceq 'PENDING' -and
        $null -eq $assessment.OverallScore -and @($assessment.ControlResults).Count -eq 0)
}
foreach ($badJson in @(
    '{"schemaVersion":"1.0.0","targets":[],"Score":100}',
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:PRIVATE-INVENTORY-FIXTURE","Hostname":"FIXTURE","Mode":"LOCAL","Enabled":true,"Evidence":{"Value":"PRIVATE-INVENTORY-FIXTURE"}}]}',
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:FIXTURE","Hostname":"FIXTURE","Mode":"LOCAL","Enabled":false,"Enabled":true}]}',
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:FIXTURE","Hostname":"FIXTURE","Mode":"LOCAL",Enabled:false,Enabled:true}]}',
    '{"schemaVersion":"1.0.0","targets":["PRIVATE-INVENTORY-FIXTURE"',
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:PRIVATE-INVENTORY-FIXTURE","Hostname":"../PRIVATE-INVENTORY-FIXTURE","Mode":"LOCAL","Enabled":true}]}'
)) {
    Test-WinSecInventoryIntegrationCase 'Untrusted inventory cannot produce a partial CLI device list' {
        $script:inventoryJson = $badJson
        $before = $script:inventoryJson
        $devices = $null
        $caught = $null
        try {
            $inventory = Import-WinSecDeviceInventory -ProjectRoot $root
            $devices = @(Get-WinSecCLIDevices -ProjectRoot $root -Devices $inventory.targets)
        }
        catch { $caught = $_ }
        Assert-WinSecInventoryIntegration ($null -ne $caught -and $null -eq $devices -and
            $script:inventoryJson -ceq $before -and $caught.Exception.Message -notmatch 'PRIVATE-INVENTORY-FIXTURE')
    }
}
Test-WinSecInventoryIntegrationCase 'File size limit rejects before reading the document' {
    $script:lengthOverride = 1048577
    $caught = $false
    try { $null = Import-WinSecDeviceInventory -ProjectRoot $root } catch { $caught = $true }
    Assert-WinSecInventoryIntegration ($caught -and $script:readCalls -eq 0)
}
Test-WinSecInventoryIntegrationCase 'Reusing a disabled local registration never rewrites or enables it' {
    function New-WinSecLocalTarget {
        return [pscustomobject]@{DeviceId='local:CURRENT-FIXTURE'; Hostname='CURRENT-FIXTURE'; Mode='LOCAL'}
    }
    $before = $script:inventoryJson
    $registration = Register-WinSecLocalDevice -ProjectRoot $root
    Assert-WinSecInventoryIntegration ($registration.Status -ceq 'ALREADY_REGISTERED' -and
        $registration.Created -ceq $false -and $script:inventoryJson -ceq $before)
}
Test-WinSecInventoryIntegrationCase 'Identity conflicts abort registration without a write' {
    function New-WinSecLocalTarget {
        return [pscustomobject]@{DeviceId='local:CURRENT-FIXTURE'; Hostname='OTHER-FIXTURE'; Mode='LOCAL'}
    }
    $before = $script:inventoryJson
    $caught = $false
    try { $null = Register-WinSecLocalDevice -ProjectRoot $root } catch { $caught = $true }
    Assert-WinSecInventoryIntegration ($caught -and $script:inventoryJson -ceq $before)
}
Test-WinSecInventoryIntegrationCase 'Corrupt inventory aborts registration before any storage preparation' {
    function New-WinSecLocalTarget {
        return [pscustomobject]@{DeviceId='local:CURRENT-FIXTURE'; Hostname='CURRENT-FIXTURE'; Mode='LOCAL'}
    }
    $script:inventoryJson = '{"schemaVersion":"1.0.0","targets":[],"Evidence":"PRIVATE-INVENTORY-FIXTURE"}'
    $caught = $false
    try { $null = Register-WinSecLocalDevice -ProjectRoot $root } catch { $caught = $true }
    Assert-WinSecInventoryIntegration ($caught)
}

Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if ($script:failed -gt 0) { throw "$script:failed inventory integration test(s) failed." }
