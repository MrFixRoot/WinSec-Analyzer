# Registration contracts with storage and lock boundaries replaced in memory.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/TargetRegistry.ps1')
. (Join-Path $root 'src/Core/DeviceInventory.ps1')
$script:registrationNativePath = (Get-Command Get-WinSecDeviceInventoryPath).ScriptBlock
$script:registrationNativeSave = (Get-Command Save-WinSecDeviceInventory).ScriptBlock
. (Join-Path $PSScriptRoot '../Fixtures/DeviceInventoryMemoryStore.ps1')
$script:passed = 0
$script:failed = 0

function Assert-WinSecRegistrationUnit {
    param([bool]$Condition)
    if (-not $Condition) { throw 'Registration assertion failed.' }
}
function Test-WinSecRegistrationUnitCase {
    param([string]$Name, [scriptblock]$Action)
    Reset-WinSecInventoryMemoryStore
    try {
        $null = & $Action
        Assert-WinSecRegistrationUnit (-not $script:inventoryMemory.LeaseHeld)
        Assert-WinSecRegistrationUnit ($script:inventoryMemory.UnexpectedWrites -eq 0 -and $script:inventoryMemory.Audits -eq 0)
        Assert-WinSecRegistrationUnit (-not [IO.Directory]::Exists($script:inventoryMemoryRoot))
        $script:passed++; Write-Host "[PASS] $Name"
    }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}
function Assert-WinSecRegistrationRejected {
    $caught = $null
    try { $null = Register-WinSecLocalDevice -ProjectRoot $root } catch { $caught = $_ }
    Assert-WinSecRegistrationUnit ($null -ne $caught)
    Assert-WinSecRegistrationUnit ($caught.Exception.Message -notmatch 'PRIVATE-INVENTORY-WRITE-FIXTURE')
}

Test-WinSecRegistrationUnitCase 'Hardware rename updates only hostname without creating another identity' {
    $id = 'local:hw1-' + ('a' * 64)
    Reset-WinSecInventoryMemoryStore -Json ('{"schemaVersion":"1.0.0","targets":[{"DeviceId":"' + $id +
        '","Hostname":"OLD-NAME","Mode":"LOCAL","Enabled":false,"Description":"Preserve","RegisteredAtUtc":"2026-01-01T00:00:00Z"}]}')
    $script:inventoryMemory.LocalId = $id
    $script:inventoryMemory.LocalHostname = 'NEW-NAME'
    $result = Register-WinSecLocalDevice -ProjectRoot $root
    $saved = Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecRegistrationUnit (-not $result.Created -and $result.Status -ceq 'ALREADY_REGISTERED' -and
        $saved.targets.Count -eq 1 -and $saved.targets[0].Hostname -ceq 'NEW-NAME' -and
        $saved.targets[0].Enabled -ceq $false -and $saved.targets[0].Description -ceq 'Preserve')
    $savedJson = $script:inventoryMemory.Json
    $null = Register-WinSecLocalDevice -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($script:inventoryMemory.Saves -eq 1 -and $script:inventoryMemory.Json -ceq $savedJson)
}
Test-WinSecRegistrationUnitCase 'A failed rename preserves saved identity metadata and enablement' {
    $id = 'local:hw1-' + ('a' * 64)
    Reset-WinSecInventoryMemoryStore -Json ('{"schemaVersion":"1.0.0","targets":[{"DeviceId":"' + $id +
        '","Hostname":"OLD-NAME","Mode":"LOCAL","Enabled":false}]}')
    $script:inventoryMemory.LocalId = $id
    $script:inventoryMemory.LocalHostname = 'NEW-NAME'
    $script:inventoryMemory.FailSave = $true
    $before = $script:inventoryMemory.Json
    $caught = $false
    try { $null = Register-WinSecLocalDevice -ProjectRoot $root } catch { $caught = $true }
    Assert-WinSecRegistrationUnit ($caught -and $script:inventoryMemory.Json -ceq $before -and
        $script:inventoryMemory.Releases -eq 1)
}
Test-WinSecRegistrationUnitCase 'Legacy identity is retained separately and its disablement is not bypassed' {
    Reset-WinSecInventoryMemoryStore
    $script:inventoryMemory.LocalId = 'local:hw1-' + ('a' * 64)
    $script:inventoryMemory.LocalHostname = 'OLD-FIXTURE'
    $result = Register-WinSecLocalDevice -ProjectRoot $root
    $saved = Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($result.Created -and $saved.targets.Count -eq 2 -and
        $saved.targets[0].DeviceId -ceq 'local:OLD-FIXTURE' -and $saved.targets[0].Enabled -ceq $false -and
        $saved.targets[1].DeviceId -ceq $script:inventoryMemory.LocalId -and $saved.targets[1].Enabled -ceq $false)
}

Test-WinSecRegistrationUnitCase 'First launch registers only the current device' {
    Reset-WinSecInventoryMemoryStore -Json '{"schemaVersion":"1.0.0","targets":[]}' -Exists $false
    $result = Register-WinSecLocalDevice -ProjectRoot $root
    $inventory = Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($result.Created -ceq $true -and $result.Status -ceq 'REGISTERED' -and
        $inventory.targets.Count -eq 1 -and $inventory.targets[0].DeviceId -ceq $script:inventoryMemory.LocalId)
    Assert-WinSecRegistrationUnit ($script:inventoryMemory.ExpectedFingerprint -ceq 'MISSING' -and
        $script:inventoryMemory.Saves -eq 1 -and $script:inventoryMemory.Releases -eq 1)
}
Test-WinSecRegistrationUnitCase 'An existing empty inventory can receive its first registration' {
    Reset-WinSecInventoryMemoryStore -Json '{"schemaVersion":"1.0.0","targets":[]}'
    $result = Register-WinSecLocalDevice -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($result.Created -ceq $true -and $script:inventoryMemory.ExpectedFingerprint -cne 'MISSING')
}
Test-WinSecRegistrationUnitCase 'Appending a device preserves all previous metadata and enablement' {
    $oldJson = ConvertTo-Json -InputObject (Import-WinSecDeviceInventory -ProjectRoot $root).targets[0] -Depth 8 -Compress
    $result = Register-WinSecLocalDevice -ProjectRoot $root
    $inventory = Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($result.Created -ceq $true -and $inventory.targets.Count -eq 2)
    Assert-WinSecRegistrationUnit ((ConvertTo-Json -InputObject $inventory.targets[0] -Depth 8 -Compress) -ceq $oldJson)
    Assert-WinSecRegistrationUnit ($inventory.targets[1].Enabled -ceq $true -and
        $inventory.targets[1].RegisteredAtUtc.ToString().Length -gt 0)
}
Test-WinSecRegistrationUnitCase 'A restart recognizes the device without another write or lock' {
    $first = Register-WinSecLocalDevice -ProjectRoot $root
    $before = $script:inventoryMemory.Json
    $second = Register-WinSecLocalDevice -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($first.Created -ceq $true -and $second.Created -ceq $false -and
        $second.Status -ceq 'ALREADY_REGISTERED' -and $script:inventoryMemory.Json -ceq $before)
    Assert-WinSecRegistrationUnit ($script:inventoryMemory.Saves -eq 1 -and $script:inventoryMemory.Opens -eq 1)
}
Test-WinSecRegistrationUnitCase 'Saved disabled registration is reused without enabling it' {
    $script:inventoryMemory.LocalId = 'local:OLD-FIXTURE'
    $script:inventoryMemory.LocalHostname = 'OLD-FIXTURE'
    $before = $script:inventoryMemory.Json
    $result = Register-WinSecLocalDevice -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($result.Created -ceq $false -and $script:inventoryMemory.Json -ceq $before -and
        $script:inventoryMemory.Saves -eq 0 -and $script:inventoryMemory.Opens -eq 0)
}
Test-WinSecRegistrationUnitCase 'Case-insensitive recognition does not replace a saved identity' {
    $script:inventoryMemory.LocalId = 'local:old-fixture'
    $script:inventoryMemory.LocalHostname = 'old-fixture'
    $result = Register-WinSecLocalDevice -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($result.DeviceId -ceq 'local:OLD-FIXTURE' -and $script:inventoryMemory.Saves -eq 0)
}
Test-WinSecRegistrationUnitCase 'Identity conflicts reject before opening storage for writes' {
    $script:inventoryMemory.LocalId = 'local:OLD-FIXTURE'
    Assert-WinSecRegistrationRejected
    Assert-WinSecRegistrationUnit ($script:inventoryMemory.Opens -eq 0 -and $script:inventoryMemory.Saves -eq 0)
}
Test-WinSecRegistrationUnitCase 'Busy storage rejects without overwriting previous devices' {
    $before = $script:inventoryMemory.Json
    $script:inventoryMemory.Busy = $true
    Assert-WinSecRegistrationRejected
    Assert-WinSecRegistrationUnit ($script:inventoryMemory.Json -ceq $before -and $script:inventoryMemory.Saves -eq 0)
}
Test-WinSecRegistrationUnitCase 'The snapshot is reloaded after acquiring the writer lock' {
    $concurrent = ConvertFrom-WinSecDeviceInventoryJson -Json $script:inventoryMemory.Json
    $concurrent.targets += [pscustomobject]@{DeviceId='local:CONCURRENT'; Hostname='CONCURRENT'; Mode='LOCAL'; Enabled=$false}
    $script:inventoryMemory.BeforeLockJson = ConvertTo-Json -InputObject $concurrent -Depth 8
    $result = Register-WinSecLocalDevice -ProjectRoot $root
    $saved = Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($result.Created -ceq $true -and $saved.targets.Count -eq 3 -and
        $saved.targets[1].DeviceId -ceq 'local:CONCURRENT' -and $saved.targets[1].Enabled -ceq $false)
}
Test-WinSecRegistrationUnitCase 'A concurrent registration is reused after the lock without duplication' {
    $concurrent = ConvertFrom-WinSecDeviceInventoryJson -Json $script:inventoryMemory.Json
    $concurrent.targets += [pscustomobject]@{DeviceId='local:CURRENT-FIXTURE'; Hostname='CURRENT-FIXTURE'; Mode='LOCAL'; Enabled=$false}
    $script:inventoryMemory.BeforeLockJson = ConvertTo-Json -InputObject $concurrent -Depth 8
    $result = Register-WinSecLocalDevice -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($result.Created -ceq $false -and $script:inventoryMemory.Saves -eq 0 -and
        $script:inventoryMemory.Releases -eq 1)
}
Test-WinSecRegistrationUnitCase 'Changes during the locked read abort without a write' {
    $script:inventoryMemory.ChangeOnSecondRead = '{"schemaVersion":"1.0.0","targets":[]}'
    Assert-WinSecRegistrationRejected
    Assert-WinSecRegistrationUnit ($script:inventoryMemory.Saves -eq 0 -and $script:inventoryMemory.Releases -eq 1)
}
Test-WinSecRegistrationUnitCase 'A conflicting concurrent identity is rejected after the locked reload' {
    $concurrent = ConvertFrom-WinSecDeviceInventoryJson -Json $script:inventoryMemory.Json
    $concurrent.targets += [pscustomobject]@{DeviceId='local:CURRENT-FIXTURE'; Hostname='OTHER-FIXTURE'; Mode='LOCAL'; Enabled=$true}
    $script:inventoryMemory.BeforeLockJson = ConvertTo-Json -InputObject $concurrent -Depth 8
    Assert-WinSecRegistrationRejected
    Assert-WinSecRegistrationUnit ($script:inventoryMemory.Saves -eq 0 -and $script:inventoryMemory.Releases -eq 1)
}
Test-WinSecRegistrationUnitCase 'Invalid local identity is rejected before reading or opening storage' {
    $script:inventoryMemory.LocalId = '../PRIVATE-INVENTORY-WRITE-FIXTURE'
    Assert-WinSecRegistrationRejected
    Assert-WinSecRegistrationUnit ($script:inventoryMemory.Reads -eq 0 -and $script:inventoryMemory.Opens -eq 0)
}
Test-WinSecRegistrationUnitCase 'A write failure preserves the previous document and releases the lock' {
    $before = $script:inventoryMemory.Json
    $script:inventoryMemory.FailSave = $true
    Assert-WinSecRegistrationRejected
    Assert-WinSecRegistrationUnit ($script:inventoryMemory.Json -ceq $before -and $script:inventoryMemory.Releases -eq 1)
}
foreach ($readNumber in @(2, 3)) {
    Test-WinSecRegistrationUnitCase "Read failure releases the write lease: read $readNumber" {
        $script:inventoryMemory.FailReadAt = $readNumber
        Assert-WinSecRegistrationRejected
        Assert-WinSecRegistrationUnit ($script:inventoryMemory.Releases -eq 1)
    }
}
foreach ($replacement in @(
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:CURRENT-FIXTURE","Hostname":"CURRENT-FIXTURE","Mode":"LOCAL","Enabled":true}]}',
    '{"schemaVersion":"1.0.0","targets":[]}',
    '{"schemaVersion":"1.0.0","targets":[],"Evidence":"not allowed"}'
)) {
    Test-WinSecRegistrationUnitCase 'Post-write verification rejects lost history missing registration or forbidden fields' {
        $script:inventoryMemory.AfterSaveJson = $replacement
        Assert-WinSecRegistrationRejected
        Assert-WinSecRegistrationUnit ($script:inventoryMemory.Releases -eq 1)
    }
}
Test-WinSecRegistrationUnitCase 'Malformed history cannot reach the writer' {
    $script:inventoryMemory.Json = '{"schemaVersion":"1.0.0","targets":["corrupt"]}'
    Assert-WinSecRegistrationRejected
    Assert-WinSecRegistrationUnit ($script:inventoryMemory.Opens -eq 0 -and $script:inventoryMemory.Saves -eq 0)
}
Test-WinSecRegistrationUnitCase 'Post-write verification rejects altered metadata even with every device still present' {
    $script:inventoryMemory.AlterSavedHistory = $true
    Assert-WinSecRegistrationRejected
    $saved = Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecRegistrationUnit ($saved.targets.Count -eq 2 -and $script:inventoryMemory.Releases -eq 1)
}
Test-WinSecRegistrationUnitCase 'Registration persists no result evidence or scoring fields' {
    $null = Register-WinSecLocalDevice -ProjectRoot $root
    $saved = ConvertFrom-WinSecDeviceInventoryJson -Json $script:inventoryMemory.SavedJson
    Assert-WinSecRegistrationUnit ($saved.targets.Count -eq 2 -and $script:inventoryMemory.SavedJson -notmatch
        '"(Evidence|RawEvidence|Score|ScanId|Findings|OverallScore)"\s*:')
}
Test-WinSecRegistrationUnitCase 'Storage path validation rejects a linked ancestor using simulated metadata' {
    function Get-Item {
        [CmdletBinding()]
        param($LiteralPath, [switch]$Force)
        if ($LiteralPath -ceq [IO.Directory]::GetParent($root).FullName) {
            return [pscustomobject]@{PSIsContainer=$true; Attributes=[IO.FileAttributes]::ReparsePoint}
        }
        Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
    }
    $caught = $false
    try { $null = & $script:registrationNativePath -ProjectRoot $root } catch { $caught = $true }
    Assert-WinSecRegistrationUnit ($caught)
}
Test-WinSecRegistrationUnitCase 'Storage path validation rejects a linked inventory file using simulated metadata' {
    $blockedInventoryPath = Join-Path $root 'data/devices.json'
    function Test-Path {
        [CmdletBinding()]
        param($LiteralPath, $PathType)
        if ($LiteralPath -ceq $blockedInventoryPath) { return $true }
        Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
    }
    function Get-Item {
        [CmdletBinding()]
        param($LiteralPath, [switch]$Force)
        if ($LiteralPath -ceq $blockedInventoryPath) {
            return [pscustomobject]@{PSIsContainer=$false; Attributes=[IO.FileAttributes]::ReparsePoint}
        }
        Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
    }
    $caught = $false
    try { $null = & $script:registrationNativePath -ProjectRoot $root } catch { $caught = $true }
    Assert-WinSecRegistrationUnit ($caught)
}
Test-WinSecRegistrationUnitCase 'The real atomic writer rejects a fabricated lease before touching storage' {
    $fake = [pscustomobject]@{ProjectRoot=$root; Path=$script:inventoryMemoryPath; Lock=[pscustomobject]@{CanWrite=$true}}
    $caught = $false
    try {
        $null = & $script:registrationNativeSave -Store $fake -Json $script:inventoryMemory.Json `
            -ExpectedFingerprint (Get-WinSecDeviceInventoryFingerprint -ProjectRoot $root)
    }
    catch { $caught = $true }
    Assert-WinSecRegistrationUnit ($caught -and $script:inventoryMemory.Saves -eq 0)
}

Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if ($script:failed -gt 0) { throw "$script:failed registration unit test(s) failed." }
