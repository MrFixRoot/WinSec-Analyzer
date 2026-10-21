# Native storage in an owned disposable project copy. The working inventory is
# protected by a read-only handle and hash check. All test identities are synthetic.
[CmdletBinding()]
param(
    [switch]$Child,
    [string]$FixtureRoot,
    [string]$FixtureUuid = '12345678-1234-4567-89ab-123456789abc',
    [string]$FixtureHostname = 'FIRST-FIXTURE'
)
$ErrorActionPreference = 'Stop'
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
function Get-CimInstance {
    [CmdletBinding()]
    param($Namespace, $ClassName, $Property, $OperationTimeoutSec)
    if ($Namespace -cne 'root/cimv2' -or $ClassName -cne 'Win32_ComputerSystemProduct' -or
        $Property -cne 'UUID' -or $OperationTimeoutSec -ne 5) { throw 'Unexpected identity query.' }
    return [pscustomobject]@{UUID=$script:FixtureUuid}
}
if ($Child) {
    $env:COMPUTERNAME = $FixtureHostname
    . (Join-Path $FixtureRoot 'src/Core/TargetRegistry.ps1')
    . (Join-Path $FixtureRoot 'src/Core/DeviceInventory.ps1')
    try {
        $registration = Register-WinSecLocalDevice -ProjectRoot $FixtureRoot
        [pscustomobject]@{Succeeded=$true; Created=$registration.Created; Status=$registration.Status;
            DeviceId=$registration.DeviceId} | ConvertTo-Json -Compress
    }
    catch { [pscustomobject]@{Succeeded=$false} | ConvertTo-Json -Compress }
    return
}
$script:passed = 0
$script:failed = 0
$savedHostname = $env:COMPUTERNAME
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$ownedName = 'WinSec-Inventory-Test-' + [guid]::NewGuid().ToString('N')
$sandbox = [IO.Path]::GetFullPath((Join-Path $temporaryBase $ownedName))
if (Test-Path -LiteralPath $sandbox) { throw 'Fixture directory must not exist.' }
$hostExecutable = (Get-Process -Id $PID).Path
$script:testScript = $PSCommandPath
$workingInventory = Join-Path $sourceRoot 'data/devices.json'
$workingGuard = $null
$workingExisted = [IO.File]::Exists($workingInventory)
$workingHash = $null
function Assert-WinSecPersistence {
    param([bool]$Condition)
    if (-not $Condition) { throw 'Persistence assertion failed.' }
}
function Test-WinSecPersistenceCase {
    param([string]$Name, [scriptblock]$Action)
    try { $null = & $Action; $script:passed++; Write-Host "[PASS] $Name" }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}
function Invoke-WinSecFixtureProcess {
    param([string]$Hostname='FIRST-FIXTURE', [string]$Uuid='12345678-1234-4567-89ab-123456789abc')
    $output = & $hostExecutable -NoLogo -NoProfile -NonInteractive -File $script:testScript `
        -Child -FixtureRoot $sandbox -FixtureUuid $Uuid -FixtureHostname $Hostname
    if ($LASTEXITCODE -ne 0) { throw 'Fixture process failed.' }
    return (($output -join [Environment]::NewLine) | ConvertFrom-Json)
}
function Show-WinSecCLICurrentScreen {
    param($State, $Context)
    $script:startupContext = $Context
    $State.ExitRequested = $true
}
try {
    if ($workingExisted) {
        $workingGuard = [IO.File]::Open($workingInventory, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $workingHash = (Get-FileHash -LiteralPath $workingInventory -Algorithm SHA256).Hash
    }
    $null = [IO.Directory]::CreateDirectory($sandbox)
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'src') -Destination $sandbox -Recurse -ErrorAction Stop
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'config') -Destination $sandbox -Recurse -ErrorAction Stop
    . (Join-Path $sandbox 'src/Core/ScanCoordinator.ps1')
    . (Join-Path $sandbox 'src/CLI/Invoke-WinSecCLI.ps1')
    # The real startup renders through this in-memory UI adapter and exits.
    function Show-WinSecCLICurrentScreen {
        param($State, $Context)
        $script:startupContext = $Context
        $State.ExitRequested = $true
    }
    $path = Join-Path $sandbox 'data/devices.json'
    Test-WinSecPersistenceCase 'First process creates and verifies native inventory without lock residue' {
        $first = Invoke-WinSecFixtureProcess
        Assert-WinSecPersistence ($first.Succeeded -and $first.Created -and $first.Status -ceq 'REGISTERED')
        $script:firstId = $first.DeviceId
        $inventory = Import-WinSecDeviceInventory -ProjectRoot $sandbox
        Assert-WinSecPersistence ($inventory.targets.Count -eq 1 -and $inventory.targets[0].DeviceId -ceq $first.DeviceId)
        Assert-WinSecPersistence (@(Get-ChildItem -LiteralPath (Join-Path $sandbox 'data') -Force).Count -eq 1)
    }
    Test-WinSecPersistenceCase 'A separate process recognizes the saved device without rewriting it' {
        $before = (Get-FileHash -LiteralPath $path).Hash
        $timestamp = (Get-Item -LiteralPath $path).LastWriteTimeUtc
        $restart = Invoke-WinSecFixtureProcess
        Assert-WinSecPersistence ($restart.Succeeded -and -not $restart.Created -and $restart.DeviceId -ceq $script:firstId)
        Assert-WinSecPersistence ((Get-FileHash -LiteralPath $path).Hash -ceq $before -and
            (Get-Item -LiteralPath $path).LastWriteTimeUtc -eq $timestamp)
    }
    Test-WinSecPersistenceCase 'Another hardware identity with the same hostname appends atomically' {
        $before = ConvertTo-Json -InputObject (Import-WinSecDeviceInventory -ProjectRoot $sandbox).targets[0] -Depth 8 -Compress
        $second = Invoke-WinSecFixtureProcess -Uuid '87654321-4321-4567-89ab-cba987654321'
        $inventory = Import-WinSecDeviceInventory -ProjectRoot $sandbox
        Assert-WinSecPersistence ($second.Succeeded -and $second.Created -and $second.DeviceId -cne $script:firstId -and
            $inventory.targets.Count -eq 2)
        Assert-WinSecPersistence ((ConvertTo-Json -InputObject $inventory.targets[0] -Depth 8 -Compress) -ceq $before)
    }
    Test-WinSecPersistenceCase 'Renamed Windows reuses hardware identity and preserves original metadata' {
        $old = (Import-WinSecDeviceInventory -ProjectRoot $sandbox).targets[0]
        $renamed = Invoke-WinSecFixtureProcess -Hostname 'RENAMED-FIXTURE'
        $inventory = Import-WinSecDeviceInventory -ProjectRoot $sandbox
        $current = @($inventory.targets | Where-Object DeviceId -CEQ $script:firstId)[0]
        Assert-WinSecPersistence ($renamed.Succeeded -and -not $renamed.Created -and $inventory.targets.Count -eq 2 -and
            $current.Hostname -ceq 'RENAMED-FIXTURE' -and $current.RegisteredAtUtc -eq $old.RegisteredAtUtc -and
            $current.Enabled -ceq $old.Enabled -and $current.Description -ceq $old.Description)
    }
    Test-WinSecPersistenceCase 'Exclusive native lock rejects a writer in another process' {
        $store = Open-WinSecDeviceInventoryStore -ProjectRoot $sandbox
        $before = (Get-FileHash -LiteralPath $path).Hash
        try { $competing = Invoke-WinSecFixtureProcess -Uuid '22222222-1234-4567-89ab-123456789abc' }
        finally { $store.Lock.Dispose() }
        Assert-WinSecPersistence (-not $competing.Succeeded -and (Get-FileHash -LiteralPath $path).Hash -ceq $before)
        Assert-WinSecPersistence (-not (Test-Path -LiteralPath (Join-Path $sandbox 'data/.devices.lock')))
    }
    Test-WinSecPersistenceCase 'A failed native replacement preserves the old file and removes temporary data' {
        # Allow reads, deny deletion/replacement only within the disposable fixture.
        $reader = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $before = (Get-FileHash -LiteralPath $path).Hash
        try { $failed = Invoke-WinSecFixtureProcess -Uuid '33333333-1234-4567-89ab-123456789abc' }
        finally { $reader.Dispose() }
        Assert-WinSecPersistence (-not $failed.Succeeded -and (Get-FileHash -LiteralPath $path).Hash -ceq $before)
        Assert-WinSecPersistence (@(Get-ChildItem -LiteralPath (Join-Path $sandbox 'data') -Force).Count -eq 1)
    }
    Test-WinSecPersistenceCase 'Actual CLI startup loads history devices but creates no scan or score' {
        $env:COMPUTERNAME = 'RENAMED-FIXTURE'
        Invoke-WinSecCLI -ProjectRoot $sandbox
        $context = $script:startupContext
        Assert-WinSecPersistence ($context.Devices.Count -eq 2 -and $context.ScanCoordinator.RequireDeviceInventory -ceq $true -and
            $context.ScanCoordinator.Sessions.Count -eq 0 -and $context.PublicScans.Count -eq 0 -and $context.ActiveScanByDevice.Count -eq 0)
        foreach ($device in $context.Devices) {
            Assert-WinSecPersistence ($null -eq $device.Score -and $device.Status -ceq 'PENDING' -and [string]::IsNullOrEmpty($device.ScanId))
        }
        $authorized = Resolve-WinSecScanTarget -Coordinator $context.ScanCoordinator -DeviceId $script:firstId
        Assert-WinSecPersistence ($authorized.Hostname -ceq 'RENAMED-FIXTURE')
    }
    Test-WinSecPersistenceCase 'Inventory cannot authorize a historical device on this hardware' {
        $other = @($script:startupContext.Devices | Where-Object DeviceId -CNE $script:firstId)[0]
        $caught = $false
        try { $null = Resolve-WinSecScanTarget -Coordinator $script:startupContext.ScanCoordinator -DeviceId $other.DeviceId }
        catch { $caught = $true }
        Assert-WinSecPersistence $caught
    }
    Test-WinSecPersistenceCase 'Inventory cannot override a configured disablement or add a catalog permission' {
        $coordinator = $script:startupContext.ScanCoordinator
        $originalRegistry = $coordinator.Registry
        try {
            foreach ($configured in @(
                [pscustomobject]@{DeviceId=$script:firstId; Hostname='RENAMED-FIXTURE'; Mode='LOCAL'; Enabled=$false},
                [pscustomobject]@{DeviceId='remote:OTHER-FIXTURE'; Hostname='OTHER-FIXTURE'; Mode='REMOTE'; Enabled=$true}
            )) {
                $coordinator.Registry = [pscustomobject]@{schemaVersion='1.0.0'; targets=@($configured)}
                $caught = $false
                try { $null = Resolve-WinSecScanTarget -Coordinator $coordinator -DeviceId $script:firstId }
                catch { $caught = $true }
                Assert-WinSecPersistence $caught
            }
        }
        finally { $coordinator.Registry = $originalRegistry }
    }
    Test-WinSecPersistenceCase 'An ambiguous inventory authorization flag fails closed' {
        $coordinator = $script:startupContext.ScanCoordinator
        $coordinator.RequireDeviceInventory = 'false'
        try {
            $caught = $false
            try { $null = Resolve-WinSecScanTarget -Coordinator $coordinator -DeviceId $script:firstId }
            catch { $caught = $true }
            Assert-WinSecPersistence $caught
        }
        finally { $coordinator.RequireDeviceInventory = $true }
    }
    Test-WinSecPersistenceCase 'Missing inventory after startup revokes backend eligibility' {
        $bytes = [IO.File]::ReadAllBytes($path)
        [IO.File]::Delete($path)
        try {
            $caught = $false
            try { $null = Resolve-WinSecScanTarget -Coordinator $script:startupContext.ScanCoordinator -DeviceId $script:firstId }
            catch { $caught = $true }
            Assert-WinSecPersistence $caught
        }
        finally { [IO.File]::WriteAllBytes($path, $bytes) }
    }
    Test-WinSecPersistenceCase 'Saved disablement blocks direct backend authorization after startup' {
        $inventory = Import-WinSecDeviceInventory -ProjectRoot $sandbox
        $inventory.targets[0].Enabled = $false
        $store = Open-WinSecDeviceInventoryStore -ProjectRoot $sandbox
        try {
            Save-WinSecDeviceInventory -Store $store -Json ($inventory | ConvertTo-Json -Depth 8) `
                -ExpectedFingerprint (Get-WinSecDeviceInventoryFingerprint -ProjectRoot $sandbox)
        }
        finally { $store.Lock.Dispose() }
        $caught = $false
        try { $null = Resolve-WinSecScanTarget -Coordinator $script:startupContext.ScanCoordinator -DeviceId $script:firstId }
        catch { $caught = $true }
        Assert-WinSecPersistence $caught
        $restart = Invoke-WinSecFixtureProcess -Hostname 'RENAMED-FIXTURE'
        Assert-WinSecPersistence ($restart.Succeeded -and -not $restart.Created -and
            (Import-WinSecDeviceInventory -ProjectRoot $sandbox).targets[0].Enabled -ceq $false)
    }
    Test-WinSecPersistenceCase 'Corruption is rejected without replacing the source or publishing partial devices' {
        [IO.File]::WriteAllText($path, '{"schemaVersion":"1.0.0","targets":[', [Text.Encoding]::UTF8)
        $before = (Get-FileHash -LiteralPath $path).Hash
        $result = Invoke-WinSecFixtureProcess
        $script:startupContext = $null
        $caught = $false
        try { Invoke-WinSecCLI -ProjectRoot $sandbox } catch { $caught = $true }
        Assert-WinSecPersistence (-not $result.Succeeded -and $caught -and $null -eq $script:startupContext -and
            (Get-FileHash -LiteralPath $path).Hash -ceq $before)
    }
}
finally {
    $env:COMPUTERNAME = $savedHostname
    $workingGuardError = $false
    try {
        if ($workingExisted) {
            if ((Get-FileHash -LiteralPath $workingInventory -Algorithm SHA256).Hash -cne $workingHash) {
                throw 'Working inventory changed during the isolated integration suite.'
            }
        }
        elseif ([IO.File]::Exists($workingInventory)) { throw 'Working inventory was unexpectedly created.' }
    }
    catch { $workingGuardError = $true }
    finally { if ($null -ne $workingGuard) { $workingGuard.Dispose() } }
    # Verify the exact owned absolute directory and all descendants before removal.
    $cleanupPath = [IO.Path]::GetFullPath($sandbox)
    if ($cleanupPath -cne [IO.Path]::GetFullPath((Join-Path $temporaryBase $ownedName)) -or
        [IO.Path]::GetDirectoryName($cleanupPath) -cne $temporaryBase -or $ownedName -cnotmatch '^WinSec-Inventory-Test-[a-f0-9]{32}$') {
        throw 'Unsafe fixture cleanup path.'
    }
    if (Test-Path -LiteralPath $cleanupPath) {
        $items = @((Get-Item -LiteralPath $cleanupPath -Force)) + @(Get-ChildItem -LiteralPath $cleanupPath -Force -Recurse)
        foreach ($item in $items) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unsafe fixture cleanup link.' }
        }
        Remove-Item -LiteralPath $cleanupPath -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $cleanupPath) { throw 'Fixture cleanup failed.' }
    Write-Host '[PASS] Disposable project and synthetic inventory removed'
    if ($workingGuardError) { throw 'Working inventory protection or verification failed.' }
    Write-Host '[PASS] Working inventory unchanged during this suite'
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if ($script:failed -gt 0) { throw 'Native inventory integration tests failed.' }
