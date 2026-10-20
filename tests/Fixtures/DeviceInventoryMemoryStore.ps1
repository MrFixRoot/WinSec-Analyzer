# In-memory I/O boundaries for inventory registration tests. Dot-source after
# DeviceInventory. No directory, lease file, temporary file or audit is created.
$script:inventoryMemoryRoot = Join-Path ([IO.Path]::GetTempPath()) ('WinSec-NoStorage-' + [guid]::NewGuid().ToString('N'))
$script:inventoryMemoryPath = Join-Path $script:inventoryMemoryRoot 'data/devices.json'
if ([IO.Directory]::Exists($script:inventoryMemoryRoot)) { throw 'Inventory fixture storage must not exist.' }

function Reset-WinSecInventoryMemoryStore {
    param(
        [string]$Json = '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:OLD-FIXTURE","Hostname":"OLD-FIXTURE","Mode":"LOCAL","Enabled":false,"Description":"Existing metadata","RegisteredAtUtc":"2026-01-01T00:00:00Z"}]}',
        [bool]$Exists = $true
    )
    $script:inventoryMemory = [pscustomobject]@{
        Json = $Json; Exists = $Exists; LocalId = 'local:CURRENT-FIXTURE'; LocalHostname = 'CURRENT-FIXTURE'
        Reads = 0; Opens = 0; Saves = 0; Releases = 0; LeaseHeld = $false; Busy = $false
        BeforeLockJson = $null; ChangeOnSecondRead = $null; AfterSaveJson = $null
        FailSave = $false; FailReadAt = 0; UnexpectedWrites = 0; Audits = 0
        AlterSavedHistory = $false
        ExpectedFingerprint = $null; SavedJson = $null
    }
}
function New-WinSecLocalTarget {
    return [pscustomobject]@{
        DeviceId = $script:inventoryMemory.LocalId; Hostname = $script:inventoryMemory.LocalHostname; Mode = 'LOCAL'
    }
}
function Get-WinSecDeviceInventoryPath { param($ProjectRoot) return $script:inventoryMemoryPath }
function Test-Path {
    [CmdletBinding()]
    param($LiteralPath, $Path, $PathType)
    if ($LiteralPath -ceq $script:inventoryMemoryPath) { return $script:inventoryMemory.Exists }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
function Get-Item {
    [CmdletBinding()]
    param($LiteralPath, [switch]$Force)
    if ($LiteralPath -ceq $script:inventoryMemoryPath) {
        return [pscustomobject]@{Length=[Text.Encoding]::UTF8.GetByteCount($script:inventoryMemory.Json)}
    }
    Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
}
function Get-Content {
    [CmdletBinding()]
    param($LiteralPath, [switch]$Raw, $Encoding)
    if ($LiteralPath -ceq $script:inventoryMemoryPath) {
        $script:inventoryMemory.Reads++
        if ($script:inventoryMemory.Reads -eq $script:inventoryMemory.FailReadAt) { throw 'Synthetic read failure.' }
        $snapshot = $script:inventoryMemory.Json
        if ($script:inventoryMemory.Reads -eq 2 -and $null -ne $script:inventoryMemory.ChangeOnSecondRead) {
            $script:inventoryMemory.Json = $script:inventoryMemory.ChangeOnSecondRead
        }
        return $snapshot
    }
    Microsoft.PowerShell.Management\Get-Content @PSBoundParameters
}
function Get-WinSecDeviceInventoryFingerprint {
    param($ProjectRoot)
    if (-not $script:inventoryMemory.Exists) { return 'MISSING' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($script:inventoryMemory.Json))).Replace('-', '') }
    finally { $sha.Dispose() }
}
function Open-WinSecDeviceInventoryStore {
    param($ProjectRoot)
    $script:inventoryMemory.Opens++
    if ($script:inventoryMemory.Busy -or $script:inventoryMemory.LeaseHeld) { throw 'Synthetic busy inventory.' }
    if ($null -ne $script:inventoryMemory.BeforeLockJson) {
        $script:inventoryMemory.Json = $script:inventoryMemory.BeforeLockJson
        $script:inventoryMemory.Exists = $true
    }
    $script:inventoryMemory.LeaseHeld = $true
    $lease = [pscustomobject]@{}
    $lease | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $script:inventoryMemory.Releases++
        $script:inventoryMemory.LeaseHeld = $false
    }
    return [pscustomobject]@{ProjectRoot=$ProjectRoot; Path=$script:inventoryMemoryPath; Lock=$lease}
}
function Save-WinSecDeviceInventory {
    param($Store, $Json, $ExpectedFingerprint)
    if (-not $script:inventoryMemory.LeaseHeld) { throw 'The test caller lost its write lease.' }
    $script:inventoryMemory.Saves++
    $script:inventoryMemory.ExpectedFingerprint = $ExpectedFingerprint
    if ((Get-WinSecDeviceInventoryFingerprint -ProjectRoot $Store.ProjectRoot) -cne $ExpectedFingerprint) {
        throw 'Synthetic stale storage snapshot.'
    }
    if ($script:inventoryMemory.FailSave) { throw 'PRIVATE-INVENTORY-WRITE-FIXTURE' }
    $script:inventoryMemory.SavedJson = $Json
    $script:inventoryMemory.Json = $Json
    $script:inventoryMemory.Exists = $true
    if ($script:inventoryMemory.AlterSavedHistory) {
        $changed = ConvertFrom-WinSecDeviceInventoryJson -Json $Json
        $changed.targets[0].Enabled = -not $changed.targets[0].Enabled
        $script:inventoryMemory.Json = ConvertTo-Json -InputObject $changed -Depth 8
    }
    if ($null -ne $script:inventoryMemory.AfterSaveJson) { $script:inventoryMemory.Json = $script:inventoryMemory.AfterSaveJson }
}
function New-Item { $script:inventoryMemory.UnexpectedWrites++; throw 'Unexpected physical fixture write.' }
function Set-Content { $script:inventoryMemory.UnexpectedWrites++; throw 'Unexpected physical fixture write.' }
function Add-Content { $script:inventoryMemory.UnexpectedWrites++; throw 'Unexpected physical fixture write.' }
function Out-File { $script:inventoryMemory.UnexpectedWrites++; throw 'Unexpected physical fixture write.' }
function Remove-Item { $script:inventoryMemory.UnexpectedWrites++; throw 'Unexpected physical fixture write.' }
function Invoke-WinSecAudit { $script:inventoryMemory.Audits++; throw 'Unexpected audit.' }
