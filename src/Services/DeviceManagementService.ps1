# Confirmed removal of application-owned device records and history only.
# No Windows configuration changes, scans, remoting or raw evidence output.

function Assert-WinSecDeviceRemovalPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot, [Parameter(Mandatory)][string]$Path)
    $root = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\','/')
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Device storage is outside the application root.'
    }
    $current = $full
    while ($current.Length -ge $root.Length) {
        if (Test-Path -LiteralPath $current -ErrorAction Stop) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked device storage is not supported.' }
            if ($current -cne $full -and -not $item.PSIsContainer) { throw 'Invalid device storage directory.' }
        }
        if ([string]::Equals($current,$root,[StringComparison]::OrdinalIgnoreCase)) { break }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    # Reuse the inventory's validation of the root and its ancestors.
    $null = Get-WinSecDeviceInventoryPath -ProjectRoot $root
}

function Assert-WinSecStoredScanRemovalOwnership {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$DeviceId)
    if ([IO.Path]::GetExtension($Path) -cne '.json' -or (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Length -gt 1048576) {
        throw 'Unrecognized stored scan file.'
    }
    $record = ConvertFrom-WinSecStoredJson -Json (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop)
    if ($record -isnot [pscustomobject] -or $record.PSObject.Properties.Name -cnotcontains 'SchemaVersion' -or
        $record.SchemaVersion -isnot [string] -or $record.SchemaVersion -cne '1.0.0' -or
        $record.PSObject.Properties.Name -cnotcontains 'DeviceId' -or
        $record.PSObject.Properties.Name -cnotcontains 'ScanId' -or $record.DeviceId -isnot [string] -or
        -not [string]::Equals($record.DeviceId,$DeviceId,[StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-WinSecTargetIdentifier $record.ScanId)) { throw 'Inconsistent stored scan ownership.' }
    $pending = New-Object 'System.Collections.Generic.Stack[object]'
    $pending.Push($record)
    $count=0
    while ($pending.Count -gt 0) {
        if (++$count -gt 10000) { throw 'Stored scan is too complex.' }
        $node=$pending.Pop()
        if ($node -is [pscustomobject]) {
            foreach ($property in $node.PSObject.Properties) {
                if ($property.Name -ieq 'DeviceId' -and ($property.Value -isnot [string] -or
                    -not [string]::Equals($property.Value,$DeviceId,[StringComparison]::OrdinalIgnoreCase))) {
                    throw 'Mixed stored device identities.'
                }
                if ($property.Name -ieq 'ScanId' -and ($property.Value -isnot [string] -or $property.Value -cne $record.ScanId)) {
                    throw 'Mixed stored scan identities.'
                }
                if ($null -ne $property.Value) { $pending.Push($property.Value) }
            }
        }
        elseif ($node -is [array]) { foreach ($value in $node) { if ($null -ne $value) { $pending.Push($value) } } }
    }
}

function Get-WinSecDeviceRemovalPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$DeviceId,
        [Parameter(Mandatory)][object]$Coordinator,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Devices
    )
    $ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
    if (-not (Test-WinSecTargetIdentifier $DeviceId)) { throw 'Invalid device identity.' }
    Assert-WinSecScanCoordinator -Coordinator $Coordinator
    if (-not [string]::Equals([IO.Path]::GetFullPath($ProjectRoot),[IO.Path]::GetFullPath($Coordinator.ProjectRoot),[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Device removal must use the coordinator installation.'
    }
    $validation = Test-WinSecTargetRegistry -Registry ([pscustomobject]@{schemaVersion='1.0.0'; targets=@($Devices)})
    if (-not $validation.Valid) { throw 'Invalid managed device list.' }
    $inventoryHash = Get-WinSecDeviceInventoryFingerprint -ProjectRoot $ProjectRoot
    $inventory = Import-WinSecDeviceInventory -ProjectRoot $ProjectRoot
    if ((Get-WinSecDeviceInventoryFingerprint -ProjectRoot $ProjectRoot) -cne $inventoryHash) { throw 'Inventory changed while preparing removal.' }
    $selected = @($Devices | Where-Object { [string]::Equals($_.DeviceId,$DeviceId,[StringComparison]::OrdinalIgnoreCase) })
    if ($selected.Count -ne 1) { throw 'Select exactly one managed device.' }
    $saved = @($inventory.targets | Where-Object { [string]::Equals($_.DeviceId,$DeviceId,[StringComparison]::OrdinalIgnoreCase) })
    $owner = if ($saved.Count -eq 1) { $saved[0] } else { $selected[0] }
    $DeviceId = [string]$owner.DeviceId
    $storageIdentities = New-Object 'System.Collections.Generic.HashSet[string]'
    $null = $storageIdentities.Add($DeviceId)
    $null = $storageIdentities.Add([string]$selected[0].DeviceId)
    $sessionKeys = @(@(
        foreach ($sessionEntry in $Coordinator.Sessions.GetEnumerator()) {
            $key = $sessionEntry.Key
            $entry = $sessionEntry.Value
            if ($entry.DeviceId -isnot [string] -or $entry.ScanId -isnot [string] -or
                $key -cne (Get-WinSecScanSessionKey -DeviceId $entry.DeviceId -ScanId $entry.ScanId)) {
                throw 'Inconsistent session ownership.'
            }
            $payload = Get-WinSecTargetField -InputObject $entry -Name 'Session'
            if ($null -ne $payload -and ($payload.DeviceId -isnot [string] -or $payload.ScanId -isnot [string] -or
                $payload.DeviceId -cne $entry.DeviceId -or $payload.ScanId -cne $entry.ScanId)) {
                throw 'Inconsistent stored session identity.'
            }
            if ([string]::Equals($entry.DeviceId,$DeviceId,[StringComparison]::OrdinalIgnoreCase)) {
                $null = $storageIdentities.Add($entry.DeviceId)
                [string]$key
            }
        }
    ) | Sort-Object)
    # This is the existing evidence hash convention; persistent scan storage
    # owns the same per-device directory convention under data/scans.
    foreach ($configured in @(Get-WinSecRegisteredTargets -Registry $Coordinator.Registry)) {
        if ([string]::Equals($configured.DeviceId,$DeviceId,[StringComparison]::OrdinalIgnoreCase)) { $null=$storageIdentities.Add($configured.DeviceId) }
    }
    $roots = @(@(
        foreach ($identity in $storageIdentities) {
            $deviceHash = Get-WinSecEvidenceHash $identity
            Join-Path $ProjectRoot ('data/scans/' + $deviceHash)
            Join-Path $ProjectRoot ('reports/evidence/' + $deviceHash)
        }
    ) | Sort-Object -Unique)
    $files = New-Object 'System.Collections.Generic.List[object]'
    $directories = New-Object 'System.Collections.Generic.List[string]'
    foreach ($storageRoot in $roots) {
        Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $storageRoot
        if (-not (Test-Path -LiteralPath $storageRoot -ErrorAction Stop)) { continue }
        if (-not (Get-Item -LiteralPath $storageRoot -Force -ErrorAction Stop).PSIsContainer) { throw 'Invalid device history directory.' }
        $pending = New-Object 'System.Collections.Generic.Stack[string]'
        $pending.Push($storageRoot)
        while ($pending.Count -gt 0) {
            $directory = $pending.Pop()
            Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $directory
            $directories.Add($directory)
            foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
                if (($files.Count + $directories.Count + $pending.Count) -ge 10000) { throw 'Device history is too large to remove in one operation.' }
                Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $item.FullName
                if ($item.PSIsContainer) { $pending.Push($item.FullName) }
                else {
                    if ([IO.Path]::GetFileName([IO.Path]::GetDirectoryName($storageRoot)) -ceq 'scans') {
                        Assert-WinSecStoredScanRemovalOwnership -Path $item.FullName -DeviceId $DeviceId
                    }
                    $files.Add([pscustomobject]@{Path=$item.FullName; Hash=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash})
                }
            }
        }
    }
    $local = New-WinSecLocalTarget
    $request = [pscustomobject]@{
        Operation='DELETE_DEVICE'; DeviceId=$DeviceId; Hostname=[string]$owner.Hostname
        MemoryScanCount=@($sessionKeys).Count; StoredFileCount=$files.Count
        IncludesHistory=$true; Irreversible=$true
        RegistersAgainOnStartup=[string]::Equals($DeviceId,$local.DeviceId,[StringComparison]::OrdinalIgnoreCase)
    }
    $requestJson = ConvertTo-Json -InputObject $request -Depth 4 -Compress
    $fingerprint = $inventoryHash + '|' + $requestJson + '|' + (@($sessionKeys) -join '|') + '|' +
        (ConvertTo-Json -InputObject @($files.ToArray() | Sort-Object Path) -Depth 4 -Compress) + '|' +
        (@($directories.ToArray() | Sort-Object) -join '|')
    return [pscustomobject]@{
        Inventory=$inventory; InventoryHash=$inventoryHash; RequestJson=$requestJson; Fingerprint=$fingerprint
        SessionKeys=@($sessionKeys); Files=$files.ToArray(); Directories=$directories.ToArray(); Roots=$roots
        DeviceId=$DeviceId
    }
}

function Remove-WinSecManagedDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$DeviceId,
        [Parameter(Mandatory)][object]$Coordinator,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Devices,
        [scriptblock]$ConfirmAction
    )
    $ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
    if ($null -eq $ConfirmAction) { throw 'Explicit device deletion confirmation is required.' }
    $plan = Get-WinSecDeviceRemovalPlan -ProjectRoot $ProjectRoot -DeviceId $DeviceId -Coordinator $Coordinator -Devices $Devices
    $preview = ConvertFrom-Json -InputObject $plan.RequestJson
    try { $answer = @(& $ConfirmAction $preview) }
    catch { throw 'Device deletion confirmation failed.' }
    if ($answer.Count -ne 1 -or $answer[0] -isnot [bool]) { throw 'Ambiguous device deletion confirmation.' }
    if (-not $answer[0]) { return $null }
    if ((ConvertTo-Json -InputObject $preview -Depth 4 -Compress) -cne $plan.RequestJson) { throw 'Device deletion request was modified.' }
    $store = Open-WinSecDeviceInventoryStore -ProjectRoot $ProjectRoot
    $started = $false
    $failureStage = 'SNAPSHOT'
    try {
        $current = Get-WinSecDeviceRemovalPlan -ProjectRoot $ProjectRoot -DeviceId $DeviceId -Coordinator $Coordinator -Devices $Devices
        if ($current.Fingerprint -cne $plan.Fingerprint) { throw 'Device data changed; confirm a new deletion request.' }
        $remaining = @($plan.Inventory.targets | Where-Object { -not [string]::Equals($_.DeviceId,$plan.DeviceId,[StringComparison]::OrdinalIgnoreCase) })
        $removedHashes = @()
        if ($plan.Inventory.schemaVersion -ceq '1.1.0') { $removedHashes = @($plan.Inventory.removedDeviceHashes) }
        $identityHash = Get-WinSecDeviceInventoryIdentityHash $plan.DeviceId
        if ($removedHashes -cnotcontains $identityHash) { $removedHashes += $identityHash }
        $updated = [pscustomobject]@{schemaVersion='1.1.0'; targets=$remaining; removedDeviceHashes=@($removedHashes)}
        $json = ConvertTo-Json -InputObject $updated -Depth 8
        $null = ConvertFrom-WinSecDeviceInventoryJson -Json $json
        # All consent/snapshot checks precede mutation. Physical deletion is
        # deliberately nonrecursive and reports an incomplete operation on error.
        $started = $true
        $failureStage = 'HISTORY'
        foreach ($file in $plan.Files) {
            Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $file.Path
            if ((Get-FileHash -LiteralPath $file.Path -Algorithm SHA256 -ErrorAction Stop).Hash -cne $file.Hash) { throw 'Device history changed during deletion.' }
            [IO.File]::Delete($file.Path)
            if ([IO.File]::Exists($file.Path)) { throw 'History file deletion failed.' }
        }
        foreach ($directory in @($plan.Directories | Sort-Object Length -Descending)) {
            Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $directory
            # Delete(false) rejects a file appearing after the snapshot.
            [IO.Directory]::Delete($directory, $false)
        }
        foreach ($path in $plan.Roots) {
            Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
            if (Test-Path -LiteralPath $path -ErrorAction Stop) { throw 'Device history was recreated during deletion.' }
        }
        $failureStage = 'INVENTORY_SAVE'
        $null = Save-WinSecDeviceInventory -Store $store -Json $json -ExpectedFingerprint $plan.InventoryHash
        $failureStage = 'INVENTORY_VERIFY'
        $saved = Import-WinSecDeviceInventory -ProjectRoot $ProjectRoot
        if ((ConvertTo-Json -InputObject $saved -Depth 8 -Compress) -cne
            (ConvertTo-Json -InputObject (ConvertFrom-WinSecDeviceInventoryJson $json) -Depth 8 -Compress)) {
            throw 'Device deletion verification failed.'
        }
        return [pscustomobject]@{Status='REMOVED'; DeviceId=$plan.DeviceId}
    }
    catch {
        if (-not $started) { throw 'Device deletion was rejected before any removal.' }
        # Do not claim atomicity across files or restore deleted history.
        # A retained row allows a fresh confirmed retry after a storage failure.
        return [pscustomobject]@{Status='INCOMPLETE'; DeviceId=$plan.DeviceId;
            FailureStage=$failureStage; FailureCode=$_.Exception.GetBaseException().HResult}
    }
    finally {
        try {
            if ($started) {
                foreach ($key in $plan.SessionKeys) { $Coordinator.Sessions.Remove($key) }
            }
        }
        finally { $store.Lock.Dispose() }
    }
}
