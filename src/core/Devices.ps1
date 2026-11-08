function Get-WinSecDeviceId {
    param([string]$HostName)
    $name=ConvertTo-WinSecSafeName $HostName
    if (-not $name -or $name -in @('.','..')) { throw 'Nombre de dispositivo no valido.' }
    return $name.ToUpperInvariant()
}

function Get-WinSecLocalDevice {
    # The OS guard must precede every hardware query. No serials or UUIDs are saved.
    $os=Assert-WinSecWindows11
    $hardware=[ordered]@{ manufacturer=$null; model=$null; memoryBytes=$null; logicalProcessors=$null; processors=@() }
    $warnings=@()
    try {
        $system=Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $safe=Select-WinSecProperties $system @('Manufacturer','Model','TotalPhysicalMemory','NumberOfLogicalProcessors')
        $hardware.manufacturer=$safe.Manufacturer
        $hardware.model=$safe.Model
        $hardware.memoryBytes=$safe.TotalPhysicalMemory
        $hardware.logicalProcessors=$safe.NumberOfLogicalProcessors
    } catch { $warnings+=('Win32_ComputerSystem: '+$_.Exception.Message) }
    try {
        $hardware.processors=@(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | ForEach-Object {
            $safe=Select-WinSecProperties $_ @('Name')
            [string]$safe.Name
        })
    } catch { $warnings+=('Win32_Processor: '+$_.Exception.Message) }
    return [pscustomobject]@{
        id=(Get-WinSecDeviceId $env:COMPUTERNAME); host=$env:COMPUTERNAME
        hardware=$hardware; warnings=$warnings
        os=[ordered]@{ family='Windows11'; edition=$os.Edition; build=$os.Build; arch=$os.Arch; productType=1 }
    }
}

function Assert-WinSecDevicePath {
    param([string]$Root,[string]$Path)
    $base=[IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $full=[IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (-not $full.StartsWith($base+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Ruta de dispositivo fuera del inventario.'
    }
    # Check ancestors too: a junction above OutputRoot can redirect deletion.
    $cursor=$full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'No se admiten enlaces o junctions en rutas de dispositivos.' }
        }
        $cursor=Split-Path -Parent $cursor
    }
    return $full
}

function Get-WinSecDeviceDirectories {
    param([string]$OutputRoot,[string]$DeviceId)
    $root=Get-WinSecOutputRoot $OutputRoot
    if (-not (Test-Path -LiteralPath $root)) { return }
    foreach ($osDir in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop)) {
        if ($osDir.Name -notmatch '^Windows11_[a-zA-Z0-9._-]+_[0-9]+$') { continue }
        [void](Assert-WinSecDevicePath $root $osDir.FullName)
        foreach ($hostDir in @(Get-ChildItem -LiteralPath $osDir.FullName -Directory -Force -ErrorAction Stop)) {
            if ($DeviceId -and (Get-WinSecDeviceId $hostDir.Name) -ne $DeviceId) { continue }
            [void](Assert-WinSecDevicePath $root $hostDir.FullName)
            $hostDir
        }
    }
}

function Get-WinSecDeviceInventory {
    param([string]$OutputRoot)
    $root=Get-WinSecOutputRoot $OutputRoot
    $path=Join-Path $root 'inventory.json'
    [void](Assert-WinSecDevicePath $root $path)
    if (Test-Path -LiteralPath $path) {
        $inventory=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($inventory.schemaVersion -ne '1') { throw 'Esquema de inventario no compatible.' }
        $seen=@{}
        foreach ($device in @($inventory.devices)) {
            if ($device.id -cne (Get-WinSecDeviceId $device.host) -or $seen.ContainsKey($device.id)) { throw 'Identidad de inventario no valida o duplicada.' }
            if ([string]::IsNullOrWhiteSpace($device.name) -or $device.name.Length -gt 80 -or $device.name -match '[\x00-\x1f\x7f]') { throw 'Nombre de inventario no valido.' }
            $seen[$device.id]=$true
        }
    } else { $inventory=[pscustomobject]@{schemaVersion='1';devices=@()} }
    # Discover older captures without changing their manifests or evidence.
    foreach ($directory in @(Get-WinSecDeviceDirectories $root)) {
        $id=Get-WinSecDeviceId $directory.Name
        if (@($inventory.devices | Where-Object {$_.id -eq $id}).Count -eq 0) {
            $inventory.devices+= [pscustomobject]@{
                id=$id;host=$directory.Name;name=$directory.Name;hardware=$null;os=$null
                warnings=@();firstSeenAtUtc=$null;lastSeenAtUtc=$null
            }
        }
    }
    return $inventory
}

function Get-WinSecDeviceSnapshots {
    param([string]$OutputRoot,[string]$DeviceId)
    $files=@(foreach ($directory in @(Get-WinSecDeviceDirectories -OutputRoot $OutputRoot -DeviceId $DeviceId)) {
        foreach ($run in @(Get-ChildItem -LiteralPath $directory.FullName -Directory -ErrorAction Stop)) {
            [void](Assert-WinSecDevicePath $OutputRoot $run.FullName)
            $path=Join-Path $run.FullName 'manifest.json'
            [void](Assert-WinSecDevicePath $OutputRoot $path)
            if (Test-Path -LiteralPath $path -PathType Leaf) { Get-Item -LiteralPath $path }
        }
    })
    return @($files | Sort-Object LastWriteTimeUtc -Descending)
}

function Save-WinSecDeviceInventory {
    param([string]$OutputRoot,$Inventory)
    $root=Get-WinSecOutputRoot $OutputRoot
    $path=Join-Path $root 'inventory.json'
    [void](Assert-WinSecDevicePath $root $path)
    [void](Save-WinSecJson -Path $path -Value $Inventory)
}

function Open-WinSecDeviceHistory {
    param($Session,[string]$DeviceId)
    $contexts=@(foreach ($file in @(Get-WinSecDeviceSnapshots -OutputRoot $Session.OutputRoot -DeviceId $DeviceId)) {
        $context=Get-WinSecSnapshotManifest -Snapshot $file.FullName
        if ((Get-WinSecDeviceId $context.Manifest.host) -ne $DeviceId) { throw 'La captura no pertenece al dispositivo seleccionado.' }
        $context
    })
    $Session.SavedContexts=$contexts
    if (-not $Session.Snapshot -and $contexts.Count -gt 0) {
        $Session.Snapshot=$contexts[0].Path
        $Session.Context=$contexts[0]
    }
}

function Register-WinSecDevice {
    param([string]$OutputRoot,$LocalDevice,$Session)
    $inventory=Get-WinSecDeviceInventory $OutputRoot
    $existing=@($inventory.devices | Where-Object {$_.id -eq $LocalDevice.id})
    $now=(Get-Date).ToUniversalTime().ToString('o')
    if ($existing.Count -eq 0) {
        $entry=[pscustomobject]@{
            id=$LocalDevice.id;host=$LocalDevice.host;name=$LocalDevice.host
            hardware=$LocalDevice.hardware;os=$LocalDevice.os;warnings=@($LocalDevice.warnings)
            firstSeenAtUtc=$now;lastSeenAtUtc=$now
        }
        $inventory.devices+= $entry
    } else {
        $entry=$existing[0]
        $entry.host=$LocalDevice.host; $entry.hardware=$LocalDevice.hardware; $entry.os=$LocalDevice.os
        $entry.warnings=@($LocalDevice.warnings); $entry.lastSeenAtUtc=$now
        if (-not $entry.firstSeenAtUtc) { $entry.firstSeenAtUtc=$now }
    }
    Save-WinSecDeviceInventory -OutputRoot $OutputRoot -Inventory $inventory
    if ($existing.Count -eq 0) { Add-WinSecNotification -Session $Session -Message ('Device created: '+$entry.name) }
    return $inventory
}

function Rename-WinSecDevice {
    param([string]$OutputRoot,[string]$DeviceId,[string]$Name)
    $name=$Name.Trim()
    if ([string]::IsNullOrWhiteSpace($name) -or $name.Length -gt 80 -or $name -match '[\x00-\x1f\x7f]') { throw 'Usa un nombre de 1 a 80 caracteres, sin caracteres de control.' }
    $inventory=Get-WinSecDeviceInventory $OutputRoot
    $entries=@($inventory.devices | Where-Object {$_.id -eq $DeviceId})
    if ($entries.Count -ne 1) { throw 'Dispositivo no encontrado.' }
    $entries[0].name=$name
    Save-WinSecDeviceInventory -OutputRoot $OutputRoot -Inventory $inventory
    return $inventory
}

function Get-WinSecDeviceRemovalPlan {
    param([string]$OutputRoot,[string]$DeviceId)
    $inventory=Get-WinSecDeviceInventory $OutputRoot
    if (@($inventory.devices | Where-Object {$_.id -eq $DeviceId}).Count -ne 1) { throw 'Dispositivo no encontrado.' }
    $paths=@(Get-WinSecDeviceDirectories -OutputRoot $OutputRoot -DeviceId $DeviceId)
    # Validate every descendant before removing anything; never follow junctions.
    foreach ($directory in $paths) {
        $pending=New-Object System.Collections.Stack
        $pending.Push($directory.FullName)
        while ($pending.Count -gt 0) {
            $next=[string]$pending.Pop()
            foreach ($item in @(Get-ChildItem -LiteralPath $next -Force -ErrorAction Stop)) {
                [void](Assert-WinSecDevicePath $OutputRoot $item.FullName)
                if ($item.PSIsContainer) { $pending.Push($item.FullName) }
            }
        }
    }
    return @($paths | ForEach-Object {$_.FullName})
}

function Remove-WinSecDeviceData {
    param([string]$OutputRoot,[string]$DeviceId,[string]$Confirmation)
    $inventory=Get-WinSecDeviceInventory $OutputRoot
    $entry=@($inventory.devices | Where-Object {$_.id -eq $DeviceId})
    if ($entry.Count -ne 1 -or $Confirmation -cne $entry[0].host) { throw 'Confirma escribiendo el hostname exacto del dispositivo.' }
    $paths=@(Get-WinSecDeviceRemovalPlan -OutputRoot $OutputRoot -DeviceId $DeviceId)
    foreach ($path in $paths) {
        $checked=Assert-WinSecDevicePath -Root $OutputRoot -Path $path
        Remove-Item -LiteralPath $checked -Recurse -Force -ErrorAction Stop
    }
    $inventory.devices=@($inventory.devices | Where-Object {$_.id -ne $DeviceId})
    Save-WinSecDeviceInventory -OutputRoot $OutputRoot -Inventory $inventory
    return $inventory
}
