
# ============================================================
# WinSec Analyzer
# Component : Device Inventory
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Persistent inventory for registered Windows devices.
#
# Features:
# - First-run local device registration
# - Persistent JSON storage
# - Duplicate DeviceId protection
# - Existing registration preservation
# - TargetRegistry schema validation
# - Atomic creation of inventory file
# - Separate device metadata from scan results
#
# PowerShell 5.1 / 7.x
#
# Security:
# - No audit execution
# - No remote connections
# - No scoring
# - No evidence collection or persistence
# - No security configuration changes
# ============================================================


# ============================================================
# RESOLVE INVENTORY STORAGE
# ============================================================

function Get-WinSecDeviceInventoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProjectRoot
    )

    $root = [System.IO.Path]::GetFullPath(
        $ProjectRoot
    )

    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'Project root does not exist.'
    }

    $dataPath = Join-Path $root 'data'

    # Never follow linked inventory directories.

    if (Test-Path -LiteralPath $dataPath) {
        $directory = Get-Item `
            -LiteralPath $dataPath `
            -Force `
            -ErrorAction Stop

        if (-not $directory.PSIsContainer) {
            throw 'Inventory data path is not a directory.'
        }

        if (
            ($directory.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw 'Linked inventory directories are not supported.'
        }
    }

    $inventoryPath = Join-Path `
        $dataPath 'devices.json'

    if (Test-Path -LiteralPath $inventoryPath) {
        $inventoryFile = Get-Item `
            -LiteralPath $inventoryPath `
            -Force `
            -ErrorAction Stop

        if ($inventoryFile.PSIsContainer) {
            throw 'Inventory path must be a file.'
        }

        if (
            ($inventoryFile.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw 'Linked inventory files are not supported.'
        }
    }

    return $inventoryPath
}


# ============================================================
# LOAD AND VALIDATE PERSISTENT INVENTORY
# ============================================================

function ConvertFrom-WinSecDeviceInventoryJson {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [object]$Json
    )

    if ($Json -isnot [string] -or
        [System.Text.Encoding]::UTF8.GetByteCount($Json) -gt 1048576) {
        throw 'Invalid device inventory JSON.'
    }
    $text = $Json.TrimStart([char]0xFEFF).Trim([char[]]@([char]32, [char]9, [char]13, [char]10))
    if ($text.Length -eq 0 -or $text[0] -ne '{') {
        throw 'Inventory JSON root must be an object.'
    }
    try {
        $registry = ConvertFrom-Json -InputObject $text -ErrorAction Stop
    }
    catch {
        # Parser diagnostics can contain parts of the supplied document.
        throw 'Invalid device inventory JSON.'
    }

    # ConvertFrom-Json can silently keep the last repeated property. Inspect
    # lexical JSON tokens after syntax parsing, preserving object
    # boundaries and decoding escaped property names before duplicate checks.
    $tokens = [regex]::Matches($text, '"(?:\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4})|[^"\\\x00-\x1F])*"|//[^\r\n]*|/\*[\s\S]*?\*/|[{}\[\]:,]|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null')
    $containers = New-Object 'System.Collections.Generic.Stack[object]'
    $consumed = 0
    for ($index = 0; $index -lt $tokens.Count; $index++) {
        # No unquoted keys, single-quoted strings, unknown escapes or other
        # parser extensions may bypass property-name inspection.
        if ([regex]::IsMatch($text.Substring($consumed, $tokens[$index].Index - $consumed), '[^ \t\r\n]')) {
            throw 'Invalid device inventory JSON.'
        }
        $consumed = $tokens[$index].Index + $tokens[$index].Length
        $token = $tokens[$index].Value
        if ($token.StartsWith('/')) {
            throw 'Inventory JSON comments are not supported.'
        }
        if ($token -ceq '{') {
            $containers.Push([pscustomobject]@{
                Kind = 'OBJECT'
                Keys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            })
        }
        elseif ($token -ceq '[') {
            $containers.Push([pscustomobject]@{ Kind = 'ARRAY' })
        }
        elseif ($token -in @('}', ']')) {
            $null = $containers.Pop()
        }
        elseif ($token -ceq ',') {
            $next = $tokens[$index].Index + 1
            while ($next -lt $text.Length -and [char]::IsWhiteSpace($text[$next])) { $next++ }
            if ($next -lt $text.Length -and $text[$next] -in @('}', ']')) {
                throw 'Inventory JSON trailing commas are not supported.'
            }
        }
        elseif ($token.StartsWith('"') -and $index + 1 -lt $tokens.Count -and
            $tokens[$index + 1].Value -ceq ':') {
            $key = (ConvertFrom-Json -InputObject ('{"Key":' + $token + '}') -ErrorAction Stop).Key
            if ($containers.Count -eq 0 -or $containers.Peek().Kind -cne 'OBJECT' -or
                -not $containers.Peek().Keys.Add([string]$key)) {
                throw 'Duplicate inventory JSON property.'
            }
        }
    }

    if ([regex]::IsMatch($text.Substring($consumed), '[^ \t\r\n]')) {
        throw 'Invalid device inventory JSON.'
    }
    $rootNames = @($registry.PSObject.Properties.Name)
    if ($registry -isnot [pscustomobject] -or $rootNames.Count -ne 2 -or
        $rootNames -cnotcontains 'schemaVersion' -or $rootNames -cnotcontains 'targets' -or
        $registry.schemaVersion -isnot [string] -or $registry.schemaVersion -cne '1.0.0' -or
        $registry.targets -isnot [array]) {
        throw 'Invalid device inventory schema.'
    }
    foreach ($target in $registry.targets) {
        if ($target -isnot [pscustomobject]) { throw 'Invalid inventory device record.' }
        $names = @($target.PSObject.Properties.Name)
        foreach ($name in $names) {
            if ($name -cnotin @('DeviceId', 'Hostname', 'Mode', 'Enabled', 'Description', 'RegisteredAtUtc')) {
                throw 'Unexpected inventory device field.'
            }
        }
        foreach ($required in @('DeviceId', 'Hostname', 'Mode', 'Enabled')) {
            if ($names -cnotcontains $required) { throw 'Missing inventory device field.' }
        }
        if ($target.DeviceId -isnot [string] -or $target.Hostname -isnot [string] -or
            $target.Mode -isnot [string] -or $target.Mode -cnotin @('LOCAL', 'REMOTE', 'IMPORTED', 'UNKNOWN') -or
            $target.Enabled -isnot [bool] -or
            ($names -ccontains 'Description' -and $target.Description -isnot [string])) {
            throw 'Invalid inventory device field type.'
        }
        if ($names -ccontains 'RegisteredAtUtc') {
            $timestamp = $target.RegisteredAtUtc
            # PowerShell 7 decodes ISO dates as DateTime; 5.1 keeps strings.
            if ($timestamp -is [DateTime]) {
                if ($timestamp.Kind -ne [DateTimeKind]::Utc) { throw 'Invalid inventory UTC timestamp.' }
            }
            elseif ($timestamp -is [string] -and
                $timestamp -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$') {
                $parsed = [DateTime]::MinValue
                if (-not [DateTime]::TryParse($timestamp, [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)) {
                    throw 'Invalid inventory UTC timestamp.'
                }
            }
            else { throw 'Invalid inventory UTC timestamp.' }
        }
    }
    $validation = Test-WinSecTargetRegistry -Registry $registry
    if (-not $validation.Valid) {
        # Do not include values embedded in TargetRegistry diagnostics.
        throw 'Invalid device inventory identities or metadata.'
    }
    return $registry
}

function Import-WinSecDeviceInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProjectRoot
    )

    $registryPath = Join-Path `
        $ProjectRoot 'src/Core/TargetRegistry.ps1'

    if (-not (
        Test-Path -LiteralPath $registryPath -PathType Leaf
    )) {
        throw 'TargetRegistry dependency not found.'
    }

    # TargetRegistry remains read-only.

    if (-not (
        Get-Command Test-WinSecTargetRegistry `
            -CommandType Function `
            -ErrorAction SilentlyContinue
    )) {
        . $registryPath
    }

    $path = Get-WinSecDeviceInventoryPath `
        -ProjectRoot $ProjectRoot

    # An absent inventory represents the first launch.

    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject]@{
            schemaVersion = '1.0.0'
            targets = @()
        }
    }

    $file = Get-Item `
        -LiteralPath $path `
        -ErrorAction Stop

    if ($file.Length -gt 1048576) {
        throw 'Device inventory exceeds 1 MiB.'
    }

    $json = Get-Content `
        -LiteralPath $path `
        -Raw `
        -Encoding UTF8 `
        -ErrorAction Stop

    return ConvertFrom-WinSecDeviceInventoryJson -Json $json
}


# ============================================================
# REGISTER CURRENT LOCAL DEVICE
# ============================================================

function Register-WinSecLocalDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProjectRoot
    )

    $registryPath = Join-Path `
        $ProjectRoot 'src/Core/TargetRegistry.ps1'

    if (-not (
        Test-Path -LiteralPath $registryPath -PathType Leaf
    )) {
        throw 'TargetRegistry dependency not found.'
    }

    if (-not (
        Get-Command New-WinSecLocalTarget `
            -CommandType Function `
            -ErrorAction SilentlyContinue
    )) {
        . $registryPath
    }

    # --------------------------------------------------------
    # Resolve the real local machine
    # --------------------------------------------------------

    $localDevice = New-WinSecLocalTarget

    if (
        $null -eq $localDevice -or
        $localDevice.Mode -cne 'LOCAL'
    ) {
        throw 'Unable to identify the local device.'
    }

    $inventory = Import-WinSecDeviceInventory `
        -ProjectRoot $ProjectRoot

    $path = Get-WinSecDeviceInventoryPath `
        -ProjectRoot $ProjectRoot

    # --------------------------------------------------------
    # Reuse an existing registration
    # --------------------------------------------------------

    foreach ($target in $inventory.targets) {
        if (
            [string]::Equals(
                [string]$target.DeviceId,
                [string]$localDevice.DeviceId,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            if (
                $target.Mode -cne 'LOCAL' -or
                -not [string]::Equals(
                    [string]$target.Hostname,
                    [string]$localDevice.Hostname,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            ) {
                throw 'Conflicting local device registration.'
            }

            # Do not change Enabled or other saved settings.
            # Existing registrations are not rewritten.

            return [pscustomobject]@{
                Created = $false
                DeviceId = [string]$target.DeviceId
                Hostname = [string]$target.Hostname
                Path = $path
                Status = 'ALREADY_REGISTERED'
            }
        }
    }

    # --------------------------------------------------------
    # Build the first persistent registration
    # --------------------------------------------------------

    $newTarget = [pscustomobject]@{
        DeviceId = [string]$localDevice.DeviceId
        Hostname = [string]$localDevice.Hostname
        Mode = 'LOCAL'
        Enabled = $true
        Description = 'Local Windows device'
        RegisteredAtUtc = (
            [DateTime]::UtcNow.ToString('o')
        )
    }

    $targets = @(
        @($inventory.targets) + @($newTarget)
    )

    $updatedInventory = [pscustomobject]@{
        schemaVersion = '1.0.0'
        targets = $targets
    }

    # --------------------------------------------------------
    # Validate before writing
    # --------------------------------------------------------

    $validation = Test-WinSecTargetRegistry `
        -Registry $updatedInventory

    if (-not $validation.Valid) {
        throw (
            'Device registration rejected: {0}' -f
            ($validation.Errors -join '; ')
        )
    }

    # --------------------------------------------------------
    # Prepare the storage directory
    # --------------------------------------------------------

    $dataDirectory = Split-Path `
        -Path $path `
        -Parent

    if (-not (
        Test-Path -LiteralPath $dataDirectory
    )) {
        $null = New-Item `
            -Path $dataDirectory `
            -ItemType Directory `
            -ErrorAction Stop
    }

    # Recheck the path after directory creation.

    $path = Get-WinSecDeviceInventoryPath `
        -ProjectRoot $ProjectRoot

    # Existing inventory files must never be overwritten
    # by first-run registration.

    if (Test-Path -LiteralPath $path) {
        throw (
            'Inventory already exists and requires ' +
            'a controlled update operation.'
        )
    }

    # --------------------------------------------------------
    # Serialize only device inventory information
    # --------------------------------------------------------

    $json = ConvertTo-Json `
        -InputObject $updatedInventory `
        -Depth 8

    if (
        [System.Text.Encoding]::UTF8.GetByteCount($json) -gt
        1048576
    ) {
        throw 'Updated inventory exceeds 1 MiB.'
    }

    # --------------------------------------------------------
    # Write through a temporary file
    # --------------------------------------------------------

    $temporaryPath = Join-Path `
        $dataDirectory `
        ('.devices-{0}.tmp' -f [Guid]::NewGuid().ToString('N'))

    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)

        [System.IO.File]::WriteAllText(
            $temporaryPath,
            $json,
            $encoding
        )

        # Atomic first creation on the same filesystem.
        # File.Move rejects an already existing destination.

        [System.IO.File]::Move(
            $temporaryPath,
            $path
        )
    }
    finally {
        if (
            Test-Path -LiteralPath $temporaryPath
        ) {
            Remove-Item `
                -LiteralPath $temporaryPath `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }

    # --------------------------------------------------------
    # Verify the stored inventory
    # --------------------------------------------------------

    $savedInventory = Import-WinSecDeviceInventory `
        -ProjectRoot $ProjectRoot

    $savedMatches = @(
        $savedInventory.targets | Where-Object {
            $_.DeviceId -ceq $localDevice.DeviceId
        }
    )

    if ($savedMatches.Count -ne 1) {
        throw 'Saved local device verification failed.'
    }

    return [pscustomobject]@{
        Created = $true
        DeviceId = [string]$localDevice.DeviceId
        Hostname = [string]$localDevice.Hostname
        Path = $path
        Status = 'REGISTERED'
    }
}
