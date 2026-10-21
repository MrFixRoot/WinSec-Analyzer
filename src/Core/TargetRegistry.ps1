
# ============================================================
# WinSec Analyzer
# Component  : Target Registry
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Secure registry of Windows assessment targets.
#
# Includes:
# - Configuration loading and schema validation
# - Local, remote, and imported target identification
# - Duplicate DeviceId protection
# - Device lookup and filtering
# - First-run local device fallback
# - CLI-compatible device representation
# - Strict separation of targets from scan results
#
# PowerShell 5.1 / 7.x
#
# IMPORTANT:
# Read-only component.
# No remote connections or security configuration changes.
# Registration does not authorize execution.
# Target metadata never authorizes a security score.
# ============================================================


# ============================================================
# OBJECT PROPERTY HELPER
# ============================================================

function Get-WinSecTargetField {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if (
                [string]::Equals(
                    [string]$key,
                    $Name,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            ) {
                return ,$InputObject[$key]
            }
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $null
    }

    return ,$property.Value
}


# ============================================================
# IDENTIFIER VALIDATION
# ============================================================

function Test-WinSecTargetIdentifier {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,

        [int]$MaximumLength = 128
    )

    if ($Value -isnot [string]) {
        return $false
    }

    if (
        [string]::IsNullOrWhiteSpace($Value) -or
        $Value.Length -gt $MaximumLength -or
        $Value -cne $Value.Trim()
    ) {
        return $false
    }

    # Identifiers cannot contain control characters,
    # whitespace, command separators, or path separators.

    return (
        $Value -cmatch '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    )
}


# ============================================================
# NORMALIZE ONE TARGET
# ============================================================

function ConvertTo-WinSecRegisteredTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Target
    )

    if (
        $Target -is [string] -or
        $Target -is [array]
    ) {
        throw 'A target must be a structured object.'
    }

    # --------------------------------------------------------
    # Device identity
    # --------------------------------------------------------

    $deviceId = Get-WinSecTargetField `
        -InputObject $Target `
        -Name 'DeviceId'

    if ($null -eq $deviceId) {
        $deviceId = Get-WinSecTargetField `
            -InputObject $Target `
            -Name 'Id'
    }

    if (-not (
        Test-WinSecTargetIdentifier -Value $deviceId
    )) {
        throw 'Target requires a valid DeviceId.'
    }

    # --------------------------------------------------------
    # Hostname
    # --------------------------------------------------------

    $hostname = Get-WinSecTargetField `
        -InputObject $Target `
        -Name 'Hostname'

    if ($null -eq $hostname) {
        $hostname = Get-WinSecTargetField `
            -InputObject $Target `
            -Name 'Name'
    }

    if ($null -eq $hostname) {
        $hostname = $deviceId
    }

    if (-not (
        Test-WinSecTargetIdentifier `
            -Value $hostname `
            -MaximumLength 253
    )) {
        throw "Invalid Hostname for target: $deviceId"
    }

    # --------------------------------------------------------
    # Collection mode
    # --------------------------------------------------------

    $declaredMode = Get-WinSecTargetField `
        -InputObject $Target `
        -Name 'Mode'

    $inferredMode = 'UNKNOWN'

    if ($deviceId.StartsWith(
        'local:',
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        $inferredMode = 'LOCAL'
    }
    elseif ($deviceId.StartsWith(
        'remote:',
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        $inferredMode = 'REMOTE'
    }
    elseif ($deviceId.StartsWith(
        'imported:',
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        $inferredMode = 'IMPORTED'
    }

    if ($null -eq $declaredMode) {
        $mode = $inferredMode
    }
    else {
        if (
            $declaredMode -isnot [string] -or
            [string]::IsNullOrWhiteSpace($declaredMode)
        ) {
            throw "Invalid Mode for target: $deviceId"
        }

        $mode = $declaredMode.ToUpperInvariant()
    }

    if ($mode -cnotin @(
        'LOCAL',
        'REMOTE',
        'IMPORTED',
        'UNKNOWN'
    )) {
        throw "Unsupported target Mode: $mode"
    }

    # A prefixed DeviceId must agree with its declared mode.

    if (
        $inferredMode -cne 'UNKNOWN' -and
        $mode -cne $inferredMode
    ) {
        throw (
            "DeviceId and Mode mismatch for target: $deviceId"
        )
    }

    # --------------------------------------------------------
    # Registry enablement
    # --------------------------------------------------------

    $enabled = Get-WinSecTargetField `
        -InputObject $Target `
        -Name 'Enabled'

    if ($null -eq $enabled) {
        $enabled = $false
    }
    elseif ($enabled -isnot [bool]) {
        throw "Enabled must be Boolean: $deviceId"
    }

    # Enabled only means the target is available for
    # selection. It never authorizes a scan by itself.

    # --------------------------------------------------------
    # Optional description
    # --------------------------------------------------------

    $description = Get-WinSecTargetField `
        -InputObject $Target `
        -Name 'Description'

    if ($null -eq $description) {
        $description = ''
    }

    if (
        $description -isnot [string] -or
        $description.Length -gt 512 -or
        $description -match '[\x00-\x1F\x7F]'
    ) {
        throw "Invalid target Description: $deviceId"
    }

    # --------------------------------------------------------
    # Return normalized target
    # --------------------------------------------------------

    # Score, ScanId, LastScan and Status are not trusted
    # when read from target configuration.
    #
    # Real values must come from scan results associated
    # with the same DeviceId and ScanId.

    return [pscustomobject]@{
        DeviceId = [string]$deviceId
        Id = [string]$deviceId

        Hostname = [string]$hostname
        Name = [string]$hostname

        Mode = $mode
        Enabled = [bool]$enabled
        Description = $description

        Score = $null
        Status = 'PENDING'
        LastScan = 'Never'
        ScanId = ''

        Source = 'CONFIG'
    }
}


# ============================================================
# VALIDATE TARGET REGISTRY
# ============================================================

function Test-WinSecTargetRegistry {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Registry
    )

    $errors = New-Object `
        'System.Collections.Generic.List[string]'

    $targetCount = 0

    # --------------------------------------------------------
    # Root object
    # --------------------------------------------------------

    if (
        $null -eq $Registry -or
        $Registry -is [array] -or
        $Registry -is [string]
    ) {
        $errors.Add(
            'Target registry root must be an object.'
        )
    }
    else {
        # ----------------------------------------------------
        # Schema version
        # ----------------------------------------------------

        $schema = Get-WinSecTargetField `
            -InputObject $Registry `
            -Name 'schemaVersion'

        if ($schema -cne '1.0.0') {
            $errors.Add(
                'Unsupported target registry schema.'
            )
        }

        # ----------------------------------------------------
        # Targets collection
        # ----------------------------------------------------

        $targets = Get-WinSecTargetField `
            -InputObject $Registry `
            -Name 'targets'

        if ($targets -isnot [array]) {
            $errors.Add(
                'Registry.targets must be a JSON array.'
            )
        }
        else {
            $seen = New-Object `
                'System.Collections.Generic.HashSet[string]' `
                ([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($target in $targets) {
                try {
                    if ($null -eq $target) {
                        throw 'Null target entry.'
                    }

                    $normalized = ConvertTo-WinSecRegisteredTarget `
                        -Target $target

                    if (-not $seen.Add(
                        $normalized.DeviceId
                    )) {
                        throw (
                            'Duplicate DeviceId: {0}' -f
                            $normalized.DeviceId
                        )
                    }

                    $targetCount++
                }
                catch {
                    $errors.Add(
                        $_.Exception.Message
                    )
                }
            }
        }
    }

    $valid = ($errors.Count -eq 0)

    return [pscustomobject]@{
        Valid = $valid

        Status = if ($valid) {
            'VALID'
        }
        else {
            'INVALID'
        }

        SchemaVersion = if ($null -ne $Registry) {
            Get-WinSecTargetField `
                -InputObject $Registry `
                -Name 'schemaVersion'
        }
        else {
            $null
        }

        TargetCount = $targetCount
        Errors = @($errors.ToArray())
    }
}


# ============================================================
# IMPORT TARGET REGISTRY
# ============================================================

function Import-WinSecTargetRegistry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProjectRoot
    )

    $root = [System.IO.Path]::GetFullPath(
        $ProjectRoot
    )

    $configPath = Join-Path `
        -Path $root `
        -ChildPath 'config'

    $path = Join-Path `
        -Path $configPath `
        -ChildPath 'targets.json'

    if (-not (
        Test-Path -LiteralPath $path -PathType Leaf
    )) {
        throw "Target registry not found: $path"
    }

    try {
        # Reject linked config directories/files to avoid
        # unintentionally reading external locations.

        foreach ($itemPath in @(
            $configPath,
            $path
        )) {
            $item = Get-Item `
                -LiteralPath $itemPath `
                -ErrorAction Stop

            if (
                ($item.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                throw (
                    'Linked target registry paths are not supported.'
                )
            }
        }

        $file = Get-Item `
            -LiteralPath $path `
            -ErrorAction Stop

        if ($file.Length -gt 1048576) {
            throw 'Target registry exceeds 1 MiB.'
        }

        $json = Get-Content `
            -LiteralPath $path `
            -Encoding UTF8 `
            -Raw `
            -ErrorAction Stop

        # Validate JSON root before ConvertFrom-Json,
        # including single-element JSON arrays.

        $trimmed = $json.TrimStart(
            [char]0xFEFF
        ).TrimStart()

        if (
            $trimmed.Length -eq 0 -or
            $trimmed[0] -ne '{'
        ) {
            throw 'Target registry JSON root must be an object.'
        }

        $registry = ConvertFrom-Json `
            -InputObject $json `
            -ErrorAction Stop

        $validation = Test-WinSecTargetRegistry `
            -Registry $registry

        if (-not $validation.Valid) {
            throw (
                'Invalid target registry: {0}' -f
                ($validation.Errors -join '; ')
            )
        }

        # Return only the validated registry.
        # No modifications to targets.json are performed.

        return $registry
    }
    catch {
        throw (
            'Unable to import target registry: {0}' -f
            $_.Exception.Message
        )
    }
}


# ============================================================
# BUILD LOCAL DEVICE FALLBACK
# ============================================================

function Get-WinSecLocalHardwareDeviceId {
    [CmdletBinding()]
    param()

    # Local identity only; no remote session, raw identifier persistence or log.
    try {
        $products = @(Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_ComputerSystemProduct' `
            -Property UUID -OperationTimeoutSec 5 -ErrorAction Stop)
        if ($products.Count -ne 1 -or $products[0].UUID -isnot [string]) { throw 'Invalid hardware identity.' }
        $uuid = $products[0].UUID
        if ($uuid -cnotmatch '^[A-Fa-f0-9]{8}(-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$' -or
            $uuid -match '^(00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$') {
            throw 'Invalid hardware identity.'
        }
        $bytes = [Text.Encoding]::UTF8.GetBytes('WinSecAnalyzer:SMBIOS-UUID:v1:' + $uuid.ToLowerInvariant())
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
        return ('local:hw1-' + $hash)
    }
    catch { throw 'Unable to establish a valid local hardware identity.' }
}

function New-WinSecLocalTarget {
    [CmdletBinding()]
    param()

    $hostname = [string]$env:COMPUTERNAME

    if ([string]::IsNullOrWhiteSpace($hostname)) {
        $hostname = [Environment]::MachineName
    }

    if (-not (
        Test-WinSecTargetIdentifier `
            -Value $hostname `
            -MaximumLength 253
    )) {
        throw 'Unable to determine a valid local hostname.'
    }

    $deviceId = Get-WinSecLocalHardwareDeviceId

    return [pscustomobject]@{
        DeviceId = $deviceId
        Id = $deviceId

        Hostname = $hostname
        Name = $hostname

        Mode = 'LOCAL'
        Enabled = $true

        Description = 'Local Windows device'

        Score = $null
        Status = 'PENDING'
        LastScan = 'Never'
        ScanId = ''

        Source = 'LOCAL_FALLBACK'
    }
}


# ============================================================
# GET REGISTERED TARGETS
# ============================================================

function Get-WinSecRegisteredTargets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Registry,

        [switch]$IncludeLocalFallback,

        [switch]$EnabledOnly
    )

    # --------------------------------------------------------
    # Validate registry before processing
    # --------------------------------------------------------

    $validation = Test-WinSecTargetRegistry `
        -Registry $Registry

    if (-not $validation.Valid) {
        throw (
            'Target registry validation failed: {0}' -f
            ($validation.Errors -join '; ')
        )
    }

    $registered = New-Object `
        'System.Collections.Generic.List[object]'

    foreach ($entry in $Registry.targets) {
        $target = ConvertTo-WinSecRegisteredTarget `
            -Target $entry

        if (
            $EnabledOnly -and
            -not $target.Enabled
        ) {
            continue
        }

        $registered.Add($target)
    }

    # --------------------------------------------------------
    # Local placeholder for an empty target catalog
    # --------------------------------------------------------

    if (
        $registered.Count -eq 0 -and
        $Registry.targets.Count -eq 0 -and
        $IncludeLocalFallback
    ) {
        $registered.Add(
            (New-WinSecLocalTarget)
        )
    }

    return $registered.ToArray()
}


# ============================================================
# LOOK UP ONE TARGET
# ============================================================

function Get-WinSecRegisteredTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Registry,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceId,

        [switch]$IncludeLocalFallback
    )

    if (-not (
        Test-WinSecTargetIdentifier -Value $DeviceId
    )) {
        throw 'Invalid DeviceId.'
    }

    $targets = @(
        Get-WinSecRegisteredTargets `
            -Registry $Registry `
            -IncludeLocalFallback:$IncludeLocalFallback
    )

    foreach ($target in $targets) {
        if (
            [string]::Equals(
                $target.DeviceId,
                $DeviceId,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            return $target
        }
    }

    return $null
}
