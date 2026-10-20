
# ============================================================
# WinSec Analyzer
# Component  : Evidence Service
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Protected local storage and retrieval of assessment evidence.
#
# Includes:
# - DeviceId / ScanId / CheckId isolation
# - Windows DPAPI CurrentUser encryption
# - Deterministic SHA-256 storage identifiers
# - Identity validation before and after decryption
# - Duplicate evidence protection
# - Atomic file creation
# - Evidence index without raw evidence values
# - Reparse point protection
# - Bounded evidence payloads
#
# PowerShell 5.1 / 7.x on Windows
#
# IMPORTANT:
# - Never modifies Windows security configuration.
# - Only stores evidence explicitly supplied by callers.
# - Does not initiate remote sessions.
# - Encrypted evidence is bound to the Windows user.
# - This component does not certify evidence authenticity.
# - Raw evidence must never be exported as a public report.
# ============================================================

# ============================================================
# CONFIGURATION
# ============================================================

$script:WinSecEvidenceSchemaVersion = '1.0.0'

$script:WinSecEvidenceMaximumBytes = 2097152

$script:WinSecEvidenceMaximumFileBytes = 4194304

$script:WinSecEvidenceEntropy = (
    [System.Text.Encoding]::UTF8.GetBytes(
        'WinSec-Analyzer:EvidenceService:0.9.0:CurrentUser'
    )
)

# ============================================================
# FIELD ACCESS
# ============================================================

function Get-WinSecEvidenceField {
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

function Test-WinSecEvidenceIdentifier {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($Value -isnot [string]) {
        return $false
    }

    if (
        [string]::IsNullOrWhiteSpace($Value) -or
        $Value.Length -gt 128
    ) {
        return $false
    }

    return (
        $Value -cmatch '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    )
}

# ============================================================
# WINDOWS DPAPI AVAILABILITY
# ============================================================

function Assert-WinSecEvidenceProtection {
    [CmdletBinding()]
    param()

    if (
        [Environment]::OSVersion.Platform -ne
        [PlatformID]::Win32NT
    ) {
        throw 'Evidence encryption requires Windows DPAPI.'
    }

    $type = 'System.Security.Cryptography.ProtectedData' -as [type]

    if ($null -eq $type) {
        try {
            Add-Type `
                -AssemblyName 'System.Security.Cryptography.ProtectedData' `
                -ErrorAction Stop
        }
        catch {
            throw 'Windows DPAPI is unavailable in this runtime.'
        }

        $type = 'System.Security.Cryptography.ProtectedData' -as [type]
    }

    if ($null -eq $type) {
        throw 'Windows DPAPI type could not be loaded.'
    }

    return $true
}

# ============================================================
# HASHED STORAGE IDENTIFIERS
# ============================================================

function Get-WinSecEvidenceHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    if (-not (
        Test-WinSecEvidenceIdentifier $Value
    )) {
        throw 'Invalid evidence storage identifier.'
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes(
        $Value
    )

    $sha = [System.Security.Cryptography.SHA256]::Create()

    try {
        $hash = $sha.ComputeHash($bytes)

        return (
            [System.BitConverter]::ToString($hash).
                Replace('-', '').ToLowerInvariant()
        )
    }
    finally {
        $sha.Dispose()
    }
}

# ============================================================
# STORAGE PATH VALIDATION
# ============================================================

function Assert-WinSecEvidenceSafePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)

    $current = $fullPath

    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (
            [System.IO.File]::Exists($current) -or
            [System.IO.Directory]::Exists($current)
        ) {
            $item = Get-Item `
                -LiteralPath $current `
                -Force `
                -ErrorAction Stop

            if (
                (
                    $item.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint
                ) -ne 0
            ) {
                throw 'Evidence path contains a reparse point.'
            }
        }

        $parent = [System.IO.Path]::GetDirectoryName(
            $current
        )

        if (
            [string]::IsNullOrWhiteSpace($parent) -or
            $parent -ceq $current
        ) {
            break
        }

        $current = $parent
    }

    return $true
}

# ============================================================
# RESOLVE EVIDENCE STORAGE ROOT
# ============================================================

function Get-WinSecEvidenceStorageRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        throw 'ProjectRoot is required.'
    }

    $root = [System.IO.Path]::GetFullPath(
        $ProjectRoot
    )

    if (-not (
        Test-Path -LiteralPath $root -PathType Container
    )) {
        throw 'ProjectRoot does not exist.'
    }

    $reports = Join-Path $root 'reports'
    $evidence = Join-Path $reports 'evidence'

    if (-not (
        Test-Path -LiteralPath $reports -PathType Container
    )) {
        throw 'Project reports directory does not exist.'
    }

    $null = Assert-WinSecEvidenceSafePath -Path $evidence

    return [System.IO.Path]::GetFullPath($evidence)
}

# ============================================================
# RESOLVE AN EVIDENCE FILE
# ============================================================

function Get-WinSecEvidencePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [Parameter(Mandatory)]
        [string]$CheckId
    )

    foreach ($identifier in @(
        $DeviceId,
        $ScanId,
        $CheckId
    )) {
        if (-not (
            Test-WinSecEvidenceIdentifier $identifier
        )) {
            throw 'Invalid DeviceId, ScanId or CheckId.'
        }
    }

    $storageRoot = Get-WinSecEvidenceStorageRoot `
        -ProjectRoot $ProjectRoot

    $deviceHash = Get-WinSecEvidenceHash $DeviceId
    $scanHash = Get-WinSecEvidenceHash $ScanId
    $checkHash = Get-WinSecEvidenceHash $CheckId

    $deviceDirectory = Join-Path `
        $storageRoot $deviceHash

    $scanDirectory = Join-Path `
        $deviceDirectory $scanHash

    $filePath = Join-Path `
        $scanDirectory "$checkHash.wse"

    $null = Assert-WinSecEvidenceSafePath `
        -Path $filePath

    return [System.IO.Path]::GetFullPath($filePath)
}

# ============================================================
# VALIDATE A COLLECTOR RESULT
# ============================================================

function Test-WinSecEvidenceRecord {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$ControlResult
    )

    if (
        $null -eq $ControlResult -or
        $ControlResult -is [string] -or
        $ControlResult -is [array]
    ) {
        return $false
    }

    $deviceId = Get-WinSecEvidenceField `
        $ControlResult 'DeviceId'

    $scanId = Get-WinSecEvidenceField `
        $ControlResult 'ScanId'

    $checkId = Get-WinSecEvidenceField `
        $ControlResult 'CheckId'

    foreach ($identifier in @(
        $deviceId,
        $scanId,
        $checkId
    )) {
        if (-not (
            Test-WinSecEvidenceIdentifier $identifier
        )) {
            return $false
        }
    }

    $evidence = Get-WinSecEvidenceField `
        $ControlResult 'Evidence'

    if (
        $null -eq $evidence -or
        $evidence -is [string] -or
        $evidence -is [array]
    ) {
        return $false
    }

    foreach ($field in @(
        'DeviceId',
        'ScanId',
        'CheckId'
    )) {
        $outer = Get-WinSecEvidenceField `
            $ControlResult $field

        $inner = Get-WinSecEvidenceField `
            $evidence $field

        if (
            $inner -isnot [string] -or
            $outer -cne $inner
        ) {
            return $false
        }
    }

    $successful = Get-WinSecEvidenceField `
        $evidence 'CollectionSuccessful'

    if ($successful -isnot [bool]) {
        return $false
    }

    return $true
}

# ============================================================
# SERIALIZE AND PROTECT EVIDENCE
# ============================================================

function Protect-WinSecEvidenceRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ControlResult
    )

    $null = Assert-WinSecEvidenceProtection

    if (-not (
        Test-WinSecEvidenceRecord $ControlResult
    )) {
        throw 'Invalid collector evidence identity or structure.'
    }

    $evidence = Get-WinSecEvidenceField `
        $ControlResult 'Evidence'

    # Only the evidence payload and required metadata
    # are persisted. Score, Source, OriginalResult and
    # other arbitrary collector fields are not copied.

    $record = [pscustomobject]@{
        SchemaVersion = $script:WinSecEvidenceSchemaVersion

        DeviceId = [string]$ControlResult.DeviceId
        ScanId = [string]$ControlResult.ScanId
        CheckId = [string]$ControlResult.CheckId

        StoredAtUTC = [DateTime]::UtcNow.ToString('o')

        Evidence = $evidence
    }

    $json = ConvertTo-Json `
        -InputObject $record `
        -Depth 60 `
        -Compress `
        -ErrorAction Stop

    $bytes = [System.Text.Encoding]::UTF8.GetBytes(
        $json
    )

    if (
        $bytes.Length -eq 0 -or
        $bytes.Length -gt $script:WinSecEvidenceMaximumBytes
    ) {
        throw 'Evidence exceeds the permitted payload size.'
    }

    try {
        return ,(
            [System.Security.Cryptography.ProtectedData]::Protect(
                $bytes,
                $script:WinSecEvidenceEntropy,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )
        )
    }
    finally {
        [System.Array]::Clear(
            $bytes,
            0,
            $bytes.Length
        )
    }
}

# ============================================================
# DECRYPT AND VALIDATE EVIDENCE
# ============================================================

function Unprotect-WinSecEvidenceRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$ProtectedBytes,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [Parameter(Mandatory)]
        [string]$CheckId
    )

    $null = Assert-WinSecEvidenceProtection

    $plainBytes = $null

    try {
        $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $ProtectedBytes,
            $script:WinSecEvidenceEntropy,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )

        if (
            $plainBytes.Length -eq 0 -or
            $plainBytes.Length -gt $script:WinSecEvidenceMaximumBytes
        ) {
            throw 'Decrypted evidence size is invalid.'
        }

        $json = [System.Text.Encoding]::UTF8.GetString(
            $plainBytes
        )

        $record = ConvertFrom-Json `
            -InputObject $json `
            -ErrorAction Stop

        if (
            $null -eq $record -or
            $record -is [array] -or
            $record.SchemaVersion -cne
                $script:WinSecEvidenceSchemaVersion -or
            $record.DeviceId -cne $DeviceId -or
            $record.ScanId -cne $ScanId -or
            $record.CheckId -cne $CheckId
        ) {
            throw 'Evidence identity or schema validation failed.'
        }

        $control = [pscustomobject]@{
            DeviceId = $record.DeviceId
            ScanId = $record.ScanId
            CheckId = $record.CheckId
            Evidence = $record.Evidence
        }

        if (-not (
            Test-WinSecEvidenceRecord $control
        )) {
            throw 'Decrypted evidence structure is invalid.'
        }

        return $record
    }
    finally {
        if ($null -ne $plainBytes) {
            [System.Array]::Clear(
                $plainBytes,
                0,
                $plainBytes.Length
            )
        }
    }
}

# ============================================================
# SAVE PROTECTED EVIDENCE
# ============================================================

function Save-WinSecEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [object]$ControlResult
    )

    if (-not (
        Test-WinSecEvidenceRecord $ControlResult
    )) {
        throw 'Cannot save an invalid evidence record.'
    }

    $path = Get-WinSecEvidencePath `
        -ProjectRoot $ProjectRoot `
        -DeviceId $ControlResult.DeviceId `
        -ScanId $ControlResult.ScanId `
        -CheckId $ControlResult.CheckId

    $directory = [System.IO.Path]::GetDirectoryName(
        $path
    )

    # Protect evidence BEFORE creating files.

    $protectedBytes = Protect-WinSecEvidenceRecord `
        -ControlResult $ControlResult

    $temporaryFile = $null

    try {
        if (
            [System.IO.File]::Exists($path)
        ) {
            throw 'Evidence already exists; overwriting is forbidden.'
        }

        $null = [System.IO.Directory]::CreateDirectory(
            $directory
        )

        $null = Assert-WinSecEvidenceSafePath `
            -Path $directory

        $temporaryFile = Join-Path `
            $directory `
            (
                '.' +
                [guid]::NewGuid().ToString('N') +
                '.tmp'
            )

        # CreateNew prevents replacing an existing temp file.

        $stream = New-Object System.IO.FileStream(
            $temporaryFile,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )

        try {
            $stream.Write(
                $protectedBytes,
                0,
                $protectedBytes.Length
            )

            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }

        # File.Move does not overwrite an existing target.
        # Both paths are in the same directory.

        [System.IO.File]::Move(
            $temporaryFile,
            $path
        )

        $temporaryFile = $null

        return [pscustomobject]@{
            DeviceId = $ControlResult.DeviceId
            ScanId = $ControlResult.ScanId
            CheckId = $ControlResult.CheckId

            StorageStatus = 'STORED'
            Protected = $true
            ProtectionScope = 'CurrentUser'

            FilePath = $path
            StoredBytes = $protectedBytes.Length
        }
    }
    finally {
        if (
            $null -ne $temporaryFile -and
            [System.IO.File]::Exists($temporaryFile)
        ) {
            [System.IO.File]::Delete($temporaryFile)
        }

        if ($null -ne $protectedBytes) {
            [System.Array]::Clear(
                $protectedBytes,
                0,
                $protectedBytes.Length
            )
        }
    }
}

# ============================================================
# READ PROTECTED EVIDENCE
# ============================================================

function Read-WinSecEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [Parameter(Mandatory)]
        [string]$CheckId
    )

    $path = Get-WinSecEvidencePath `
        -ProjectRoot $ProjectRoot `
        -DeviceId $DeviceId `
        -ScanId $ScanId `
        -CheckId $CheckId

    if (-not (
        Test-Path -LiteralPath $path -PathType Leaf
    )) {
        throw 'Requested evidence record was not found.'
    }

    $null = Assert-WinSecEvidenceSafePath `
        -Path $path

    $file = Get-Item `
        -LiteralPath $path `
        -ErrorAction Stop

    if (
        $file.Length -eq 0 -or
        $file.Length -gt $script:WinSecEvidenceMaximumFileBytes
    ) {
        throw 'Stored evidence file size is invalid.'
    }

    $bytes = [System.IO.File]::ReadAllBytes($path)

    try {
        return Unprotect-WinSecEvidenceRecord `
            -ProtectedBytes $bytes `
            -DeviceId $DeviceId `
            -ScanId $ScanId `
            -CheckId $CheckId
    }
    finally {
        [System.Array]::Clear(
            $bytes,
            0,
            $bytes.Length
        )
    }
}

# ============================================================
# LIST EVIDENCE FOR ONE DEVICE AND SCAN
# ============================================================

function Get-WinSecEvidenceIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$ScanId
    )

    foreach ($identifier in @(
        $DeviceId,
        $ScanId
    )) {
        if (-not (
            Test-WinSecEvidenceIdentifier $identifier
        )) {
            throw 'Invalid evidence index identity.'
        }
    }

    $root = Get-WinSecEvidenceStorageRoot `
        -ProjectRoot $ProjectRoot

    $deviceHash = Get-WinSecEvidenceHash $DeviceId
    $scanHash = Get-WinSecEvidenceHash $ScanId

    $directory = Join-Path `
        (Join-Path $root $deviceHash) `
        $scanHash

    $null = Assert-WinSecEvidenceSafePath `
        -Path $directory

    if (-not (
        Test-Path -LiteralPath $directory -PathType Container
    )) {
        return @()
    }

    $records = New-Object `
        'System.Collections.Generic.List[object]'

    $files = @(
        Get-ChildItem `
            -LiteralPath $directory `
            -Filter '*.wse' `
            -File `
            -ErrorAction Stop
    )

    foreach ($file in $files) {
        $null = Assert-WinSecEvidenceSafePath `
            -Path $file.FullName

        if (
            $file.Length -eq 0 -or
            $file.Length -gt $script:WinSecEvidenceMaximumFileBytes
        ) {
            throw 'Evidence index contains an invalid file.'
        }

        $bytes = [System.IO.File]::ReadAllBytes(
            $file.FullName
        )

        try {
            # Decrypt the envelope to establish actual
            # identity, not merely its filename.

            $null = Assert-WinSecEvidenceProtection

            $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $bytes,
                $script:WinSecEvidenceEntropy,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )

            try {
                if (
                    $plain.Length -eq 0 -or
                    $plain.Length -gt $script:WinSecEvidenceMaximumBytes
                ) {
                    throw 'Invalid evidence index payload.'
                }

                $json = [System.Text.Encoding]::UTF8.GetString(
                    $plain
                )

                $record = ConvertFrom-Json `
                    -InputObject $json `
                    -ErrorAction Stop

                if (
                    $record.DeviceId -cne $DeviceId -or
                    $record.ScanId -cne $ScanId -or
                    $record.SchemaVersion -cne
                        $script:WinSecEvidenceSchemaVersion
                ) {
                    throw 'Foreign evidence in scan directory.'
                }

                $expectedName = (
                    Get-WinSecEvidenceHash $record.CheckId
                ) + '.wse'

                if ($file.Name -cne $expectedName) {
                    throw 'Evidence file identity mismatch.'
                }

                $control = [pscustomobject]@{
                    DeviceId = $record.DeviceId
                    ScanId = $record.ScanId
                    CheckId = $record.CheckId
                    Evidence = $record.Evidence
                }

                if (-not (
                    Test-WinSecEvidenceRecord $control
                )) {
                    throw 'Evidence index record is invalid.'
                }

                # No raw Evidence property in the index.

                $records.Add(
                    [pscustomobject]@{
                        DeviceId = $record.DeviceId
                        ScanId = $record.ScanId
                        CheckId = $record.CheckId
                        StoredAtUTC = $record.StoredAtUTC
                        CollectionSuccessful = (
                            $record.Evidence.CollectionSuccessful
                        )
                        Protected = $true
                    }
                )
            }
            finally {
                [System.Array]::Clear(
                    $plain,
                    0,
                    $plain.Length
                )
            }
        }
        finally {
            [System.Array]::Clear(
                $bytes,
                0,
                $bytes.Length
            )
        }
    }

    return @(
        $records.ToArray() |
            Sort-Object CheckId
    )
}
