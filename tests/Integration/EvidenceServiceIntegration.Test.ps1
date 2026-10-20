
# ============================================================
# WinSec Analyzer
# Test Suite : Evidence Service Integration
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Integration tests for protected Windows evidence storage.
#
# Includes:
# - EvidenceService and ResultModel compatibility
# - Windows DPAPI CurrentUser encryption
# - Protected evidence storage and recovery
# - DeviceId / ScanId / CheckId isolation
# - Duplicate and overwrite protection
# - Encrypted file tampering detection
# - Evidence index validation and privacy
# - Collector metadata isolation
# - Temporary file cleanup
# - Production configuration integrity
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# - Uses synthetic evidence only.
# - Writes exclusively to isolated temporary directories.
# - Never writes to production reports/evidence.
# - Does not modify Windows security settings.
# - Does not initiate remote connections.
# - Test directories are deleted after each scenario.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

# ============================================================
# PROJECT PATHS
# ============================================================

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

$script:ServicePath = Join-Path `
    $script:ProjectRoot 'src/Services/EvidenceService.ps1'

$script:ModelPath = Join-Path `
    $script:ProjectRoot 'src/Core/ResultModel.ps1'

$script:ScoringConfigPath = Join-Path `
    $script:ProjectRoot 'config/scoring.json'

$script:SecretMarker = 'WINSEC_INTEGRATION_SECRET_8392'

# ============================================================
# ASSERTIONS
# ============================================================

function Assert-Equal {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [string]$Message = 'Values differ.'
    )

    if ($null -eq $Expected) {
        if ($null -ne $Actual) {
            throw "$Message Expected null; got [$Actual]."
        }

        return
    }

    if (
        $null -eq $Actual -or
        $Actual -cne $Expected
    ) {
        throw (
            '{0} Expected [{1}]; got [{2}].' -f
            $Message, $Expected, $Actual
        )
    }
}

function Assert-True {
    [CmdletBinding()]
    param(
        [bool]$Condition,
        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Throws {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    $caught = $null

    try {
        $null = & $Action
    }
    catch {
        $caught = $_
    }

    if ($null -eq $caught) {
        throw 'Expected an exception, but none occurred.'
    }
}

# ============================================================
# TEST RUNNER
# ============================================================

function Test-Case {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    try {
        $null = & $Action

        $script:Passed++

        Write-Host (
            '[PASS] {0}' -f $Name
        ) -ForegroundColor Green
    }
    catch {
        $script:Failed++

        Write-Host (
            '[FAIL] {0} - {1}' -f
            $Name, $_.Exception.Message
        ) -ForegroundColor Red

        if ($_.ScriptStackTrace) {
            Write-Host $_.ScriptStackTrace `
                -ForegroundColor DarkGray
        }
    }
}

# ============================================================
# TEMPORARY TEST SANDBOX
# ============================================================

function Invoke-WithEvidenceSandbox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    $root = Join-Path `
        ([System.IO.Path]::GetTempPath()) `
        (
            'WinSec-EvidenceIntegration-' +
            [guid]::NewGuid().ToString('N')
        )

    $reports = Join-Path $root 'reports'

    try {
        $null = [System.IO.Directory]::CreateDirectory(
            $reports
        )

        $null = & $Action $root
    }
    finally {
        if (
            [System.IO.Directory]::Exists($root)
        ) {
            [System.IO.Directory]::Delete(
                $root,
                $true
            )
        }
    }
}

# ============================================================
# SYNTHETIC COLLECTOR FIXTURE
# ============================================================

function New-TestControl {
    [CmdletBinding()]
    param(
        [string]$DeviceId = 'local:TEST-PC',
        [string]$ScanId = 'SCAN-001',
        [string]$CheckId = 'WSA-SYS-001',
        [bool]$CollectionSuccessful = $true
    )

    return [pscustomobject]@{
        DeviceId = $DeviceId
        ScanId = $ScanId
        CheckId = $CheckId

        SectionKey = 'SystemSecurity'
        Status = 'INFORMATIONAL'

        Evidence = [pscustomobject]@{
            DeviceId = $DeviceId
            ScanId = $ScanId
            CheckId = $CheckId

            CollectionSuccessful = $CollectionSuccessful

            Settings = [pscustomobject]@{
                ProtectionEnabled = $true
                TestValue = 123
                Secret = $script:SecretMarker
            }
        }
    }
}

# ============================================================
# SOURCE CODE VALIDATION
# ============================================================

function Assert-ScriptParses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $tokens = $null
    $parseErrors = $null

    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$tokens,
        [ref]$parseErrors
    )

    if (@($parseErrors).Count -gt 0) {
        $description = @(
            $parseErrors | ForEach-Object {
                'Line {0}: {1}' -f
                    $_.Extent.StartLineNumber,
                    $_.Message
            }
        ) -join '; '

        throw "PowerShell syntax error: $description"
    }
}

# ============================================================
# INITIALIZATION
# ============================================================

Write-Host ''
Write-Host (
    'WinSec Analyzer - Evidence Service Integration Tests'
) -ForegroundColor Cyan
Write-Host ''

foreach ($path in @(
    $script:ServicePath,
    $script:ModelPath,
    $script:ScoringConfigPath
)) {
    if (-not (
        Test-Path -LiteralPath $path -PathType Leaf
    )) {
        throw "Missing integration dependency: $path"
    }
}

# Record the production configuration hash.
# The suite must never modify this file.

$script:ScoringHashBefore = (
    Get-FileHash `
        -LiteralPath $script:ScoringConfigPath `
        -Algorithm SHA256
).Hash

# Load existing project components.

. $script:ServicePath
. $script:ModelPath

# ============================================================
# GROUP 1: COMPONENT CONTRACTS
# ============================================================

Test-Case 'EvidenceService parses without syntax errors' {
    Assert-ScriptParses -Path $script:ServicePath
}

Test-Case 'ResultModel parses without syntax errors' {
    Assert-ScriptParses -Path $script:ModelPath
}

Test-Case 'Required functions are available' {
    foreach ($name in @(
        'Assert-WinSecEvidenceProtection'
        'Get-WinSecEvidencePath'
        'Save-WinSecEvidence'
        'Read-WinSecEvidence'
        'Get-WinSecEvidenceIndex'
        'New-WinSecResultSession'
        'Test-WinSecResultSession'
        'ConvertTo-WinSecPublicScanResult'
    )) {
        $command = Get-Command `
            -Name $name `
            -CommandType Function `
            -ErrorAction SilentlyContinue

        Assert-True (
            $null -ne $command
        ) "Missing function: $name"
    }
}

Test-Case 'Windows DPAPI is available' {
    Assert-Equal (
        Assert-WinSecEvidenceProtection
    ) $true
}

# ============================================================
# GROUP 2: STORAGE AND RECOVERY
# ============================================================

Test-Case 'Evidence is saved as a protected file' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $result = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        Assert-Equal $result.StorageStatus 'STORED'
        Assert-Equal $result.Protected $true
        Assert-Equal $result.ProtectionScope 'CurrentUser'

        Assert-True (
            Test-Path `
                -LiteralPath $result.FilePath `
                -PathType Leaf
        ) 'Protected evidence file was not created.'

        Assert-True (
            $result.FilePath.EndsWith('.wse')
        ) 'Unexpected evidence file extension.'
    }
}

Test-Case 'Stored evidence can be recovered' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        $restored = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId $control.DeviceId `
            -ScanId $control.ScanId `
            -CheckId $control.CheckId

        Assert-Equal $restored.DeviceId $control.DeviceId
        Assert-Equal $restored.ScanId $control.ScanId
        Assert-Equal $restored.CheckId $control.CheckId

        Assert-Equal (
            $restored.Evidence.Settings.Secret
        ) $script:SecretMarker

        Assert-Equal (
            $restored.Evidence.Settings.TestValue
        ) 123
    }
}

Test-Case 'Stored files do not contain plaintext evidence' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $saved = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        $bytes = [System.IO.File]::ReadAllBytes(
            $saved.FilePath
        )

        $text = [System.Text.Encoding]::UTF8.GetString(
            $bytes
        )

        Assert-True (
            -not $text.Contains($script:SecretMarker)
        ) 'Plaintext evidence was found in stored bytes.'
    }
}

Test-Case 'Failed collection evidence is preserved' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl `
            -CollectionSuccessful $false

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        $restored = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId $control.DeviceId `
            -ScanId $control.ScanId `
            -CheckId $control.CheckId

        Assert-Equal (
            $restored.Evidence.CollectionSuccessful
        ) $false
    }
}

Test-Case 'Existing evidence cannot be overwritten' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        Assert-Throws {
            Save-WinSecEvidence `
                -ProjectRoot $root `
                -ControlResult $control
        }

        $restored = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId $control.DeviceId `
            -ScanId $control.ScanId `
            -CheckId $control.CheckId

        Assert-Equal (
            $restored.Evidence.Settings.TestValue
        ) 123
    }
}

Test-Case 'Successful storage leaves no temporary files' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $saved = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult (New-TestControl)

        $directory = [System.IO.Path]::GetDirectoryName(
            $saved.FilePath
        )

        $temporaryFiles = @(
            Get-ChildItem `
                -LiteralPath $directory `
                -Filter '*.tmp' `
                -File `
                -Force
        )

        Assert-Equal $temporaryFiles.Count 0
    }
}

# ============================================================
# GROUP 3: DEVICE, SCAN AND CHECK ISOLATION
# ============================================================

Test-Case 'Two checks in one scan remain independent' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $first = New-TestControl `
            -CheckId 'WSA-SYS-001'

        $second = New-TestControl `
            -CheckId 'WSA-SYS-002'

        $a = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $first

        $b = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $second

        Assert-True (
            $a.FilePath -cne $b.FilePath
        ) 'Different checks share a storage file.'

        $recordA = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId $first.DeviceId `
            -ScanId $first.ScanId `
            -CheckId $first.CheckId

        $recordB = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId $second.DeviceId `
            -ScanId $second.ScanId `
            -CheckId $second.CheckId

        Assert-Equal $recordA.CheckId 'WSA-SYS-001'
        Assert-Equal $recordB.CheckId 'WSA-SYS-002'
    }
}

Test-Case 'Two scans of one device remain independent' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $first = New-TestControl -ScanId 'SCAN-001'
        $second = New-TestControl -ScanId 'SCAN-002'

        $a = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $first

        $b = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $second

        Assert-True (
            $a.FilePath -cne $b.FilePath
        ) 'Different scans share a storage file.'

        Assert-Equal (
            (Read-WinSecEvidence `
                -ProjectRoot $root `
                -DeviceId $first.DeviceId `
                -ScanId $first.ScanId `
                -CheckId $first.CheckId).ScanId
        ) 'SCAN-001'

        Assert-Equal (
            (Read-WinSecEvidence `
                -ProjectRoot $root `
                -DeviceId $second.DeviceId `
                -ScanId $second.ScanId `
                -CheckId $second.CheckId).ScanId
        ) 'SCAN-002'
    }
}

Test-Case 'Evidence from different devices remains isolated' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $first = New-TestControl `
            -DeviceId 'local:PC-A'

        $second = New-TestControl `
            -DeviceId 'remote:PC-B'

        $a = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $first

        $b = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $second

        Assert-True (
            $a.FilePath -cne $b.FilePath
        )

        $recordA = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId 'local:PC-A' `
            -ScanId 'SCAN-001' `
            -CheckId 'WSA-SYS-001'

        $recordB = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId 'remote:PC-B' `
            -ScanId 'SCAN-001' `
            -CheckId 'WSA-SYS-001'

        Assert-Equal $recordA.DeviceId 'local:PC-A'
        Assert-Equal $recordB.DeviceId 'remote:PC-B'
    }
}

Test-Case 'Reading evidence with wrong ScanId fails' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        Assert-Throws {
            Read-WinSecEvidence `
                -ProjectRoot $root `
                -DeviceId $control.DeviceId `
                -ScanId 'FOREIGN-SCAN' `
                -CheckId $control.CheckId
        }
    }
}

Test-Case 'Reading evidence with wrong DeviceId fails' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        Assert-Throws {
            Read-WinSecEvidence `
                -ProjectRoot $root `
                -DeviceId 'local:FOREIGN-PC' `
                -ScanId $control.ScanId `
                -CheckId $control.CheckId
        }
    }
}

Test-Case 'Reading nonexistent evidence fails' {
    Invoke-WithEvidenceSandbox {
        param($root)

        Assert-Throws {
            Read-WinSecEvidence `
                -ProjectRoot $root `
                -DeviceId 'local:TEST-PC' `
                -ScanId 'SCAN-001' `
                -CheckId 'WSA-SYS-999'
        }
    }
}

# ============================================================
# GROUP 4: ENCRYPTED FILE INTEGRITY
# ============================================================

Test-Case 'Modified ciphertext is rejected' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $saved = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        $bytes = [System.IO.File]::ReadAllBytes(
            $saved.FilePath
        )

        $offset = [int][Math]::Floor(
            $bytes.Length / 2
        )

        $bytes[$offset] = (
            $bytes[$offset] -bxor 1
        )

        [System.IO.File]::WriteAllBytes(
            $saved.FilePath,
            $bytes
        )

        Assert-Throws {
            Read-WinSecEvidence `
                -ProjectRoot $root `
                -DeviceId $control.DeviceId `
                -ScanId $control.ScanId `
                -CheckId $control.CheckId
        }
    }
}

Test-Case 'Swapped evidence files are rejected' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $first = New-TestControl `
            -CheckId 'WSA-SYS-001'

        $second = New-TestControl `
            -CheckId 'WSA-SYS-002'

        $a = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $first

        $b = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $second

        # Simulates someone replacing the file for check B
        # with the valid ciphertext for check A.
        # Only the temporary test sandbox is modified.

        [System.IO.File]::Copy(
            $a.FilePath,
            $b.FilePath,
            $true
        )

        Assert-Throws {
            Read-WinSecEvidence `
                -ProjectRoot $root `
                -DeviceId $second.DeviceId `
                -ScanId $second.ScanId `
                -CheckId $second.CheckId
        }
    }
}

Test-Case 'Truncated evidence file is rejected' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $saved = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        [System.IO.File]::WriteAllBytes(
            $saved.FilePath,
            [byte[]]@(1, 2, 3, 4)
        )

        Assert-Throws {
            Read-WinSecEvidence `
                -ProjectRoot $root `
                -DeviceId $control.DeviceId `
                -ScanId $control.ScanId `
                -CheckId $control.CheckId
        }
    }
}

# ============================================================
# GROUP 5: EVIDENCE INDEX
# ============================================================

Test-Case 'Missing scan has an empty evidence index' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $index = @(
            Get-WinSecEvidenceIndex `
                -ProjectRoot $root `
                -DeviceId 'local:TEST-PC' `
                -ScanId 'SCAN-001'
        )

        Assert-Equal $index.Count 0
    }
}

Test-Case 'Evidence index lists both saved checks' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult (
                New-TestControl -CheckId 'WSA-SYS-001'
            )

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult (
                New-TestControl -CheckId 'WSA-SYS-002'
            )

        $index = @(
            Get-WinSecEvidenceIndex `
                -ProjectRoot $root `
                -DeviceId 'local:TEST-PC' `
                -ScanId 'SCAN-001'
        )

        Assert-Equal $index.Count 2

        Assert-Equal $index[0].CheckId 'WSA-SYS-001'
        Assert-Equal $index[1].CheckId 'WSA-SYS-002'

        Assert-Equal $index[0].Protected $true
        Assert-Equal $index[1].Protected $true
    }
}

Test-Case 'Evidence index never includes raw evidence' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult (New-TestControl)

        $index = @(
            Get-WinSecEvidenceIndex `
                -ProjectRoot $root `
                -DeviceId 'local:TEST-PC' `
                -ScanId 'SCAN-001'
        )

        Assert-Equal $index.Count 1

        Assert-True (
            $null -eq $index[0].PSObject.Properties['Evidence']
        ) 'Index exposes the raw Evidence property.'

        $json = ConvertTo-Json `
            -InputObject $index `
            -Depth 20

        Assert-True (
            -not $json.Contains($script:SecretMarker)
        ) 'Sensitive value leaked into the evidence index.'
    }
}

Test-Case 'Evidence index is isolated by ScanId' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult (
                New-TestControl -ScanId 'SCAN-001'
            )

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult (
                New-TestControl -ScanId 'SCAN-002'
            )

        $indexA = @(
            Get-WinSecEvidenceIndex `
                -ProjectRoot $root `
                -DeviceId 'local:TEST-PC' `
                -ScanId 'SCAN-001'
        )

        $indexB = @(
            Get-WinSecEvidenceIndex `
                -ProjectRoot $root `
                -DeviceId 'local:TEST-PC' `
                -ScanId 'SCAN-002'
        )

        Assert-Equal $indexA.Count 1
        Assert-Equal $indexB.Count 1

        Assert-Equal $indexA[0].ScanId 'SCAN-001'
        Assert-Equal $indexB[0].ScanId 'SCAN-002'
    }
}

Test-Case 'Evidence index is isolated by DeviceId' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult (
                New-TestControl -DeviceId 'local:PC-A'
            )

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult (
                New-TestControl -DeviceId 'local:PC-B'
            )

        $indexA = @(
            Get-WinSecEvidenceIndex `
                -ProjectRoot $root `
                -DeviceId 'local:PC-A' `
                -ScanId 'SCAN-001'
        )

        $indexB = @(
            Get-WinSecEvidenceIndex `
                -ProjectRoot $root `
                -DeviceId 'local:PC-B' `
                -ScanId 'SCAN-001'
        )

        Assert-Equal $indexA.Count 1
        Assert-Equal $indexB.Count 1

        Assert-Equal $indexA[0].DeviceId 'local:PC-A'
        Assert-Equal $indexB[0].DeviceId 'local:PC-B'
    }
}

Test-Case 'Evidence index detects swapped files' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $a = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult (
                New-TestControl -CheckId 'WSA-SYS-001'
            )

        $b = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult (
                New-TestControl -CheckId 'WSA-SYS-002'
            )

        [System.IO.File]::Copy(
            $a.FilePath,
            $b.FilePath,
            $true
        )

        Assert-Throws {
            Get-WinSecEvidenceIndex `
                -ProjectRoot $root `
                -DeviceId 'local:TEST-PC' `
                -ScanId 'SCAN-001'
        }
    }
}

# ============================================================
# GROUP 6: METADATA PROTECTION
# ============================================================

Test-Case 'Forged score metadata is not persisted' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $control | Add-Member `
            -NotePropertyName Score `
            -NotePropertyValue 100

        $control | Add-Member `
            -NotePropertyName ScoringEligible `
            -NotePropertyValue $true

        $control | Add-Member `
            -NotePropertyName OriginalResult `
            -NotePropertyValue 'FORGED-CONTROL'

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        $restored = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId $control.DeviceId `
            -ScanId $control.ScanId `
            -CheckId $control.CheckId

        foreach ($field in @(
            'Score'
            'ScoringEligible'
            'OriginalResult'
        )) {
            Assert-True (
                $null -eq $restored.PSObject.Properties[$field]
            ) "Unexpected persisted field: $field"
        }
    }
}

Test-Case 'Invalid evidence identity cannot be saved' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $control.Evidence.DeviceId = 'local:FOREIGN-PC'

        Assert-Throws {
            Save-WinSecEvidence `
                -ProjectRoot $root `
                -ControlResult $control
        }

        $storage = Get-WinSecEvidenceStorageRoot `
            -ProjectRoot $root

        Assert-True (
            -not (Test-Path -LiteralPath $storage)
        ) 'Invalid evidence caused file creation.'
    }
}

# ============================================================
# GROUP 7: RESULT MODEL INTEGRATION
# ============================================================

Test-Case 'Recovered evidence supports ResultModel session' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        $restored = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId $control.DeviceId `
            -ScanId $control.ScanId `
            -CheckId $control.CheckId

        $restoredControl = [pscustomobject]@{
            DeviceId = $restored.DeviceId
            ScanId = $restored.ScanId
            CheckId = $restored.CheckId

            SectionKey = 'SystemSecurity'
            Status = 'INFORMATIONAL'

            Evidence = $restored.Evidence
        }

        $session = New-WinSecResultSession `
            -DeviceId $control.DeviceId `
            -ScanId $control.ScanId `
            -ExpectedCheckIds @($control.CheckId) `
            -ControlResults @($restoredControl)

        Assert-Equal (
            Test-WinSecResultSession -Session $session
        ) $true

        Assert-Equal $session.OverallScore $null
        Assert-Equal $session.OverallStatus 'NOT_SCORED'
        Assert-Equal $session.ScoringEligible $false
    }
}

Test-Case 'Public ResultModel output excludes evidence secret' {
    Invoke-WithEvidenceSandbox {
        param($root)

        $control = New-TestControl

        $null = Save-WinSecEvidence `
            -ProjectRoot $root `
            -ControlResult $control

        $restored = Read-WinSecEvidence `
            -ProjectRoot $root `
            -DeviceId $control.DeviceId `
            -ScanId $control.ScanId `
            -CheckId $control.CheckId

        $restoredControl = [pscustomobject]@{
            DeviceId = $restored.DeviceId
            ScanId = $restored.ScanId
            CheckId = $restored.CheckId

            SectionKey = 'SystemSecurity'
            Status = 'INFORMATIONAL'

            Evidence = $restored.Evidence
        }

        $session = New-WinSecResultSession `
            -DeviceId $control.DeviceId `
            -ScanId $control.ScanId `
            -ControlResults @($restoredControl)

        $public = ConvertTo-WinSecPublicScanResult `
            -Session $session

        $json = ConvertTo-Json `
            -InputObject $public `
            -Depth 40

        Assert-Equal $public.ContainsRawEvidence $false

        Assert-True (
            -not $json.Contains($script:SecretMarker)
        ) 'Public scan result contains a private evidence value.'

        Assert-Equal $public.OverallScore $null
    }
}

# ============================================================
# GROUP 8: SECURITY AND CONFIGURATION INTEGRITY
# ============================================================

Test-Case 'EvidenceService contains no remediation commands' {
    $tokens = $null
    $errors = $null

    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:ServicePath,
        [ref]$tokens,
        [ref]$errors
    )

    Assert-Equal @($errors).Count 0

    $commands = $ast.FindAll({
        param($node)

        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true)

    $forbidden = @(
        'Set-MpPreference'
        'Add-MpPreference'
        'Remove-MpPreference'
        'Set-NetFirewallProfile'
        'Set-ItemProperty'
        'Invoke-Command'
        'New-PSSession'
        'Restart-Computer'
    )

    foreach ($command in $commands) {
        $name = $command.GetCommandName()

        Assert-True (
            $name -notin $forbidden
        ) "Forbidden remediation command: $name"
    }
}

Test-Case 'Production scoring configuration remains unchanged' {
    $hashAfter = (
        Get-FileHash `
            -LiteralPath $script:ScoringConfigPath `
            -Algorithm SHA256
    ).Hash

    Assert-Equal `
        -Actual $hashAfter `
        -Expected $script:ScoringHashBefore `
        -Message 'Production scoring.json was modified.'
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray

Write-Host (
    'EVIDENCE SERVICE INTEGRATION TEST SUMMARY'
) -ForegroundColor Cyan

Write-Host "TOTAL : $total"

Write-Host "PASS  : $($script:Passed)" `
    -ForegroundColor Green

Write-Host "FAIL  : $($script:Failed)" `
    -ForegroundColor $(
        if ($script:Failed -gt 0) {
            'Red'
        }
        else {
            'Green'
        }
    )

Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''

if ($script:Failed -gt 0) {
    throw (
        '{0} EvidenceService integration test(s) failed.' -f
        $script:Failed
    )
}

Write-Host 'All EvidenceService integration tests passed.' `
    -ForegroundColor Green
