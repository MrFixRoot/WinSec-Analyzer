
# ============================================================
# WinSec Analyzer
# Test Suite : Evidence Service Unit Tests
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit tests for protected evidence handling.
#
# Includes:
# - Public function validation
# - Safe DeviceId, ScanId and CheckId validation
# - SHA-256 storage identifiers
# - Collector evidence identity validation
# - DPAPI CurrentUser encryption and decryption
# - Tampering and cross-identity rejection
# - Sensitive data isolation
# - Payload size limits
# - Read-only Windows security guarantee
#
# PowerShell 5.1 / 7.x on Windows
# No Pester required.
#
# IMPORTANT:
# Uses synthetic evidence only.
# Does not change Windows security configuration.
# Does not store evidence in production directories.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

$script:ServicePath = Join-Path `
    $script:ProjectRoot 'src/Services/EvidenceService.ps1'

# ============================================================
# ASSERTIONS
# ============================================================

function Assert-Equal {
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

    if ($null -eq $Actual -or $Actual -cne $Expected) {
        throw "$Message Expected [$Expected]; got [$Actual]."
    }
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)][scriptblock]$Action
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

function Test-Case {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    try {
        $null = & $Action
        $script:Passed++

        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:Failed++

        Write-Host (
            "[FAIL] {0} - {1}" -f $Name, $_.Exception.Message
        ) -ForegroundColor Red

        if ($_.ScriptStackTrace) {
            Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
        }
    }
}

# ============================================================
# SYNTHETIC EVIDENCE FIXTURES
# ============================================================

function New-TestEvidence {
    param(
        [string]$DeviceId = 'local:TEST-PC',
        [string]$ScanId = 'TEST-SCAN-001',
        [string]$CheckId = 'WSA-SYS-001',
        [bool]$CollectionSuccessful = $true
    )

    return [pscustomobject]@{
        DeviceId = $DeviceId
        ScanId = $ScanId
        CheckId = $CheckId

        Status = 'INFORMATIONAL'

        Evidence = [pscustomobject]@{
            DeviceId = $DeviceId
            ScanId = $ScanId
            CheckId = $CheckId

            CollectionSuccessful = $CollectionSuccessful

            TestData = [pscustomobject]@{
                Enabled = $true
                Value = 123
                Secret = 'WINSEC_PRIVATE_EVIDENCE_9267'
            }
        }
    }
}

function Copy-TestObject {
    param([Parameter(Mandatory)][object]$Value)

    return (
        $Value |
        ConvertTo-Json -Depth 40 |
        ConvertFrom-Json
    )
}

# ============================================================
# INITIALIZATION
# ============================================================

Write-Host ''
Write-Host 'WinSec Analyzer - Evidence Service Unit Tests' `
    -ForegroundColor Cyan
Write-Host ''

if (-not (
    Test-Path -LiteralPath $script:ServicePath -PathType Leaf
)) {
    throw "EvidenceService not found: $script:ServicePath"
}

. $script:ServicePath

# ============================================================
# GROUP 1: PUBLIC CONTRACT
# ============================================================

Test-Case 'EvidenceService parses correctly' {
    $tokens = $null
    $errors = $null

    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:ServicePath,
        [ref]$tokens,
        [ref]$errors
    )

    Assert-Equal @($errors).Count 0
}

Test-Case 'All EvidenceService functions exist' {
    foreach ($name in @(
        'Get-WinSecEvidenceField'
        'Test-WinSecEvidenceIdentifier'
        'Assert-WinSecEvidenceProtection'
        'Get-WinSecEvidenceHash'
        'Assert-WinSecEvidenceSafePath'
        'Get-WinSecEvidenceStorageRoot'
        'Get-WinSecEvidencePath'
        'Test-WinSecEvidenceRecord'
        'Protect-WinSecEvidenceRecord'
        'Unprotect-WinSecEvidenceRecord'
        'Save-WinSecEvidence'
        'Read-WinSecEvidence'
        'Get-WinSecEvidenceIndex'
    )) {
        Assert-True (
            $null -ne (
                Get-Command $name `
                    -CommandType Function `
                    -ErrorAction SilentlyContinue
            )
        ) "Missing function: $name"
    }
}

Test-Case 'PSCustomObject fields are readable' {
    $value = [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
    }

    Assert-Equal (
        Get-WinSecEvidenceField $value 'CheckId'
    ) 'WSA-SYS-001'
}

Test-Case 'Dictionary lookup is case-insensitive' {
    $value = @{
        DeviceId = 'local:TEST-PC'
    }

    Assert-Equal (
        Get-WinSecEvidenceField $value 'deviceid'
    ) 'local:TEST-PC'
}

Test-Case 'Missing field returns null' {
    Assert-Equal (
        Get-WinSecEvidenceField @{
            CheckId = 'WSA-SYS-001'
        } 'Missing'
    ) $null
}

# ============================================================
# GROUP 2: IDENTIFIERS AND HASHING
# ============================================================

Test-Case 'Valid evidence identifiers are accepted' {
    foreach ($value in @(
        'local:PC-001'
        'remote:SRV-01'
        'SCAN-001'
        'WSA-SYS-001'
        'imported:PC_02'
    )) {
        Assert-Equal (
            Test-WinSecEvidenceIdentifier $value
        ) $true
    }
}

Test-Case 'Unsafe evidence identifiers are rejected' {
    foreach ($value in @(
        ' '
        'local:PC 001'
        '../TEST'
        'C:\TEMP'
        'SCAN/001'
        'SCAN;001'
        'SCAN|001'
        "SCAN`n001"
        ('A' * 129)
    )) {
        Assert-Equal (
            Test-WinSecEvidenceIdentifier $value
        ) $false
    }
}

Test-Case 'Evidence hash is deterministic' {
    $first = Get-WinSecEvidenceHash 'WSA-SYS-001'
    $second = Get-WinSecEvidenceHash 'WSA-SYS-001'

    Assert-Equal $first $second
    Assert-Equal $first.Length 64

    Assert-True (
        $first -cmatch '^[0-9a-f]{64}$'
    )
}

Test-Case 'Different identifiers produce different hashes' {
    $first = Get-WinSecEvidenceHash 'WSA-SYS-001'
    $second = Get-WinSecEvidenceHash 'WSA-SYS-002'

    Assert-True ($first -cne $second)
}

Test-Case 'Hash function rejects invalid identifiers' {
    Assert-Throws {
        Get-WinSecEvidenceHash '../SECRET'
    }
}

# ============================================================
# GROUP 3: RECORD VALIDATION
# ============================================================

Test-Case 'Valid collector evidence is accepted' {
    $record = New-TestEvidence

    Assert-Equal (
        Test-WinSecEvidenceRecord $record
    ) $true
}

Test-Case 'Failed collection remains a valid evidence record' {
    $record = New-TestEvidence `
        -CollectionSuccessful $false

    Assert-Equal (
        Test-WinSecEvidenceRecord $record
    ) $true
}

Test-Case 'Missing Evidence is rejected' {
    $record = New-TestEvidence
    $record.Evidence = $null

    Assert-Equal (
        Test-WinSecEvidenceRecord $record
    ) $false
}

Test-Case 'Foreign DeviceId inside evidence is rejected' {
    $record = New-TestEvidence
    $record.Evidence.DeviceId = 'local:OTHER-PC'

    Assert-Equal (
        Test-WinSecEvidenceRecord $record
    ) $false
}

Test-Case 'Foreign ScanId inside evidence is rejected' {
    $record = New-TestEvidence
    $record.Evidence.ScanId = 'OTHER-SCAN'

    Assert-Equal (
        Test-WinSecEvidenceRecord $record
    ) $false
}

Test-Case 'Foreign CheckId inside evidence is rejected' {
    $record = New-TestEvidence
    $record.Evidence.CheckId = 'WSA-SYS-999'

    Assert-Equal (
        Test-WinSecEvidenceRecord $record
    ) $false
}

Test-Case 'CollectionSuccessful must be Boolean' {
    $record = New-TestEvidence
    $record.Evidence.CollectionSuccessful = 'true'

    Assert-Equal (
        Test-WinSecEvidenceRecord $record
    ) $false
}

Test-Case 'String evidence is rejected' {
    $record = New-TestEvidence
    $record.Evidence = 'FAKE-EVIDENCE'

    Assert-Equal (
        Test-WinSecEvidenceRecord $record
    ) $false
}

Test-Case 'Array evidence is rejected' {
    $record = New-TestEvidence
    $record.Evidence = @(
        [pscustomobject]@{
            DeviceId = 'local:TEST-PC'
        }
    )

    Assert-Equal (
        Test-WinSecEvidenceRecord $record
    ) $false
}

# ============================================================
# GROUP 4: DPAPI PROTECTION
# ============================================================

Test-Case 'Windows DPAPI protection is available' {
    Assert-Equal (
        Assert-WinSecEvidenceProtection
    ) $true
}

Test-Case 'Evidence is encrypted into byte array' {
    $protected = Protect-WinSecEvidenceRecord `
        -ControlResult (New-TestEvidence)

    Assert-True ($protected -is [byte[]])
    Assert-True ($protected.Length -gt 0)
}

Test-Case 'Protected evidence does not contain plaintext secret' {
    $protected = Protect-WinSecEvidenceRecord `
        -ControlResult (New-TestEvidence)

    $encoded = [Convert]::ToBase64String($protected)

    Assert-True (
        -not $encoded.Contains(
            'WINSEC_PRIVATE_EVIDENCE_9267'
        )
    )
}

Test-Case 'DPAPI roundtrip preserves identity and evidence' {
    $record = New-TestEvidence

    $protected = Protect-WinSecEvidenceRecord `
        -ControlResult $record

    $restored = Unprotect-WinSecEvidenceRecord `
        -ProtectedBytes $protected `
        -DeviceId $record.DeviceId `
        -ScanId $record.ScanId `
        -CheckId $record.CheckId

    Assert-Equal $restored.DeviceId $record.DeviceId
    Assert-Equal $restored.ScanId $record.ScanId
    Assert-Equal $restored.CheckId $record.CheckId

    Assert-Equal (
        $restored.Evidence.TestData.Secret
    ) 'WINSEC_PRIVATE_EVIDENCE_9267'
}

Test-Case 'DPAPI record rejects another DeviceId' {
    $protected = Protect-WinSecEvidenceRecord `
        -ControlResult (New-TestEvidence)

    Assert-Throws {
        Unprotect-WinSecEvidenceRecord `
            -ProtectedBytes $protected `
            -DeviceId 'local:OTHER-PC' `
            -ScanId 'TEST-SCAN-001' `
            -CheckId 'WSA-SYS-001'
    }
}

Test-Case 'DPAPI record rejects another ScanId' {
    $protected = Protect-WinSecEvidenceRecord `
        -ControlResult (New-TestEvidence)

    Assert-Throws {
        Unprotect-WinSecEvidenceRecord `
            -ProtectedBytes $protected `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'OTHER-SCAN' `
            -CheckId 'WSA-SYS-001'
    }
}

Test-Case 'DPAPI record rejects another CheckId' {
    $protected = Protect-WinSecEvidenceRecord `
        -ControlResult (New-TestEvidence)

    Assert-Throws {
        Unprotect-WinSecEvidenceRecord `
            -ProtectedBytes $protected `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'TEST-SCAN-001' `
            -CheckId 'WSA-SYS-999'
    }
}

Test-Case 'Corrupted protected payload is rejected' {
    $protected = Protect-WinSecEvidenceRecord `
        -ControlResult (New-TestEvidence)

    $tampered = [byte[]]$protected.Clone()
    $offset = [int][Math]::Floor($tampered.Length / 2)

    $tampered[$offset] = (
        $tampered[$offset] -bxor 1
    )

    Assert-Throws {
        Unprotect-WinSecEvidenceRecord `
            -ProtectedBytes $tampered `
            -DeviceId 'local:TEST-PC' `
            -ScanId 'TEST-SCAN-001' `
            -CheckId 'WSA-SYS-001'
    }
}

Test-Case 'Extra collector score is not persisted' {
    $record = New-TestEvidence

    $record | Add-Member `
        -NotePropertyName Score `
        -NotePropertyValue 100

    $record | Add-Member `
        -NotePropertyName OriginalResult `
        -NotePropertyValue 'PRIVATE-UNTRUSTED-RESULT'

    $protected = Protect-WinSecEvidenceRecord `
        -ControlResult $record

    $restored = Unprotect-WinSecEvidenceRecord `
        -ProtectedBytes $protected `
        -DeviceId $record.DeviceId `
        -ScanId $record.ScanId `
        -CheckId $record.CheckId

    Assert-Equal (
        $restored.PSObject.Properties['Score']
    ) $null

    Assert-Equal (
        $restored.PSObject.Properties['OriginalResult']
    ) $null
}

Test-Case 'Evidence protection does not mutate original input' {
    $record = New-TestEvidence

    $before = ConvertTo-Json `
        -InputObject $record `
        -Depth 30 `
        -Compress

    $null = Protect-WinSecEvidenceRecord `
        -ControlResult $record

    $after = ConvertTo-Json `
        -InputObject $record `
        -Depth 30 `
        -Compress

    Assert-Equal $after $before
}

Test-Case 'Oversized evidence payload is rejected' {
    $record = New-TestEvidence

    $record.Evidence.TestData.Secret = (
        'X' * 2097152
    )

    Assert-Throws {
        Protect-WinSecEvidenceRecord `
            -ControlResult $record
    }
}

# ============================================================
# GROUP 5: PATH AND SECURITY CONTRACT
# ============================================================

Test-Case 'Storage paths contain hashed identities' {
    $path = Get-WinSecEvidencePath `
        -ProjectRoot $script:ProjectRoot `
        -DeviceId 'local:TEST-PC' `
        -ScanId 'TEST-SCAN-001' `
        -CheckId 'WSA-SYS-001'

    Assert-True ($path.EndsWith('.wse'))

    Assert-True (
        $path.Contains(
            (Get-WinSecEvidenceHash 'local:TEST-PC')
        )
    )

    Assert-True (
        $path.Contains(
            (Get-WinSecEvidenceHash 'TEST-SCAN-001')
        )
    )

    Assert-True (
        $path.Contains(
            (Get-WinSecEvidenceHash 'WSA-SYS-001')
        )
    )
}

Test-Case 'Invalid storage identifiers are rejected' {
    Assert-Throws {
        Get-WinSecEvidencePath `
            -ProjectRoot $script:ProjectRoot `
            -DeviceId 'local:TEST PC' `
            -ScanId 'TEST-SCAN-001' `
            -CheckId 'WSA-SYS-001'
    }
}

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
        Assert-True (
            $command.GetCommandName() -notin $forbidden
        ) "Forbidden command: $($command.GetCommandName())"
    }
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'EVIDENCE SERVICE UNIT TEST SUMMARY' -ForegroundColor Cyan

Write-Host "TOTAL : $total"
Write-Host "PASS  : $($script:Passed)" -ForegroundColor Green
Write-Host "FAIL  : $($script:Failed)" -ForegroundColor $(
    if ($script:Failed -gt 0) { 'Red' } else { 'Green' }
)

Write-Host ('=' * 60) -ForegroundColor DarkGray

if ($script:Failed -gt 0) {
    throw "$($script:Failed) EvidenceService unit test(s) failed."
}

Write-Host 'All EvidenceService unit tests passed.' `
    -ForegroundColor Green
