
# ============================================================
# WinSec Analyzer
# Test Suite : Target Registry Integration
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Integration tests for target registration and scan identity.
#
# Includes:
# - Production targets.json loading
# - Registry schema validation
# - Local device fallback
# - CLI-compatible target properties
# - ResultModel session compatibility
# - Multi-device and multi-scan isolation
# - Forged score metadata protection
# - Rejection of malformed configurations
# - Production configuration integrity
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# - No modifications to production configuration.
# - Temporary test files are automatically removed.
# - No remote sessions are created.
# - No Windows security settings are modified.
# - Synthetic devices never represent real audit results.
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

$script:TargetPath = Join-Path `
    $script:ProjectRoot 'src/Core/TargetRegistry.ps1'

$script:ModelPath = Join-Path `
    $script:ProjectRoot 'src/Core/ResultModel.ps1'

$script:ConfigPath = Join-Path `
    $script:ProjectRoot 'config/targets.json'


# ============================================================
# ASSERTIONS
# ============================================================

function Assert-Equal {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Expected,

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
            '{0} Expected [{1}]; got [{2}].' -f `
                $Message,
                $Expected,
                $Actual
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
        [scriptblock]$Action,

        [string]$MessagePattern = ''
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

    if (
        -not [string]::IsNullOrWhiteSpace($MessagePattern) -and
        $caught.Exception.Message -notmatch $MessagePattern
    ) {
        throw (
            'Unexpected exception: {0}' -f
                $caught.Exception.Message
        )
    }
}


# ============================================================
# TEST RUNNER
# ============================================================

function Test-Case {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Action
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
                $Name,
                $_.Exception.Message
        ) -ForegroundColor Red

        if ($_.ScriptStackTrace) {
            Write-Host $_.ScriptStackTrace `
                -ForegroundColor DarkGray
        }
    }
}


# ============================================================
# SYNTHETIC REGISTRY FIXTURES
# ============================================================

function New-TestTarget {
    [CmdletBinding()]
    param(
        [string]$DeviceId = 'local:TEST-PC',

        [string]$Hostname = 'TEST-PC',

        [string]$Mode = 'LOCAL',

        [bool]$Enabled = $true
    )

    return [pscustomobject]@{
        DeviceId = $DeviceId
        Hostname = $Hostname
        Mode = $Mode
        Enabled = $Enabled
        Description = 'Synthetic integration target'
    }
}


function New-TestRegistry {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Targets = @()
    )

    return [pscustomobject]@{
        schemaVersion = '1.0.0'
        targets = @($Targets)
    }
}


function New-MultipleDeviceRegistry {
    [CmdletBinding()]
    param()

    $targets = @(
        (New-TestTarget `
            -DeviceId 'local:PC-001' `
            -Hostname 'PC-001' `
            -Mode 'LOCAL' `
            -Enabled $true)

        (New-TestTarget `
            -DeviceId 'remote:SRV-001' `
            -Hostname 'SRV-001' `
            -Mode 'REMOTE' `
            -Enabled $true)

        (New-TestTarget `
            -DeviceId 'imported:PC-002' `
            -Hostname 'PC-002' `
            -Mode 'IMPORTED' `
            -Enabled $false)
    )

    return New-TestRegistry -Targets $targets
}


# ============================================================
# TEMPORARY CONFIGURATION IMPORT
# ============================================================

function Import-TemporaryTargetRegistry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Json
    )

    $temporaryRoot = Join-Path `
        ([System.IO.Path]::GetTempPath()) `
        (
            'WinSec-TargetRegistry-Test-' +
            [guid]::NewGuid().ToString('N')
        )

    $temporaryConfig = Join-Path `
        $temporaryRoot 'config'

    $temporaryFile = Join-Path `
        $temporaryConfig 'targets.json'

    try {
        $null = New-Item `
            -ItemType Directory `
            -Path $temporaryConfig `
            -Force `
            -ErrorAction Stop

        $encoding = New-Object `
            System.Text.UTF8Encoding($false)

        [System.IO.File]::WriteAllText(
            $temporaryFile,
            $Json,
            $encoding
        )

        return Import-WinSecTargetRegistry `
            -ProjectRoot $temporaryRoot
    }
    finally {
        if (
            [System.IO.Directory]::Exists(
                $temporaryRoot
            )
        ) {
            [System.IO.Directory]::Delete(
                $temporaryRoot,
                $true
            )
        }
    }
}


# ============================================================
# SOURCE CODE PARSER
# ============================================================

function Assert-ScriptParses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $tokens = $null
    $parseErrors = $null

    
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$tokens,
        [ref]$parseErrors
    )


    Assert-Equal `
        -Actual @($parseErrors).Count `
        -Expected 0 `
        -Message "Syntax errors in $Path."
}


# ============================================================
# INITIALIZATION
# ============================================================

Write-Host ''
Write-Host (
    'WinSec Analyzer - Target Registry Integration Tests'
) -ForegroundColor Cyan
Write-Host ''

foreach ($path in @(
    $script:TargetPath,
    $script:ModelPath,
    $script:ConfigPath
)) {
    if (-not (
        Test-Path -LiteralPath $path -PathType Leaf
    )) {
        throw (
            'Required dependency not found: {0}' -f $path
        )
    }
}

# Save original configuration hash.
# The test suite must never modify targets.json.

$script:ConfigHashBefore = (
    Get-FileHash `
        -LiteralPath $script:ConfigPath `
        -Algorithm SHA256
).Hash

# Load real project components.

. $script:TargetPath
. $script:ModelPath


# ============================================================
# GROUP 1: COMPONENT CONTRACTS
# ============================================================

Test-Case 'TargetRegistry parses without syntax errors' {
    Assert-ScriptParses -Path $script:TargetPath
}


Test-Case 'ResultModel parses without syntax errors' {
    Assert-ScriptParses -Path $script:ModelPath
}


Test-Case 'Integration functions are available' {
    $requiredFunctions = @(
        'Import-WinSecTargetRegistry'
        'Test-WinSecTargetRegistry'
        'Get-WinSecRegisteredTargets'
        'Get-WinSecRegisteredTarget'
        'New-WinSecLocalTarget'
        'ConvertTo-WinSecRegisteredTarget'
        'New-WinSecResultSession'
        'Test-WinSecResultSession'
    )

    foreach ($name in $requiredFunctions) {
        $command = Get-Command `
            -Name $name `
            -CommandType Function `
            -ErrorAction SilentlyContinue

        Assert-True `
            -Condition ($null -ne $command) `
            -Message "Missing function: $name"
    }
}


# ============================================================
# GROUP 2: PRODUCTION TARGET REGISTRY
# ============================================================

Test-Case 'Production target registry imports successfully' {
    $registry = Import-WinSecTargetRegistry `
        -ProjectRoot $script:ProjectRoot

    Assert-True `
        -Condition ($null -ne $registry) `
        -Message 'Import returned null.'

    Assert-Equal `
        -Actual $registry.schemaVersion `
        -Expected '1.0.0'
}


Test-Case 'Production registry passes schema validation' {
    $registry = Import-WinSecTargetRegistry `
        -ProjectRoot $script:ProjectRoot

    $validation = Test-WinSecTargetRegistry `
        -Registry $registry

    Assert-Equal `
        -Actual $validation.Valid `
        -Expected $true

    Assert-Equal `
        -Actual $validation.Status `
        -Expected 'VALID'
}


Test-Case 'Production registry count matches its entries' {
    $registry = Import-WinSecTargetRegistry `
        -ProjectRoot $script:ProjectRoot

    $validation = Test-WinSecTargetRegistry `
        -Registry $registry

    Assert-Equal `
        -Actual $validation.TargetCount `
        -Expected @($registry.targets).Count
}


Test-Case 'Production target enumeration is consistent' {
    $registry = Import-WinSecTargetRegistry `
        -ProjectRoot $script:ProjectRoot

    $targets = @(
        Get-WinSecRegisteredTargets `
            -Registry $registry
    )

    Assert-Equal `
        -Actual $targets.Count `
        -Expected @($registry.targets).Count
}


# ============================================================
# GROUP 3: LOCAL DEVICE FALLBACK
# ============================================================

Test-Case 'Empty registry provides one local fallback' {
    $registry = New-TestRegistry

    $targets = @(
        Get-WinSecRegisteredTargets `
            -Registry $registry `
            -IncludeLocalFallback
    )

    Assert-Equal $targets.Count 1
    Assert-Equal $targets[0].Mode 'LOCAL'

    Assert-Equal `
        -Actual $targets[0].Source `
        -Expected 'LOCAL_FALLBACK'
}


Test-Case 'Local fallback matches current computer name' {
    $target = New-WinSecLocalTarget

    $hostname = [string]$env:COMPUTERNAME

    if ([string]::IsNullOrWhiteSpace($hostname)) {
        $hostname = [Environment]::MachineName
    }

    Assert-Equal `
        -Actual $target.Hostname `
        -Expected $hostname

    Assert-Equal `
        -Actual $target.DeviceId `
        -Expected "local:$hostname"

    Assert-Equal `
        -Actual $target.Enabled `
        -Expected $true
}


Test-Case 'Local fallback never has a fabricated score' {
    $target = New-WinSecLocalTarget

    Assert-Equal `
        -Actual $target.Score `
        -Expected $null

    Assert-Equal `
        -Actual $target.Status `
        -Expected 'PENDING'

    Assert-Equal `
        -Actual $target.ScanId `
        -Expected ''

    Assert-Equal `
        -Actual $target.LastScan `
        -Expected 'Never'
}


Test-Case 'Local fallback is retrievable by DeviceId' {
    $registry = New-TestRegistry

    $localTarget = New-WinSecLocalTarget

    $found = Get-WinSecRegisteredTarget `
        -Registry $registry `
        -DeviceId $localTarget.DeviceId `
        -IncludeLocalFallback

    Assert-True `
        -Condition ($null -ne $found) `
        -Message 'Local target was not found.'

    Assert-Equal `
        -Actual $found.DeviceId `
        -Expected $localTarget.DeviceId
}


Test-Case 'Existing targets prevent local fallback insertion' {
    $registry = New-TestRegistry -Targets @(
        (New-TestTarget `
            -DeviceId 'remote:SRV-001' `
            -Hostname 'SRV-001' `
            -Mode 'REMOTE')
    )

    $targets = @(
        Get-WinSecRegisteredTargets `
            -Registry $registry `
            -IncludeLocalFallback
    )

    Assert-Equal $targets.Count 1

    Assert-Equal `
        -Actual $targets[0].DeviceId `
        -Expected 'remote:SRV-001'
}


# ============================================================
# GROUP 4: MULTIPLE DEVICES
# ============================================================

Test-Case 'Registry supports three independent devices' {
    $registry = New-MultipleDeviceRegistry

    $validation = Test-WinSecTargetRegistry `
        -Registry $registry

    Assert-Equal $validation.Valid $true
    Assert-Equal $validation.TargetCount 3
}


Test-Case 'Target enumeration preserves device modes' {
    $registry = New-MultipleDeviceRegistry

    $targets = @(
        Get-WinSecRegisteredTargets `
            -Registry $registry
    )

    Assert-Equal $targets.Count 3

    $local = @(
        $targets | Where-Object {
            $_.Mode -ceq 'LOCAL'
        }
    )

    $remote = @(
        $targets | Where-Object {
            $_.Mode -ceq 'REMOTE'
        }
    )

    $imported = @(
        $targets | Where-Object {
            $_.Mode -ceq 'IMPORTED'
        }
    )

    Assert-Equal $local.Count 1
    Assert-Equal $remote.Count 1
    Assert-Equal $imported.Count 1
}


Test-Case 'EnabledOnly excludes disabled devices' {
    $registry = New-MultipleDeviceRegistry

    $targets = @(
        Get-WinSecRegisteredTargets `
            -Registry $registry `
            -EnabledOnly
    )

    Assert-Equal $targets.Count 2

    Assert-True `
        -Condition (
            @(
                $targets | Where-Object {
                    -not $_.Enabled
                }
            ).Count -eq 0
        ) `
        -Message 'Disabled target was returned.'
}


Test-Case 'Lookup does not confuse device identities' {
    $registry = New-MultipleDeviceRegistry

    $target = Get-WinSecRegisteredTarget `
        -Registry $registry `
        -DeviceId 'remote:SRV-001'

    Assert-Equal `
        -Actual $target.DeviceId `
        -Expected 'remote:SRV-001'

    Assert-Equal `
        -Actual $target.Mode `
        -Expected 'REMOTE'
}


Test-Case 'Device lookup is case-insensitive' {
    $registry = New-MultipleDeviceRegistry

    $target = Get-WinSecRegisteredTarget `
        -Registry $registry `
        -DeviceId 'REMOTE:srv-001'

    Assert-Equal `
        -Actual $target.DeviceId `
        -Expected 'remote:SRV-001'
}


Test-Case 'Unknown device lookup returns null' {
    $registry = New-MultipleDeviceRegistry

    $target = Get-WinSecRegisteredTarget `
        -Registry $registry `
        -DeviceId 'remote:UNKNOWN-SERVER'

    Assert-Equal `
        -Actual $target `
        -Expected $null
}


# ============================================================
# GROUP 5: CLI-COMPATIBLE TARGET DATA
# ============================================================

Test-Case 'Registered targets expose CLI identity fields' {
    $registry = New-MultipleDeviceRegistry

    $targets = @(
        Get-WinSecRegisteredTargets `
            -Registry $registry
    )

    foreach ($target in $targets) {
        Assert-Equal `
            -Actual $target.Id `
            -Expected $target.DeviceId

        Assert-Equal `
            -Actual $target.Name `
            -Expected $target.Hostname

        Assert-True `
            -Condition (
                $null -ne $target.PSObject.Properties['Status']
            ) `
            -Message 'CLI Status field is missing.'
    }
}


Test-Case 'Configured score metadata cannot be trusted' {
    $configured = [pscustomobject]@{
        DeviceId = 'local:TEST-PC'
        Hostname = 'TEST-PC'
        Mode = 'LOCAL'
        Enabled = $true

        Score = 100
        Status = 'PASS'
        ScanId = 'FORGED-SCAN'
        LastScan = '2026-01-01'
    }

    $target = ConvertTo-WinSecRegisteredTarget `
        -Target $configured

    Assert-Equal `
        -Actual $target.Score `
        -Expected $null

    Assert-Equal `
        -Actual $target.Status `
        -Expected 'PENDING'

    Assert-Equal `
        -Actual $target.ScanId `
        -Expected ''

    Assert-Equal `
        -Actual $target.LastScan `
        -Expected 'Never'
}


# ============================================================
# GROUP 6: RESULT MODEL INTEGRATION
# ============================================================

Test-Case 'Registered device can create a result session' {
    $registry = New-MultipleDeviceRegistry

    $target = Get-WinSecRegisteredTarget `
        -Registry $registry `
        -DeviceId 'local:PC-001'

    $session = New-WinSecResultSession `
        -DeviceId $target.DeviceId `
        -ScanId 'SCAN-001' `
        -ExpectedCheckIds @('WSA-SYS-001')

    Assert-Equal `
        -Actual $session.DeviceId `
        -Expected 'local:PC-001'

    Assert-Equal `
        -Actual $session.ScanId `
        -Expected 'SCAN-001'

    Assert-Equal `
        -Actual (
            Test-WinSecResultSession -Session $session
        ) `
        -Expected $true
}


Test-Case 'Different devices have independent sessions' {
    $registry = New-MultipleDeviceRegistry

    $targetA = Get-WinSecRegisteredTarget `
        -Registry $registry `
        -DeviceId 'local:PC-001'

    $targetB = Get-WinSecRegisteredTarget `
        -Registry $registry `
        -DeviceId 'remote:SRV-001'

    $sessionA = New-WinSecResultSession `
        -DeviceId $targetA.DeviceId `
        -ScanId 'SCAN-A' `
        -ExpectedCheckIds @('WSA-SYS-001')

    $sessionB = New-WinSecResultSession `
        -DeviceId $targetB.DeviceId `
        -ScanId 'SCAN-B' `
        -ExpectedCheckIds @('WSA-SYS-001')

    Assert-Equal `
        -Actual $sessionA.DeviceId `
        -Expected 'local:PC-001'

    Assert-Equal `
        -Actual $sessionB.DeviceId `
        -Expected 'remote:SRV-001'

    Assert-True `
        -Condition (
            $sessionA.DeviceId -cne $sessionB.DeviceId
        ) `
        -Message 'Device identities were mixed.'
}


Test-Case 'Same device supports independent scan identities' {
    $deviceId = 'local:PC-001'

    $sessionA = New-WinSecResultSession `
        -DeviceId $deviceId `
        -ScanId 'SCAN-001' `
        -ExpectedCheckIds @('WSA-SYS-001')

    $sessionB = New-WinSecResultSession `
        -DeviceId $deviceId `
        -ScanId 'SCAN-002' `
        -ExpectedCheckIds @('WSA-SYS-001')

    Assert-Equal `
        -Actual $sessionA.DeviceId `
        -Expected $sessionB.DeviceId

    Assert-True `
        -Condition (
            $sessionA.ScanId -cne $sessionB.ScanId
        ) `
        -Message 'Scan identities were mixed.'
}


Test-Case 'Target registration never creates a security score' {
    $registry = New-MultipleDeviceRegistry

    $target = Get-WinSecRegisteredTarget `
        -Registry $registry `
        -DeviceId 'local:PC-001'

    $session = New-WinSecResultSession `
        -DeviceId $target.DeviceId `
        -ScanId 'SCAN-001' `
        -ExpectedCheckIds @('WSA-SYS-001')

    Assert-Equal `
        -Actual $session.OverallScore `
        -Expected $null

    Assert-Equal `
        -Actual $session.OverallStatus `
        -Expected 'NOT_SCORED'

    Assert-Equal `
        -Actual $session.ScoringEligible `
        -Expected $false
}


Test-Case 'Independent sessions do not share result arrays' {
    $sessionA = New-WinSecResultSession `
        -DeviceId 'local:PC-001' `
        -ScanId 'SCAN-A' `
        -ExpectedCheckIds @('WSA-SYS-001')

    $sessionB = New-WinSecResultSession `
        -DeviceId 'remote:SRV-001' `
        -ScanId 'SCAN-B' `
        -ExpectedCheckIds @('WSA-SYS-001')

    Assert-Equal `
        -Actual @($sessionA.ControlResults).Count `
        -Expected 0

    Assert-Equal `
        -Actual @($sessionB.ControlResults).Count `
        -Expected 0

    Assert-Equal `
        -Actual @($sessionA.Findings).Count `
        -Expected 0

    Assert-Equal `
        -Actual @($sessionB.Findings).Count `
        -Expected 0
}


# ============================================================
# GROUP 7: INVALID TEMPORARY CONFIGURATION
# ============================================================

Test-Case 'Valid temporary target registry imports' {
    $json = @'
{
  "schemaVersion": "1.0.0",
  "targets": [
    {
      "DeviceId": "local:TEST-PC",
      "Hostname": "TEST-PC",
      "Mode": "LOCAL",
      "Enabled": true
    }
  ]
}
'@

    $registry = Import-TemporaryTargetRegistry `
        -Json $json

    Assert-Equal `
        -Actual @($registry.targets).Count `
        -Expected 1
}


Test-Case 'Malformed JSON is rejected' {
    $json = '{"schemaVersion":"1.0.0","targets":['

    Assert-Throws {
        Import-TemporaryTargetRegistry -Json $json
    }
}


Test-Case 'JSON array root is rejected' {
    $json = @'
[
  {
    "schemaVersion": "1.0.0",
    "targets": []
  }
]
'@

    Assert-Throws {
        Import-TemporaryTargetRegistry -Json $json
    } 'root'
}


Test-Case 'Missing targets array is rejected' {
    $json = @'
{
  "schemaVersion": "1.0.0"
}
'@

    Assert-Throws {
        Import-TemporaryTargetRegistry -Json $json
    }
}


Test-Case 'Unsupported schema version is rejected' {
    $json = @'
{
  "schemaVersion": "999.0.0",
  "targets": []
}
'@

    Assert-Throws {
        Import-TemporaryTargetRegistry -Json $json
    } 'schema'
}


Test-Case 'Duplicate DeviceId is rejected' {
    $json = @'
{
  "schemaVersion": "1.0.0",
  "targets": [
    {
      "DeviceId": "local:TEST-PC",
      "Hostname": "TEST-PC",
      "Mode": "LOCAL",
      "Enabled": true
    },
    {
      "DeviceId": "local:test-pc",
      "Hostname": "TEST-PC",
      "Mode": "LOCAL",
      "Enabled": true
    }
  ]
}
'@

    Assert-Throws {
        Import-TemporaryTargetRegistry -Json $json
    } 'Duplicate'
}


Test-Case 'Contradictory device mode is rejected' {
    $json = @'
{
  "schemaVersion": "1.0.0",
  "targets": [
    {
      "DeviceId": "local:TEST-PC",
      "Hostname": "TEST-PC",
      "Mode": "REMOTE",
      "Enabled": true
    }
  ]
}
'@

    Assert-Throws {
        Import-TemporaryTargetRegistry -Json $json
    } 'mismatch'
}


Test-Case 'String Enabled value is rejected' {
    $json = @'
{
  "schemaVersion": "1.0.0",
  "targets": [
    {
      "DeviceId": "local:TEST-PC",
      "Hostname": "TEST-PC",
      "Mode": "LOCAL",
      "Enabled": "true"
    }
  ]
}
'@

    Assert-Throws {
        Import-TemporaryTargetRegistry -Json $json
    } 'Boolean'
}


Test-Case 'Unsafe device identifier is rejected' {
    $json = @'
{
  "schemaVersion": "1.0.0",
  "targets": [
    {
      "DeviceId": "local:TEST PC",
      "Hostname": "TEST-PC",
      "Mode": "LOCAL",
      "Enabled": true
    }
  ]
}
'@

    Assert-Throws {
        Import-TemporaryTargetRegistry -Json $json
    } 'DeviceId'
}


# ============================================================
# GROUP 8: PRODUCTION FILE INTEGRITY
# ============================================================

Test-Case 'Production targets.json remains unchanged' {
    $hashAfter = (
        Get-FileHash `
            -LiteralPath $script:ConfigPath `
            -Algorithm SHA256
    ).Hash

    Assert-Equal `
        -Actual $hashAfter `
        -Expected $script:ConfigHashBefore `
        -Message 'Production configuration was modified.'
}


# ============================================================
# TEST SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray

Write-Host (
    'TARGET REGISTRY INTEGRATION TEST SUMMARY'
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
        '{0} TargetRegistry integration test(s) failed.' -f
            $script:Failed
    )
}

Write-Host (
    'All TargetRegistry integration tests passed.'
) -ForegroundColor Green
