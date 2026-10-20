
# ============================================================
# WinSec Analyzer
# Test Suite : Target Registry Unit Tests
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit tests for TargetRegistry.ps1.
#
# Includes:
# - Device identifier validation
# - LOCAL / REMOTE / IMPORTED modes
# - Target schema validation
# - Duplicate detection
# - Local device fallback
# - Lookup and filtering
# - Untrusted score metadata protection
# - Read-only source inspection
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# Synthetic data only.
# Does not modify project files or Windows settings.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

$script:RegistryPath = Join-Path `
    $script:ProjectRoot 'src/Core/TargetRegistry.ps1'

# ============================================================
# ASSERTIONS
# ============================================================

function Assert-WinSecEqual {
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

function Assert-WinSecTrue {
    param(
        [bool]$Condition,
        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-WinSecThrows {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
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
        $MessagePattern -and
        $caught.Exception.Message -notmatch $MessagePattern
    ) {
        throw (
            "Unexpected exception: $($caught.Exception.Message)"
        )
    }
}

function Test-WinSecCase {
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
# FIXTURES
# ============================================================

function New-WinSecFixtureTarget {
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
        Description = 'Synthetic test target'
    }
}

function New-WinSecFixtureRegistry {
    param(
        [AllowEmptyCollection()]
        [object[]]$Targets = @()
    )

    return [pscustomobject]@{
        schemaVersion = '1.0.0'
        targets = @($Targets)
    }
}

# ============================================================
# INITIALIZATION
# ============================================================

Write-Host ''
Write-Host 'WinSec Analyzer - Target Registry Unit Tests' `
    -ForegroundColor Cyan
Write-Host ''

if (-not (
    Test-Path -LiteralPath $script:RegistryPath -PathType Leaf
)) {
    throw "TargetRegistry not found: $script:RegistryPath"
}

. $script:RegistryPath

# ============================================================
# GROUP 1: PUBLIC CONTRACT
# ============================================================

Test-WinSecCase 'TargetRegistry parses correctly' {
    $tokens = $null
    $errors = $null

    
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:RegistryPath,
        [ref]$tokens,
        [ref]$errors
    )


    Assert-WinSecEqual @($errors).Count 0
}

Test-WinSecCase 'All public functions are available' {
    foreach ($name in @(
        'Get-WinSecTargetField'
        'Test-WinSecTargetIdentifier'
        'ConvertTo-WinSecRegisteredTarget'
        'Test-WinSecTargetRegistry'
        'Import-WinSecTargetRegistry'
        'New-WinSecLocalTarget'
        'Get-WinSecRegisteredTargets'
        'Get-WinSecRegisteredTarget'
    )) {
        Assert-WinSecTrue (
            $null -ne (
                Get-Command $name `
                    -CommandType Function `
                    -ErrorAction SilentlyContinue
            )
        ) "Missing function: $name"
    }
}

Test-WinSecCase 'Dictionary properties are case-insensitive' {
    $target = @{
        DeviceId = 'local:TEST-PC'
    }

    Assert-WinSecEqual (
        Get-WinSecTargetField $target 'deviceid'
    ) 'local:TEST-PC'
}

Test-WinSecCase 'Object properties are readable' {
    $target = [pscustomobject]@{
        DeviceId = 'local:TEST-PC'
    }

    Assert-WinSecEqual (
        Get-WinSecTargetField $target 'DeviceId'
    ) 'local:TEST-PC'
}

Test-WinSecCase 'Missing property returns null' {
    $target = [pscustomobject]@{
        DeviceId = 'local:TEST-PC'
    }

    Assert-WinSecEqual (
        Get-WinSecTargetField $target 'Missing'
    ) $null
}

# ============================================================
# GROUP 2: DEVICE IDENTIFIERS
# ============================================================

Test-WinSecCase 'Valid DeviceId is accepted' {
    Assert-WinSecEqual (
        Test-WinSecTargetIdentifier 'local:TEST-PC'
    ) $true
}

Test-WinSecCase 'Whitespace identifiers are rejected' {
    foreach ($value in @(
        ' '
        'local:TEST PC'
        ' local:TEST-PC'
        'local:TEST-PC '
    )) {
        Assert-WinSecEqual (
            Test-WinSecTargetIdentifier $value
        ) $false
    }
}

Test-WinSecCase 'Path and command characters are rejected' {
    foreach ($value in @(
        'local:PC/ONE'
        'local:PC\ONE'
        'local:PC;ONE'
        'local:PC|ONE'
        'local:PC$(TEST)'
    )) {
        Assert-WinSecEqual (
            Test-WinSecTargetIdentifier $value
        ) $false
    }
}

Test-WinSecCase 'Excessively long identifiers are rejected' {
    $identifier = 'A' * 129

    Assert-WinSecEqual (
        Test-WinSecTargetIdentifier $identifier
    ) $false
}

# ============================================================
# GROUP 3: TARGET NORMALIZATION
# ============================================================

Test-WinSecCase 'Minimal target normalizes correctly' {
    $target = ConvertTo-WinSecRegisteredTarget `
        -Target (New-WinSecFixtureTarget)

    Assert-WinSecEqual $target.DeviceId 'local:TEST-PC'
    Assert-WinSecEqual $target.Hostname 'TEST-PC'
    Assert-WinSecEqual $target.Mode 'LOCAL'
    Assert-WinSecEqual $target.Enabled $true
}

Test-WinSecCase 'Id and Name aliases are preserved' {
    $target = ConvertTo-WinSecRegisteredTarget `
        -Target @{
            Id = 'remote:SERVER-01'
            Name = 'SERVER-01'
            Mode = 'REMOTE'
        }

    Assert-WinSecEqual $target.DeviceId 'remote:SERVER-01'
    Assert-WinSecEqual $target.Hostname 'SERVER-01'
    Assert-WinSecEqual $target.Id $target.DeviceId
    Assert-WinSecEqual $target.Name $target.Hostname
}

Test-WinSecCase 'Supported device modes are accepted' {
    foreach ($test in @(
        @{ Id = 'local:PC-01'; Mode = 'LOCAL' }
        @{ Id = 'remote:SRV-01'; Mode = 'REMOTE' }
        @{ Id = 'imported:PC-02'; Mode = 'IMPORTED' }
    )) {
        $target = ConvertTo-WinSecRegisteredTarget `
            -Target @{
                DeviceId = $test.Id
                Hostname = 'TESTHOST'
                Mode = $test.Mode
            }

        Assert-WinSecEqual $target.Mode $test.Mode
    }
}

Test-WinSecCase 'DeviceId and Mode mismatch is rejected' {
    Assert-WinSecThrows {
        ConvertTo-WinSecRegisteredTarget `
            -Target @{
                DeviceId = 'local:TEST-PC'
                Hostname = 'TEST-PC'
                Mode = 'REMOTE'
            }
    } 'mismatch'
}

Test-WinSecCase 'Unsupported collection mode is rejected' {
    Assert-WinSecThrows {
        ConvertTo-WinSecRegisteredTarget `
            -Target @{
                DeviceId = 'remote:SERVER-01'
                Hostname = 'SERVER-01'
                Mode = 'UNSUPPORTED'
            }
    } 'Mode'
}

Test-WinSecCase 'Unprefixed identifier permits UNKNOWN mode' {
    $target = ConvertTo-WinSecRegisteredTarget `
        -Target @{
            DeviceId = 'DEVICE-001'
            Hostname = 'DEVICE-001'
        }

    Assert-WinSecEqual $target.Mode 'UNKNOWN'
}

Test-WinSecCase 'Missing Enabled defaults to false' {
    $target = ConvertTo-WinSecRegisteredTarget `
        -Target @{
            DeviceId = 'remote:SERVER-01'
            Hostname = 'SERVER-01'
            Mode = 'REMOTE'
        }

    Assert-WinSecEqual $target.Enabled $false
}

Test-WinSecCase 'Enabled must be Boolean' {
    Assert-WinSecThrows {
        ConvertTo-WinSecRegisteredTarget `
            -Target @{
                DeviceId = 'local:TEST-PC'
                Hostname = 'TEST-PC'
                Enabled = 'true'
            }
    } 'Boolean'
}

Test-WinSecCase 'Valid description is preserved' {
    $target = ConvertTo-WinSecRegisteredTarget `
        -Target @{
            DeviceId = 'local:TEST-PC'
            Hostname = 'TEST-PC'
            Description = 'Workstation for synthetic testing'
        }

    Assert-WinSecEqual (
        $target.Description
    ) 'Workstation for synthetic testing'
}

Test-WinSecCase 'Control characters in description are rejected' {
    Assert-WinSecThrows {
        ConvertTo-WinSecRegisteredTarget `
            -Target @{
                DeviceId = 'local:TEST-PC'
                Hostname = 'TEST-PC'
                Description = "Invalid`nDescription"
            }
    } 'Description'
}

Test-WinSecCase 'Invalid hostname is rejected' {
    Assert-WinSecThrows {
        ConvertTo-WinSecRegisteredTarget `
            -Target @{
                DeviceId = 'remote:SERVER-01'
                Hostname = 'SERVER 01'
                Mode = 'REMOTE'
            }
    } 'Hostname'
}

Test-WinSecCase 'Forged scan and score metadata are ignored' {
    $target = ConvertTo-WinSecRegisteredTarget `
        -Target @{
            DeviceId = 'local:TEST-PC'
            Hostname = 'TEST-PC'
            Mode = 'LOCAL'
            Enabled = $true

            Score = 100
            Status = 'PASS'
            ScanId = 'FORGED-SCAN'
            LastScan = '2026-01-01'
        }

    Assert-WinSecEqual $target.Score $null
    Assert-WinSecEqual $target.Status 'PENDING'
    Assert-WinSecEqual $target.ScanId ''
    Assert-WinSecEqual $target.LastScan 'Never'
}

# ============================================================
# GROUP 4: REGISTRY VALIDATION
# ============================================================

Test-WinSecCase 'Empty registry is valid' {
    $result = Test-WinSecTargetRegistry `
        -Registry (New-WinSecFixtureRegistry)

    Assert-WinSecEqual $result.Valid $true
    Assert-WinSecEqual $result.TargetCount 0
}

Test-WinSecCase 'Array root is rejected' {
    $result = Test-WinSecTargetRegistry `
        -Registry @(
            [pscustomobject]@{
                schemaVersion = '1.0.0'
                targets = @()
            }
        )

    Assert-WinSecEqual $result.Valid $false
}

Test-WinSecCase 'Unsupported schema is rejected' {
    $registry = New-WinSecFixtureRegistry
    $registry.schemaVersion = '999.0.0'

    $result = Test-WinSecTargetRegistry `
        -Registry $registry

    Assert-WinSecEqual $result.Valid $false
}

Test-WinSecCase 'Missing targets collection is rejected' {
    $result = Test-WinSecTargetRegistry `
        -Registry @{
            schemaVersion = '1.0.0'
        }

    Assert-WinSecEqual $result.Valid $false
}

Test-WinSecCase 'Null targets collection is rejected' {
    $result = Test-WinSecTargetRegistry `
        -Registry @{
            schemaVersion = '1.0.0'
            targets = $null
        }

    Assert-WinSecEqual $result.Valid $false
}

Test-WinSecCase 'Duplicate DeviceId is rejected case-insensitively' {
    $registry = New-WinSecFixtureRegistry -Targets @(
        (New-WinSecFixtureTarget -DeviceId 'local:TEST-PC')
        (New-WinSecFixtureTarget -DeviceId 'local:test-pc')
    )

    $result = Test-WinSecTargetRegistry `
        -Registry $registry

    Assert-WinSecEqual $result.Valid $false

    Assert-WinSecTrue (
        ($result.Errors -join ' ') -match 'Duplicate'
    ) 'Expected duplicate DeviceId diagnostic.'
}

Test-WinSecCase 'Malformed target entry is rejected' {
    $registry = New-WinSecFixtureRegistry -Targets @(
        @{
            Hostname = 'TEST-PC'
            Mode = 'LOCAL'
        }
    )

    $result = Test-WinSecTargetRegistry `
        -Registry $registry

    Assert-WinSecEqual $result.Valid $false
}

Test-WinSecCase 'Three independent targets are valid' {
    $registry = New-WinSecFixtureRegistry -Targets @(
        (New-WinSecFixtureTarget `
            -DeviceId 'local:PC-001' `
            -Hostname 'PC-001')

        (New-WinSecFixtureTarget `
            -DeviceId 'remote:SRV-001' `
            -Hostname 'SRV-001' `
            -Mode 'REMOTE')

        (New-WinSecFixtureTarget `
            -DeviceId 'imported:PC-002' `
            -Hostname 'PC-002' `
            -Mode 'IMPORTED')
    )

    $result = Test-WinSecTargetRegistry `
        -Registry $registry

    Assert-WinSecEqual $result.Valid $true
    Assert-WinSecEqual $result.TargetCount 3
}

# ============================================================
# GROUP 5: ENUMERATION AND LOOKUP
# ============================================================

Test-WinSecCase 'Registered targets are enumerated' {
    $registry = New-WinSecFixtureRegistry -Targets @(
        (New-WinSecFixtureTarget `
            -DeviceId 'local:PC-001' `
            -Hostname 'PC-001')

        (New-WinSecFixtureTarget `
            -DeviceId 'remote:SRV-001' `
            -Hostname 'SRV-001' `
            -Mode 'REMOTE')
    )

    $targets = @(
        Get-WinSecRegisteredTargets -Registry $registry
    )

    Assert-WinSecEqual $targets.Count 2
}

Test-WinSecCase 'EnabledOnly excludes disabled targets' {
    $registry = New-WinSecFixtureRegistry -Targets @(
        (New-WinSecFixtureTarget `
            -DeviceId 'local:PC-001' `
            -Hostname 'PC-001' `
            -Enabled $true)

        (New-WinSecFixtureTarget `
            -DeviceId 'remote:SRV-001' `
            -Hostname 'SRV-001' `
            -Mode 'REMOTE' `
            -Enabled $false)
    )

    $targets = @(
        Get-WinSecRegisteredTargets `
            -Registry $registry `
            -EnabledOnly
    )

    Assert-WinSecEqual $targets.Count 1
    Assert-WinSecEqual $targets[0].DeviceId 'local:PC-001'
}

Test-WinSecCase 'Empty registry provides local fallback' {
    $registry = New-WinSecFixtureRegistry

    $targets = @(
        Get-WinSecRegisteredTargets `
            -Registry $registry `
            -IncludeLocalFallback
    )

    Assert-WinSecEqual $targets.Count 1
    Assert-WinSecEqual $targets[0].Mode 'LOCAL'
    Assert-WinSecEqual $targets[0].Source 'LOCAL_FALLBACK'
}

Test-WinSecCase 'Nonempty registry does not add fallback' {
    $registry = New-WinSecFixtureRegistry -Targets @(
        (New-WinSecFixtureTarget `
            -DeviceId 'remote:SERVER-01' `
            -Hostname 'SERVER-01' `
            -Mode 'REMOTE')
    )

    $targets = @(
        Get-WinSecRegisteredTargets `
            -Registry $registry `
            -IncludeLocalFallback
    )

    Assert-WinSecEqual $targets.Count 1
    Assert-WinSecEqual $targets[0].Mode 'REMOTE'
}

Test-WinSecCase 'Device lookup is case-insensitive' {
    $registry = New-WinSecFixtureRegistry -Targets @(
        (New-WinSecFixtureTarget)
    )

    $target = Get-WinSecRegisteredTarget `
        -Registry $registry `
        -DeviceId 'LOCAL:test-pc'

    Assert-WinSecEqual $target.DeviceId 'local:TEST-PC'
}

Test-WinSecCase 'Unknown DeviceId returns null' {
    $registry = New-WinSecFixtureRegistry

    $target = Get-WinSecRegisteredTarget `
        -Registry $registry `
        -DeviceId 'remote:NOT-REGISTERED'

    Assert-WinSecEqual $target $null
}

Test-WinSecCase 'Invalid lookup identifier is rejected' {
    $registry = New-WinSecFixtureRegistry

    Assert-WinSecThrows {
        Get-WinSecRegisteredTarget `
            -Registry $registry `
            -DeviceId 'invalid device'
    } 'DeviceId'
}

# ============================================================
# GROUP 6: READ-ONLY GUARANTEE
# ============================================================

Test-WinSecCase 'TargetRegistry has no system modification commands' {
    $tokens = $null
    $errors = $null

    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:RegistryPath,
        [ref]$tokens,
        [ref]$errors
    )

    $commands = $ast.FindAll({
        param($node)

        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true)

    $forbidden = @(
        'Set-ItemProperty'
        'New-Item'
        'Remove-Item'
        'Set-Content'
        'Add-Content'
        'Out-File'
        'Set-MpPreference'
        'Set-NetFirewallProfile'
        'Invoke-Command'
        'New-PSSession'
        'Enter-PSSession'
        'Restart-Computer'
    )

    foreach ($command in $commands) {
        $name = $command.GetCommandName()

        Assert-WinSecTrue (
            $name -notin $forbidden
        ) "Forbidden command found: $name"
    }
}

# ============================================================
# SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'TARGET REGISTRY UNIT TEST SUMMARY' -ForegroundColor Cyan
Write-Host "TOTAL : $total"
Write-Host "PASS  : $($script:Passed)" -ForegroundColor Green
Write-Host "FAIL  : $($script:Failed)" -ForegroundColor $(
    if ($script:Failed -gt 0) { 'Red' } else { 'Green' }
)
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''

if ($script:Failed -gt 0) {
    throw "$($script:Failed) TargetRegistry unit test(s) failed."
}

Write-Host 'All TargetRegistry unit tests passed.' `
    -ForegroundColor Green
