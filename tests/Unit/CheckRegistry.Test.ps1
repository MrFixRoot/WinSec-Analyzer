
# ============================================================
# WinSec Analyzer
# Test Suite : CheckRegistry
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit tests for security check registration.
#
# Tests:
# - Catalog loading and validation
# - Unique check identifiers
# - Security section definitions
# - Control metadata
# - Execution eligibility
# - Script path restrictions
# - PowerShell syntax verification
# - Declared function detection
# - Invalid JSON handling
#
# Requirements:
# - PowerShell 5.1+
# - No external dependencies
# - No administrator privileges required
#
# Security:
# - No security checks are executed
# - Production configuration remains unchanged
# - Temporary test files are removed afterward
# 
# .\tests\Unit\CheckRegistry.Test.ps1
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# Project paths
# ------------------------------------------------------------

$projectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)

$registryPath = Join-Path `
    -Path $projectRoot `
    -ChildPath 'src/Core/CheckRegistry.ps1'

$catalogPath = Join-Path `
    -Path $projectRoot `
    -ChildPath 'config/checks.json'

# ------------------------------------------------------------
# Required files
# ------------------------------------------------------------

if (-not (Test-Path -LiteralPath $registryPath -PathType Leaf)) {
    throw "CheckRegistry.ps1 not found: $registryPath"
}

if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
    throw "checks.json not found: $catalogPath"
}

# ------------------------------------------------------------
# Load module
# ------------------------------------------------------------

. $registryPath

# ------------------------------------------------------------
# Test state
# ------------------------------------------------------------

$script:TestsPassed = 0
$script:TestsFailed = 0

$script:BaseCatalog = $null
$script:BaseRegistry = $null

$script:FixtureRoot = Join-Path `
    -Path ([System.IO.Path]::GetTempPath()) `
    -ChildPath (
        'WinSec-RegistryTests-' +
        [guid]::NewGuid().ToString('N')
    )

# ------------------------------------------------------------
# Assertions
# ------------------------------------------------------------

function Assert-WinSecEqual {
    param(
        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Expected,

        [string]$Message = 'Values do not match.'
    )

    if ($Actual -ne $Expected) {
        throw (
            '{0} Expected: [{1}], Actual: [{2}]' -f `
                $Message,
                $Expected,
                $Actual
        )
    }
}


function Assert-WinSecTrue {
    param(
        [bool]$Condition,

        [string]$Message = 'Expected condition is false.'
    )

    if (-not $Condition) {
        throw $Message
    }
}


function Assert-WinSecThrows {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action,

        [string]$ExpectedPattern = ''
    )

    $caught = $false
    $message = ''

    try {
        $null = & $Action
    }
    catch {
        $caught = $true
        $message = $_.Exception.Message
    }

    if (-not $caught) {
        throw 'Expected an exception, but none occurred.'
    }

    if (
        $ExpectedPattern -and
        $message -notmatch $ExpectedPattern
    ) {
        throw (
            'Unexpected exception: {0}' -f $message
        )
    }
}


# ------------------------------------------------------------
# Test execution wrapper
# ------------------------------------------------------------

function Invoke-WinSecRegistryTest {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Test
    )

    try {
        $null = & $Test

        $script:TestsPassed++

        Write-Host "[PASS] $Name" `
            -ForegroundColor Green
    }
    catch {
        $script:TestsFailed++

        Write-Host "[FAIL] $Name" `
            -ForegroundColor Red

        Write-Host (
            '       {0}' -f $_.Exception.Message
        ) -ForegroundColor DarkGray
    }
}


# ------------------------------------------------------------
# Create independent catalog copy
# ------------------------------------------------------------

function Copy-WinSecTestCatalog {
    [CmdletBinding()]
    param()

    $json = ConvertTo-Json `
        -InputObject $script:BaseCatalog `
        -Depth 50

    return ConvertFrom-Json `
        -InputObject $json
}


# ------------------------------------------------------------
# Save temporary catalog
# ------------------------------------------------------------

function New-WinSecTestCatalogFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Catalog
    )

    $path = Join-Path `
        -Path $script:FixtureRoot `
        -ChildPath (
            [guid]::NewGuid().ToString('N') + '.json'
        )

    $json = ConvertTo-Json `
        -InputObject $Catalog `
        -Depth 50

    Set-Content `
        -LiteralPath $path `
        -Value $json `
        -Encoding UTF8

    return $path
}


# ------------------------------------------------------------
# Test a modified catalog
# ------------------------------------------------------------

function Assert-WinSecInvalidCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Catalog,

        [Parameter(Mandatory)]
        [string]$ExpectedPattern
    )

    Assert-WinSecThrows `
        -Action {
            Test-WinSecCheckCatalog -Catalog $Catalog
        } `
        -ExpectedPattern $ExpectedPattern
}


# ------------------------------------------------------------
# Prepare test environment
# ------------------------------------------------------------

Write-Host ''
Write-Host ('=' * 55) -ForegroundColor DarkGray
Write-Host 'WINSEC ANALYZER - CHECK REGISTRY UNIT TESTS' `
    -ForegroundColor Cyan
Write-Host ('=' * 55) -ForegroundColor DarkGray
Write-Host ''

New-Item `
    -Path $script:FixtureRoot `
    -ItemType Directory `
    -Force | Out-Null

try {

    # --------------------------------------------------------
    # Load production catalog without modifying it
    # --------------------------------------------------------

    $content = Get-Content `
        -LiteralPath $catalogPath `
        -Raw `
        -Encoding UTF8

    $script:BaseCatalog = ConvertFrom-Json `
        -InputObject $content

    $script:BaseRegistry = Get-WinSecCheckRegistry `
        -ProjectRoot $projectRoot `
        -Path $catalogPath


    # ========================================================
    # GROUP 1 - CATALOG STRUCTURE
    # ========================================================

    Write-Host '[1] CATALOG STRUCTURE' `
        -ForegroundColor Cyan

    Write-Host ''

    Invoke-WinSecRegistryTest `
        -Name 'Catalog passes structural validation' `
        -Test {

            $valid = Test-WinSecCheckCatalog `
                -Catalog $script:BaseCatalog

            Assert-WinSecEqual `
                -Actual $valid `
                -Expected $true
        }


    Invoke-WinSecRegistryTest `
        -Name 'Catalog contains five security sections' `
        -Test {

            Assert-WinSecEqual `
                -Actual $script:BaseRegistry.Sections.Count `
                -Expected 5

            $expected = @(
                'SystemSecurity'
                'NetworkSecurity'
                'IdentityAccess'
                'LoggingAuditing'
                'ServicesHardening'
            )

            $actual = @(
                $script:BaseRegistry.Sections |
                    ForEach-Object { $_.key }
            )

            foreach ($key in $expected) {

                Assert-WinSecTrue `
                    -Condition ($key -in $actual) `
                    -Message "Missing section: $key"
            }
        }


    Invoke-WinSecRegistryTest `
        -Name 'Catalog contains 14 registered controls' `
        -Test {

            Assert-WinSecEqual `
                -Actual $script:BaseRegistry.TotalChecks `
                -Expected 14

            Assert-WinSecEqual `
                -Actual $script:BaseRegistry.Checks.Count `
                -Expected 14
        }


    Invoke-WinSecRegistryTest `
        -Name 'Only individually validated System Security controls are executable' `
        -Test {

            $summary = Get-WinSecCheckRegistrySummary `
                -Registry $script:BaseRegistry

            Assert-WinSecEqual `
                -Actual $summary.Planned `
                -Expected 2

            Assert-WinSecEqual `
                -Actual $summary.PendingValidation `
                -Expected 9

            Assert-WinSecEqual `
                -Actual $summary.Enabled `
                -Expected 3

            Assert-WinSecEqual `
                -Actual $summary.Ready `
                -Expected 3
            $executable=@($script:BaseRegistry.Checks|Where-Object ExecutionEnabled)
            Assert-WinSecEqual -Actual (($executable.CheckId | Sort-Object) -join '|') -Expected 'WSA-SYS-001|WSA-SYS-002|WSA-SYS-003'
            foreach ($check in $executable) {
                Assert-WinSecEqual -Actual $check.ImplementationStatus -Expected 'VALIDATED'
                Assert-WinSecEqual -Actual $check.ExecutionReady -Expected $true
            }
        }


    Invoke-WinSecRegistryTest `
        -Name 'Registry filters Network Security controls' `
        -Test {

            $network = @(
                Get-WinSecRegisteredChecks `
                    -Registry $script:BaseRegistry `
                    -SectionKey 'NetworkSecurity'
            )

            Assert-WinSecEqual `
                -Actual $network.Count `
                -Expected 5

            foreach ($check in $network) {

                Assert-WinSecEqual `
                    -Actual $check.SectionKey `
                    -Expected 'NetworkSecurity'
            }
        }


    Invoke-WinSecRegistryTest `
        -Name 'CheckId lookup returns correct control' `
        -Test {

            $check = Get-WinSecRegisteredCheck `
                -Registry $script:BaseRegistry `
                -CheckId 'WSA-SYS-001'

            Assert-WinSecEqual `
                -Actual $check.ControlKey `
                -Expected 'Defender'

            Assert-WinSecEqual `
                -Actual $check.SectionKey `
                -Expected 'SystemSecurity'

            $missing = Get-WinSecRegisteredCheck `
                -Registry $script:BaseRegistry `
                -CheckId 'WSA-SYS-999'

            Assert-WinSecEqual `
                -Actual $missing `
                -Expected $null
        }


    Invoke-WinSecRegistryTest `
        -Name 'Only executable controls are returned' `
        -Test {

            $ready = @(
                Get-WinSecExecutableChecks `
                    -Registry $script:BaseRegistry
            )

            Assert-WinSecEqual `
                -Actual $ready.Count `
                -Expected 3
            Assert-WinSecEqual -Actual (($ready.CheckId | Sort-Object) -join '|') -Expected 'WSA-SYS-001|WSA-SYS-002|WSA-SYS-003'
        }


    # ========================================================
    # GROUP 2 - UNIQUE IDENTIFIERS
    # ========================================================

    Write-Host ''
    Write-Host '[2] IDENTIFIER VALIDATION' `
        -ForegroundColor Cyan

    Write-Host ''

    Invoke-WinSecRegistryTest `
        -Name 'Duplicate CheckId is rejected' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.checks[1].checkId = (
                $copy.checks[0].checkId
            )

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'Duplicate CheckId'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Duplicate controlKey is rejected' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.checks[1].controlKey = (
                $copy.checks[0].controlKey
            )

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'Duplicate controlKey'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Duplicate section key is rejected' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.sections[1].key = (
                $copy.sections[0].key
            )

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'Duplicate security section'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Duplicate section order is rejected' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.sections[1].order = (
                $copy.sections[0].order
            )

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'Duplicate section order'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Duplicate control order is rejected' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.checks[1].order = (
                $copy.checks[0].order
            )

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'Duplicate control order'
        }


    Invoke-WinSecRegistryTest `
        -Name 'CheckId must match its security section' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.checks[0].checkId = 'WSA-NET-999'

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'Invalid CheckId'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Unknown security section is rejected' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.checks[0].sectionKey = 'UnknownSection'

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'unknown section'
        }


    # ========================================================
    # GROUP 3 - EXECUTION POLICY
    # ========================================================

    Write-Host ''
    Write-Host '[3] EXECUTION POLICY' `
        -ForegroundColor Cyan

    Write-Host ''

    Invoke-WinSecRegistryTest `
        -Name 'Automatic execution is rejected' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.executionPolicy.automaticExecutionOnStartup = $true

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'execution policy'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Read-only requirement is enforced' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.executionPolicy.readOnly = $false

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'execution policy'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Unvalidated enabled control is rejected' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.checks[0].execution.enabled = $true
            $copy.checks[0].implementationStatus = 'PENDING_VALIDATION'

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'before implementation validation'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Informational control cannot earn points' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $openPorts = @(
                $copy.checks | Where-Object {
                    $_.controlKey -eq 'OpenPorts'
                }
            )[0]

            $openPorts.assessment.scoringEligible = $true
            $openPorts.assessment.criteriaSource = 'TEST-ONLY'

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'Informational check'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Scoring control requires documented criteria' `
        -Test {

            $copy = Copy-WinSecTestCatalog

            $copy.checks[0].assessment.scoringEligible = $true
            $copy.checks[0].assessment.criteriaSource = $null

            Assert-WinSecInvalidCatalog `
                -Catalog $copy `
                -ExpectedPattern 'criteriaSource'
        }


    # ========================================================
    # GROUP 4 - SCRIPT PATH SECURITY
    # ========================================================

    Write-Host ''
    Write-Host '[4] SCRIPT PATH VALIDATION' `
        -ForegroundColor Cyan

    Write-Host ''

    Invoke-WinSecRegistryTest `
        -Name 'Valid relative script path is accepted' `
        -Test {

            $path = Resolve-WinSecCheckScriptPath `
                -ProjectRoot $projectRoot `
                -RelativePath (
                    'src/Checks/Defender/Test-Defender.ps1'
                )

            Assert-WinSecEqual `
                -Actual (
                    [System.IO.Path]::GetFileName($path)
                ) `
                -Expected 'Test-Defender.ps1'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Directory traversal is rejected' `
        -Test {

            Assert-WinSecThrows `
                -Action {

                    Resolve-WinSecCheckScriptPath `
                        -ProjectRoot $projectRoot `
                        -RelativePath (
                            'src/Checks/../../config/checks.json'
                        )
                } `
                -ExpectedPattern 'src/Checks'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Absolute script paths are rejected' `
        -Test {

            Assert-WinSecThrows `
                -Action {

                    Resolve-WinSecCheckScriptPath `
                        -ProjectRoot $projectRoot `
                        -RelativePath $registryPath
                } `
                -ExpectedPattern 'Absolute security check paths'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Non-PowerShell script extensions are rejected' `
        -Test {

            Assert-WinSecThrows `
                -Action {

                    Resolve-WinSecCheckScriptPath `
                        -ProjectRoot $projectRoot `
                        -RelativePath (
                            'src/Checks/Test-Invalid.exe'
                        )
                } `
                -ExpectedPattern '\.ps1'
        }


    # ========================================================
    # GROUP 5 - SCRIPT INSPECTION
    # ========================================================

    Write-Host ''
    Write-Host '[5] SCRIPT INSPECTION' `
        -ForegroundColor Cyan

    Write-Host ''

    $validScriptPath = Join-Path `
        -Path $script:FixtureRoot `
        -ChildPath 'ValidCheck.ps1'

    $invalidScriptPath = Join-Path `
        -Path $script:FixtureRoot `
        -ChildPath 'InvalidCheck.ps1'

    Set-Content `
        -LiteralPath $validScriptPath `
        -Encoding UTF8 `
        -Value @'
function Test-WinSecFixture {
    return 'TEST ONLY'
}
'@

    Set-Content `
        -LiteralPath $invalidScriptPath `
        -Encoding UTF8 `
        -Value @'
function Test-WinSecFixture {
    if (
}
'@


    Invoke-WinSecRegistryTest `
        -Name 'Valid PowerShell function is detected' `
        -Test {

            $valid = Test-WinSecCheckScript `
                -ScriptPath $validScriptPath `
                -FunctionName 'Test-WinSecFixture'

            Assert-WinSecEqual `
                -Actual $valid `
                -Expected $true
        }


    Invoke-WinSecRegistryTest `
        -Name 'Missing declared function is rejected' `
        -Test {

            Assert-WinSecThrows `
                -Action {

                    Test-WinSecCheckScript `
                        -ScriptPath $validScriptPath `
                        -FunctionName 'Test-WinSecMissing'
                } `
                -ExpectedPattern 'Expected function'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Invalid PowerShell syntax is rejected' `
        -Test {

            Assert-WinSecThrows `
                -Action {

                    Test-WinSecCheckScript `
                        -ScriptPath $invalidScriptPath `
                        -FunctionName 'Test-WinSecFixture'
                } `
                -ExpectedPattern 'syntax error'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Missing script file is rejected' `
        -Test {

            $missingPath = Join-Path `
                -Path $script:FixtureRoot `
                -ChildPath 'DoesNotExist.ps1'

            Assert-WinSecThrows `
                -Action {

                    Test-WinSecCheckScript `
                        -ScriptPath $missingPath `
                        -FunctionName 'Test-WinSecFixture'
                } `
                -ExpectedPattern 'not found'
        }


    # ========================================================
    # GROUP 6 - EXECUTION ELIGIBILITY
    # ========================================================

    Write-Host ''
    Write-Host '[6] EXECUTION ELIGIBILITY' `
        -ForegroundColor Cyan

    Write-Host ''

    Invoke-WinSecRegistryTest `
        -Name 'Validated enabled check becomes READY' `
        -Test {

            # -----------------------------------------------
            # Use a temporary project, not the production one
            # -----------------------------------------------

            $copy = Copy-WinSecTestCatalog
            # This temporary project contains only the synthetic script below.
            foreach ($check in $copy.checks) {
                $check.execution.enabled = $false
            }

            $firstCheck = $copy.checks[0]

            $firstCheck.implementationStatus = 'VALIDATED'
            $firstCheck.execution.enabled = $true

            # -----------------------------------------------
            # Create a synthetic script in the test directory
            # -----------------------------------------------

            $relativePath = (
                $firstCheck.execution.script
            ).Replace('/', '\')

            $scriptPath = Join-Path `
                -Path $script:FixtureRoot `
                -ChildPath $relativePath

            $scriptDirectory = (
                [System.IO.Path]::GetDirectoryName(
                    $scriptPath
                )
            )

            New-Item `
                -Path $scriptDirectory `
                -ItemType Directory `
                -Force | Out-Null

            $markerPath = Join-Path `
                -Path $script:FixtureRoot `
                -ChildPath 'SCRIPT-EXECUTED.marker'

            $escapedMarker = $markerPath.Replace(
                "'",
                "''"
            )

            $functionName = (
                $firstCheck.execution.function
            )

            # This top-level statement would create a marker
            # if the script were accidentally executed.
            # Registry validation must only parse the source.

            $scriptContent = @"
Set-Content -LiteralPath '$escapedMarker' -Value 'EXECUTED'

function $functionName {
    return 'SYNTHETIC TEST'
}
"@

            Set-Content `
                -LiteralPath $scriptPath `
                -Value $scriptContent `
                -Encoding UTF8

            # -----------------------------------------------
            # Save the temporary catalog
            # -----------------------------------------------

            $fixtureCatalogPath = New-WinSecTestCatalogFile `
                -Catalog $copy

            # -----------------------------------------------
            # Load fixture registry
            # -----------------------------------------------

            $registry = Get-WinSecCheckRegistry `
                -ProjectRoot $script:FixtureRoot `
                -Path $fixtureCatalogPath

            $ready = @(
                Get-WinSecExecutableChecks `
                    -Registry $registry
            )

            Assert-WinSecEqual `
                -Actual $ready.Count `
                -Expected 1

            Assert-WinSecEqual `
                -Actual $ready[0].CheckId `
                -Expected 'WSA-SYS-001'

            Assert-WinSecEqual `
                -Actual $ready[0].RegistryStatus `
                -Expected 'READY'

            # -----------------------------------------------
            # Confirm validation did not execute the script
            # -----------------------------------------------

            Assert-WinSecTrue `
                -Condition (
                    -not (
                        Test-Path `
                            -LiteralPath $markerPath
                    )
                ) `
                -Message (
                    'Registry executed a script while validating.'
                )
        }


    # ========================================================
    # GROUP 7 - JSON ERROR HANDLING
    # ========================================================

    Write-Host ''
    Write-Host '[7] JSON ERROR HANDLING' `
        -ForegroundColor Cyan

    Write-Host ''

    Invoke-WinSecRegistryTest `
        -Name 'Malformed JSON is rejected' `
        -Test {

            $path = Join-Path `
                -Path $script:FixtureRoot `
                -ChildPath 'Malformed.json'

            Set-Content `
                -LiteralPath $path `
                -Value '{"checks": [' `
                -Encoding UTF8

            Assert-WinSecThrows `
                -Action {

                    Get-WinSecCheckRegistry `
                        -ProjectRoot $script:FixtureRoot `
                        -Path $path
                } `
                -ExpectedPattern 'Unable to load'
        }


    Invoke-WinSecRegistryTest `
        -Name 'Empty catalog is rejected' `
        -Test {

            $path = Join-Path `
                -Path $script:FixtureRoot `
                -ChildPath 'Empty.json'

            [System.IO.File]::WriteAllText(
                $path,
                ''
            )

            Assert-WinSecThrows `
                -Action {

                    Get-WinSecCheckRegistry `
                        -ProjectRoot $script:FixtureRoot `
                        -Path $path
                } `
                -ExpectedPattern 'empty'
        }

}
finally {

    # --------------------------------------------------------
    # Remove temporary test artifacts
    # --------------------------------------------------------

    if (
        Test-Path `
            -LiteralPath $script:FixtureRoot `
            -PathType Container
    ) {

        try {

            Remove-Item `
                -LiteralPath $script:FixtureRoot `
                -Recurse `
                -Force `
                -ErrorAction Stop
        }
        catch {

            Write-Warning (
                'Unable to remove test directory: {0}' -f `
                    $script:FixtureRoot
            )
        }
    }
}


# ============================================================
# FINAL SUMMARY
# ============================================================

$total = (
    $script:TestsPassed +
    $script:TestsFailed
)

Write-Host ''
Write-Host ('=' * 55) -ForegroundColor DarkGray

Write-Host 'CHECK REGISTRY TEST SUMMARY' `
    -ForegroundColor Cyan

Write-Host ''

Write-Host "Total tests : $total"

Write-Host "Passed      : $script:TestsPassed" `
    -ForegroundColor Green

$failureColor = 'Green'

if ($script:TestsFailed -gt 0) {
    $failureColor = 'Red'
}

Write-Host "Failed      : $script:TestsFailed" `
    -ForegroundColor $failureColor

Write-Host ''

if ($script:TestsFailed -gt 0) {

    throw (
        '{0} CheckRegistry unit test(s) failed.' -f `
            $script:TestsFailed
    )
}

Write-Host 'All CheckRegistry unit tests passed.' `
    -ForegroundColor Green

Write-Host ''
Write-Host 'Security check registry validation completed.' `
    -ForegroundColor DarkGray

Write-Host ''
