
# ============================================================
# WinSec Analyzer
# Test Suite : AuditEngine
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit and component integration tests for AuditEngine.
#
# Compatible with:
# - Windows PowerShell 5.1
# - PowerShell 7.x
#
# No Pester required.
# No administrator privileges required.
#
# All simulated check scripts are created in a temporary
# directory and removed after the tests.
#
# .\tests\Unit\AuditEngine.Test.ps1
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# Project paths
# ------------------------------------------------------------

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)

$script:RegistryPath = Join-Path `
    $script:ProjectRoot 'src/Core/CheckRegistry.ps1'

$script:ScoreEnginePath = Join-Path `
    $script:ProjectRoot 'src/Core/ScoreEngine.ps1'

$script:AuditEnginePath = Join-Path `
    $script:ProjectRoot 'src/Core/AuditEngine.ps1'

$script:CatalogPath = Join-Path `
    $script:ProjectRoot 'config/checks.json'

foreach ($path in @(
    $script:RegistryPath
    $script:ScoreEnginePath
    $script:AuditEnginePath
    $script:CatalogPath
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required project file not found: $path"
    }
}

# ------------------------------------------------------------
# Load production components
# ------------------------------------------------------------

. $script:RegistryPath
. $script:ScoreEnginePath
. $script:AuditEnginePath

# ------------------------------------------------------------
# Test state
# ------------------------------------------------------------

$script:TestsPassed = 0
$script:TestsFailed = 0

$script:BaseCatalog = $null
$script:BaseRegistry = $null

$script:FixtureRoot = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    ('WinSec-AuditTests-' + [guid]::NewGuid().ToString('N'))

$script:OriginalCatalogBytes = (
    [System.IO.File]::ReadAllBytes($script:CatalogPath)
)

# ------------------------------------------------------------
# Assertions
# ------------------------------------------------------------

function Assert-WinSecAuditEqual {
    param(
        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Expected,

        [string]$Message = 'Values do not match.'
    )

    if ($null -eq $Expected) {
        if ($null -ne $Actual) {
            throw "$Message Expected null, received [$Actual]."
        }

        return
    }

    if ($Actual -ne $Expected) {
        throw (
            '{0} Expected [{1}], received [{2}].' -f `
                $Message, $Expected, $Actual
        )
    }
}

function Assert-WinSecAuditTrue {
    param(
        [bool]$Condition,
        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-WinSecAuditThrows {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action,

        [string]$MessagePattern = ''
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
        throw 'Expected an exception, but none was thrown.'
    }

    if (
        $MessagePattern -and
        $message -notmatch $MessagePattern
    ) {
        throw "Unexpected exception: $message"
    }
}

# ------------------------------------------------------------
# Test runner
# ------------------------------------------------------------

function Invoke-WinSecAuditTest {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Test
    )

    try {
        $null = & $Test

        $script:TestsPassed++

        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:TestsFailed++

        Write-Host "[FAIL] $Name" -ForegroundColor Red

        Write-Host (
            '       {0}' -f $_.Exception.Message
        ) -ForegroundColor DarkGray
    }
}

# ------------------------------------------------------------
# Create a synthetic registered check
# ------------------------------------------------------------

function New-WinSecAuditFixture {
    [CmdletBinding()]
    param(
        [ValidateSet(
            'PASS',
            'FAIL',
            'ERROR',
            'PENDING',
            'THROW',
            'NO_EVIDENCE',
            'WRONG_DEVICE',
            'WRONG_SCAN',
            'WRONG_CHECK',
            'WRONG_SECTION',
            'MULTIPLE',
            'NONE',
            'WARNING',
            'NOT_APPLICABLE',
            'NOT_APPLICABLE_NO_REASON'
        )]
        [string]$Scenario = 'PASS',

        [bool]$ScoringEligible = $true,

        [switch]$TopLevelStatement,

        [switch]$RequiresDirective
    )

    # --------------------------------------------------------
    # Create an isolated temporary project directory
    # --------------------------------------------------------

    $root = Join-Path `
        $script:FixtureRoot `
        ([guid]::NewGuid().ToString('N'))

    New-Item `
        -Path $root `
        -ItemType Directory `
        -Force | Out-Null

    # --------------------------------------------------------
    # Clone production catalog into memory
    # --------------------------------------------------------

    $json = ConvertTo-Json `
        -InputObject $script:BaseCatalog `
        -Depth 50

    $catalog = ConvertFrom-Json -InputObject $json

    $check = @(
        $catalog.checks | Where-Object {
            $_.checkId -eq 'WSA-SYS-001'
        }
    )[0]

    # This validation applies ONLY to the synthetic fixture.
    $check.implementationStatus = 'VALIDATED'
    $check.execution.enabled = $true

    $check.assessment.scoringEligible = $ScoringEligible

    if ($ScoringEligible) {
        $check.assessment.criteriaSource = 'SYNTHETIC_TEST_ONLY'
    }
    else {
        $check.assessment.criteriaSource = $null
    }

    # --------------------------------------------------------
    # Create the fixture script at its registered location
    # --------------------------------------------------------

    $relativePath = $check.execution.script.Replace(
        '/',
        [System.IO.Path]::DirectorySeparatorChar
    )

    $scriptPath = Join-Path $root $relativePath

    $scriptDirectory = [System.IO.Path]::GetDirectoryName(
        $scriptPath
    )

    New-Item `
        -Path $scriptDirectory `
        -ItemType Directory `
        -Force | Out-Null

    # --------------------------------------------------------
    # Synthetic implementation
    # --------------------------------------------------------

    $source = @'
function Test-WinSecDefender {
    param(
        [string]$DeviceId,
        [string]$ScanId,
        [string]$CheckId
    )

    $result = [PSCustomObject]@{
        CheckId = $CheckId
        DeviceId = $DeviceId
        ScanId = $ScanId
        SectionKey = 'SystemSecurity'
        Status = 'PASS'
        Evidence = @{
            Source = 'SyntheticFixture'
            Observed = 'Enabled'
        }
        NotApplicableReason = ''
        ErrorMessage = ''
    }

    switch ('__SCENARIO__') {

        'PASS' {
            return $result
        }

        'FAIL' {
            $result.Status = 'FAIL'
            $result.Evidence = 'Synthetic noncompliance'
            return $result
        }

        'ERROR' {
            $result.Status = 'ERROR'
            $result.Evidence = $null
            $result.ErrorMessage = 'Simulated collection error'
            return $result
        }

        'PENDING' {
            $result.Status = 'PENDING'
            return $result
        }

        'THROW' {
            throw 'Simulated execution failure'
        }

        'NO_EVIDENCE' {
            $result.Evidence = $null
            return $result
        }

        'WRONG_DEVICE' {
            $result.DeviceId = 'FOREIGN-DEVICE'
            return $result
        }

        'WRONG_SCAN' {
            $result.ScanId = 'FOREIGN-SCAN'
            return $result
        }

        'WRONG_CHECK' {
            $result.CheckId = 'WSA-SYS-999'
            return $result
        }

        'WRONG_SECTION' {
            $result.SectionKey = 'NetworkSecurity'
            return $result
        }

        'MULTIPLE' {
            $result
            $result
            return
        }

        'NONE' {
            return
        }

        'WARNING' {
            $result.Status = 'WARNING'
            return $result
        }

        'NOT_APPLICABLE' {
            $result.Status = 'NOT_APPLICABLE'
            $result.Evidence = $null
            $result.NotApplicableReason = 'Synthetic feature unavailable'
            return $result
        }

        'NOT_APPLICABLE_NO_REASON' {
            $result.Status = 'NOT_APPLICABLE'
            $result.Evidence = $null
            return $result
        }
    }
}
'@

    $source = $source.Replace('__SCENARIO__', $Scenario)

    # --------------------------------------------------------
    # Optional top-level execution trap
    # --------------------------------------------------------

    $markerPath = Join-Path `
        $root 'UNAUTHORIZED_EXECUTION.marker'

    if ($TopLevelStatement) {

        $escapedMarker = $markerPath.Replace("'", "''")

        $source = (
            "Set-Content -LiteralPath '$escapedMarker' " +
            "-Value 'EXECUTED'`r`n"
        ) + $source
    }

    if ($RequiresDirective) {
        $source = "#Requires -Version 99.0`r`n" + $source
    }

    Set-Content `
        -LiteralPath $scriptPath `
        -Value $source `
        -Encoding UTF8

    # --------------------------------------------------------
    # Save fixture catalog
    # --------------------------------------------------------

    $catalogPath = Join-Path $root 'checks-fixture.json'

    $fixtureJson = ConvertTo-Json `
        -InputObject $catalog `
        -Depth 50

    Set-Content `
        -LiteralPath $catalogPath `
        -Value $fixtureJson `
        -Encoding UTF8

    # --------------------------------------------------------
    # Load registry using fixture files only
    # --------------------------------------------------------

    $registry = Get-WinSecCheckRegistry `
        -ProjectRoot $root `
        -Path $catalogPath

    return [PSCustomObject]@{
        Root = $root
        Registry = $registry
        CatalogPath = $catalogPath
        ScriptPath = $scriptPath
        MarkerPath = $markerPath
    }
}

# ------------------------------------------------------------
# Run synthetic fixture audit
# ------------------------------------------------------------

function Invoke-WinSecFixtureAudit {
    [CmdletBinding()]
    param(
        [string]$Scenario = 'PASS',

        [bool]$ScoringEligible = $true,

        [switch]$SkipScoring
    )

    $fixture = New-WinSecAuditFixture `
        -Scenario $Scenario `
        -ScoringEligible $ScoringEligible

    return Invoke-WinSecAudit `
        -Registry $fixture.Registry `
        -SkipScoring:$SkipScoring
}

# ------------------------------------------------------------
# Retrieve Defender record
# ------------------------------------------------------------

function Get-WinSecFixtureRecord {
    param(
        [Parameter(Mandatory)]
        [object]$Audit
    )

    return @(
        $Audit.ControlResults | Where-Object {
            $_.CheckId -eq 'WSA-SYS-001'
        }
    )[0]
}

# ------------------------------------------------------------
# Verify normalized execution error
# ------------------------------------------------------------

function Assert-WinSecFixtureError {
    param(
        [Parameter(Mandatory)]
        [object]$Audit,

        [string]$ExpectedMessage = ''
    )

    $record = Get-WinSecFixtureRecord -Audit $Audit

    Assert-WinSecAuditEqual $record.Status 'ERROR'
    Assert-WinSecAuditEqual $record.ObservedStatus 'ERROR'

    Assert-WinSecAuditEqual `
        $Audit.ExecutionStatus 'COMPLETED_WITH_ERRORS'

    Assert-WinSecAuditEqual $Audit.ExecutionErrors 1

    Assert-WinSecAuditEqual $Audit.OverallScore 0
    Assert-WinSecAuditEqual $Audit.OverallCoverage 0

    if ($ExpectedMessage) {

        Assert-WinSecAuditTrue `
            ($record.ErrorMessage -match $ExpectedMessage) `
            "Expected error text was not found: $ExpectedMessage"
    }
}

# ============================================================
# TEST EXECUTION
# ============================================================

Write-Host ''
Write-Host ('=' * 55) -ForegroundColor DarkGray

Write-Host 'WINSEC ANALYZER - AUDIT ENGINE UNIT TESTS' `
    -ForegroundColor Cyan

Write-Host ('=' * 55) -ForegroundColor DarkGray
Write-Host ''

New-Item `
    -Path $script:FixtureRoot `
    -ItemType Directory `
    -Force | Out-Null

try {

    $script:BaseCatalog = ConvertFrom-Json `
        -InputObject (
            Get-Content `
                -LiteralPath $script:CatalogPath `
                -Raw `
                -Encoding UTF8
        )

    $script:BaseRegistry = Get-WinSecCheckRegistry `
        -ProjectRoot $script:ProjectRoot `
        -Path $script:CatalogPath

    # ========================================================
    # GROUP 1 - EXECUTION SAFETY
    # ========================================================

    Write-Host '[1] EXECUTION SAFETY' -ForegroundColor Cyan
    Write-Host ''

    Invoke-WinSecAuditTest `
        -Name 'Empty audit executes no disabled controls' `
        -Test {

            $audit = Invoke-WinSecAudit `
                -Registry $script:BaseRegistry

            Assert-WinSecAuditEqual `
                $audit.ExecutionStatus 'NO_EXECUTABLE_CHECKS'

            Assert-WinSecAuditEqual $audit.ExecutedChecks 0
            Assert-WinSecAuditEqual $audit.TotalRegisteredChecks 14

            Assert-WinSecAuditEqual $audit.OverallScore $null
            Assert-WinSecAuditEqual $audit.OverallCoverage $null

            Assert-WinSecAuditTrue (
                @(
                    $audit.ControlResults | Where-Object {
                        $_.Status -ne 'NOT_SELECTED'
                    }
                ).Count -eq 0
            ) 'A disabled control was marked as executed.'
        }

    Invoke-WinSecAuditTest `
        -Name 'Scan identifiers are unique' `
        -Test {

            $first = New-WinSecAuditScanId
            $second = New-WinSecAuditScanId

            Assert-WinSecAuditTrue `
                ($first -ne $second) `
                'Generated scan identifiers are duplicated.'
        }

    Invoke-WinSecAuditTest `
        -Name 'Explicit execution of disabled control is rejected' `
        -Test {

            Assert-WinSecAuditThrows `
                -Action {
                    Invoke-WinSecAudit `
                        -Registry $script:BaseRegistry `
                        -CheckIds @('WSA-SYS-001') `
                        -SkipScoring
                } `
                -MessagePattern 'not ready'
        }

    Invoke-WinSecAuditTest `
        -Name 'Unregistered CheckId is rejected' `
        -Test {

            Assert-WinSecAuditThrows `
                -Action {
                    Invoke-WinSecAudit `
                        -Registry $script:BaseRegistry `
                        -CheckIds @('WSA-SYS-999') `
                        -SkipScoring
                } `
                -MessagePattern 'Unregistered security check'
        }

    Invoke-WinSecAuditTest `
        -Name 'Duplicate selected CheckIds are rejected' `
        -Test {

            Assert-WinSecAuditThrows `
                -Action {
                    Invoke-WinSecAudit `
                        -Registry $script:BaseRegistry `
                        -CheckIds @(
                            'WSA-SYS-001'
                            'WSA-SYS-001'
                        ) `
                        -SkipScoring
                } `
                -MessagePattern 'Duplicate selected CheckId'
        }

    Invoke-WinSecAuditTest `
        -Name 'Remote target execution is rejected' `
        -Test {

            Assert-WinSecAuditThrows `
                -Action {
                    Invoke-WinSecAudit `
                        -Registry $script:BaseRegistry `
                        -DeviceId 'remote:TEST-PC' `
                        -SkipScoring
                } `
                -MessagePattern 'Remote device execution'
        }

    Invoke-WinSecAuditTest `
        -Name 'Empty explicit check selection is rejected' `
        -Test {

            Assert-WinSecAuditThrows `
                -Action {
                    Invoke-WinSecAudit `
                        -Registry $script:BaseRegistry `
                        -CheckIds @() `
                        -SkipScoring
                } `
                -MessagePattern 'empty explicit selection'
        }

    # ========================================================
    # GROUP 2 - VALID EXECUTION AND SCORING
    # ========================================================

    Write-Host ''
    Write-Host '[2] VALID EXECUTION AND SCORING' `
        -ForegroundColor Cyan
    Write-Host ''

    Invoke-WinSecAuditTest `
        -Name 'Authorized PASS produces a verified score' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit -Scenario 'PASS'
            $record = Get-WinSecFixtureRecord -Audit $audit

            Assert-WinSecAuditEqual $audit.ExecutedChecks 1
            Assert-WinSecAuditEqual $audit.SelectedChecks 1

            Assert-WinSecAuditEqual $record.Status 'PASS'
            Assert-WinSecAuditEqual $audit.OverallScore 100
            Assert-WinSecAuditEqual $audit.OverallCoverage 100

            Assert-WinSecAuditEqual `
                $audit.ExecutionStatus 'COMPLETED'

            Assert-WinSecAuditEqual `
                $audit.OverallStatus 'COMPLETE'

            Assert-WinSecAuditTrue (
                $record.DeviceId -eq $audit.DeviceId -and
                $record.ScanId -eq $audit.ScanId
            ) 'Record identity was not preserved.'
        }

    Invoke-WinSecAuditTest `
        -Name 'FAIL produces zero score and full coverage' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit -Scenario 'FAIL'
            $record = Get-WinSecFixtureRecord -Audit $audit

            Assert-WinSecAuditEqual $record.Status 'FAIL'
            Assert-WinSecAuditEqual $audit.OverallScore 0
            Assert-WinSecAuditEqual $audit.OverallCoverage 100
            Assert-WinSecAuditEqual $audit.OverallStatus 'COMPLETE'
        }

    Invoke-WinSecAuditTest `
        -Name 'Reported ERROR reduces verification coverage' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit -Scenario 'ERROR'

            Assert-WinSecFixtureError `
                -Audit $audit
        }

    Invoke-WinSecAuditTest `
        -Name 'PENDING does not generate a security score' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit -Scenario 'PENDING'
            $record = Get-WinSecFixtureRecord -Audit $audit

            Assert-WinSecAuditEqual $record.Status 'PENDING'
            Assert-WinSecAuditEqual $audit.OverallScore $null
            Assert-WinSecAuditEqual $audit.OverallCoverage 0
            Assert-WinSecAuditEqual $audit.OverallStatus 'PROVISIONAL'
        }

    Invoke-WinSecAuditTest `
        -Name 'SkipScoring prevents score calculation' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'PASS' `
                -SkipScoring

            $record = Get-WinSecFixtureRecord -Audit $audit

            Assert-WinSecAuditEqual $record.Status 'PASS'
            Assert-WinSecAuditEqual $audit.OverallScore $null
            Assert-WinSecAuditEqual $audit.OverallCoverage $null

            Assert-WinSecAuditEqual $audit.ScoringEnabled $false
            Assert-WinSecAuditEqual $audit.ScoreResult $null
        }

    Invoke-WinSecAuditTest `
        -Name 'Non-scoring check remains informational' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'PASS' `
                -ScoringEligible $false

            $record = Get-WinSecFixtureRecord -Audit $audit

            Assert-WinSecAuditEqual `
                $record.Status 'INFORMATIONAL'

            Assert-WinSecAuditEqual `
                $record.ObservedStatus 'PASS'

            Assert-WinSecAuditEqual $audit.OverallScore $null
            Assert-WinSecAuditEqual $audit.OverallCoverage $null
        }

    Invoke-WinSecAuditTest `
        -Name 'Explicit selection executes only requested check' `
        -Test {

            $fixture = New-WinSecAuditFixture -Scenario 'PASS'

            $audit = Invoke-WinSecAudit `
                -Registry $fixture.Registry `
                -CheckIds @('WSA-SYS-001')

            Assert-WinSecAuditEqual $audit.ExecutedChecks 1
            Assert-WinSecAuditEqual $audit.UnselectedChecks 13

            Assert-WinSecAuditEqual `
                @(
                    $audit.ControlResults | Where-Object {
                        $_.Status -eq 'PASS'
                    }
                ).Count 1
        }

    Invoke-WinSecAuditTest `
        -Name 'Consecutive scans preserve independent identifiers' `
        -Test {

            $fixture = New-WinSecAuditFixture -Scenario 'PASS'

            $first = Invoke-WinSecAudit -Registry $fixture.Registry
            $second = Invoke-WinSecAudit -Registry $fixture.Registry

            Assert-WinSecAuditTrue `
                ($first.ScanId -ne $second.ScanId) `
                'Different audit executions shared a ScanId.'

            foreach ($record in $first.ControlResults) {
                Assert-WinSecAuditEqual $record.ScanId $first.ScanId
            }

            foreach ($record in $second.ControlResults) {
                Assert-WinSecAuditEqual $record.ScanId $second.ScanId
            }

            Assert-WinSecAuditEqual $first.OverallScore 100
            Assert-WinSecAuditEqual $second.OverallScore 100
        }

    # ========================================================
    # GROUP 3 - RESULT VALIDATION
    # ========================================================

    Write-Host ''
    Write-Host '[3] RESULT VALIDATION' -ForegroundColor Cyan
    Write-Host ''

    Invoke-WinSecAuditTest `
        -Name 'PASS without evidence is downgraded to UNKNOWN' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'NO_EVIDENCE'

            $record = Get-WinSecFixtureRecord -Audit $audit

            Assert-WinSecAuditEqual $record.Status 'UNKNOWN'
            Assert-WinSecAuditEqual $audit.OverallScore 0
            Assert-WinSecAuditEqual $audit.OverallCoverage 0

            Assert-WinSecAuditTrue (
                $record.ValidationIssue -match 'without evidence'
            ) 'Evidence validation warning is missing.'
        }

    Invoke-WinSecAuditTest `
        -Name 'Thrown exception produces ERROR instead of PASS' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit -Scenario 'THROW'

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage 'Simulated execution failure'
        }

    Invoke-WinSecAuditTest `
        -Name 'Foreign DeviceId is rejected' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'WRONG_DEVICE'

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage 'identity mismatch'
        }

    Invoke-WinSecAuditTest `
        -Name 'Foreign ScanId is rejected' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'WRONG_SCAN'

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage 'identity mismatch'
        }

    Invoke-WinSecAuditTest `
        -Name 'Incorrect CheckId is rejected' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'WRONG_CHECK'

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage 'identity mismatch'
        }

    Invoke-WinSecAuditTest `
        -Name 'Incorrect SectionKey is rejected' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'WRONG_SECTION'

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage 'identity mismatch'
        }

    Invoke-WinSecAuditTest `
        -Name 'Multiple returned records are rejected' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'MULTIPLE'

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage 'exactly one'
        }

    Invoke-WinSecAuditTest `
        -Name 'Missing check result produces ERROR' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'NONE'

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage 'exactly one'
        }

    Invoke-WinSecAuditTest `
        -Name 'Unsupported WARNING status is rejected' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'WARNING'

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage 'Unsupported check result status'
        }

    Invoke-WinSecAuditTest `
        -Name 'NOT_APPLICABLE requires a valid reason' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'NOT_APPLICABLE'

            $record = Get-WinSecFixtureRecord -Audit $audit

            Assert-WinSecAuditEqual `
                $record.Status 'NOT_APPLICABLE'

            Assert-WinSecAuditTrue (
                -not [string]::IsNullOrWhiteSpace(
                    $record.NotApplicableReason
                )
            ) 'Applicability reason was not preserved.'

            Assert-WinSecAuditEqual $audit.OverallScore $null
            Assert-WinSecAuditEqual $audit.OverallCoverage $null
        }

    Invoke-WinSecAuditTest `
        -Name 'NOT_APPLICABLE without reason produces ERROR' `
        -Test {

            $audit = Invoke-WinSecFixtureAudit `
                -Scenario 'NOT_APPLICABLE_NO_REASON'

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage 'requires a reason'
        }

    # ========================================================
    # GROUP 4 - IMPLEMENTATION SECURITY
    # ========================================================

    Write-Host ''
    Write-Host '[4] IMPLEMENTATION SECURITY' `
        -ForegroundColor Cyan
    Write-Host ''

    Invoke-WinSecAuditTest `
        -Name 'Top-level statements are not executed' `
        -Test {

            $fixture = New-WinSecAuditFixture `
                -Scenario 'PASS' `
                -TopLevelStatement

            $audit = Invoke-WinSecAudit `
                -Registry $fixture.Registry

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage 'Top-level executable statements'

            Assert-WinSecAuditTrue (
                -not (
                    Test-Path -LiteralPath $fixture.MarkerPath
                )
            ) 'A top-level statement was executed.'
        }

    Invoke-WinSecAuditTest `
        -Name '#Requires directives are blocked' `
        -Test {

            $fixture = New-WinSecAuditFixture `
                -Scenario 'PASS' `
                -RequiresDirective

            $audit = Invoke-WinSecAudit `
                -Registry $fixture.Registry

            Assert-WinSecFixtureError `
                -Audit $audit `
                -ExpectedMessage '#Requires directive'
        }

    Invoke-WinSecAuditTest `
        -Name 'AuditEngine loads dependencies independently' `
        -Test {

            # ------------------------------------------------
            # Test in a separate PowerShell runspace.
            # This ensures CheckRegistry and ScoreEngine are
            # not already loaded by the test harness.
            # ------------------------------------------------

            $instance = [powershell]::Create()

            try {

                $escapedPath = (
                    $script:AuditEnginePath.Replace("'", "''")
                )

                $testScript = @"
`$ErrorActionPreference = 'Stop'

. '$escapedPath'

`$audit = Invoke-WinSecAudit -SkipScoring

if (`$audit.ExecutionStatus -ne 'NO_EXECUTABLE_CHECKS') {
    throw 'Unexpected standalone audit status.'
}
"@

                $null = $instance.AddScript($testScript).Invoke()

                if ($instance.HadErrors) {

                    $firstError = @(
                        $instance.Streams.Error
                    )[0]

                    throw (
                        'Standalone AuditEngine failure: {0}' -f `
                            $firstError.ToString()
                    )
                }
            }
            finally {
                $instance.Dispose()
            }
        }

}
finally {

    # --------------------------------------------------------
    # Cleanup: remove temporary synthetic projects
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
                'Could not delete temporary test files: {0}' -f `
                    $_.Exception.Message
            )
        }
    }
}

# ============================================================
# FINAL INTEGRITY CHECK
# ============================================================

Write-Host ''
Write-Host '[5] PRODUCTION CATALOG INTEGRITY' `
    -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecAuditTest `
    -Name 'Production checks.json remains unchanged' `
    -Test {

        $currentBytes = [System.IO.File]::ReadAllBytes(
            $script:CatalogPath
        )

        $originalHash = [Convert]::ToBase64String(
            $script:OriginalCatalogBytes
        )

        $currentHash = [Convert]::ToBase64String(
            $currentBytes
        )

        Assert-WinSecAuditEqual `
            $currentHash `
            $originalHash `
            'Production catalog was modified.'
    }

# ============================================================
# TEST SUMMARY
# ============================================================

$total = $script:TestsPassed + $script:TestsFailed

Write-Host ''
Write-Host ('=' * 55) -ForegroundColor DarkGray
Write-Host 'AUDIT ENGINE TEST SUMMARY' -ForegroundColor Cyan
Write-Host ''

Write-Host "Total tests : $total"
Write-Host "Passed      : $script:TestsPassed" `
    -ForegroundColor Green

$failureColor = if ($script:TestsFailed -gt 0) {
    'Red'
}
else {
    'Green'
}

Write-Host "Failed      : $script:TestsFailed" `
    -ForegroundColor $failureColor

Write-Host ''

if ($script:TestsFailed -gt 0) {
    throw "$($script:TestsFailed) AuditEngine test(s) failed."
}

Write-Host 'All AuditEngine unit tests passed.' `
    -ForegroundColor Green

Write-Host ''
