
# ============================================================
# WinSec Analyzer
# Test Suite : Defender Integration
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Microsoft Defender Antivirus integration tests.
#
# Includes:
# - Real local Defender evidence collection
# - PowerShell syntax validation
# - Static read-only command verification
# - Result schema and identity validation
# - Defender operating mode
# - Real-time protection telemetry
# - Antivirus signatures and scanning
# - Nine internal security analysis areas
# - PUA protection assessment
# - Cloud-delivered protection
# - Network Protection
# - Controlled Folder Access
# - Attack Surface Reduction (ASR)
# - Evidence privacy
# - Error handling
# - No compliance scoring without approved criteria
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# These tests query Microsoft Defender on the local device.
# They do not modify Windows security settings.
# They do not execute remediation commands.
# Unavailable telemetry is reported explicitly.
# ============================================================

[CmdletBinding()]
param(
    [switch]$SkipLive
)

$ErrorActionPreference = 'Stop'

# ============================================================
# TEST STATE
# ============================================================

$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestsSkipped = 0

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)

$script:DefenderPath = Join-Path `
    $script:ProjectRoot `
    'src/Checks/Defender/Test-Defender.ps1'

$script:DeviceId = $null

$script:ScanId = (
    'DEFENDER-INTEGRATION-{0}' -f
    [guid]::NewGuid().ToString('N')
)

$script:CheckId = 'WSA-SYS-001'

$script:DefenderResult = $null


# ============================================================
# ASSERTION HELPERS
# ============================================================

function Assert-WinSecIntegrationTrue {
    [CmdletBinding()]
    param(
        [bool]$Condition,

        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) {
        throw $Message
    }
}


function Assert-WinSecIntegrationEqual {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Expected,

        [string]$Message = 'Values do not match.'
    )

    if ($null -eq $Expected) {
        if ($null -ne $Actual) {
            throw (
                '{0} Expected null, received [{1}].' -f
                $Message, $Actual
            )
        }

        return
    }

    if ($null -eq $Actual) {
        throw (
            '{0} Expected [{1}], received null.' -f
            $Message, $Expected
        )
    }

    if ($Actual -ne $Expected) {
        throw (
            '{0} Expected [{1}], received [{2}].' -f
            $Message, $Expected, $Actual
        )
    }
}


function Assert-WinSecIntegrationAllowed {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory)]
        [string[]]$AllowedValues,

        [string]$Message = 'Unexpected value.'
    )

    if (
        $null -eq $Value -or
        [string]$Value -cnotin $AllowedValues
    ) {
        throw (
            '{0} Received [{1}].' -f
            $Message, $Value
        )
    }
}


# ============================================================
# TEST EXECUTION
# ============================================================

function Invoke-WinSecIntegrationTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Test
    )

    try {
        $null = & $Test

        $script:TestsPassed++

        Write-Host (
            '[PASS] {0}' -f $Name
        ) -ForegroundColor Green
    }
    catch {
        $script:TestsFailed++

        Write-Host (
            '[FAIL] {0}' -f $Name
        ) -ForegroundColor Red

        Write-Host (
            '       {0}' -f $_.Exception.Message
        ) -ForegroundColor DarkGray
    }
}


function Skip-WinSecIntegrationTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Reason
    )

    $script:TestsSkipped++

    Write-Host (
        '[SKIP] {0} - {1}' -f $Name, $Reason
    ) -ForegroundColor Yellow
}


# ============================================================
# RESULT HELPERS
# ============================================================

function Get-WinSecIntegrationArea {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (
        $null -eq $Result.Evidence -or
        $null -eq $Result.Evidence.Analysis -or
        $null -eq $Result.Evidence.Analysis.Areas
    ) {
        return $null
    }

    $property = (
        $Result.Evidence.Analysis.Areas.PSObject.Properties[$Name]
    )

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}


function Get-WinSecIntegrationIndicator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result,

        [Parameter(Mandatory)]
        [string]$Area,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $section = Get-WinSecIntegrationArea `
        -Result $Result `
        -Name $Area

    if ($null -eq $section) {
        return @()
    }

    return @(
        $section.Indicators |
        Where-Object {
            $_.Name -eq $Name
        }
    )
}


# ============================================================
# TEST SUMMARY
# ============================================================

function Complete-WinSecIntegrationTests {
    [CmdletBinding()]
    param()

    $total = (
        $script:TestsPassed +
        $script:TestsFailed +
        $script:TestsSkipped
    )

    Write-Host ''
    Write-Host ('=' * 60) -ForegroundColor DarkGray

    Write-Host (
        'DEFENDER INTEGRATION SUMMARY'
    ) -ForegroundColor Cyan

    Write-Host ''

    Write-Host "TOTAL : $total"

    Write-Host (
        'PASS  : {0}' -f $script:TestsPassed
    ) -ForegroundColor Green

    $failureColor = if ($script:TestsFailed -gt 0) {
        'Red'
    }
    else {
        'Green'
    }

    Write-Host (
        'FAIL  : {0}' -f $script:TestsFailed
    ) -ForegroundColor $failureColor

    Write-Host (
        'SKIP  : {0}' -f $script:TestsSkipped
    ) -ForegroundColor Yellow

    Write-Host ('=' * 60) -ForegroundColor DarkGray
    Write-Host ''

    if ($script:TestsFailed -gt 0) {
        throw (
            '{0} Defender integration test(s) failed.' -f
            $script:TestsFailed
        )
    }

    if ($script:TestsSkipped -gt 0) {
        Write-Host (
            'Integration tests completed with unavailable coverage.'
        ) -ForegroundColor Yellow

        Write-Host (
            'Skipped tests must not be interpreted as PASS.'
        ) -ForegroundColor Yellow

        return
    }

    Write-Host (
        'All Defender integration tests passed.'
    ) -ForegroundColor Green
}


# ============================================================
# TEST EXECUTION START
# ============================================================

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray

Write-Host (
    'WinSec Analyzer - Defender Integration Tests'
) -ForegroundColor Cyan

Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''


# ============================================================
# GROUP 1 - FILE VALIDATION
# ============================================================

Write-Host '[1] COLLECTOR VALIDATION' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Collector exists on disk' `
    -Test {

        Assert-WinSecIntegrationTrue (
            Test-Path `
                -LiteralPath $script:DefenderPath `
                -PathType Leaf
        ) 'Microsoft Defender collector was not found.'
    }


if (-not (
    Test-Path -LiteralPath $script:DefenderPath -PathType Leaf
)) {
    Complete-WinSecIntegrationTests
    return
}


# ------------------------------------------------------------
# PowerShell parser validation
# ------------------------------------------------------------

Invoke-WinSecIntegrationTest `
    -Name 'Collector parses without syntax errors' `
    -Test {

        $tokens = $null
        $parseErrors = $null

        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:DefenderPath,
            [ref]$tokens,
            [ref]$parseErrors
        )

        Assert-WinSecIntegrationEqual `
            -Actual @($parseErrors).Count `
            -Expected 0 `
            -Message 'PowerShell parser errors were detected.'
    }


# ------------------------------------------------------------
# Read-only static verification
# ------------------------------------------------------------

Invoke-WinSecIntegrationTest `
    -Name 'Collector has no known modification commands' `
    -Test {

        $tokens = $null
        $parseErrors = $null

        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:DefenderPath,
            [ref]$tokens,
            [ref]$parseErrors
        )

        Assert-WinSecIntegrationEqual `
            -Actual @($parseErrors).Count `
            -Expected 0

        $forbidden = (
            '^(Set-Mp|Add-Mp|Remove-Mp|' +
            'Start-MpScan$|Update-MpSignature$|' +
            'Set-Item|New-Item|Remove-Item|' +
            'Clear-Item|Set-Content|Add-Content|' +
            'Out-File$|Export-|' +
            'Set-Service$|Start-Service$|' +
            'Stop-Service$|Restart-Service$|' +
            'Invoke-CimMethod$|Set-CimInstance$|' +
            'Remove-CimInstance$|New-CimInstance$|' +
            'Invoke-Expression$|Start-Process$|' +
            'Invoke-Command$|Restart-Computer$)'
        )

        $commandNodes = $ast.FindAll(
            {
                param($node)

                $node -is [System.Management.Automation.Language.CommandAst]
            },
            $true
        )

        foreach ($command in $commandNodes) {
            $name = $command.GetCommandName()

            Assert-WinSecIntegrationTrue (
                -not ($name -match $forbidden)
            ) "Prohibited command detected: $name"
        }
    }


# ============================================================
# GROUP 2 - OPERATING SYSTEM
# ============================================================

Write-Host ''
Write-Host '[2] OPERATING SYSTEM' -ForegroundColor Cyan
Write-Host ''

if ($SkipLive -or $env:OS -ne 'Windows_NT') {

    Skip-WinSecIntegrationTest `
        -Name 'Windows Defender availability' `
        -Reason 'Live collection was skipped or Windows is unavailable.'

    Complete-WinSecIntegrationTests
    return
}


Invoke-WinSecIntegrationTest `
    -Name 'Windows operating system detected' `
    -Test {

        Assert-WinSecIntegrationEqual `
            -Actual $env:OS `
            -Expected 'Windows_NT'
    }


# ============================================================
# GROUP 3 - COLLECTOR IMPORT
# ============================================================

Write-Host ''
Write-Host '[3] COLLECTOR IMPORT' -ForegroundColor Cyan
Write-Host ''

try {
    . (Join-Path $script:ProjectRoot 'src/Core/TargetRegistry.ps1')
    . $script:DefenderPath
    $script:DeviceId = Get-WinSecLocalHardwareDeviceId
}
catch {
    $script:TestsFailed++

    Write-Host (
        '[FAIL] Collector import - {0}' -f
        $_.Exception.Message
    ) -ForegroundColor Red

    Complete-WinSecIntegrationTests
    return
}


Invoke-WinSecIntegrationTest `
    -Name 'Defender collector imports successfully' `
    -Test {

        $command = Get-Command `
            -Name 'Test-WinSecDefender' `
            -CommandType Function `
            -ErrorAction Stop

        Assert-WinSecIntegrationTrue (
            $null -ne $command
        )
    }


# ============================================================
# GROUP 4 - REAL DEFENDER COLLECTION
# ============================================================

Write-Host ''
Write-Host '[4] REAL DEFENDER COLLECTION' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Local collector returns exactly one result' `
    -Test {

        $results = @(
            Test-WinSecDefender `
                -DeviceId $script:DeviceId `
                -ScanId $script:ScanId `
                -CheckId $script:CheckId
        )

        Assert-WinSecIntegrationEqual `
            -Actual $results.Count `
            -Expected 1

        $script:DefenderResult = $results[0]
    }


if ($null -eq $script:DefenderResult) {
    Complete-WinSecIntegrationTests
    return
}


# ============================================================
# GROUP 5 - RESULT CONTRACT
# ============================================================

Write-Host ''
Write-Host '[5] RESULT CONTRACT' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Check identity is preserved' `
    -Test {

        Assert-WinSecIntegrationEqual `
            -Actual $script:DefenderResult.CheckId `
            -Expected 'WSA-SYS-001'

        Assert-WinSecIntegrationEqual `
            -Actual $script:DefenderResult.SectionKey `
            -Expected 'SystemSecurity'
    }


Invoke-WinSecIntegrationTest `
    -Name 'Device identity is preserved' `
    -Test {

        Assert-WinSecIntegrationEqual `
            -Actual $script:DefenderResult.DeviceId `
            -Expected $script:DeviceId

        Assert-WinSecIntegrationEqual `
            -Actual $script:DefenderResult.Evidence.DeviceId `
            -Expected $script:DeviceId
    }


Invoke-WinSecIntegrationTest `
    -Name 'Scan identity is preserved' `
    -Test {

        Assert-WinSecIntegrationEqual `
            -Actual $script:DefenderResult.ScanId `
            -Expected $script:ScanId

        Assert-WinSecIntegrationEqual `
            -Actual $script:DefenderResult.Evidence.ScanId `
            -Expected $script:ScanId
    }


Invoke-WinSecIntegrationTest `
    -Name 'Collector status uses the documented contract' `
    -Test {

        Assert-WinSecIntegrationAllowed `
            -Value $script:DefenderResult.Status `
            -AllowedValues @(
                'INFORMATIONAL',
                'ERROR'
            )
    }


Invoke-WinSecIntegrationTest `
    -Name 'Evidence timestamp is valid and recent' `
    -Test {

        $timestamp = [DateTimeOffset]::Parse(
            $script:DefenderResult.Evidence.CollectedAtUTC
        )

        $current = [DateTimeOffset]::UtcNow

        Assert-WinSecIntegrationTrue (
            $timestamp -le $current
        ) 'Timestamp is in the future.'

        Assert-WinSecIntegrationTrue (
            $timestamp -gt $current.AddMinutes(-10)
        ) 'Timestamp is unexpectedly old.'
    }


Invoke-WinSecIntegrationTest `
    -Name 'Collector does not calculate compliance scores' `
    -Test {

        $evidence = $script:DefenderResult.Evidence

        Assert-WinSecIntegrationEqual `
            -Actual $evidence.ScoringEligible `
            -Expected $false

        Assert-WinSecIntegrationEqual `
            -Actual $evidence.ComplianceAssessment `
            -Expected 'NOT_EVALUATED'

        Assert-WinSecIntegrationEqual `
            -Actual $evidence.CriteriaSource `
            -Expected $null
    }


# ============================================================
# GROUP 6 - EVIDENCE PRIVACY
# ============================================================

Write-Host ''
Write-Host '[6] EVIDENCE PRIVACY' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Raw Defender exclusion arrays are not exported' `
    -Test {

        $preferences = (
            $script:DefenderResult.Evidence.DefenderPreferences
        )

        if ($null -eq $preferences) {
            return
        }

        $privateProperties = @(
            'ExclusionPath'
            'ExclusionProcess'
            'ExclusionExtension'
            'AttackSurfaceReductionOnlyExclusions'
            'ControlledFolderAccessAllowedApplications'
            'ControlledFolderAccessProtectedFolders'
        )

        foreach ($name in $privateProperties) {
            Assert-WinSecIntegrationTrue (
                $null -eq $preferences.PSObject.Properties[$name]
            ) "Sensitive property was exported: $name"
        }
    }


Invoke-WinSecIntegrationTest `
    -Name 'Collection sources or errors are reported' `
    -Test {

        $result = $script:DefenderResult

        if ($result.Status -eq 'INFORMATIONAL') {
            Assert-WinSecIntegrationTrue (
                -not [string]::IsNullOrWhiteSpace(
                    [string]$result.Evidence.StatusSource
                )
            ) 'Missing Defender telemetry source.'
        }
        else {
            Assert-WinSecIntegrationTrue (
                -not [string]::IsNullOrWhiteSpace(
                    [string]$result.ErrorMessage
                )
            ) 'Collection error was not reported.'
        }
    }


# ============================================================
# HANDLE UNAVAILABLE DEFENDER TELEMETRY
# ============================================================

if ($script:DefenderResult.Status -eq 'ERROR') {

    Write-Host ''
    Write-Host (
        'Microsoft Defender status telemetry is unavailable.'
    ) -ForegroundColor Yellow

    $dependentTests = @(
        'Nine internal security analysis areas'
        'Core antivirus telemetry'
        'PUA threat protection indicator'
        'PUA operating mode'
        'Cloud-delivered protection'
        'Network Protection'
        'Controlled Folder Access'
        'Attack Surface Reduction inventory'
        'ASR rule identifiers and modes'
        'ASR unlisted rules'
        'Antivirus signatures'
        'All indicators remain ungraded'
        'Analysis indicator counts'
    )

    foreach ($name in $dependentTests) {
        Skip-WinSecIntegrationTest `
            -Name $name `
            -Reason 'Recognizable Defender telemetry unavailable.'
    }

    Complete-WinSecIntegrationTests
    return
}


# ============================================================
# GROUP 7 - SECURITY ANALYSIS AREAS
# ============================================================

Write-Host ''
Write-Host '[7] SECURITY ANALYSIS AREAS' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Nine internal security analysis areas' `
    -Test {

        $areas = (
            $script:DefenderResult.Evidence.Analysis.Areas
        )

        $required = @(
            'CoreProtection'
            'ThreatProtection'
            'CloudProtection'
            'Integrity'
            'NetworkProtection'
            'RansomwareProtection'
            'AttackSurfaceReduction'
            'UpdatesAndScans'
            'ExclusionsAndHardening'
        )

        Assert-WinSecIntegrationEqual `
            -Actual @($areas.PSObject.Properties).Count `
            -Expected 9

        foreach ($name in $required) {
            Assert-WinSecIntegrationTrue (
                $null -ne $areas.PSObject.Properties[$name]
            ) "Missing analysis area: $name"
        }
    }


# ============================================================
# GROUP 8 - CORE ANTIVIRUS
# ============================================================

Write-Host ''
Write-Host '[8] CORE ANTIVIRUS' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Core antivirus telemetry' `
    -Test {

        $status = (
            $script:DefenderResult.Evidence.DefenderStatus
        )

        Assert-WinSecIntegrationTrue (
            $null -ne $status
        ) 'Defender status evidence is missing.'

        $properties = @(
            'AMRunningMode'
            'AntivirusEnabled'
            'RealTimeProtectionEnabled'
            'BehaviorMonitorEnabled'
            'IsTamperProtected'
        )

        foreach ($name in $properties) {
            Assert-WinSecIntegrationTrue (
                $null -ne $status.PSObject.Properties[$name]
            ) "Missing Defender status property: $name"
        }

        # A null telemetry value is acceptable.
        # Missing data must not silently become false.
    }


# ============================================================
# GROUP 9 - THREAT PROTECTION / PUA
# ============================================================

Write-Host ''
Write-Host '[9] THREAT PROTECTION' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'PUA threat protection indicator' `
    -Test {

        $items = @(
            Get-WinSecIntegrationIndicator `
                -Result $script:DefenderResult `
                -Area 'ThreatProtection' `
                -Name 'Potentially unwanted applications (PUA)'
        )

        Assert-WinSecIntegrationEqual `
            -Actual $items.Count `
            -Expected 1

        $areas = (
            $script:DefenderResult.Evidence.Analysis.Areas
        )

        Assert-WinSecIntegrationTrue (
            $null -eq $areas.PSObject.Properties['PUA']
        ) 'PUA must not be a standalone analysis area.'
    }


Invoke-WinSecIntegrationTest `
    -Name 'PUA operating mode' `
    -Test {

        $pua = (
            $script:DefenderResult.Evidence.PUAProtectionAssessment
        )

        Assert-WinSecIntegrationTrue (
            $null -ne $pua
        ) 'Missing PUA assessment.'

        Assert-WinSecIntegrationAllowed `
            -Value $pua.Mode `
            -AllowedValues @(
                'DISABLED'
                'BLOCK'
                'AUDIT'
                'UNKNOWN'
            )

        Assert-WinSecIntegrationEqual `
            -Actual $pua.EffectiveProtectionConfirmed `
            -Expected $false

        Assert-WinSecIntegrationEqual `
            -Actual $pua.DownloadBlockingEvaluated `
            -Expected $false

        Assert-WinSecIntegrationEqual `
            -Actual $pua.DownloadBlocking `
            -Expected $null

        Assert-WinSecIntegrationEqual `
            -Actual $pua.ScoringEligible `
            -Expected $false
    }


# ============================================================
# GROUP 10 - CLOUD PROTECTION
# ============================================================

Write-Host ''
Write-Host '[10] CLOUD PROTECTION' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Cloud-delivered protection' `
    -Test {

        $items = @(
            Get-WinSecIntegrationIndicator `
                -Result $script:DefenderResult `
                -Area 'CloudProtection' `
                -Name 'Cloud-delivered protection (MAPS)'
        )

        Assert-WinSecIntegrationEqual `
            -Actual $items.Count `
            -Expected 1

        Assert-WinSecIntegrationAllowed `
            -Value $items[0].State `
            -AllowedValues @(
                'CONFIGURED'
                'DISABLED'
                'UNKNOWN'
            )

        Assert-WinSecIntegrationEqual `
            -Actual $items[0].EffectiveProtectionConfirmed `
            -Expected $false
    }


# ============================================================
# GROUP 11 - NETWORK PROTECTION
# ============================================================

Write-Host ''
Write-Host '[11] NETWORK PROTECTION' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Network Protection' `
    -Test {

        $items = @(
            Get-WinSecIntegrationIndicator `
                -Result $script:DefenderResult `
                -Area 'NetworkProtection' `
                -Name 'Microsoft Defender Network Protection'
        )

        Assert-WinSecIntegrationEqual `
            -Actual $items.Count `
            -Expected 1

        Assert-WinSecIntegrationAllowed `
            -Value $items[0].State `
            -AllowedValues @(
                'DISABLED'
                'BLOCK'
                'AUDIT'
                'UNKNOWN'
            )

        Assert-WinSecIntegrationEqual `
            -Actual $items[0].ScoringEligible `
            -Expected $false
    }


# ============================================================
# GROUP 12 - RANSOMWARE PROTECTION
# ============================================================

Write-Host ''
Write-Host '[12] RANSOMWARE PROTECTION' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Controlled Folder Access' `
    -Test {

        $items = @(
            Get-WinSecIntegrationIndicator `
                -Result $script:DefenderResult `
                -Area 'RansomwareProtection' `
                -Name 'Controlled folder access'
        )

        Assert-WinSecIntegrationEqual `
            -Actual $items.Count `
            -Expected 1

        Assert-WinSecIntegrationAllowed `
            -Value $items[0].State `
            -AllowedValues @(
                'DISABLED'
                'BLOCK'
                'AUDIT'
                'BLOCK_DISK_MODIFICATION'
                'AUDIT_DISK_MODIFICATION'
                'UNKNOWN'
            )
    }


# ============================================================
# GROUP 13 - ATTACK SURFACE REDUCTION
# ============================================================

Write-Host ''
Write-Host '[13] ATTACK SURFACE REDUCTION' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Attack Surface Reduction inventory' `
    -Test {

        $asr = (
            $script:DefenderResult.Evidence.AttackSurfaceReduction
        )

        Assert-WinSecIntegrationTrue (
            $null -ne $asr
        ) 'ASR inventory was not returned.'

        Assert-WinSecIntegrationTrue (
            $null -ne $asr.Rules
        ) 'ASR rules collection is missing.'

        Assert-WinSecIntegrationTrue (
            $null -ne $asr.Modes
        ) 'ASR mode counters are missing.'
    }


Invoke-WinSecIntegrationTest `
    -Name 'ASR rule identifiers and modes' `
    -Test {

        $asr = (
            $script:DefenderResult.Evidence.AttackSurfaceReduction
        )

        foreach ($rule in @($asr.Rules)) {
            $guid = [guid]::Empty

            Assert-WinSecIntegrationTrue (
                [guid]::TryParse(
                    [string]$rule.RuleId,
                    [ref]$guid
                )
            ) 'Invalid ASR rule GUID.'

            Assert-WinSecIntegrationAllowed `
                -Value $rule.Mode `
                -AllowedValues @(
                    'BLOCK'
                    'AUDIT'
                    'WARN'
                    'DISABLED'
                    'NOT_CONFIGURED'
                    'UNKNOWN'
                )

            Assert-WinSecIntegrationEqual `
                -Actual $rule.EffectiveEnforcementConfirmed `
                -Expected $false
        }
    }


Invoke-WinSecIntegrationTest `
    -Name 'ASR unlisted rules' `
    -Test {

        $asr = (
            $script:DefenderResult.Evidence.AttackSurfaceReduction
        )

        Assert-WinSecIntegrationEqual `
            -Actual $asr.UnlistedRulesAssessed `
            -Expected $false
    }


# ============================================================
# GROUP 14 - SIGNATURES AND SCANNING
# ============================================================

Write-Host ''
Write-Host '[14] SIGNATURES AND SCANNING' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'Antivirus signatures' `
    -Test {

        $status = (
            $script:DefenderResult.Evidence.DefenderStatus
        )

        $required = @(
            'DefenderSignaturesOutOfDate'
            'AntivirusSignatureAge'
            'AntivirusSignatureVersion'
            'QuickScanAge'
            'FullScanAge'
        )

        foreach ($name in $required) {
            Assert-WinSecIntegrationTrue (
                $null -ne $status.PSObject.Properties[$name]
            ) "Missing signature or scan property: $name"
        }

        # These properties may legitimately be null.
        # This collector never initiates an antivirus scan.
    }


# ============================================================
# GROUP 15 - INDICATOR SCORING SAFEGUARDS
# ============================================================

Write-Host ''
Write-Host '[15] SCORING SAFEGUARDS' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecIntegrationTest `
    -Name 'All indicators remain ungraded' `
    -Test {

        $areas = (
            $script:DefenderResult.Evidence.Analysis.Areas
        )

        foreach ($area in $areas.PSObject.Properties) {
            foreach ($indicator in @($area.Value.Indicators)) {

                Assert-WinSecIntegrationEqual `
                    -Actual $indicator.ScoringEligible `
                    -Expected $false

                Assert-WinSecIntegrationEqual `
                    -Actual $indicator.ComplianceStatus `
                    -Expected 'NOT_EVALUATED'

                Assert-WinSecIntegrationEqual `
                    -Actual $indicator.EffectiveProtectionConfirmed `
                    -Expected $false
            }
        }
    }


Invoke-WinSecIntegrationTest `
    -Name 'Analysis indicator counts' `
    -Test {

        $analysis = (
            $script:DefenderResult.Evidence.Analysis
        )

        $total = 0
        $unknown = 0
        $review = 0

        foreach ($area in $analysis.Areas.PSObject.Properties) {

            $items = @($area.Value.Indicators)

            Assert-WinSecIntegrationEqual `
                -Actual $area.Value.IndicatorCount `
                -Expected $items.Count

            $total += $items.Count

            $unknown += @(
                $items | Where-Object {
                    $_.State -eq 'UNKNOWN'
                }
            ).Count

            $review += @(
                $items | Where-Object {
                    $_.ReviewRecommended
                }
            ).Count
        }

        Assert-WinSecIntegrationEqual `
            -Actual $analysis.IndicatorCount `
            -Expected $total

        Assert-WinSecIntegrationEqual `
            -Actual $analysis.UnknownIndicatorCount `
            -Expected $unknown

        Assert-WinSecIntegrationEqual `
            -Actual $analysis.ReviewIndicatorCount `
            -Expected $review
    }


# ============================================================
# FINAL SUMMARY
# ============================================================

Complete-WinSecIntegrationTests
