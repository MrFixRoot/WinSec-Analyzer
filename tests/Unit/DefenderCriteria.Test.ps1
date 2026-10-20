
# ============================================================
# WinSec Analyzer
# Test Suite : Defender Criteria
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Unit tests for the Microsoft Defender criteria catalog.
#
# Includes:
# - JSON catalog validation
# - Catalog identity and version
# - Criterion identifiers and uniqueness
# - Evidence property paths
# - Security analysis areas
# - Supported evaluation operators
# - Expected value validation
# - Source documentation validation
# - Windows applicability metadata
# - Framework mapping safeguards
# - PUA integration within ThreatProtection
# - Review-only indicators
# - Approval and verification safeguards
# - Evaluation Engine compatibility
# - No compliance scoring for draft criteria
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# All evaluations use synthetic evidence.
# Draft criteria are not approved security requirements.
# This suite never modifies Windows security settings.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ============================================================
# PROJECT PATHS
# ============================================================

$script:ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)

$script:CatalogPath = Join-Path `
    $script:ProjectRoot `
    'config/criteria/defender.json'

$script:EnginePath = Join-Path `
    $script:ProjectRoot `
    'src/Core/EvaluationEngine.ps1'

$script:CollectorPath = Join-Path `
    $script:ProjectRoot `
    'src/Checks/Defender/Test-Defender.ps1'

$script:Passed = 0
$script:Failed = 0


# ============================================================
# ASSERTION HELPERS
# ============================================================

function Assert-WinSecCriteriaTrue {
    [CmdletBinding()]
    param(
        [bool]$Condition,

        [string]$Message = 'Assertion failed.'
    )

    if (-not $Condition) {
        throw $Message
    }
}


function Assert-WinSecCriteriaEqual {
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
            throw "$Message Expected null, got [$Actual]."
        }

        return
    }

    if ($null -eq $Actual) {
        throw "$Message Expected [$Expected], got null."
    }

    if ($Actual -is [array] -or $Expected -is [array]) {
        throw "$Message Scalar comparison expected."
    }

    if ($Actual -cne $Expected) {
        throw "$Message Expected [$Expected], got [$Actual]."
    }
}


function Assert-WinSecCriteriaText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,

        [string]$Message = 'Expected nonempty text.'
    )

    Assert-WinSecCriteriaTrue (
        $Value -is [string] -and
        -not [string]::IsNullOrWhiteSpace($Value)
    ) $Message
}


function Assert-WinSecCriteriaUrl {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    Assert-WinSecCriteriaText `
        -Value $Value `
        -Message 'Documentation URL is missing.'

    $uri = $null

    $valid = [System.Uri]::TryCreate(
        [string]$Value,
        [System.UriKind]::Absolute,
        [ref]$uri
    )

    Assert-WinSecCriteriaTrue $valid (
        "Invalid documentation URL: $Value"
    )

    Assert-WinSecCriteriaEqual `
        -Actual $uri.Scheme `
        -Expected 'https' `
        -Message 'Documentation must use HTTPS.'

    Assert-WinSecCriteriaEqual `
        -Actual $uri.Host `
        -Expected 'learn.microsoft.com' `
        -Message 'Unexpected draft documentation domain.'
}


# ============================================================
# TEST EXECUTOR
# ============================================================

function Invoke-WinSecCriteriaTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Test
    )

    try {
        $null = & $Test

        $script:Passed++

        Write-Host (
            '[PASS] {0}' -f $Name
        ) -ForegroundColor Green
    }
    catch {
        $script:Failed++

        Write-Host (
            '[FAIL] {0}' -f $Name
        ) -ForegroundColor Red

        Write-Host (
            '       {0}' -f $_.Exception.Message
        ) -ForegroundColor DarkGray
    }
}


# ============================================================
# CATALOG CONTRACT
# ============================================================

$script:ExpectedAreas = @(
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

$script:ExpectedMappingNames = @(
    'CISBenchmarks'
    'CISControls'
    'NISTCSF'
    'MITREATTACK'
)

$script:ExpectedOperators = @(
    'Equals'
    'In'
)

# ------------------------------------------------------------
# Evidence property contract
#
# This list represents the expected structure produced
# by the current Defender collector.
#
# It does not imply that each property will contain a
# non-null value on every Windows device.
# ------------------------------------------------------------

$script:EvidenceProperties = @{
    DefenderStatus = @(
        'AMRunningMode'
        'AMServiceEnabled'
        'AntivirusEnabled'
        'RealTimeProtectionEnabled'
        'BehaviorMonitorEnabled'
        'OnAccessProtectionEnabled'
        'IoavProtectionEnabled'
        'NISEnabled'
        'IsTamperProtected'
        'DefenderSignaturesOutOfDate'
        'AntivirusSignatureAge'
        'NISSignatureAge'
        'AntivirusSignatureVersion'
        'QuickScanAge'
        'FullScanAge'
    )

    DefenderPreferences = @(
        'DisableRealtimeMonitoring'
        'DisableBehaviorMonitoring'
        'DisableScriptScanning'
        'DisableArchiveScanning'
        'DisableEmailScanning'
        'DisableRemovableDriveScanning'
        'PUAProtection'
        'MAPSReporting'
        'SubmitSamplesConsent'
        'DisableBlockAtFirstSeen'
        'EnableNetworkProtection'
        'EnableControlledFolderAccess'
        'CloudBlockLevel'
        'CloudExtendedTimeout'
    )

    PUAProtectionAssessment = @(
        'Mode'
        'BlockingConfigured'
        'EffectiveProtectionConfirmed'
    )

    AttackSurfaceReduction = @(
        'Rules'
        'Complete'
        'ConfiguredRuleCount'
    )

    ExclusionCounts = @(
        'Paths'
        'Processes'
        'Extensions'
        'ASR'
        'ControlledFolderAllowedApplications'
        'ControlledFolderProtectedFolders'
    )
}


# ============================================================
# EVIDENCE PATH VALIDATION
# ============================================================

function Test-WinSecCatalogEvidencePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (
        $Path -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$'
    ) {
        return $false
    }

    $segments = $Path.Split('.')

    $rootName = $segments[0]
    $propertyName = $segments[1]

    if (-not $script:EvidenceProperties.ContainsKey($rootName)) {
        return $false
    }

    return (
        $propertyName -cin $script:EvidenceProperties[$rootName]
    )
}


# ============================================================
# FILE VALIDATION
# ============================================================

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'WINSEC ANALYZER - DEFENDER CRITERIA UNIT TESTS' `
    -ForegroundColor Cyan
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''

Invoke-WinSecCriteriaTest `
    -Name 'Defender criteria catalog exists' `
    -Test {

        Assert-WinSecCriteriaTrue (
            Test-Path `
                -LiteralPath $script:CatalogPath `
                -PathType Leaf
        ) 'Missing config/criteria/defender.json.'
    }

Invoke-WinSecCriteriaTest `
    -Name 'Evaluation Engine exists' `
    -Test {

        Assert-WinSecCriteriaTrue (
            Test-Path `
                -LiteralPath $script:EnginePath `
                -PathType Leaf
        ) 'Missing EvaluationEngine.ps1.'
    }

Invoke-WinSecCriteriaTest `
    -Name 'Defender collector exists' `
    -Test {

        Assert-WinSecCriteriaTrue (
            Test-Path `
                -LiteralPath $script:CollectorPath `
                -PathType Leaf
        ) 'Missing Test-Defender.ps1.'
    }

if ($script:Failed -gt 0) {
    throw 'Required WinSec Analyzer files are missing.'
}


# ============================================================
# LOAD CATALOG AND EVALUATION ENGINE
# ============================================================

$script:Catalog = $null

try {
    $rawJson = Get-Content `
        -LiteralPath $script:CatalogPath `
        -Raw `
        -Encoding UTF8

    $script:Catalog = ConvertFrom-Json `
        -InputObject $rawJson

    . $script:EnginePath
}
catch {
    throw (
        'Unable to load catalog or Evaluation Engine: {0}' -f
        $_.Exception.Message
    )
}


# ============================================================
# GROUP 1 - CATALOG METADATA
# ============================================================

Write-Host '[1] CATALOG METADATA' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecCriteriaTest `
    -Name 'Catalog identity is correct' `
    -Test {

        Assert-WinSecCriteriaEqual `
            $script:Catalog.CatalogId `
            'WSA-DEFENDER'
    }

Invoke-WinSecCriteriaTest `
    -Name 'Catalog version is 0.9.0' `
    -Test {

        Assert-WinSecCriteriaEqual `
            $script:Catalog.CatalogVersion `
            '0.9.0'
    }

Invoke-WinSecCriteriaTest `
    -Name 'Catalog belongs to Microsoft Defender check' `
    -Test {

        Assert-WinSecCriteriaEqual `
            $script:Catalog.CheckId `
            'WSA-SYS-001'
    }

Invoke-WinSecCriteriaTest `
    -Name 'Catalog remains unapproved' `
    -Test {

        Assert-WinSecCriteriaEqual `
            $script:Catalog.Status `
            'DRAFT_UNAPPROVED'
    }

Invoke-WinSecCriteriaTest `
    -Name 'Catalog scoring is disabled' `
    -Test {

        Assert-WinSecCriteriaEqual `
            $script:Catalog.ScoringEnabled `
            $false
    }

Invoke-WinSecCriteriaTest `
    -Name 'Catalog prohibits device changes' `
    -Test {

        Assert-WinSecCriteriaEqual `
            $script:Catalog.DeviceChangesAllowed `
            $false
    }

Invoke-WinSecCriteriaTest `
    -Name 'Catalog contains twenty candidate criteria' `
    -Test {

        Assert-WinSecCriteriaEqual `
            @($script:Catalog.Criteria).Count `
            20
    }

Invoke-WinSecCriteriaTest `
    -Name 'Catalog contains fourteen review-only observations' `
    -Test {

        Assert-WinSecCriteriaEqual `
            @($script:Catalog.ReviewOnly).Count `
            14
    }

Invoke-WinSecCriteriaTest `
    -Name 'Automatic approval is prohibited' `
    -Test {

        Assert-WinSecCriteriaEqual `
            $script:Catalog.ActivationPolicy.ProhibitAutomaticApproval `
            $true
    }

Invoke-WinSecCriteriaTest `
    -Name 'Framework mappings require verification' `
    -Test {

        Assert-WinSecCriteriaEqual `
            $script:Catalog.ActivationPolicy.MappingsRequireVerification `
            $true
    }

Invoke-WinSecCriteriaTest `
    -Name 'Unknown evidence must not be graded' `
    -Test {

        Assert-WinSecCriteriaEqual `
            $script:Catalog.ActivationPolicy.UnknownMustNotBeGraded `
            $true
    }

Invoke-WinSecCriteriaTest `
    -Name 'Catalog operators match the draft contract' `
    -Test {

        $actual = @(
            $script:Catalog.SupportedEngineOperators
        )

        Assert-WinSecCriteriaEqual $actual.Count 2

        foreach ($operator in $actual) {
            Assert-WinSecCriteriaTrue (
                $operator -cin $script:ExpectedOperators
            ) "Unsupported catalog operator: $operator"
        }
    }


# ============================================================
# GROUP 2 - CRITERION IDENTIFIERS
# ============================================================

Write-Host ''
Write-Host '[2] CRITERION IDENTIFIERS' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecCriteriaTest `
    -Name 'Criterion identifiers are unique' `
    -Test {

        $ids = @(
            $script:Catalog.Criteria |
                ForEach-Object {
                    $_.CriterionId
                }
        )

        $unique = @(
            $ids | Select-Object -Unique
        )

        Assert-WinSecCriteriaEqual `
            $unique.Count `
            $ids.Count
    }

Invoke-WinSecCriteriaTest `
    -Name 'Draft identifiers follow expected sequence' `
    -Test {

        $actual = @(
            $script:Catalog.Criteria |
                ForEach-Object {
                    $_.CriterionId
                }
        )

        for ($i = 1; $i -le 20; $i++) {
            $expected = 'WSA-DEF-DRAFT-{0:D3}' -f $i

            Assert-WinSecCriteriaTrue (
                $expected -cin $actual
            ) "Missing draft identifier: $expected"
        }
    }


# ============================================================
# GROUP 3 - VALIDATE EACH CRITERION
# ============================================================

Write-Host ''
Write-Host '[3] INDIVIDUAL CRITERIA' -ForegroundColor Cyan
Write-Host ''

foreach ($criterion in $script:Catalog.Criteria) {

    $current = $criterion

    Invoke-WinSecCriteriaTest `
        -Name ('Criterion {0}' -f $current.CriterionId) `
        -Test {

            # ------------------------------------------------
            # Identity
            # ------------------------------------------------

            Assert-WinSecCriteriaText `
                $current.CriterionId

            Assert-WinSecCriteriaEqual `
                $current.CheckId `
                'WSA-SYS-001'

            Assert-WinSecCriteriaText `
                $current.Name

            # ------------------------------------------------
            # Area
            # ------------------------------------------------

            Assert-WinSecCriteriaTrue (
                $current.Area -cin $script:ExpectedAreas
            ) "Unknown area: $($current.Area)"

            # ------------------------------------------------
            # Evidence path
            # ------------------------------------------------

            Assert-WinSecCriteriaTrue (
                Test-WinSecCatalogEvidencePath `
                    -Path $current.EvidencePath
            ) "Unsupported evidence path: $($current.EvidencePath)"

            # ------------------------------------------------
            # Operator and expected value
            # ------------------------------------------------

            Assert-WinSecCriteriaTrue (
                $current.Operator -cin $script:ExpectedOperators
            ) "Unsupported operator: $($current.Operator)"

            Assert-WinSecCriteriaTrue (
                $null -ne $current.ExpectedValue
            ) 'ExpectedValue is null.'

            if ($current.Operator -eq 'In') {
                Assert-WinSecCriteriaTrue (
                    $current.ExpectedValue -is [array]
                ) 'In requires an array.'

                Assert-WinSecCriteriaTrue (
                    @($current.ExpectedValue).Count -gt 0
                ) 'In requires a nonempty array.'
            }
            else {
                Assert-WinSecCriteriaTrue (
                    $current.ExpectedValue -isnot [array]
                ) 'Equals requires a scalar value.'
            }

            # ------------------------------------------------
            # Approval safeguards
            # ------------------------------------------------

            Assert-WinSecCriteriaEqual `
                $current.Approved `
                $false

            Assert-WinSecCriteriaEqual `
                $current.Verification.Status `
                'PENDING'

            Assert-WinSecCriteriaEqual `
                $current.Verification.ReviewedBy `
                $null

            Assert-WinSecCriteriaEqual `
                $current.Verification.ReviewedAtUTC `
                $null

            # ------------------------------------------------
            # Documentation
            # ------------------------------------------------

            Assert-WinSecCriteriaEqual `
                $current.Source.Framework `
                'MICROSOFT_DOCUMENTATION'

            Assert-WinSecCriteriaEqual `
                $current.Source.ControlId `
                'NOT_ASSIGNED'

            Assert-WinSecCriteriaEqual `
                $current.Source.Version `
                'ONLINE'

            Assert-WinSecCriteriaText `
                $current.Source.Title

            Assert-WinSecCriteriaUrl `
                $current.Source.Url

            # ------------------------------------------------
            # Windows applicability
            # ------------------------------------------------

            Assert-WinSecCriteriaEqual `
                $current.Applicability.OSFamily `
                'Windows'

            foreach ($name in @(
                'OSRelease',
                'Edition',
                'Profile'
            )) {
                Assert-WinSecCriteriaEqual `
                    $current.Applicability.$name `
                    'PENDING_SELECTION'
            }

            # ------------------------------------------------
            # Technical recommendation
            # ------------------------------------------------

            Assert-WinSecCriteriaText `
                $current.Recommendation

            Assert-WinSecCriteriaText `
                $current.Interpretation

            Assert-WinSecCriteriaTrue (
                @($current.ActivationDependencies).Count -gt 0
            ) 'Activation dependencies are missing.'

            # ------------------------------------------------
            # No invented framework references
            # ------------------------------------------------

            foreach ($name in $script:ExpectedMappingNames) {
                $mapping = $current.FrameworkMappings

                Assert-WinSecCriteriaTrue (
                    $null -ne $mapping.PSObject.Properties[$name]
                ) "Missing framework mapping field: $name"

                Assert-WinSecCriteriaEqual `
                    @($mapping.$name).Count `
                    0 `
                    "Unexpected unverified mapping: $name"
            }

            # ------------------------------------------------
            # Engine must reject draft approval
            # ------------------------------------------------

            $validation = Test-WinSecEvaluationCriterion `
                -Criterion $current

            Assert-WinSecCriteriaEqual `
                $validation.Valid `
                $false
        }
}


# ============================================================
# GROUP 4 - REVIEW-ONLY INDICATORS
# ============================================================

Write-Host ''
Write-Host '[4] REVIEW-ONLY INDICATORS' -ForegroundColor Cyan
Write-Host ''

foreach ($entry in $script:Catalog.ReviewOnly) {

    $current = $entry

    Invoke-WinSecCriteriaTest `
        -Name ('Review-only: {0}' -f $current.Name) `
        -Test {

            Assert-WinSecCriteriaText `
                $current.Name

            Assert-WinSecCriteriaTrue (
                $current.Area -cin $script:ExpectedAreas
            ) "Unknown analysis area: $($current.Area)"

            Assert-WinSecCriteriaEqual `
                $current.Assessment `
                'REVIEW_ONLY'

            Assert-WinSecCriteriaTrue (
                Test-WinSecCatalogEvidencePath `
                    -Path $current.EvidencePath
            ) "Unsupported review evidence path: $($current.EvidencePath)"

            Assert-WinSecCriteriaText `
                $current.Reason

            Assert-WinSecCriteriaUrl `
                $current.ReferenceUrl

            # Review-only entries are not valid criteria.

            $validation = Test-WinSecEvaluationCriterion `
                -Criterion $current

            Assert-WinSecCriteriaEqual `
                $validation.Valid `
                $false
        }
}


# ============================================================
# GROUP 5 - CATALOG CONSISTENCY
# ============================================================

Write-Host ''
Write-Host '[5] CATALOG CONSISTENCY' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecCriteriaTest `
    -Name 'All candidate criteria use unique evidence paths' `
    -Test {

        $paths = @(
            $script:Catalog.Criteria |
                ForEach-Object {
                    $_.EvidencePath
                }
        )

        Assert-WinSecCriteriaEqual `
            @($paths | Select-Object -Unique).Count `
            $paths.Count
    }


Invoke-WinSecCriteriaTest `
    -Name 'Review-only entries are unique' `
    -Test {

        $keys = @(
            $script:Catalog.ReviewOnly |
                ForEach-Object {
                    '{0}|{1}' -f $_.Area, $_.Name
                }
        )

        Assert-WinSecCriteriaEqual `
            @($keys | Select-Object -Unique).Count `
            $keys.Count
    }


Invoke-WinSecCriteriaTest `
    -Name 'PUA belongs to ThreatProtection' `
    -Test {

        $pua = @(
            $script:Catalog.Criteria |
                Where-Object {
                    $_.CriterionId -eq 'WSA-DEF-DRAFT-011'
                }
        )

        Assert-WinSecCriteriaEqual $pua.Count 1

        Assert-WinSecCriteriaEqual `
            $pua[0].Area `
            'ThreatProtection'

        Assert-WinSecCriteriaEqual `
            $pua[0].EvidencePath `
            'PUAProtectionAssessment.Mode'
    }


Invoke-WinSecCriteriaTest `
    -Name 'PUA does not have a separate catalog area' `
    -Test {

        $areas = @(
            $script:Catalog.Criteria.Area
            $script:Catalog.ReviewOnly.Area
        )

        Assert-WinSecCriteriaTrue (
            'PUA' -cnotin $areas
        ) 'PUA must remain inside ThreatProtection.'
    }


Invoke-WinSecCriteriaTest `
    -Name 'ASR rule inventory remains review-only' `
    -Test {

        $rules = @(
            $script:Catalog.ReviewOnly |
                Where-Object {
                    $_.EvidencePath -eq 'AttackSurfaceReduction.Rules'
                }
        )

        Assert-WinSecCriteriaEqual $rules.Count 1

        Assert-WinSecCriteriaEqual `
            $rules[0].Assessment `
            'REVIEW_ONLY'
    }


Invoke-WinSecCriteriaTest `
    -Name 'Every criterion is awaiting approval' `
    -Test {

        $approved = @(
            $script:Catalog.Criteria |
                Where-Object {
                    $_.Approved -eq $true
                }
        )

        Assert-WinSecCriteriaEqual $approved.Count 0
    }


# ============================================================
# GROUP 6 - EVALUATION ENGINE SAFEGUARDS
# ============================================================

Write-Host ''
Write-Host '[6] EVALUATION ENGINE SAFEGUARDS' `
    -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------
# Synthetic evidence only
# ------------------------------------------------------------

$script:FixtureControl = [pscustomobject]@{
    CheckId = 'WSA-SYS-001'
    DeviceId = 'local:CRITERIA-TEST'
    ScanId = 'CRITERIA-UNIT-001'
    Status = 'INFORMATIONAL'

    Evidence = [pscustomobject]@{
        CheckId = 'WSA-SYS-001'
        DeviceId = 'local:CRITERIA-TEST'
        ScanId = 'CRITERIA-UNIT-001'

        CollectionSuccessful = $true

        PUAProtectionAssessment = [pscustomobject]@{
            Mode = 'BLOCK'
        }
    }
}

$script:FixtureContext = [pscustomobject]@{
    DeviceId = 'local:CRITERIA-TEST'
    ScanId = 'CRITERIA-UNIT-001'

    OSFamily = 'Windows'
    OSRelease = 'PENDING_SELECTION'
    Edition = 'PENDING_SELECTION'
    Profile = 'PENDING_SELECTION'
}


Invoke-WinSecCriteriaTest `
    -Name 'Draft criteria cannot produce a security score' `
    -Test {

        $result = Invoke-WinSecControlEvaluation `
            -ControlResult $script:FixtureControl `
            -Criteria @($script:Catalog.Criteria) `
            -TargetContext $script:FixtureContext

        Assert-WinSecCriteriaEqual `
            $result.Status `
            'UNKNOWN'

        Assert-WinSecCriteriaEqual `
            $result.ScoringEligible `
            $false

        Assert-WinSecCriteriaEqual `
            $result.PassedCriteria `
            0

        Assert-WinSecCriteriaEqual `
            $result.FailedCriteria `
            0

        Assert-WinSecCriteriaEqual `
            $result.NotEvaluatedCriteria `
            20
    }


Invoke-WinSecCriteriaTest `
    -Name 'All draft evaluations remain NOT_EVALUATED' `
    -Test {

        $result = Invoke-WinSecControlEvaluation `
            -ControlResult $script:FixtureControl `
            -Criteria @($script:Catalog.Criteria) `
            -TargetContext $script:FixtureContext

        Assert-WinSecCriteriaEqual `
            @($result.Evaluations).Count `
            20

        foreach ($evaluation in $result.Evaluations) {
            Assert-WinSecCriteriaEqual `
                $evaluation.Status `
                'NOT_EVALUATED'

            Assert-WinSecCriteriaEqual `
                $evaluation.ScoringEligible `
                $false
        }
    }


Invoke-WinSecCriteriaTest `
    -Name 'A matching PUA value does not bypass approval' `
    -Test {

        $puaCriterion = @(
            $script:Catalog.Criteria |
                Where-Object {
                    $_.CriterionId -eq 'WSA-DEF-DRAFT-011'
                }
        )[0]

        $result = Invoke-WinSecControlEvaluation `
            -ControlResult $script:FixtureControl `
            -Criteria @($puaCriterion) `
            -TargetContext $script:FixtureContext

        Assert-WinSecCriteriaEqual `
            $result.Status `
            'UNKNOWN'

        Assert-WinSecCriteriaEqual `
            $result.ScoringEligible `
            $false

        Assert-WinSecCriteriaEqual `
            $result.NotEvaluatedCriteria `
            1
    }


Invoke-WinSecCriteriaTest `
    -Name 'Approval flag alone cannot authorize a criterion' `
    -Test {

        $criterion = (
            $script:Catalog.Criteria[0] |
                ConvertTo-Json -Depth 20 |
                ConvertFrom-Json
        )

        $criterion.Approved = $true

        $validation = Test-WinSecEvaluationCriterion `
            -Criterion $criterion

        Assert-WinSecCriteriaEqual `
            $validation.Valid `
            $false
    }


Invoke-WinSecCriteriaTest `
    -Name 'Pending verification prevents evaluation' `
    -Test {

        $criterion = (
            $script:Catalog.Criteria[0] |
                ConvertTo-Json -Depth 20 |
                ConvertFrom-Json
        )

        $criterion.Approved = $true

        $criterion.Source.Framework = 'LOCAL_POLICY'

        $validation = Test-WinSecEvaluationCriterion `
            -Criterion $criterion

        Assert-WinSecCriteriaEqual `
            $validation.Valid `
            $false
    }


Invoke-WinSecCriteriaTest `
    -Name 'No criteria returns NOT_EVALUATED' `
    -Test {

        $result = Invoke-WinSecControlEvaluation `
            -ControlResult $script:FixtureControl

        Assert-WinSecCriteriaEqual `
            $result.Status `
            'NOT_EVALUATED'

        Assert-WinSecCriteriaEqual `
            $result.ScoringEligible `
            $false
    }


# ============================================================
# GROUP 7 - SOURCE CODE VALIDATION
# ============================================================

Write-Host ''
Write-Host '[7] SOURCE VALIDATION' -ForegroundColor Cyan
Write-Host ''

Invoke-WinSecCriteriaTest `
    -Name 'Evaluation Engine parses correctly' `
    -Test {

        $tokens = $null
        $errors = $null

        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:EnginePath,
            [ref]$tokens,
            [ref]$errors
        )

        Assert-WinSecCriteriaEqual `
            @($errors).Count `
            0
    }


Invoke-WinSecCriteriaTest `
    -Name 'Defender collector parses correctly' `
    -Test {

        $tokens = $null
        $errors = $null

        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:CollectorPath,
            [ref]$tokens,
            [ref]$errors
        )

        Assert-WinSecCriteriaEqual `
            @($errors).Count `
            0
    }


# ============================================================
# FINAL SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host 'DEFENDER CRITERIA TEST SUMMARY' `
    -ForegroundColor Cyan
Write-Host ''

Write-Host "TOTAL : $total"

Write-Host (
    'PASS  : {0}' -f $script:Passed
) -ForegroundColor Green

$failureColor = if ($script:Failed -gt 0) {
    'Red'
}
else {
    'Green'
}

Write-Host (
    'FAIL  : {0}' -f $script:Failed
) -ForegroundColor $failureColor

Write-Host ('=' * 60) -ForegroundColor DarkGray
Write-Host ''

if ($script:Failed -gt 0) {
    throw (
        '{0} Defender criteria unit test(s) failed.' -f
        $script:Failed
    )
}

Write-Host 'All Defender criteria unit tests passed.' `
    -ForegroundColor Green

Write-Host ''
Write-Host 'Catalog remains DRAFT_UNAPPROVED.' `
    -ForegroundColor Yellow

Write-Host 'No compliance scores were generated.' `
    -ForegroundColor Yellow
