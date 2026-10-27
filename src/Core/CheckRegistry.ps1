
# ============================================================
# WinSec Analyzer
# Component : CheckRegistry
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Loads and validates the security checks catalog.
#
# PowerShell 5.1+ compatible.
# Does not execute security checks.
# ============================================================

$script:WinSecRegistryProjectRoot = (
    [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..')
    )
)

$script:WinSecRegistryCatalogPath = Join-Path `
    -Path $script:WinSecRegistryProjectRoot `
    -ChildPath 'config/checks.json'


# ------------------------------------------------------------
# Read an object property
# ------------------------------------------------------------

function Get-WinSecRegistryField {
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
                return $InputObject[$key]
            }
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}


# ------------------------------------------------------------
# Validate required string property
# ------------------------------------------------------------

function Assert-WinSecRegistryString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Context
    )

    $value = Get-WinSecRegistryField `
        -InputObject $InputObject `
        -Name $Name

    if (
        $value -isnot [string] -or
        [string]::IsNullOrWhiteSpace($value)
    ) {
        throw "Missing or invalid '$Name' in $Context."
    }

    return $value.Trim()
}


# ------------------------------------------------------------
# Validate required Boolean property
# ------------------------------------------------------------

function Assert-WinSecRegistryBoolean {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Context
    )

    $value = Get-WinSecRegistryField `
        -InputObject $InputObject `
        -Name $Name

    if ($value -isnot [bool]) {
        throw "Missing or invalid Boolean '$Name' in $Context."
    }

    return $value
}


# ------------------------------------------------------------
# Resolve a check script path
# ------------------------------------------------------------

function Resolve-WinSecCheckScriptPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [string]$RelativePath
    )

    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        throw 'Security check script path cannot be empty.'
    }

    $separator = [System.IO.Path]::DirectorySeparatorChar

    $normalized = $RelativePath.Replace(
        '/',
        $separator
    ).Replace(
        '\',
        $separator
    )

    if ([System.IO.Path]::IsPathRooted($normalized)) {
        throw "Absolute security check paths are not allowed: $RelativePath"
    }

    $checksDirectory = [System.IO.Path]::GetFullPath(
        (Join-Path $ProjectRoot 'src/Checks')
    )

    $resolvedPath = [System.IO.Path]::GetFullPath(
        (Join-Path $ProjectRoot $normalized)
    )

    $allowedPrefix = $checksDirectory.TrimEnd(
        [char]$separator
    ) + [string]$separator

    if (
        -not $resolvedPath.StartsWith(
            $allowedPrefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "Security check path must remain inside src/Checks: $RelativePath"
    }

    if (
        [System.IO.Path]::GetExtension(
            $resolvedPath
        ) -ine '.ps1'
    ) {
        throw "Security check must be a .ps1 file: $RelativePath"
    }

    return $resolvedPath
}


# ------------------------------------------------------------
# Validate script syntax and declared function
# ------------------------------------------------------------

function Test-WinSecCheckScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath,

        [Parameter(Mandatory)]
        [string]$FunctionName
    )

    if (-not (
        Test-Path -LiteralPath $ScriptPath -PathType Leaf
    )) {
        throw "Security check script not found: $ScriptPath"
    }

    # Navigation repeatedly validates public manifests against this catalog.
    # Cache only successful syntax/function checks, never execution rights.
    # Hash current bytes on every call and hold a read lease while parsing so
    # the cached answer belongs to exactly the source that was inspected.
    $fullPath = [IO.Path]::GetFullPath($ScriptPath)
    $lease = [IO.File]::Open($fullPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = [BitConverter]::ToString($sha.ComputeHash($lease)).Replace('-','') }
        finally { $sha.Dispose() }
        $cacheKey = '{0}:{1}{2}:{3}:{4}' -f $fullPath.Length,$fullPath.ToUpperInvariant(),
            $FunctionName.Length,$FunctionName.ToUpperInvariant(),$digest
        $cache = Get-Variable -Name WinSecScriptSyntaxCache -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($cache -isnot [hashtable]) { $cache = @{}; $script:WinSecScriptSyntaxCache = $cache }
        if ($cache.ContainsKey($cacheKey) -and $cache[$cacheKey] -is [bool] -and $cache[$cacheKey]) { return $true }

        $tokens = $null
        $parseErrors = $null

        # Parse the source WITHOUT executing it.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $fullPath,
            [ref]$tokens,
            [ref]$parseErrors
        )

        if (
            $null -ne $parseErrors -and
            $parseErrors.Count -gt 0
        ) {
            $firstError = $parseErrors[0]

            throw (
                "PowerShell syntax error in '{0}': {1}" -f `
                    $ScriptPath,
                    $firstError.Message
            )
        }

        $functions = @(
            $ast.FindAll(
                {
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
                },
                $true
            )
        )
        $found = $false
        foreach ($function in $functions) {
            if ([string]::Equals($function.Name,$FunctionName,[System.StringComparison]::OrdinalIgnoreCase)) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            throw (
                "Expected function '{0}' was not found in '{1}'." -f `
                    $FunctionName,
                    $ScriptPath
            )
        }

        # Bound memory even if many installations/source revisions are opened.
        if ($cache.Count -ge 128) { $cache.Clear() }
        $cache[$cacheKey] = $true
        return $true
    }
    finally { $lease.Dispose() }
}


# ------------------------------------------------------------
# Validate security checks catalog
# ------------------------------------------------------------

function Test-WinSecCheckCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Catalog
    )

    $null = Assert-WinSecRegistryString `
        -InputObject $Catalog `
        -Name 'schemaVersion' `
        -Context 'checks catalog'

    $null = Assert-WinSecRegistryString `
        -InputObject $Catalog `
        -Name 'catalogVersion' `
        -Context 'checks catalog'

    $catalogId = Assert-WinSecRegistryString `
        -InputObject $Catalog `
        -Name 'catalogId' `
        -Context 'checks catalog'

    if ($catalogId -ne 'winsec-windows-checks') {
        throw "Unsupported catalog identifier: $catalogId"
    }

    $catalogEnabled = Assert-WinSecRegistryBoolean `
        -InputObject $Catalog `
        -Name 'enabled' `
        -Context 'checks catalog'

    if (-not $catalogEnabled) {
        throw 'Security checks catalog is disabled.'
    }

    if ($Catalog.platform -ne 'Windows') {
        throw 'Only Windows security checks are supported.'
    }

    if ($Catalog.sections -isnot [array]) {
        throw 'Catalog sections must be an array.'
    }

    if ($Catalog.checks -isnot [array]) {
        throw 'Catalog checks must be an array.'
    }

    # --------------------------------------------------------
    # Validate execution policy
    # --------------------------------------------------------

    $policy = $Catalog.executionPolicy

    if ($null -eq $policy) {
        throw 'Missing executionPolicy.'
    }

    if ($policy.mode -ne 'EXPLICIT') {
        throw 'Security checks must use explicit execution.'
    }

    if (
        $policy.automaticExecutionOnStartup -ne $false -or
        $policy.executeOnScreenRender -ne $false -or
        $policy.automaticRemediation -ne $false -or
        $policy.readOnly -ne $true -or
        $policy.allowUnvalidatedChecks -ne $false -or
        $policy.requireEnabledCheck -ne $true -or
        $policy.requireImplementationValidation -ne $true
    ) {
        throw 'Unsupported or unsafe execution policy.'
    }

    # --------------------------------------------------------
    # Validate sections
    # --------------------------------------------------------

    $expectedSections = @(
        'SystemSecurity'
        'NetworkSecurity'
        'IdentityAccess'
        'LoggingAuditing'
        'ServicesHardening'
    )

    $sectionKeys = @{}
    $sectionOrders = @{}

    foreach ($section in $Catalog.sections) {

        $key = Assert-WinSecRegistryString `
            -InputObject $section `
            -Name 'key' `
            -Context 'section'

        $null = Assert-WinSecRegistryString `
            -InputObject $section `
            -Name 'name' `
            -Context "section $key"

        if ($key -notin $expectedSections) {
            throw "Unknown security section: $key"
        }

        if ($sectionKeys.ContainsKey($key)) {
            throw "Duplicate security section: $key"
        }

        $order = 0

        if (
            -not [int]::TryParse(
                [string]$section.order,
                [ref]$order
            ) -or
            $order -le 0
        ) {
            throw "Invalid section order: $key"
        }

        if ($sectionOrders.ContainsKey($order)) {
            throw "Duplicate section order: $order"
        }

        $sectionKeys[$key] = $true
        $sectionOrders[$order] = $true
    }

    foreach ($key in $expectedSections) {

        if (-not $sectionKeys.ContainsKey($key)) {
            throw "Required security section missing: $key"
        }
    }

    # --------------------------------------------------------
    # Validate checks
    # --------------------------------------------------------

    $checkIds = @{}
    $controlKeys = @{}
    $checkOrders = @{}

    $sectionPrefixes = @{
        SystemSecurity    = 'SYS'
        NetworkSecurity   = 'NET'
        IdentityAccess    = 'IAM'
        LoggingAuditing   = 'LOG'
        ServicesHardening = 'HRD'
    }

    foreach ($check in $Catalog.checks) {

        $checkId = Assert-WinSecRegistryString `
            -InputObject $check `
            -Name 'checkId' `
            -Context 'security check'

        $controlKey = Assert-WinSecRegistryString `
            -InputObject $check `
            -Name 'controlKey' `
            -Context $checkId

        $sectionKey = Assert-WinSecRegistryString `
            -InputObject $check `
            -Name 'sectionKey' `
            -Context $checkId

        $null = Assert-WinSecRegistryString `
            -InputObject $check `
            -Name 'name' `
            -Context $checkId

        if (-not $sectionKeys.ContainsKey($sectionKey)) {
            throw (
                "Check '$checkId' references unknown section " +
                "'$sectionKey'."
            )
        }

        $prefix = $sectionPrefixes[$sectionKey]

        $expectedPattern = (
            '^WSA-{0}-\d{{3}}$' -f $prefix
        )

        if ($checkId -cnotmatch $expectedPattern) {
            throw "Invalid CheckId for section ${sectionKey}: $checkId"
        }

        if ($checkIds.ContainsKey($checkId)) {
            throw "Duplicate CheckId: $checkId"
        }

        $checkIds[$checkId] = $true

        # ----------------------------------------------------
        # Detect duplicate controls
        # ----------------------------------------------------

        $compositeKey = "$sectionKey|$controlKey"

        if ($controlKeys.ContainsKey($compositeKey)) {
            throw "Duplicate controlKey in section: $compositeKey"
        }

        $controlKeys[$compositeKey] = $true

        # ----------------------------------------------------
        # Validate execution order
        # ----------------------------------------------------

        $order = 0

        if (
            -not [int]::TryParse(
                [string]$check.order,
                [ref]$order
            ) -or
            $order -le 0
        ) {
            throw "Invalid order for check: $checkId"
        }

        $orderKey = "$sectionKey|$order"

        if ($checkOrders.ContainsKey($orderKey)) {
            throw "Duplicate control order in section: $orderKey"
        }

        $checkOrders[$orderKey] = $true

        # ----------------------------------------------------
        # Validate implementation status
        # ----------------------------------------------------

        $implementationStatus = Assert-WinSecRegistryString `
            -InputObject $check `
            -Name 'implementationStatus' `
            -Context $checkId

        if (
            $implementationStatus -notin @(
                'PLANNED'
                'PENDING_VALIDATION'
                'VALIDATED'
            )
        ) {
            throw "Unsupported implementationStatus: $checkId"
        }

        $null = Assert-WinSecRegistryBoolean `
            -InputObject $check `
            -Name 'visible' `
            -Context $checkId

        # ----------------------------------------------------
        # Validate execution definition
        # ----------------------------------------------------

        $execution = $check.execution

        if ($null -eq $execution) {
            throw "Missing execution definition: $checkId"
        }

        $executionEnabled = Assert-WinSecRegistryBoolean `
            -InputObject $execution `
            -Name 'enabled' `
            -Context $checkId

        if ($execution.type -ne 'PowerShell') {
            throw "Unsupported execution type: $checkId"
        }

        $null = Assert-WinSecRegistryString `
            -InputObject $execution `
            -Name 'script' `
            -Context $checkId

        $functionName = Assert-WinSecRegistryString `
            -InputObject $execution `
            -Name 'function' `
            -Context $checkId

        if (
            $functionName -cnotmatch
            '^Test-WinSec[A-Za-z0-9]+$'
        ) {
            throw "Invalid security check function: $functionName"
        }

        if (
            $executionEnabled -and
            $implementationStatus -ne 'VALIDATED'
        ) {
            throw (
                "Check '$checkId' cannot be enabled " +
                "before implementation validation."
            )
        }

        # ----------------------------------------------------
        # Validate assessment metadata
        # ----------------------------------------------------

        $assessment = $check.assessment

        if ($null -eq $assessment) {
            throw "Missing assessment configuration: $checkId"
        }

        $assessmentMode = Assert-WinSecRegistryString `
            -InputObject $assessment `
            -Name 'mode' `
            -Context $checkId

        if (
            $assessmentMode -notin @(
                'CONFIGURATION'
                'INFORMATIONAL'
                'BASELINE_REQUIRED'
            )
        ) {
            throw "Unsupported assessment mode: $checkId"
        }

        $scoringEligible = Assert-WinSecRegistryBoolean `
            -InputObject $assessment `
            -Name 'scoringEligible' `
            -Context $checkId

        if (
            $scoringEligible -and
            $assessmentMode -eq 'INFORMATIONAL'
        ) {
            throw (
                "Informational check cannot receive " +
                "compliance points: $checkId"
            )
        }

        if ($scoringEligible) {

            $criteriaSource = [string]$assessment.criteriaSource

            if ([string]::IsNullOrWhiteSpace($criteriaSource)) {
                throw (
                    "Scoring check requires a documented " +
                    "criteriaSource: $checkId"
                )
            }
        }

        # ----------------------------------------------------
        # Validate applicability metadata
        # ----------------------------------------------------

        $applicability = $check.applicability

        if ($null -eq $applicability) {
            throw "Missing applicability definition: $checkId"
        }

        if ($applicability.platform -ne 'Windows') {
            throw "Unsupported check platform: $checkId"
        }

        if ($applicability.strategy -ne 'RUNTIME') {
            throw "Unsupported applicability strategy: $checkId"
        }

        if ($applicability.onUnknown -ne 'UNKNOWN') {
            throw "Invalid applicability fallback: $checkId"
        }
    }

    return $true
}


# ------------------------------------------------------------
# Load the security checks registry
# ------------------------------------------------------------

function Get-WinSecCheckRegistry {
    [CmdletBinding()]
    param(
        [string]$ProjectRoot = $script:WinSecRegistryProjectRoot,

        [string]$Path = ''
    )

    $ProjectRoot = [System.IO.Path]::GetFullPath(
        $ProjectRoot
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path `
            -Path $ProjectRoot `
            -ChildPath 'config/checks.json'
    }

    if (-not (
        Test-Path -LiteralPath $Path -PathType Leaf
    )) {
        throw "Security checks catalog not found: $Path"
    }

    try {

        $content = Get-Content `
            -LiteralPath $Path `
            -Encoding UTF8 `
            -Raw `
            -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($content)) {
            throw 'Security checks catalog is empty.'
        }

        $catalog = ConvertFrom-Json `
            -InputObject $content `
            -ErrorAction Stop

        if ($null -eq $catalog) {
            throw 'Security checks catalog contains null.'
        }

        $null = Test-WinSecCheckCatalog `
            -Catalog $catalog
    }
    catch {
        throw (
            "Unable to load security checks catalog: {0}" -f `
                $_.Exception.Message
        )
    }

    # --------------------------------------------------------
    # Register checks
    # --------------------------------------------------------

    $registeredChecks = New-Object `
        'System.Collections.Generic.List[object]'

    $enabledCount = 0
    $readyCount = 0
    $missingScriptCount = 0

    foreach ($check in $catalog.checks) {

        $scriptPath = Resolve-WinSecCheckScriptPath `
            -ProjectRoot $ProjectRoot `
            -RelativePath $check.execution.script

        $scriptExists = Test-Path `
            -LiteralPath $scriptPath `
            -PathType Leaf

        if (-not $scriptExists) {
            $missingScriptCount++
        }

        $executionEnabled = [bool]$check.execution.enabled
        $executionReady = $false
        $registryStatus = 'DISABLED'

        if ($executionEnabled) {

            $enabledCount++

            if (-not $scriptExists) {
                throw (
                    "Enabled check script not found: {0}" -f `
                        $check.execution.script
                )
            }

            $null = Test-WinSecCheckScript `
                -ScriptPath $scriptPath `
                -FunctionName $check.execution.function

            $executionReady = $true
            $registryStatus = 'READY'
            $readyCount++
        }
        elseif ($check.implementationStatus -eq 'PLANNED') {
            $registryStatus = 'PLANNED'
        }
        elseif (
            $check.implementationStatus -eq 'PENDING_VALIDATION'
        ) {
            $registryStatus = 'PENDING_VALIDATION'
        }
        elseif ($check.implementationStatus -eq 'VALIDATED') {
            $registryStatus = 'VALIDATED_DISABLED'
        }

        $registeredChecks.Add(
            [PSCustomObject]@{
                CheckId              = $check.checkId
                ControlKey           = $check.controlKey
                SectionKey           = $check.sectionKey

                Name                 = $check.name
                Description          = $check.description
                Order                = [int]$check.order

                Visible              = [bool]$check.visible
                ImplementationStatus = $check.implementationStatus
                RegistryStatus       = $registryStatus

                ExecutionEnabled     = $executionEnabled
                ExecutionReady       = $executionReady
                ExecutionType        = $check.execution.type

                Script               = $check.execution.script
                ScriptPath           = $scriptPath
                ScriptExists         = [bool]$scriptExists
                FunctionName         = $check.execution.function

                AssessmentMode       = $check.assessment.mode
                ScoringEligible      = [bool]$check.assessment.scoringEligible
                CriteriaSource       = $check.assessment.criteriaSource

                Applicability        = $check.applicability
                Definition           = $check
            }
        )
    }

    return [PSCustomObject]@{
        CatalogId      = $catalog.catalogId
        CatalogVersion = $catalog.catalogVersion
        SchemaVersion  = $catalog.schemaVersion

        ProjectRoot    = $ProjectRoot
        CatalogPath    = $Path
        Platform       = $catalog.platform

        Sections       = @(
            $catalog.sections | Sort-Object -Property order
        )

        Checks         = @(
            $registeredChecks.ToArray() |
                Sort-Object -Property SectionKey, Order
        )

        TotalChecks    = $registeredChecks.Count
        EnabledChecks  = $enabledCount
        ReadyChecks    = $readyCount
        MissingScripts = $missingScriptCount

        ExecutionMode  = $catalog.executionPolicy.mode
        LoadedAtUTC    = [DateTime]::UtcNow
    }
}


# ------------------------------------------------------------
# Get registered controls
# ------------------------------------------------------------

function Get-WinSecRegisteredChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Registry,

        [string]$SectionKey = '',

        [switch]$OnlyVisible,

        [switch]$OnlyEnabled,

        [switch]$OnlyReady
    )

    foreach ($check in $Registry.Checks) {

        if (
            $SectionKey -and
            $check.SectionKey -ne $SectionKey
        ) {
            continue
        }

        if ($OnlyVisible -and -not $check.Visible) {
            continue
        }

        if ($OnlyEnabled -and -not $check.ExecutionEnabled) {
            continue
        }

        if ($OnlyReady -and -not $check.ExecutionReady) {
            continue
        }

        $check
    }
}


# ------------------------------------------------------------
# Get one registered control
# ------------------------------------------------------------

function Get-WinSecRegisteredCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Registry,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CheckId
    )

    foreach ($check in $Registry.Checks) {

        if ($check.CheckId -eq $CheckId) {
            return $check
        }
    }

    return $null
}


# ------------------------------------------------------------
# Get controls eligible for execution
# ------------------------------------------------------------

function Get-WinSecExecutableChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Registry,

        [string]$SectionKey = ''
    )

    Get-WinSecRegisteredChecks `
        -Registry $Registry `
        -SectionKey $SectionKey `
        -OnlyEnabled `
        -OnlyReady
}


# ------------------------------------------------------------
# Get registry summary
# ------------------------------------------------------------

function Get-WinSecCheckRegistrySummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Registry
    )

    $planned = @(
        $Registry.Checks | Where-Object {
            $_.ImplementationStatus -eq 'PLANNED'
        }
    ).Count

    $pendingValidation = @(
        $Registry.Checks | Where-Object {
            $_.ImplementationStatus -eq 'PENDING_VALIDATION'
        }
    ).Count

    $validated = @(
        $Registry.Checks | Where-Object {
            $_.ImplementationStatus -eq 'VALIDATED'
        }
    ).Count

    $scoringEligible = @(
        $Registry.Checks | Where-Object {
            $_.ScoringEligible
        }
    ).Count

    return [PSCustomObject]@{
        CatalogVersion   = $Registry.CatalogVersion
        Platform         = $Registry.Platform
        TotalSections    = @($Registry.Sections).Count
        TotalChecks      = $Registry.TotalChecks

        Planned          = $planned
        PendingValidation = $pendingValidation
        Validated        = $validated

        Enabled          = $Registry.EnabledChecks
        Ready            = $Registry.ReadyChecks
        ScoringEligible  = $scoringEligible
        MissingScripts   = $Registry.MissingScripts
    }
}
