
# ============================================================
# WinSec Analyzer
# Component : FrameworkMappingEngine
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Maps Windows security checks to cybersecurity
# framework references using configured JSON mappings.
#
# Supported frameworks:
# - CIS Controls
# - NIST CSF
# - MITRE ATT&CK
#
# This engine does not execute audits or modify systems.
# ============================================================


# ------------------------------------------------------------
# Read a property from an object or hashtable
# ------------------------------------------------------------

function Get-WinSecFrameworkField {
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
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
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
# Read a string with fallback
# ------------------------------------------------------------

function Get-WinSecFrameworkString {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Default = ''
    )

    $value = Get-WinSecFrameworkField `
        -InputObject $InputObject `
        -Name $Name

    if ($null -eq $value) {
        return $Default
    }

    $text = ([string]$value).Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $Default
    }

    return $text
}


# ------------------------------------------------------------
# Validate Windows platform compatibility
# ------------------------------------------------------------

function Test-WinSecFrameworkPlatform {
    [CmdletBinding()]
    param(
        [string]$Platform = '',

        [AllowEmptyCollection()]
        [object[]]$AllowedPlatforms = @()
    )

    if ([string]::IsNullOrWhiteSpace($Platform)) {
        return $false
    }

    $target = $Platform.Trim()

    foreach ($allowed in $AllowedPlatforms) {

        if ($null -eq $allowed) {
            continue
        }

        $candidate = ([string]$allowed).Trim()

        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        # Exact platform match
        if ($candidate -eq $target) {
            return $true
        }

        # Generic Windows family mapping
        if (
            $candidate -eq 'Windows' -and
            $target -match '^Windows(\s|$)'
        ) {
            return $true
        }

        # Example:
        # Windows 11 -> Windows 11 Enterprise
        if (
            $target.StartsWith(
                "$candidate ",
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            return $true
        }
    }

    return $false
}


# ------------------------------------------------------------
# Resolve declared mapping platforms
# ------------------------------------------------------------

function Get-WinSecMappingPlatforms {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Mapping,

        [AllowNull()]
        [object]$Framework
    )

    $platforms = Get-WinSecFrameworkField `
        -InputObject $Mapping `
        -Name 'platforms'

    if ($null -eq $platforms) {
        $platforms = Get-WinSecFrameworkField `
            -InputObject $Mapping `
            -Name 'platform'
    }

    if ($null -eq $platforms) {
        $platforms = Get-WinSecFrameworkField `
            -InputObject $Framework `
            -Name 'platforms'
    }

    if ($null -eq $platforms) {
        return
    }

    foreach ($platform in @($platforms)) {
        if (-not [string]::IsNullOrWhiteSpace(
            [string]$platform
        )) {
            [string]$platform
        }
    }
}


# ------------------------------------------------------------
# Validate framework reference
# ------------------------------------------------------------

function Test-WinSecFrameworkReference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FrameworkId,

        [Parameter(Mandatory)]
        [object]$Reference,

        [Parameter(Mandatory)]
        [object]$Mapping,

        [Parameter(Mandatory)]
        [object]$Framework
    )

    $referenceId = Get-WinSecFrameworkString `
        -InputObject $Reference -Name 'id'

    if ([string]::IsNullOrWhiteSpace($referenceId)) {
        return $false
    }

    $version = Get-WinSecFrameworkString `
        -InputObject $Framework -Name 'frameworkVersion'

    switch ($FrameworkId) {

        'cis-controls' {

            if ([string]::IsNullOrWhiteSpace($version)) {
                return $false
            }

            $safeguardId = Get-WinSecFrameworkString `
                -InputObject $Reference -Name 'safeguardId'

            if (-not $safeguardId) {
                $safeguardId = $referenceId
            }

            return (
                $safeguardId -match '^\d{1,2}\.\d{1,2}$'
            )
        }

        'nist-csf' {

            if ([string]::IsNullOrWhiteSpace($version)) {
                return $false
            }

            $functionId = Get-WinSecFrameworkString `
                -InputObject $Reference -Name 'functionId'

            $categoryId = Get-WinSecFrameworkString `
                -InputObject $Reference -Name 'categoryId'

            $subcategoryId = Get-WinSecFrameworkString `
                -InputObject $Reference -Name 'subcategoryId'

            if (
                $functionId -notin @(
                    'GV', 'ID', 'PR', 'DE', 'RS', 'RC'
                )
            ) {
                return $false
            }

            if (
                $categoryId -notmatch '^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}$'
            ) {
                return $false
            }

            if (
                $subcategoryId -notmatch '^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$'
            ) {
                return $false
            }

            if (
                -not $categoryId.StartsWith("$functionId.") -or
                -not $subcategoryId.StartsWith("$categoryId-") -or
                $referenceId -ne $subcategoryId
            ) {
                return $false
            }

            return $true
        }

        'mitre-attack' {

            $techniqueId = Get-WinSecFrameworkString `
                -InputObject $Reference -Name 'techniqueId'

            if (-not $techniqueId) {
                $techniqueId = $referenceId
            }

            return (
                $techniqueId -match '^T\d{4}(\.\d{3})?$'
            )
        }

        default {
            return $false
        }
    }
}


# ------------------------------------------------------------
# Resolve framework mappings for a security check
# ------------------------------------------------------------

function Get-WinSecFrameworkMappings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CheckId,

        [AllowEmptyCollection()]
        [object[]]$Frameworks = @(),

        [string]$Platform = '',
        [string]$CriterionId = ''
    )

    # Prevent duplicate framework references
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($framework in $Frameworks) {

        if ($null -eq $framework) {
            continue
        }

        $frameworkId = Get-WinSecFrameworkString `
            -InputObject $framework -Name 'frameworkId'

        $frameworkName = Get-WinSecFrameworkString `
            -InputObject $framework -Name 'name'

        $frameworkVersion = Get-WinSecFrameworkString `
            -InputObject $framework -Name 'frameworkVersion'

        $enabled = Get-WinSecFrameworkField `
            -InputObject $framework -Name 'enabled'

        if ($enabled -eq $false) {
            continue
        }

        if ($frameworkId -notin @(
            'cis-controls',
            'nist-csf',
            'mitre-attack'
        )) {
            continue
        }

        $rules = Get-WinSecFrameworkField `
            -InputObject $framework -Name 'mappingRules'

        $requirePlatform = Get-WinSecFrameworkField `
            -InputObject $rules -Name 'requirePlatformMatch'

        $mappings = Get-WinSecFrameworkField `
            -InputObject $framework -Name 'mappings'

        if ($null -eq $mappings) {
            continue
        }

        foreach ($mapping in @($mappings)) {

            if ($null -eq $mapping) {
                continue
            }

            $mappingCheckId = Get-WinSecFrameworkString `
                -InputObject $mapping -Name 'checkId'

            # Match the actual WinSec security check
            if ($mappingCheckId -ne $CheckId) {
                continue
            }

            # Validate platform requirements
            if ($requirePlatform -eq $true) {

                $allowedPlatforms = @(
                    Get-WinSecMappingPlatforms `
                        -Mapping $mapping `
                        -Framework $framework
                )

                if (-not (
                    Test-WinSecFrameworkPlatform `
                        -Platform $Platform `
                        -AllowedPlatforms $allowedPlatforms
                )) {
                    Write-Verbose (
                        "Platform mismatch for $frameworkId / $CheckId"
                    )

                    continue
                }
            }

            $references = Get-WinSecFrameworkField `
                -InputObject $mapping -Name 'references'

            if ($null -eq $references) {
                continue
            }

            foreach ($reference in @($references)) {

                if ($null -eq $reference) {
                    continue
                }
                # Read the collection directly: pipeline output unwraps a one-item array.
                # Retain its original type so malformed scalar mappings still fail closed.
                $criterionIds=$null
                if ($reference -is [System.Collections.IDictionary]) {
                    if ($reference.Contains('criterionIds')) {$criterionIds=$reference['criterionIds']}
                } elseif ($null -ne $reference.PSObject.Properties['criterionIds']) {
                    $criterionIds=$reference.PSObject.Properties['criterionIds'].Value
                }
                if ($null -ne $criterionIds -and
                    ($criterionIds -isnot [array] -or $criterionIds.Count -eq 0 -or $criterionIds -cnotcontains $CriterionId)) { continue }

                # Validate framework-specific requirements
                $valid = Test-WinSecFrameworkReference `
                    -FrameworkId $frameworkId `
                    -Reference $reference `
                    -Mapping $mapping `
                    -Framework $framework

                if (-not $valid) {
                    Write-Verbose (
                        "Invalid reference skipped: $frameworkId / $CheckId"
                    )

                    continue
                }

                $referenceId = Get-WinSecFrameworkString `
                    -InputObject $reference -Name 'id'

                $referenceType = Get-WinSecFrameworkString `
                    -InputObject $reference -Name 'type'

                $title = Get-WinSecFrameworkString `
                    -InputObject $reference -Name 'title'

                $url = Get-WinSecFrameworkString `
                    -InputObject $reference -Name 'url'

                $benchmarkId = Get-WinSecFrameworkString `
                    -InputObject $mapping -Name 'benchmarkId'

                $benchmarkVersion = Get-WinSecFrameworkString `
                    -InputObject $mapping -Name 'benchmarkVersion'

                $functionId = Get-WinSecFrameworkString `
                    -InputObject $reference -Name 'functionId'

                $categoryId = Get-WinSecFrameworkString `
                    -InputObject $reference -Name 'categoryId'

                $subcategoryId = Get-WinSecFrameworkString `
                    -InputObject $reference -Name 'subcategoryId'

                $techniqueId = Get-WinSecFrameworkString `
                    -InputObject $reference -Name 'techniqueId'

                # Assign framework-specific reference type
                if (-not $referenceType) {

                    $referenceType = switch ($frameworkId) {
                        'cis-controls'   { 'Safeguard' }
                        'nist-csf'       { 'Subcategory' }
                        'mitre-attack'   { 'Technique' }
                    }
                }

                if ($frameworkId -eq 'mitre-attack') {
                    if (-not $techniqueId) {
                        $techniqueId = $referenceId
                    }
                }

                # Validate optional external URL
                if (
                    $url -and
                    -not (
                        $url -match '^https://'
                    )
                ) {
                    $url = ''
                }

                # Unique reference per framework/check
                $identity = '{0}|{1}|{2}|{3}' -f `
                    $frameworkId,
                    $CheckId,
                    $benchmarkId,
                    $referenceId

                if (-not $seen.Add($identity)) {
                    continue
                }

                # Return normalized framework reference
                [PSCustomObject]@{
                    FrameworkId      = $frameworkId
                    FrameworkName    = $frameworkName
                    FrameworkVersion = $frameworkVersion

                    CheckId          = $CheckId
                    ReferenceId      = $referenceId
                    ReferenceType    = $referenceType
                    Title            = $title
                    Url              = $url
                    Description      = Get-WinSecFrameworkString -InputObject $reference -Name 'description'
                    Recommendation   = Get-WinSecFrameworkString -InputObject $reference -Name 'recommendation'

                    BenchmarkId      = $benchmarkId
                    BenchmarkVersion = $benchmarkVersion

                    FunctionId       = $functionId
                    CategoryId       = $categoryId
                    SubcategoryId    = $subcategoryId

                    TechniqueId      = $techniqueId

                    Platform         = $Platform
                }
            }
        }
    }
}
