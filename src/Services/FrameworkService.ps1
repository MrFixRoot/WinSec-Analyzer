
# ============================================================
# WinSec Analyzer
# Component : FrameworkService
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Loads and validates cybersecurity framework catalogs.
#
# Supported:
# - CIS Benchmarks
# - CIS Controls v8.1
# - NIST CSF 2.0
# - MITRE ATT&CK Enterprise
#
# Read-only service. Does not execute security audits.
# ============================================================


# ------------------------------------------------------------
# Framework configuration directory
# ------------------------------------------------------------

$script:WinSecFrameworkDirectory = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\config\frameworks')
)


# ------------------------------------------------------------
# Get supported framework definitions
# ------------------------------------------------------------

function Get-WinSecFrameworkDefinitions {
    [CmdletBinding()]
    param()

    return @(
        [PSCustomObject]@{
            Id       = 'cis-benchmarks'
            FileName = 'cis-benchmarks.json'
        }

        [PSCustomObject]@{
            Id       = 'cis-controls'
            FileName = 'cis-controls.json'
        }

        [PSCustomObject]@{
            Id       = 'nist-csf'
            FileName = 'nist-csf.json'
        }

        [PSCustomObject]@{
            Id       = 'mitre-attack'
            FileName = 'mitre-attack.json'
        }
    )
}


# ------------------------------------------------------------
# Validate framework document structure
# ------------------------------------------------------------

function Test-WinSecFrameworkDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Document,

        [Parameter(Mandatory)]
        [string]$ExpectedId
    )

    if ($Document -isnot [PSCustomObject]) {
        throw "Invalid JSON root for framework: $ExpectedId"
    }

    if ($Document.frameworkId -ne $ExpectedId) {
        throw "Framework identifier mismatch: $ExpectedId"
    }

    if ([string]::IsNullOrWhiteSpace(
        [string]$Document.schemaVersion
    )) {
        throw "Missing schemaVersion: $ExpectedId"
    }

    if ([string]::IsNullOrWhiteSpace(
        [string]$Document.name
    )) {
        throw "Missing framework name: $ExpectedId"
    }

    if ($Document.enabled -isnot [bool]) {
        throw "Invalid enabled property: $ExpectedId"
    }

    if ($Document.mappings -isnot [array]) {
        throw "Mappings must be an array: $ExpectedId"
    }

    if ($Document.mappingRules -isnot [PSCustomObject]) {
        throw "Missing mappingRules: $ExpectedId"
    }

    # Framework-specific validation
    switch ($ExpectedId) {

        'cis-benchmarks' {

            if ($Document.benchmarks -isnot [array]) {
                throw 'CIS Benchmarks catalog is invalid.'
            }
        }

        'cis-controls' {

            if (
                $Document.frameworkVersion -ne '8.1' -or
                $Document.controls -isnot [array] -or
                $Document.safeguards -isnot [array]
            ) {
                throw 'CIS Controls v8.1 catalog is invalid.'
            }
        }

        'nist-csf' {

            if (
                $Document.frameworkVersion -ne '2.0' -or
                $Document.functions -isnot [array] -or
                $Document.categories -isnot [array] -or
                $Document.subcategories -isnot [array]
            ) {
                throw 'NIST CSF 2.0 catalog is invalid.'
            }
        }

        'mitre-attack' {

            if (
                $Document.tactics -isnot [array] -or
                $Document.techniques -isnot [array] -or
                $Document.subtechniques -isnot [array] -or
                $Document.mitigations -isnot [array]
            ) {
                throw 'MITRE ATT&CK catalog is invalid.'
            }
        }
    }

    # Validate mapping structure
    for ($i = 0; $i -lt $Document.mappings.Count; $i++) {

        $mapping = $Document.mappings[$i]

        if ($mapping -isnot [PSCustomObject]) {
            throw "Invalid mapping at index ${i}: $ExpectedId"
        }

        if ([string]::IsNullOrWhiteSpace(
            [string]$mapping.checkId
        )) {
            throw "Missing checkId at mapping ${i}: $ExpectedId"
        }

        if ($mapping.references -isnot [array]) {
            throw "Missing references array at mapping ${i}: $ExpectedId"
        }

        foreach ($reference in $mapping.references) {

            if (
                $reference -isnot [PSCustomObject] -or
                [string]::IsNullOrWhiteSpace(
                    [string]$reference.id
                )
            ) {
                throw "Invalid reference in mapping ${i}: $ExpectedId"
            }
        }
    }

    return $true
}


# ------------------------------------------------------------
# Load and validate framework configuration
# ------------------------------------------------------------

function Get-WinSecFrameworkCatalog {
    [CmdletBinding()]
    param(
        [string]$Directory = $script:WinSecFrameworkDirectory,

        [switch]$IncludeDisabled
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw "Framework directory not found: $Directory"
    }

    $definitions = @(
        Get-WinSecFrameworkDefinitions
    )

    $frameworks = [System.Collections.Generic.List[object]]::new()

    $mappingCount = 0
    $disabledCount = 0

    foreach ($definition in $definitions) {

        $path = Join-Path `
            -Path $Directory `
            -ChildPath $definition.FileName

        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Framework configuration not found: $path"
        }

        try {

            $content = Get-Content `
                -LiteralPath $path `
                -Raw `
                -Encoding UTF8 `
                -ErrorAction Stop

            $document = ConvertFrom-Json `
                -InputObject $content `
                -ErrorAction Stop

            # Structural validation
            $null = Test-WinSecFrameworkDocument `
                -Document $document `
                -ExpectedId $definition.Id

            if (-not $document.enabled) {

                $disabledCount++

                if (-not $IncludeDisabled) {
                    continue
                }
            }

            $frameworks.Add($document)

            $mappingCount += $document.mappings.Count
        }
        catch {

            throw (
                "Unable to load framework '{0}': {1}" -f `
                    $definition.Id,
                    $_.Exception.Message
            )
        }
    }

    return [PSCustomObject]@{
        Directory     = $Directory
        Frameworks    = $frameworks.ToArray()
        TotalFiles    = $definitions.Count
        LoadedCount   = $frameworks.Count
        DisabledCount = $disabledCount
        MappingCount  = $mappingCount
        LoadedAtUTC   = [DateTime]::UtcNow
    }
}


# ------------------------------------------------------------
# Get framework configuration summary
# ------------------------------------------------------------

function Get-WinSecFrameworkSummary {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Catalog = $null
    )

    if ($null -eq $Catalog) {
        $Catalog = Get-WinSecFrameworkCatalog
    }

    $summary = @(
        foreach ($framework in $Catalog.Frameworks) {

            $mappingCount = @($framework.mappings).Count

            $status = if (-not $framework.enabled) {
                'DISABLED'
            }
            elseif ($mappingCount -eq 0) {
                'UNMAPPED'
            }
            else {
                'CONFIGURED'
            }

            $version = [string]$framework.frameworkVersion

            if ([string]::IsNullOrWhiteSpace($version)) {
                $version = 'NOT SET'
            }

            [PSCustomObject]@{
                FrameworkId = $framework.frameworkId
                Name        = $framework.name
                Version     = $version
                Enabled     = $framework.enabled
                Mappings    = $mappingCount
                Status      = $status
            }
        }
    )

    return $summary
}


# ------------------------------------------------------------
# Resolve framework references for a security check
# ------------------------------------------------------------

function Get-WinSecCheckFrameworkReferences {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CheckId,

        [string]$Platform = '',

        [AllowNull()]
        [object]$Catalog = $null
    )

    # Load catalog when not explicitly supplied
    if ($null -eq $Catalog) {
        $Catalog = Get-WinSecFrameworkCatalog
    }

    # FrameworkMappingEngine must be loaded by the caller
    $mappingCommand = Get-Command `
        -Name 'Get-WinSecFrameworkMappings' `
        -CommandType Function `
        -ErrorAction SilentlyContinue

    if ($null -eq $mappingCommand) {
        throw (
            'FrameworkMappingEngine.ps1 is not loaded. ' +
            'Load it before resolving framework references.'
        )
    }

    $frameworks = @(
        $Catalog.Frameworks | Where-Object {
            $_.enabled -eq $true
        }
    )

    if ($frameworks.Count -eq 0) {
        return
    }

    # Map using real configured references
    Get-WinSecFrameworkMappings `
        -CheckId $CheckId `
        -Frameworks $frameworks `
        -Platform $Platform
}
