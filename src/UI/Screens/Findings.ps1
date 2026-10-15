
# ============================================================
# WinSec Analyzer
# Component : Findings
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Displays prioritized security findings with evidence,
# remediation guidance and framework references.
#
# Features:
# - Multi-device and multi-scan isolation
# - P1-P5 finding prioritization
# - CIS, NIST and MITRE references
# - Adaptive terminal layout
# - Selected finding details
# - Persistent navigation selection
#
# This component does not execute security checks.
# ============================================================


# ------------------------------------------------------------
# Load required finding components
# ------------------------------------------------------------

$winSecProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\..')
)

$winSecFindingDependencies = @(
    @{
        Command = 'Invoke-WinSecFindingPrioritization'
        Path    = 'src/Core/FindingPriorityEngine.ps1'
    }
    @{
        Command = 'Get-WinSecFrameworkMappings'
        Path    = 'src/Core/FrameworkMappingEngine.ps1'
    }
    @{
        Command = 'Get-WinSecCheckFrameworkReferences'
        Path    = 'src/Services/FrameworkService.ps1'
    }
)

foreach ($dependency in $winSecFindingDependencies) {

    $command = Get-Command `
        -Name $dependency.Command `
        -CommandType Function `
        -ErrorAction SilentlyContinue

    if ($null -ne $command) {
        continue
    }

    $path = Join-Path `
        -Path $winSecProjectRoot `
        -ChildPath $dependency.Path

    if (Test-Path -LiteralPath $path -PathType Leaf) {
        . $path
    }
}


# ------------------------------------------------------------
# Read a property from a finding or mapping
# ------------------------------------------------------------

function Get-WinSecFindingProperty {
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
# Safely convert assessment data into display text
# ------------------------------------------------------------

function ConvertTo-WinSecFindingText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [string]) {
        return $Value.Trim()
    }

    if ($Value -is [array]) {

        $parts = @(
            foreach ($item in $Value) {
                ConvertTo-WinSecFindingText -Value $item
            }
        )

        return ($parts -join '; ')
    }

    if (
        $Value -is [PSCustomObject] -or
        $Value -is [System.Collections.IDictionary]
    ) {
        return ConvertTo-Json `
            -InputObject $Value `
            -Compress `
            -Depth 6
    }

    return [string]$Value
}


# ------------------------------------------------------------
# Read navigation context
# ------------------------------------------------------------

function Get-WinSecFindingsContext {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null
    )

    $sectionIndex = 0
    $controlIndex = 0
    $findingIndex = 0
    $scope = 'Section'
    $deviceId = ''

    if ($null -ne $NavigationState) {

        $sectionValue = Get-WinSecFindingProperty `
            -InputObject $NavigationState `
            -Name 'SectionIndex'

        $controlValue = Get-WinSecFindingProperty `
            -InputObject $NavigationState `
            -Name 'ControlIndex'

        $findingValue = Get-WinSecFindingProperty `
            -InputObject $NavigationState `
            -Name 'FindingsOffset'

        $scopeValue = Get-WinSecFindingProperty `
            -InputObject $NavigationState `
            -Name 'FindingsScope'

        $deviceValue = Get-WinSecFindingProperty `
            -InputObject $NavigationState `
            -Name 'SelectedDeviceId'

        if ($null -ne $sectionValue) {
            $sectionIndex = [int]$sectionValue
        }

        if ($null -ne $controlValue) {
            $controlIndex = [int]$controlValue
        }

        if ($null -ne $findingValue) {
            $findingIndex = [int]$findingValue
        }

        if ($scopeValue -eq 'Control') {
            $scope = 'Control'
        }

        $deviceId = [string]$deviceValue
    }

    return [PSCustomObject]@{
        DeviceId     = $deviceId
        SectionIndex = $sectionIndex
        ControlIndex = $controlIndex
        FindingIndex = $findingIndex
        Scope        = $scope
    }
}


# ------------------------------------------------------------
# Resolve framework references for one finding
# ------------------------------------------------------------

function Get-WinSecFindingFrameworkReferences {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Finding,

        [AllowNull()]
        [object]$Catalog = $null,

        [string]$Platform = 'Windows'
    )

    # Preserve references explicitly supplied by
    # the assessment engine.

    $existing = Get-WinSecFindingProperty `
        -InputObject $Finding `
        -Name 'FrameworkReferences'

    if ($null -ne $existing) {

        $references = @(
            $existing | Where-Object {
                $null -ne $_
            }
        )

        if ($references.Count -gt 0) {
            return $references
        }
    }

    $checkId = [string](
        Get-WinSecFindingProperty `
            -InputObject $Finding `
            -Name 'CheckId'
    )

    if ([string]::IsNullOrWhiteSpace($checkId)) {
        return
    }

    if ($null -eq $Catalog) {
        return
    }

    $command = Get-Command `
        -Name 'Get-WinSecCheckFrameworkReferences' `
        -CommandType Function `
        -ErrorAction SilentlyContinue

    if ($null -eq $command) {
        return
    }

    try {

        Get-WinSecCheckFrameworkReferences `
            -CheckId $checkId `
            -Platform $Platform `
            -Catalog $Catalog `
            -ErrorAction Stop
    }
    catch {

        Write-Verbose (
            "Framework mapping failed for {0}: {1}" -f `
                $checkId,
                $_.Exception.Message
        )
    }
}


# ------------------------------------------------------------
# Prepare findings for the selected assessment
# ------------------------------------------------------------

function Get-WinSecSelectedFindings {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [AllowEmptyCollection()]
        [object[]]$SectionResults = @(),

        [AllowEmptyCollection()]
        [object[]]$ControlResults = @(),

        [AllowEmptyCollection()]
        [object[]]$Findings = @(),

        [string]$ScanId = '',

        [string]$Platform = 'Windows'
    )

    # --------------------------------------------------------
    # Resolve selected section
    # --------------------------------------------------------

    $context = Get-WinSecFindingsContext `
        -NavigationState $NavigationState

    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $SectionResults
    )

    if ($sections.Count -eq 0) {
        return $null
    }

    $sectionIndex = [Math]::Max(
        0,
        [Math]::Min(
            $context.SectionIndex,
            $sections.Count - 1
        )
    )

    $section = $sections[$sectionIndex]

    $title = $section.Name
    $score = $section.Score
    $status = $section.Status

    $control = $null

    # --------------------------------------------------------
    # Resolve selected control when applicable
    # --------------------------------------------------------

    if ($context.Scope -eq 'Control') {

        $controls = @(
            Get-WinSecSectionControls `
                -SectionKey $section.Key `
                -ControlResults $ControlResults
        )

        if ($controls.Count -gt 0) {

            $controlIndex = [Math]::Max(
                0,
                [Math]::Min(
                    $context.ControlIndex,
                    $controls.Count - 1
                )
            )

            $control = $controls[$controlIndex]

            $title = $control.Name
            $score = $control.Score
            $status = $control.Status
        }
    }

    # --------------------------------------------------------
    # Filter findings without mixing devices
    # --------------------------------------------------------

    $warning = ''

    if ([string]::IsNullOrWhiteSpace($context.DeviceId)) {

        $warning = (
            'No device selected. Select a device ' +
            'before viewing assessment findings.'
        )

        $matched = @()
    }
    else {

        $matched = @(
            foreach ($finding in $Findings) {

                if ($null -eq $finding) {
                    continue
                }

                $findingDevice = [string](
                    Get-WinSecFindingProperty `
                        -InputObject $finding `
                        -Name 'DeviceId'
                )

                if ($findingDevice -ne $context.DeviceId) {
                    continue
                }

                $findingSection = [string](
                    Get-WinSecFindingProperty `
                        -InputObject $finding `
                        -Name 'SectionKey'
                )

                if ($findingSection -ne $section.Key) {
                    continue
                }

                $findingScan = [string](
                    Get-WinSecFindingProperty `
                        -InputObject $finding `
                        -Name 'ScanId'
                )

                if ($ScanId -and $findingScan -ne $ScanId) {
                    continue
                }

                if ($context.Scope -eq 'Control') {

                    if ($null -eq $control) {
                        continue
                    }

                    $findingControl = [string](
                        Get-WinSecFindingProperty `
                            -InputObject $finding `
                            -Name 'ControlKey'
                    )

                    $findingCheck = [string](
                        Get-WinSecFindingProperty `
                            -InputObject $finding `
                            -Name 'CheckId'
                    )

                    $controlCheck = [string](
                        Get-WinSecFindingProperty `
                            -InputObject $control `
                            -Name 'CheckId'
                    )

                    $matchesControl = (
                        $findingControl -eq $control.Key -or
                        (
                            $controlCheck -and
                            $findingCheck -eq $controlCheck
                        )
                    )

                    if (-not $matchesControl) {
                        continue
                    }
                }

                $finding
            }
        )
    }

    # --------------------------------------------------------
    # Prevent combining separate assessment executions
    # --------------------------------------------------------

    $resolvedScanId = $ScanId

    if (-not $ScanId -and $matched.Count -gt 0) {

        $scanIds = @(
            $matched | ForEach-Object {

                $value = [string](
                    Get-WinSecFindingProperty `
                        -InputObject $_ `
                        -Name 'ScanId'
                )

                if ($value) {
                    $value
                }
                else {
                    '__UNSPECIFIED_SCAN__'
                }

            } | Select-Object -Unique
        )

        if ($scanIds.Count -gt 1) {

            $matched = @()

            $warning = (
                'Multiple scan executions detected. ' +
                'Select a specific ScanId to view findings.'
            )
        }
        elseif (
            $scanIds.Count -eq 1 -and
            $scanIds[0] -ne '__UNSPECIFIED_SCAN__'
        ) {
            $resolvedScanId = $scanIds[0]
        }
    }

    # --------------------------------------------------------
    # Load framework catalog
    # --------------------------------------------------------

    $catalog = $null
    $frameworkStatus = 'UNAVAILABLE'

    $catalogCommand = Get-Command `
        -Name 'Get-WinSecFrameworkCatalog' `
        -CommandType Function `
        -ErrorAction SilentlyContinue

    if ($null -ne $catalogCommand) {

        try {

            $catalog = Get-WinSecFrameworkCatalog `
                -ErrorAction Stop

            $frameworkStatus = 'LOADED'
        }
        catch {

            $frameworkStatus = 'ERROR'

            Write-Verbose $_.Exception.Message
        }
    }

    # --------------------------------------------------------
    # Normalize finding records
    # --------------------------------------------------------

    $normalized = @(
        $index = 0

        foreach ($finding in $matched) {

            $index++

            $id = [string](
                Get-WinSecFindingProperty `
                    -InputObject $finding `
                    -Name 'Id'
            )

            if (-not $id) {

                $id = [string](
                    Get-WinSecFindingProperty `
                        -InputObject $finding `
                        -Name 'FindingId'
                )
            }

            if (-not $id) {
                $id = '{0:D3}' -f $index
            }

            $name = [string](
                Get-WinSecFindingProperty `
                    -InputObject $finding `
                    -Name 'Finding'
            )

            if (-not $name) {

                $name = [string](
                    Get-WinSecFindingProperty `
                        -InputObject $finding `
                        -Name 'Title'
                )
            }

            $description = ConvertTo-WinSecFindingText `
                -Value (
                    Get-WinSecFindingProperty `
                        -InputObject $finding `
                        -Name 'Description'
                )

            if (-not $name) {
                $name = $description
            }

            if (-not $name) {
                $name = 'Unnamed finding'
            }

            $severity = [string](
                Get-WinSecFindingProperty `
                    -InputObject $finding `
                    -Name 'Severity'
            )

            if (-not $severity) {
                $severity = 'UNRATED'
            }

            $priority = [string](
                Get-WinSecFindingProperty `
                    -InputObject $finding `
                    -Name 'Priority'
            )

            $evidence = ConvertTo-WinSecFindingText `
                -Value (
                    Get-WinSecFindingProperty `
                        -InputObject $finding `
                        -Name 'Evidence'
                )

            $recommendation = ConvertTo-WinSecFindingText `
                -Value (
                    Get-WinSecFindingProperty `
                        -InputObject $finding `
                        -Name 'Recommendation'
                )

            $checkId = [string](
                Get-WinSecFindingProperty `
                    -InputObject $finding `
                    -Name 'CheckId'
            )

            $controlKey = [string](
                Get-WinSecFindingProperty `
                    -InputObject $finding `
                    -Name 'ControlKey'
            )

            $legacyReference = [string](
                Get-WinSecFindingProperty `
                    -InputObject $finding `
                    -Name 'Reference'
            )

            $references = @(
                Get-WinSecFindingFrameworkReferences `
                    -Finding $finding `
                    -Catalog $catalog `
                    -Platform $Platform
            )

            [PSCustomObject]@{
                Id                  = $id
                Finding             = $name
                Description         = $description
                Severity            = $severity.ToUpperInvariant()
                Priority            = $priority
                Evidence            = $evidence
                Recommendation      = $recommendation
                Reference           = $legacyReference
                FrameworkReferences = $references

                CheckId             = $checkId
                ControlKey          = $controlKey
                SectionKey          = $section.Key
                DeviceId            = $context.DeviceId
                ScanId              = $resolvedScanId
            }
        }
    )

    # --------------------------------------------------------
    # Classify and sort by priority
    # --------------------------------------------------------

    $priorityCommand = Get-Command `
        -Name 'Invoke-WinSecFindingPrioritization' `
        -CommandType Function `
        -ErrorAction SilentlyContinue

    if ($null -ne $priorityCommand) {

        $normalized = @(
            Invoke-WinSecFindingPrioritization `
                -Findings $normalized
        )
    }
    else {

        # Missing priority engine must not create
        # a false classification.

        $normalized = @(
            foreach ($finding in $normalized) {

                $finding.Priority = 'UNRATED'
                $finding
            }
        )
    }

    return [PSCustomObject]@{
        Scope           = $context.Scope
        Title           = $title

        DeviceId        = $context.DeviceId
        ScanId          = $resolvedScanId
        SectionKey      = $section.Key

        Score           = $score
        Status          = $status
        Findings        = $normalized

        FrameworkStatus = $frameworkStatus
        Warning         = $warning
    }
}


# ------------------------------------------------------------
# Format framework references for display
# ------------------------------------------------------------

function Get-WinSecFindingReferenceLines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Finding
    )

    $lines = @(
        foreach ($reference in @($Finding.FrameworkReferences)) {

            if ($null -eq $reference) {
                continue
            }

            $framework = [string](
                Get-WinSecFindingProperty `
                    -InputObject $reference `
                    -Name 'FrameworkName'
            )

            if (-not $framework) {

                $framework = [string](
                    Get-WinSecFindingProperty `
                        -InputObject $reference `
                        -Name 'FrameworkId'
                )
            }

            $referenceId = [string](
                Get-WinSecFindingProperty `
                    -InputObject $reference `
                    -Name 'ReferenceId'
            )

            if (-not $referenceId) {

                $referenceId = [string](
                    Get-WinSecFindingProperty `
                        -InputObject $reference `
                        -Name 'id'
                )
            }

            if (-not $framework -or -not $referenceId) {
                continue
            }

            '{0}: {1}' -f $framework, $referenceId
        }
    )

    $legacyReference = [string]$Finding.Reference

    if ($legacyReference) {
        $lines += "Additional reference: $legacyReference"
    }

    return @(
        $lines | Select-Object -Unique
    )
}


# ------------------------------------------------------------
# Render a bounded text field
# ------------------------------------------------------------

function Write-WinSecFindingField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [AllowEmptyString()]
        [string]$Value = '',

        [ValidateRange(1, 10)]
        [int]$MaxLines = 1
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        $Value = 'Not provided'
    }

    $terminal = Get-WinSecTerminalSize

    $width = [Math]::Max(
        1,
        [int]$terminal.ContentWidth
    )

    $prefix = "${Label}: "

    $availableWidth = [Math]::Max(
        1,
        $width - $prefix.Length
    )

    # Keep evidence on logical display lines.
    $remaining = (
        $Value -replace '\s+', ' '
    ).Trim()

    for ($i = 0; $i -lt $MaxLines; $i++) {

        if (-not $remaining) {
            break
        }

        $take = [Math]::Min(
            $availableWidth,
            $remaining.Length
        )

        $part = $remaining.Substring(0, $take)

        if ($take -lt $remaining.Length) {

            $lastSpace = $part.LastIndexOf(' ')

            if ($lastSpace -gt 0) {
                $take = $lastSpace
                $part = $remaining.Substring(0, $take)
            }
        }

        $remaining = $remaining.Substring(
            $take
        ).TrimStart()

        # Show truncation on the final allocated line.
        if (
            $i -eq ($MaxLines - 1) -and
            $remaining.Length -gt 0
        ) {

            if ($part.Length -ge 3) {

                $part = $part.Substring(
                    0,
                    $part.Length - 3
                ) + '...'
            }
        }

        $line = if ($i -eq 0) {
            $prefix + $part
        }
        else {
            (' ' * $prefix.Length) + $part
        }

        Write-WinSecText `
            -Text $line `
            -Color Gray
    }
}


# ------------------------------------------------------------
# Determine available space for finding details
# ------------------------------------------------------------

function Get-WinSecFindingDetailPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Layout
    )

    # ContentRows already excludes banner, keyboard help
    # and the fixed screen reservations.

    $available = [int]$Layout.ContentRows

    $detailRows = 0
    $textLines = 0
    $referenceLines = 0

    # Expanded details on taller terminals
    if ($available -ge 24) {

        $detailRows = 13
        $textLines = 2
        $referenceLines = 2
    }
    elseif ($available -ge 16) {

        # Compact details
        $detailRows = 9
        $textLines = 1
        $referenceLines = 1
    }

    return [PSCustomObject]@{
        ShowDetails    = ($detailRows -gt 0)
        ReservedRows   = $detailRows
        TextLines      = $textLines
        ReferenceLines = $referenceLines
    }
}


# ------------------------------------------------------------
# Render selected finding details
# ------------------------------------------------------------

function Write-WinSecFindingDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Finding,

        [Parameter(Mandatory)]
        [psobject]$DetailPlan,

        [string]$FrameworkStatus = 'UNAVAILABLE'
    )

    if (-not $DetailPlan.ShowDetails) {
        return
    }

    Write-WinSecSectionTitle `
        -Title 'Finding Details'

    $priorityColor = 'Gray'

    if (
        Get-Command 'Get-WinSecPriorityColor' `
            -CommandType Function `
            -ErrorAction SilentlyContinue
    ) {

        $priorityColor = Get-WinSecPriorityColor `
            -Priority $Finding.Priority
    }

    Write-WinSecText `
        -Text "PRIORITY: $($Finding.Priority) | SEVERITY: $($Finding.Severity)" `
        -Color $priorityColor

    Write-WinSecFindingField `
        -Label 'Description' `
        -Value $Finding.Description `
        -MaxLines $DetailPlan.TextLines

    Write-WinSecFindingField `
        -Label 'Evidence' `
        -Value $Finding.Evidence `
        -MaxLines $DetailPlan.TextLines

    Write-WinSecFindingField `
        -Label 'Recommendation' `
        -Value $Finding.Recommendation `
        -MaxLines $DetailPlan.TextLines

    # --------------------------------------------------------
    # Display configured framework references
    # --------------------------------------------------------

    $references = @(
        Get-WinSecFindingReferenceLines `
            -Finding $Finding
    )

    if ($references.Count -eq 0) {

        $message = 'No configured framework references.'

        if ($FrameworkStatus -ne 'LOADED') {
            $message = 'Framework catalog unavailable.'
        }

        Write-WinSecText `
            -Text $message `
            -Color DarkGray

        return
    }

    Write-WinSecText `
        -Text "FRAMEWORK REFERENCES: $($references.Count)" `
        -Color DarkCyan

    foreach ($reference in (
        $references | Select-Object `
            -First $DetailPlan.ReferenceLines
    )) {

        Write-WinSecFindingField `
            -Label 'Ref' `
            -Value $reference `
            -MaxLines 1
    }
}


# ------------------------------------------------------------
# Render security findings screen
# ------------------------------------------------------------

function Show-WinSecFindings {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [AllowEmptyCollection()]
        [object[]]$SectionResults = @(),

        [AllowEmptyCollection()]
        [object[]]$ControlResults = @(),

        [AllowEmptyCollection()]
        [object[]]$Findings = @(),

        [string]$ScanId = '',

        [string]$Platform = 'Windows',

        [string]$Version = '0.9.0'
    )

    # --------------------------------------------------------
    # Get assessment information
    # --------------------------------------------------------

    $assessment = Get-WinSecSelectedFindings `
        -NavigationState $NavigationState `
        -SectionResults $SectionResults `
        -ControlResults $ControlResults `
        -Findings $Findings `
        -ScanId $ScanId `
        -Platform $Platform

    # --------------------------------------------------------
    # Get adaptive layout
    # --------------------------------------------------------

    $baseLayout = Get-WinSecLayout `
        -Screen 'Findings' `
        -ReservedRows 12

    Clear-WinSecScreen

    # --------------------------------------------------------
    # Minimum terminal dimensions
    # --------------------------------------------------------

    if ($baseLayout.IsTooSmall) {

        Write-WinSecText `
            -Text 'WINSEC ANALYZER' `
            -Color Cyan `
            -Align Center

        Write-Host ''

        Write-WinSecText `
            -Text 'Terminal window is too small.' `
            -Color Yellow `
            -Align Center

        Write-WinSecText `
            -Text "Minimum: $($baseLayout.MinimumWidth) x $($baseLayout.MinimumHeight)" `
            -Color DarkGray `
            -Align Center

        return
    }

    if ($null -eq $assessment) {

        Write-WinSecText `
            -Text 'No assessment information available.' `
            -Color Yellow

        Write-WinSecKeyboardHelp -Screen 'Findings'

        return
    }

    # --------------------------------------------------------
    # Calculate detail area
    # --------------------------------------------------------

    $count = @($assessment.Findings).Count

    $detailPlan = Get-WinSecFindingDetailPlan `
        -Layout $baseLayout

    if ($count -eq 0) {

        $detailPlan = [PSCustomObject]@{
            ShowDetails    = $false
            ReservedRows   = 0
            TextLines      = 0
            ReferenceLines = 0
        }
    }

    # Reserve enough space for selected finding details.
    # The remaining content area belongs to the table.

    $reservedRows = (
        12 + $detailPlan.ReservedRows
    )

    $layout = Get-WinSecLayout `
        -Screen 'Findings' `
        -BannerRows $baseLayout.BannerRows `
        -ReservedRows $reservedRows

    # --------------------------------------------------------
    # Render adaptive project branding
    # --------------------------------------------------------

    if ($layout.BannerRows -gt 2) {

        Show-Banner -Version $Version
    }
    else {

        Write-WinSecText `
            -Text "WINSEC ANALYZER v$Version" `
            -Color Cyan `
            -Align Center

        Write-WinSecText `
            -Text 'mrRoot | Security Findings' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Display assessment context
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title "Findings - $($assessment.Title)"

    $deviceName = $assessment.DeviceId

    if ($null -ne $NavigationState) {

        $selectedName = [string](
            Get-WinSecFindingProperty `
                -InputObject $NavigationState `
                -Name 'SelectedDeviceName'
        )

        if ($selectedName) {
            $deviceName = $selectedName
        }
    }

    if (-not $deviceName) {
        $deviceName = 'NOT SELECTED'
    }

    $contextText = "DEVICE: $deviceName"

    if ($assessment.ScanId) {
        $contextText += " | SCAN: $($assessment.ScanId)"
    }

    Write-WinSecText `
        -Text $contextText `
        -Color Gray

    $statusColor = Get-WinSecStatusColor `
        -Status $assessment.Status

    Write-WinSecText `
        -Text "SCORE: $($assessment.Score) | STATUS: $($assessment.Status)" `
        -Color $statusColor

    Write-WinSecText `
        -Text "SECURITY FINDINGS: $count" `
        -Color Cyan

    # --------------------------------------------------------
    # Display assessment isolation warning
    # --------------------------------------------------------

    if ($assessment.Warning) {

        Write-WinSecFindingField `
            -Label 'Warning' `
            -Value $assessment.Warning `
            -MaxLines 1
    }

    Write-Host ''

    # --------------------------------------------------------
    # Define responsive findings table
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Id'
            Header   = 'ID'
            Width    = 5
            MinWidth = 3
            MaxWidth = 8
            Priority = 1
        }

        @{
            Key      = 'Priority'
            Header   = 'Priority'
            Width    = 9
            MinWidth = 7
            MaxWidth = 9
            Priority = 2
        }

        @{
            Key      = 'Severity'
            Header   = 'Severity'
            Width    = 10
            MinWidth = 8
            MaxWidth = 10
            Priority = 3
        }

        @{
            Key      = 'Finding'
            Header   = 'Security Finding'
            Width    = 46
            MinWidth = 14
            MaxWidth = 72
            Priority = 1
            Expand   = $true
        }
    )

    # --------------------------------------------------------
    # Restore finding selection
    # --------------------------------------------------------

    $context = Get-WinSecFindingsContext `
        -NavigationState $NavigationState

    $selectedIndex = 0

    if ($count -gt 0) {

        $selectedIndex = [Math]::Max(
            0,
            [Math]::Min(
                $context.FindingIndex,
                $count - 1
            )
        )
    }

    # --------------------------------------------------------
    # Calculate visible table rows
    # --------------------------------------------------------

    $maxRows = [Math]::Max(
        1,
        [int]$layout.MaxTableRows
    )

    # --------------------------------------------------------
    # Render prioritized security findings
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $assessment.Findings `
        -SelectedIndex $selectedIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Render details if vertical space is available
    # --------------------------------------------------------

    if (
        $count -gt 0 -and
        $detailPlan.ShowDetails
    ) {

        $selectedFinding = $assessment.Findings[
            $selectedIndex
        ]

        Write-WinSecFindingDetails `
            -Finding $selectedFinding `
            -DetailPlan $detailPlan `
            -FrameworkStatus $assessment.FrameworkStatus
    }

    # --------------------------------------------------------
    # Render empty assessment state
    # --------------------------------------------------------

    if ($count -eq 0 -and -not $assessment.Warning) {

        Write-WinSecText `
            -Text 'No findings available for this selection.' `
            -Color Yellow

        Write-WinSecText `
            -Text 'An empty list does not confirm a successful audit.' `
            -Color DarkGray
    }

    # --------------------------------------------------------
    # Render contextual keyboard help
    # --------------------------------------------------------

    Write-WinSecKeyboardHelp -Screen 'Findings'
}
