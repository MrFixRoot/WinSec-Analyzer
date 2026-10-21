
# ============================================================
# WinSec Analyzer
# Component : Invoke-WinSecCLI
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Main interactive terminal controller.
#
# Features:
# - Centralized keyboard controller
# - Multi-device assessment navigation
# - Device-specific results and findings
# - Navigation history
# - Resize-aware terminal rendering
# - Persistent screen selection
#
# Security:
# - Read-only interface
# - No audits during rendering
# - No automatic remote connections
# - No mixing of device or scan evidence
# ============================================================

# ------------------------------------------------------------
# Read an object or dictionary property
# ------------------------------------------------------------

function Get-WinSecCLIValue {
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
# Load registered devices
# ------------------------------------------------------------

function Get-WinSecCLIDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [AllowEmptyCollection()]
        [object[]]$Devices = @()
    )

    # --------------------------------------------------------
    # Load TargetRegistry dependency
    # --------------------------------------------------------

    $registryPath = Join-Path `
        -Path $ProjectRoot `
        -ChildPath 'src/Core/TargetRegistry.ps1'

    if (-not (
        Test-Path -LiteralPath $registryPath -PathType Leaf
    )) {
        throw "TargetRegistry not found: $registryPath"
    }

    . $registryPath

    # --------------------------------------------------------
    # Preserve explicit device input
    # --------------------------------------------------------

    $providedDevices = @(
        $Devices | Where-Object {
            $null -ne $_
        }
    )

    # --------------------------------------------------------
    # Build or import a validated target registry
    # --------------------------------------------------------

    if ($providedDevices.Count -gt 0) {
        $registry = [pscustomobject]@{
            schemaVersion = '1.0.0'
            targets = @($providedDevices)
        }
    }
    else {
        $registry = Import-WinSecTargetRegistry `
            -ProjectRoot $ProjectRoot
    }

    # --------------------------------------------------------
    # Validate schema, identities, modes and duplicates
    # --------------------------------------------------------

    $validation = Test-WinSecTargetRegistry `
        -Registry $registry

    if (-not $validation.Valid) {
        throw (
            'Invalid target registry: {0}' -f
            ($validation.Errors -join '; ')
        )
    }

    # --------------------------------------------------------
    # Return normalized devices
    # --------------------------------------------------------

    # TargetRegistry deliberately resets these fields:
    #
    # Score    = null
    # Status   = PENDING
    # ScanId   = empty
    # LastScan = Never
    #
    # These values must come from verified scan sessions,
    # not from device configuration.

    $registeredDevices = @(
        Get-WinSecRegisteredTargets `
            -Registry $registry `
            -IncludeLocalFallback:(
                $providedDevices.Count -eq 0
            )
    )

    return $registeredDevices
}

# ------------------------------------------------------------
# Filter assessment records by device and scan
# ------------------------------------------------------------

function Get-WinSecCLIRecords {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Records = @(),

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [AllowEmptyString()]
        [string]$ScanId = ''
    )

    foreach ($record in $Records) {
        if ($null -eq $record) {
            continue
        }

        $recordDevice = [string](
            Get-WinSecCLIValue `
                -InputObject $record `
                -Name 'DeviceId'
        )

        $recordScan = [string](
            Get-WinSecCLIValue `
                -InputObject $record `
                -Name 'ScanId'
        )

        if (
            $recordDevice -eq $DeviceId -and
            $recordScan -eq $ScanId
        ) {
            $record
        }
    }
}

# ------------------------------------------------------------
# Resolve assessment belonging to the selected device
# ------------------------------------------------------------

function Get-WinSecCLIActiveAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Context
    )

    $deviceId = [string]$State.SelectedDeviceId

    $empty = [PSCustomObject]@{
        SectionResults = @()
        ControlResults = @()
        Findings       = @()
        ScanId         = ''
        OverallScore   = $null
        OverallStatus  = 'PENDING'
        Warning        = ''
    }
    if ([string]::IsNullOrWhiteSpace($deviceId)) {
        return $empty
    }

    
    # ========================================================
    # WinSec Analyzer v0.9.0
    # Public Scan Result Integration
    #
    # Resolve the active coordinated scan for the selected
    # device. Legacy records are validated separately below.
    # ========================================================

    $activeScanMap = Get-WinSecCLIValue `
        -InputObject $Context `
        -Name 'ActiveScanByDevice'

    $publicScanMap = Get-WinSecCLIValue `
        -InputObject $Context `
        -Name 'PublicScans'

    $expectedScope = $null
    $scopeMap = Get-WinSecCLIValue $Context 'ActiveScanByScope'
    if ($null -ne $scopeMap -and $scopeMap -isnot [hashtable]) { throw 'Invalid scope selection map.' }
    if ($null -ne $scopeMap -and $scopeMap.Count -gt 0 -and
        $State.Screen -cin @('Section','Results','Findings')) {
        $viewScope = Get-WinSecCLIViewScope -State $State
        $candidates = @($viewScope)
        if ($viewScope.ScopeType -ceq 'CONTROL') {
            $sections = @(Get-WinSecMainMenuSections)
            $candidates += [pscustomobject]@{ScopeType='SECTION';ScopeKey=$sections[$State.SectionIndex].Key}
        }
        foreach ($candidate in $candidates) {
            $scopeKey = Get-WinSecCLIScopeKey $deviceId $candidate.ScopeType $candidate.ScopeKey
            if ($scopeMap.ContainsKey($scopeKey)) {
                $activeScanMap = @{ $deviceId = $scopeMap[$scopeKey] }
                $expectedScope = $candidate
                break
            }
        }
    }

    if (
        $activeScanMap -is [System.Collections.IDictionary] -and
        $activeScanMap.Contains($deviceId)
    ) {
        $activeScanId = $activeScanMap[$deviceId]

        if ($activeScanId -isnot [string] -or
            [string]::IsNullOrWhiteSpace($activeScanId)) {
            throw 'Active scan identifier is missing.'
        }

        if (
            $publicScanMap -isnot
                [System.Collections.IDictionary]
        ) {
            throw 'Public scan collection is unavailable.'
        }

        # ----------------------------------------------------
        # Resolve the exact DeviceId + ScanId session
        # ----------------------------------------------------

        $sessionKey = '{0}:{1}{2}:{3}' -f `
            $deviceId.Length,
            $deviceId,
            $activeScanId.Length,
            $activeScanId

        if (-not $publicScanMap.Contains($sessionKey)) {
            throw 'Selected public scan session was not found.'
        }

        $publicResult = $publicScanMap[$sessionKey]

        if ($null -eq $publicResult) {
            throw 'Selected public scan result is null.'
        }

        # Own a bounded data snapshot before reading flags or display fields.
        # Standalone CLI consumers may not have initialized the coordinator.
        # Loading ResultModel defines functions only; no collection/storage.
        if ($null -eq (Get-Command 'Copy-WinSecResultData' `
            -CommandType Function -ErrorAction SilentlyContinue)) {
            . (Join-Path $PSScriptRoot '../Core/ResultModel.ps1')
        }
        $publicResult = Copy-WinSecResultData -Value $publicResult
        if ($null -ne $expectedScope -and
            ($publicResult.ScopeType -isnot [string] -or $publicResult.ScopeKey -isnot [string] -or
             $publicResult.ScopeType -cne $expectedScope.ScopeType -or $publicResult.ScopeKey -cne $expectedScope.ScopeKey)) {
            throw 'Public session does not match the selected scope.'
        }
        if ($null -eq $expectedScope -and $State.Screen -cin @('MainMenu','Section','Results','Findings') -and
            ($null -ne $publicResult.ScopeType -or $null -ne $publicResult.ScopeKey) -and
            ($publicResult.ScopeType -isnot [string] -or $publicResult.ScopeKey -isnot [string] -or
             $publicResult.ScopeType -cne 'DEVICE' -or $publicResult.ScopeKey -cne 'ALL')) {
            throw 'A partial session cannot replace the device assessment.'
        }

        # ----------------------------------------------------
        # Validate the public result before rendering
        # ----------------------------------------------------

        if (
            $publicResult.PublicProjection -isnot [bool] -or
            $publicResult.ContainsRawEvidence -isnot [bool] -or
            $publicResult.ScoringEligible -isnot [bool] -or
            $publicResult.DeviceId -isnot [string] -or
            $publicResult.ScanId -isnot [string] -or
            $publicResult.PublicProjection -cne $true -or
            $publicResult.ContainsRawEvidence -cne $false -or
            $publicResult.DeviceId -cne $deviceId -or
            $publicResult.ScanId -cne $activeScanId -or
            $publicResult.ScoringEligible -cne $false -or
            $null -ne $publicResult.OverallScore -or
            $publicResult.OverallStatus -cne 'NOT_SCORED'
        ) {
            throw 'Invalid public assessment projection.'
        }

        # PublicProjection is a marker, not proof that every nested field is
        # safe. Inspect the whole snapshot, including aliases and collections
        # not currently rendered. The copier already enforces depth/node
        # limits, data-only properties and absence of cycles.
        $publicValues = New-Object 'System.Collections.Generic.Stack[object]'
        $publicValues.Push($publicResult)
        while ($publicValues.Count -gt 0) {
            $value = $publicValues.Pop()
            if ($null -eq $value -or $value -is [string] -or $value -is [ValueType]) {
                continue
            }
            if ($value -is [System.Collections.IList]) {
                foreach ($item in $value) { $publicValues.Push($item) }
                continue
            }
            $isDictionary = $value -is [System.Collections.IDictionary]
            $names = if ($isDictionary) { @($value.psbase.Keys) }
                else { @($value.PSObject.Properties.Name) }
            foreach ($name in $names) {
                if ($name -in @('Evidence','RawEvidence','OriginalResult','ObservedValue','ExpectedValue')) {
                    throw 'Raw data is not allowed in public CLI results.'
                }
                if ($isDictionary) { $childValue = $value[$name] }
                else { $childValue = $value.PSObject.Properties[$name].Value }
                if ($name -in @('Score','OverallScore','ScoreValue','ScoreResult','ScoringPolicy') -and
                    $null -ne $childValue) {
                    throw 'Unapproved scoring data is not allowed in public CLI results.'
                }
                if ($name -in @('ScoringEnabled','ScoringEligible') -and
                    ($childValue -isnot [bool] -or $childValue -ne $false)) {
                    throw 'Scoring authorization is not allowed in public CLI results.'
                }
                $publicValues.Push($childValue)
            }
        }

        # ----------------------------------------------------
        # Read public collections safely
        # ----------------------------------------------------

        $publicSections = @(
            $publicResult.SectionResults |
                Where-Object { $null -ne $_ }
        )

        $publicControls = @(
            $publicResult.ControlResults |
                Where-Object { $null -ne $_ }
        )

        $publicFindings = @(
            $publicResult.Findings |
                Where-Object { $null -ne $_ }
        )

        # ----------------------------------------------------
        # Reject foreign, scored or raw nested records
        # ----------------------------------------------------

        foreach ($record in @(
            $publicSections + $publicControls + $publicFindings
        )) {
            # Validate each record independently of the public envelope.
            # Do not coerce arrays or numbers into identity strings.

            $recordDeviceId = $record.DeviceId
            $recordScanId = $record.ScanId

            if (
                $recordDeviceId -isnot [string] -or
                $recordScanId -isnot [string] -or
                $recordDeviceId -cne $deviceId -or
                $recordScanId -cne $activeScanId
            ) {
                throw 'Public record identity does not match the selected assessment.'
            }

            if (
                $null -ne $record.PSObject.Properties['Evidence'] -or
                $null -ne $record.PSObject.Properties['RawEvidence']
            ) {
                throw 'Unsafe evidence field in public record.'
            }

            $scoreProperty = $record.PSObject.Properties['Score']

            if (
                $null -ne $scoreProperty -and
                $null -ne $scoreProperty.Value
            ) {
                throw 'Unapproved numeric score in public record.'
            }
        }

        # ----------------------------------------------------
        # Return only the selected public assessment
        # ----------------------------------------------------

        # Preserve the existing UI result contract.
        # Do not calculate security scores in the CLI.

        return [PSCustomObject]@{
            SectionResults = @($publicSections)
            ControlResults = @($publicControls)
            Findings       = @($publicFindings)

            ScanId         = $activeScanId
            OverallScore   = $null
            OverallStatus  = 'NOT_SCORED'

            Warning        = ''
            SourceScopeType = Get-WinSecCLIValue $publicResult 'ScopeType'
            SourceScopeKey = Get-WinSecCLIValue $publicResult 'ScopeKey'
            CatalogVersion = Get-WinSecCLIValue $publicResult 'CatalogVersion'
        }
    }

    # --------------------------------------------------------
    # No coordinated scan selected for this device.
    # Continue with the existing legacy assessment logic.
    # --------------------------------------------------------


    # --------------------------------------------------------
    # Collect only records belonging to the active device
    # --------------------------------------------------------

    $allRecords = @(
        @($Context.SectionResults) +
        @($Context.ControlResults) +
        @($Context.Findings)
    )

    $deviceRecords = @(
        foreach ($record in $allRecords) {
            if ($null -eq $record) {
                continue
            }

            $recordDevice = [string](
                Get-WinSecCLIValue `
                    -InputObject $record `
                    -Name 'DeviceId'
            )

            if ($recordDevice -eq $deviceId) {
                $record
            }
        }
    )

    # --------------------------------------------------------
    # Determine scan identifier
    # --------------------------------------------------------

    $selectedScan = [string]$Context.ScanId

    $scanIds = @(
        $deviceRecords | ForEach-Object {
            $value = [string](
                Get-WinSecCLIValue `
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

    # Never combine findings from separate executions.

    if (-not $selectedScan) {
        if ($scanIds.Count -gt 1) {
            $empty.Warning = (
                'Multiple scan executions were found. ' +
                'Specify a ScanId to view one assessment.'
            )

            return $empty
        }

        if (
            $scanIds.Count -eq 1 -and
            $scanIds[0] -ne '__UNSPECIFIED_SCAN__'
        ) {
            $selectedScan = $scanIds[0]
        }
    }

    # --------------------------------------------------------
    # Filter all assessment collections
    # --------------------------------------------------------

    $sectionResults = @(
        Get-WinSecCLIRecords `
            -Records $Context.SectionResults `
            -DeviceId $deviceId `
            -ScanId $selectedScan
    )

    $controlResults = @(
        Get-WinSecCLIRecords `
            -Records $Context.ControlResults `
            -DeviceId $deviceId `
            -ScanId $selectedScan
    )

    $findings = @(
        Get-WinSecCLIRecords `
            -Records $Context.Findings `
            -DeviceId $deviceId `
            -ScanId $selectedScan
    )

    # --------------------------------------------------------
    # Keep internal evidence and scoring out of legacy views
    # --------------------------------------------------------

    # Legacy input is not a ResultModel public projection. Inspect
    # only the selected records, including structured display fields,
    # before publishing any part of the assessment. Reject rather
    # than silently dropping evidence or accepting scoring metadata.

    $inspectionLimit = 10000

    if ($sectionResults.Count + $controlResults.Count + $findings.Count -gt $inspectionLimit) {
        throw 'Legacy assessment exceeds the safe inspection limit.'
    }

    $pendingValues = New-Object 'System.Collections.Generic.Stack[object]'

    foreach ($record in @($sectionResults + $controlResults + $findings)) {
        $pendingValues.Push($record)
    }

    $visitedValues = 0

    while ($pendingValues.Count -gt 0) {
        $value = $pendingValues.Pop()
        $visitedValues++

        # Bound inspection even for cyclic objects or oversized graphs.
        if ($visitedValues -gt $inspectionLimit) {
            throw 'Legacy assessment exceeds the safe inspection limit.'
        }

        if ($null -eq $value -or $value -is [string] -or $value -is [ValueType]) {
            continue
        }

        if ($value -is [System.Collections.IList]) {
            if ($visitedValues + $pendingValues.Count + $value.Count -gt $inspectionLimit) {
                throw 'Legacy assessment exceeds the safe inspection limit.'
            }
            foreach ($item in $value) {
                $pendingValues.Push($item)
            }
            continue
        }

        $isDictionary = $value -is [System.Collections.IDictionary]

        if ($isDictionary) {
            # A dictionary entry named Keys must not hide other entries.
            $names = @($value.psbase.Keys)
        }
        elseif ($value -is [PSCustomObject]) {
            $names = @($value.PSObject.Properties.Name)
        }
        else {
            throw 'Legacy assessment contains unsupported structured data.'
        }

        if ($visitedValues + $pendingValues.Count + $names.Count -gt $inspectionLimit) {
            throw 'Legacy assessment exceeds the safe inspection limit.'
        }

        foreach ($name in $names) {
            if ($name -isnot [string]) {
                throw 'Legacy assessment contains an invalid property name.'
            }

            if ($name -in @('Evidence', 'RawEvidence', 'OriginalResult',
                'ObservedValue', 'ExpectedValue')) {
                throw 'Raw data is not allowed in legacy CLI results.'
            }

            if ($isDictionary) {
                $childValue = $value[$name]
            }
            else {
                $property = $value.PSObject.Properties[$name]
                if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty) {
                    throw 'Legacy assessment requires plain data properties.'
                }
                $childValue = $property.Value
            }

            if ($name -in @('Score', 'OverallScore', 'ScoreValue',
                'ScoreResult', 'ScoringPolicy') -and $null -ne $childValue) {
                throw 'Unapproved scoring data is not allowed in legacy CLI results.'
            }

            if ($name -in @('ScoringEnabled', 'ScoringEligible') -and
                ($childValue -isnot [bool] -or $childValue -ne $false)) {
                throw 'Scoring authorization is not allowed in legacy CLI results.'
            }

            $pendingValues.Push($childValue)
        }
    }

    # --------------------------------------------------------
    # Resolve device score for matching assessment only
    # --------------------------------------------------------

    $overallScore = $null
    $overallStatus = 'PENDING'

    $selectedDevice = @(
        $Context.Devices | Where-Object {
            $_.DeviceId -eq $deviceId
        }
    ) | Select-Object -First 1

    if ($null -ne $selectedDevice) {
        $deviceScan = [string]$selectedDevice.ScanId

        if (
            $selectedScan -and
            $deviceScan -eq $selectedScan
        ) {
            $overallScore = $null
            $overallStatus = 'PENDING'

            $hasAssessmentData = (
                $sectionResults.Count -gt 0 -or
                $controlResults.Count -gt 0 -or
                $findings.Count -gt 0
            )

            if ($hasAssessmentData) {
                $overallStatus = 'NOT_SCORED'
            }
        }
    }

    # Assessment data establishes NOT_SCORED regardless of device
    # inventory ScanId, which is intentionally untrusted metadata.

    if (
        $sectionResults.Count -gt 0 -or
        $controlResults.Count -gt 0 -or
        $findings.Count -gt 0
    ) {
        $overallStatus = 'NOT_SCORED'
    }

    return [PSCustomObject]@{
        SectionResults = $sectionResults
        ControlResults = $controlResults
        Findings       = $findings
        ScanId         = $selectedScan
        OverallScore   = $overallScore
        OverallStatus  = $overallStatus
        Warning        = ''
    }
}

# ------------------------------------------------------------
# Render current application screen
# ------------------------------------------------------------

function Show-WinSecCLICurrentScreen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Context
    )

    # --------------------------------------------------------
    # Devices do not require an assessment
    # --------------------------------------------------------

    if ($State.Screen -eq 'Devices') {
        $scanPresentation = Get-WinSecCLIScanPresentation -State $State -Context $Context
        Show-WinSecDevices `
            -NavigationState $State `
            -Devices $Context.Devices `
            -Version $Context.Version `
            -Message ([string](Get-WinSecCLIValue -InputObject $Context -Name 'LastDeviceMessage')) @scanPresentation

        return
    }

    $assessment = Get-WinSecCLIActiveAssessment `
        -State $State `
        -Context $Context

    # --------------------------------------------------------
    # Block ambiguous multi-scan views
    # --------------------------------------------------------

    if ($assessment.Warning) {
        Clear-WinSecScreen

        Write-WinSecText `
            -Text 'WINSEC ANALYZER' `
            -Color Cyan `
            -Align Center

        Write-Host ''

        Write-WinSecText `
            -Text 'Assessment selection required' `
            -Color Yellow

        Write-Host ''

        Write-WinSecText `
            -Text $assessment.Warning `
            -Color Gray

        Write-Host ''

        Write-WinSecKeyboardHelp `
            -Screen $State.Screen

        return
    }

    # --------------------------------------------------------
    # Render the active screen
    # --------------------------------------------------------

    switch ($State.Screen) {
        
        
        'MainMenu' {

            # ================================================
            # WinSec Analyzer v0.9.0
            # Main Menu - Scan / Rescan Integration
            # ================================================

            # -----------------------------------------------
            # Validate local scan authorization
            # -----------------------------------------------
            $scanPresentation = Get-WinSecCLIScanPresentation -State $State -Context $Context

            # -----------------------------------------------
            # Render existing main menu
            # -----------------------------------------------

            Show-WinSecMainMenu `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -OverallScore $assessment.OverallScore `
                -OverallStatus $assessment.OverallStatus `
                -Version $Context.Version `
                @scanPresentation

            # -----------------------------------------------
            # Display last scan notification
            # -----------------------------------------------

            $scanMessage = Get-WinSecCLIValue `
                -InputObject $Context `
                -Name 'LastScanMessage'

            if (
                -not [string]::IsNullOrWhiteSpace(
                    [string]$scanMessage
                )
            ) {

                Write-Host ''

                Write-WinSecText `
                    -Text ([string]$scanMessage) `
                    -Color Yellow
            }
        }



        'Section' {
            $scanPresentation = Get-WinSecCLIScanPresentation -State $State -Context $Context
            Show-WinSecResults `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -ControlResults $assessment.ControlResults `
                -Version $Context.Version @scanPresentation
        }

        'Results' {
            $scanPresentation = Get-WinSecCLIScanPresentation -State $State -Context $Context
            Show-WinSecResults `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -ControlResults $assessment.ControlResults `
                -Version $Context.Version @scanPresentation
        }

        'Findings' {
            $enableExport = Test-WinSecCLIFindingsExportEligibility -State $State -Context $Context
            Show-WinSecFindings `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -ControlResults $assessment.ControlResults `
                -Findings $assessment.Findings `
                -ScanId $assessment.ScanId `
                -Version $Context.Version -EnableExport:$enableExport -Message ([string](Get-WinSecCLIValue $Context 'LastExportMessage'))
        }

        default {
            Clear-WinSecScreen

            Write-WinSecText `
                -Text 'WINSEC ANALYZER' `
                -Color Cyan `
                -Align Center

            Write-Host ''

            Write-WinSecText `
                -Text "SCREEN: $($State.Screen)" `
                -Color Gray

            Write-WinSecText `
                -Text 'Screen integration pending.' `
                -Color Yellow

            Write-Host ''

            Write-WinSecText `
                -Text '[ESC] Back' `
                -Color DarkGray
        }
    }
}

# ------------------------------------------------------------
# Calculate navigation boundaries
# ------------------------------------------------------------

function Get-WinSecCLINavigationCounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Context
    )

    $assessment = Get-WinSecCLIActiveAssessment `
        -State $State `
        -Context $Context

    $sections = @(
        Get-WinSecMainMenuSections `
            -SectionResults $assessment.SectionResults
    )

    $controls = @()
    $section = $null

    # --------------------------------------------------------
    # Resolve selected security section
    # --------------------------------------------------------

    if ($sections.Count -gt 0) {
        $sectionIndex = [Math]::Max(
            0,
            [Math]::Min(
                [int]$State.SectionIndex,
                $sections.Count - 1
            )
        )

        $section = $sections[$sectionIndex]

        $controls = @(
            Get-WinSecSectionControls `
                -SectionKey $section.Key `
                -ControlResults $assessment.ControlResults
        )
    }

    # --------------------------------------------------------
    # Count findings for current selection
    # --------------------------------------------------------

    $findingCount = 0
    if ($null -ne $section -and @($assessment.Findings).Count -gt 0) {
        # Use the same catalog/identity/scope resolution and ordering as the
        # screen. Public findings have CheckId, not necessarily SectionKey.
        $findingView = Get-WinSecSelectedFindings `
            -NavigationState $State `
            -SectionResults $assessment.SectionResults `
            -ControlResults $assessment.ControlResults `
            -Findings $assessment.Findings `
            -ScanId $assessment.ScanId
        $findingCount = @($findingView.Findings).Count
    }

    return [PSCustomObject]@{
        SectionCount  = $sections.Count
        ControlCount  = $controls.Count
        FindingCount  = $findingCount
        SettingsCount = 0
    }
}

# ------------------------------------------------------------
# Main interactive application controller
# ------------------------------------------------------------

# ============================================================
# WinSec Analyzer
# Component : CLI Local Rescan Authorization
# Version   : 0.9.0
# Author    : mrRoot
#
# PowerShell 5.1 / 7.x
# No audit execution
# ============================================================

function Get-WinSecCLIFindingsExportSelection {
    [CmdletBinding()]
    param([psobject]$State,[psobject]$Context)
    if ($State.Screen -cne 'Findings' -or -not (Get-WinSecCLIValue $Context 'ProjectRoot')) { throw 'Export unavailable.' }
    $assessment=Get-WinSecCLIActiveAssessment -State $State -Context $Context
    Assert-WinSecResultScope $assessment.SourceScopeType $assessment.SourceScopeKey
    $scope=Get-WinSecCLIViewScope $State
    $view=Get-WinSecSelectedFindings -NavigationState $State -SectionResults $assessment.SectionResults `
        -ControlResults $assessment.ControlResults -Findings $assessment.Findings -ScanId $assessment.ScanId
    if ($view.Warning -or @($view.Findings).Count -eq 0 -or $view.DeviceId -cne $State.SelectedDeviceId -or
        $view.ScanId -cne $assessment.ScanId) { throw 'No verified findings to export.' }
    return [pscustomobject]@{DeviceId=$view.DeviceId;ScanId=$view.ScanId;SourceScopeType=$assessment.SourceScopeType;
        SourceScopeKey=$assessment.SourceScopeKey;ScopeType=$scope.ScopeType;ScopeKey=$scope.ScopeKey;
        CatalogVersion=$assessment.CatalogVersion;Findings=@(foreach($f in $view.Findings){
            [pscustomobject]@{FindingId=$f.FindingId;CheckId=$f.CheckId;DeviceId=$f.DeviceId;ScanId=$f.ScanId;
                Kind=$f.Kind;EvaluationStatus=$f.EvaluationStatus}
        })}
}

function Test-WinSecCLIFindingsExportEligibility {
    [CmdletBinding()]
    param([psobject]$State,[psobject]$Context)
    try { $null=Get-WinSecCLIFindingsExportSelection -State $State -Context $Context;return $true }
    catch { return $false }
}

function Invoke-WinSecCLIFindingsExport {
    [CmdletBinding()]
    param([psobject]$State,[psobject]$Context)
    $selection=Get-WinSecCLIFindingsExportSelection -State $State -Context $Context
    $result=Export-WinSecFindingsMarkdown -ProjectRoot $Context.ProjectRoot -Selection $selection
    $Context | Add-Member -NotePropertyName LastExportMessage -NotePropertyValue ('Exported: ' + $result.RelativePath) -Force
    return $result
}

function Get-WinSecCLIScanScope {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$State)
    if ($State.Screen -ceq 'Devices') {
        return [pscustomobject]@{ScopeType='DEVICE';ScopeKey='ALL';Label='Local Device'}
    }
    if ($State.Screen -cnotin @('MainMenu','Section','Results')) { throw 'This screen has no scan scope.' }
    $sections = @(Get-WinSecMainMenuSections)
    if ($State.SectionIndex -isnot [int] -or $State.SectionIndex -lt 0 -or $State.SectionIndex -ge $sections.Count) {
        throw 'Invalid scan section selection.'
    }
    $section = $sections[$State.SectionIndex]
    if ($State.Screen -cin @('Section','Results')) {
        $controls = @(Get-WinSecSectionControls -SectionKey $section.Key)
        if ($State.ControlIndex -isnot [int] -or $State.ControlIndex -lt 0 -or $State.ControlIndex -ge $controls.Count) {
            throw 'Invalid scan control selection.'
        }
        return [pscustomobject]@{ScopeType='CONTROL';ScopeKey=$controls[$State.ControlIndex].CheckId;Label='Control'}
    }
    return [pscustomobject]@{ScopeType='SECTION';ScopeKey=$section.Key;Label='Section'}
}

function Get-WinSecCLIViewScope {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$State)
    $sections = @(Get-WinSecMainMenuSections)
    if ($State.SectionIndex -isnot [int] -or $State.SectionIndex -lt 0 -or $State.SectionIndex -ge $sections.Count) {
        throw 'Invalid assessment section selection.'
    }
    if ($State.Screen -ceq 'Findings') {
        if ($State.FindingsScope -cnotin @('Section','Control')) { throw 'Invalid findings scope.' }
        if ($State.FindingsScope -ceq 'Control') {
            return Get-WinSecCLIScanScope -State ([pscustomobject]@{Screen='Section';SectionIndex=$State.SectionIndex;ControlIndex=$State.ControlIndex})
        }
    }
    return [pscustomobject]@{ScopeType='SECTION';ScopeKey=$sections[$State.SectionIndex].Key;Label='Section'}
}

function Get-WinSecCLIScanDeviceId {
    [CmdletBinding()]
    param([psobject]$State,[AllowEmptyCollection()][object[]]$Devices=@())
    if ($State.Screen -ceq 'Devices') {
        if ($State.DeviceIndex -isnot [int] -or $State.DeviceIndex -lt 0 -or $State.DeviceIndex -ge $Devices.Count) {
            throw 'Invalid scan device selection.'
        }
        $id = Get-WinSecCLIValue $Devices[$State.DeviceIndex] 'DeviceId'
    } else { $id = $State.SelectedDeviceId }
    if ($id -isnot [string] -or [string]::IsNullOrWhiteSpace($id)) { throw 'No scan device selected.' }
    return $id
}

function Get-WinSecCLIScopeKey {
    [CmdletBinding()]
    param([string]$DeviceId,[object]$ScopeType,[object]$ScopeKey)
    Assert-WinSecResultScope -ScopeType $ScopeType -ScopeKey $ScopeKey
    return '{0}:{1}{2}:{3}{4}:{5}' -f $DeviceId.Length,$DeviceId,$ScopeType.Length,$ScopeType,$ScopeKey.Length,$ScopeKey
}

function Get-WinSecCLIScanPresentation {
    [CmdletBinding()]
    param([psobject]$State,[psobject]$Context)
    $devices = @(Get-WinSecCLIValue $Context 'Devices' | Where-Object { $null -ne $_ })
    $enabled = $false
    $action = 'Scan'
    try {
        $scope = Get-WinSecCLIScanScope $State
        $deviceId = Get-WinSecCLIScanDeviceId -State $State -Devices $devices
        $enabled = Test-WinSecCLIRescanEligibility -State $State -Devices $devices -Coordinator $Context.ScanCoordinator
        $action = Get-WinSecScanAction $Context.ScanCoordinator $deviceId $scope.ScopeType $scope.ScopeKey
    } catch { $enabled = $false }
    return @{EnableRescan=[bool]$enabled;ScanAction=$action}
}

function Test-WinSecCLIRescanEligibility {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Devices,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Coordinator
    )

    # --------------------------------------------------------
    # Require a coordinator and a supported scan screen
    # --------------------------------------------------------

    if ($null -eq $Coordinator) {
        return $false
    }

    if ($State.Screen -cnotin @('Devices','MainMenu','Section','Results')) {
        return $false
    }

    try { $selectedId = Get-WinSecCLIScanDeviceId -State $State -Devices $Devices }
    catch { return $false }

    if ([string]::IsNullOrWhiteSpace($selectedId)) {
        return $false
    }

    # --------------------------------------------------------
    # Confirm this computer is the selected target
    # --------------------------------------------------------

    try {
        $requestedScope = Get-WinSecCLIScanScope -State $State
        if ($requestedScope.ScopeType -ceq 'CONTROL') {
            $registry = Get-WinSecCheckRegistry -ProjectRoot $Coordinator.ProjectRoot
            $check = Get-WinSecRegisteredCheck -Registry $registry -CheckId $requestedScope.ScopeKey
            if ($null -eq $check -or $check.ExecutionEnabled -cne $true -or $check.ExecutionReady -cne $true -or
                $check.ImplementationStatus -cne 'VALIDATED' -or $check.RegistryStatus -cne 'READY') { return $false }
        }
        $localTarget = New-WinSecLocalTarget

        if ($null -eq $localTarget) {
            return $false
        }

        if (-not [string]::Equals($selectedId, $localTarget.DeviceId, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }

        # ----------------------------------------------------
        # Require one enabled LOCAL registry entry
        # ----------------------------------------------------

        $matches = @(
            foreach ($device in $Devices) {
                if ($null -eq $device) {
                    continue
                }

                $id = [string](
                    Get-WinSecCLIValue `
                        -InputObject $device `
                        -Name 'DeviceId'
                )

                $mode = [string](
                    Get-WinSecCLIValue `
                        -InputObject $device `
                        -Name 'Mode'
                )

                $enabled = Get-WinSecCLIValue `
                    -InputObject $device `
                    -Name 'Enabled'

                if (
                    $id -ceq $selectedId -and
                    $mode -ceq 'LOCAL' -and
                    $enabled -is [bool] -and
                    $enabled -eq $true
                ) {
                    $device
                }
            }
        )

        if ($matches.Count -ne 1) {
            return $false
        }

        # ----------------------------------------------------
        # Final target authorization
        # ----------------------------------------------------

        # This validates the target. It does NOT execute
        # an audit, open a remote session or save evidence.

        $null = Resolve-WinSecScanTarget `
            -Coordinator $Coordinator `
            -DeviceId $selectedId `
            -ErrorAction Stop

        return $true
    }
    catch {
        # Fail closed. No authorization on errors.
        return $false
    }
}

# ============================================================
# WinSec Analyzer
# Component : CLI Local Scan Execution
# Version   : 0.9.0
# Author    : mrRoot
#
# PowerShell 5.1 / 7.x
#
# Security:
# - Local targets only
# - No scoring
# - No automatic evidence persistence
# - No remote execution
# ============================================================

function Invoke-WinSecCLILocalRescan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Context
    )

    # --------------------------------------------------------
    # Resolve coordinator and selected device
    # --------------------------------------------------------

    $coordinator = $Context.ScanCoordinator
    $deviceId = Get-WinSecCLIScanDeviceId -State $State -Devices @($Context.Devices)
    $scope = Get-WinSecCLIScanScope -State $State
    $scopeMap = Get-WinSecCLIValue $Context 'ActiveScanByScope'
    if ($null -ne $scopeMap -and $scopeMap -isnot [hashtable]) { throw 'Invalid scope selection map.' }
    if ($null -eq $scopeMap) { $scopeMap = @{} }

    if ([string]::IsNullOrWhiteSpace($deviceId)) {
        throw 'No target device selected.'
    }

    # --------------------------------------------------------
    # Validate target authorization
    # --------------------------------------------------------

    $authorized = Test-WinSecCLIRescanEligibility `
        -State $State `
        -Devices @($Context.Devices) `
        -Coordinator $coordinator

    if ($authorized -ne $true) {
        throw 'Local scan authorization denied.'
    }

    # --------------------------------------------------------
    # Enforce production security restrictions
    # --------------------------------------------------------

    if (
        $coordinator.ScoringEnabled -ne $false -or
        $coordinator.RemoteExecution -ne $false -or
        $coordinator.AutomaticEvidencePersistence -ne $false
    ) {
        throw 'Unsafe scan coordinator configuration.'
    }

    # --------------------------------------------------------
    # Validate local state collections
    # --------------------------------------------------------

    if (
        $Context.ActiveScanByDevice -isnot [System.Collections.IDictionary] -or
        $Context.PublicScans -isnot [System.Collections.IDictionary]
    ) {
        throw 'CLI scan state is not initialized.'
    }

    # --------------------------------------------------------
    # Execute authorized local scan
    # --------------------------------------------------------

    # ScanCoordinator validates the target again.
    # The coordinator calls AuditEngine with SkipScoring.
    #
    # PersistEvidence is intentionally NOT supplied.

    $scopeArguments = @{}
    if ($scope.ScopeType -cne 'DEVICE') {
        $scopeArguments = @{ScopeType=$scope.ScopeType;ScopeKey=$scope.ScopeKey}
    }
    $publicResult = Invoke-WinSecCoordinatedScan @scopeArguments `
        -Coordinator $coordinator `
        -DeviceId $deviceId `
        -ConfirmAction {
            param($Request)
            $before = Get-WinSecCLIScanScope -State $State
            if ((Get-WinSecCLIScanDeviceId -State $State -Devices @($Context.Devices)) -cne $deviceId -or $before.ScopeType -cne $scope.ScopeType -or
                $before.ScopeKey -cne $scope.ScopeKey) { throw 'Scan navigation changed before confirmation.' }
            $answer = Show-WinSecScanConfirmation -Request $Request
            $after = Get-WinSecCLIScanScope -State $State
            if ((Get-WinSecCLIScanDeviceId -State $State -Devices @($Context.Devices)) -cne $deviceId -or $after.ScopeType -cne $scope.ScopeType -or
                $after.ScopeKey -cne $scope.ScopeKey) { throw 'Scan navigation changed during confirmation.' }
            return $answer
        } `
        -ErrorAction Stop

    # --------------------------------------------------------
    # Validate public result
    # --------------------------------------------------------

    if ($null -eq $publicResult) {
        # Cancellation is not a completed scan and must not replace history.
        return $null
    }

    # Own the producer's data before reading metadata. Do not retain its
    # references or execute calculated input properties while validating.
    if ($null -eq (Get-Command 'Copy-WinSecResultData' `
        -CommandType Function -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot '../Core/ResultModel.ps1')
    }
    $publicResult = Copy-WinSecResultData -Value $publicResult
    if ($scope.ScopeType -cne 'DEVICE' -or $null -ne $publicResult.ScopeType -or $null -ne $publicResult.ScopeKey) {
        if ($publicResult.ScopeType -cne $scope.ScopeType -or $publicResult.ScopeKey -cne $scope.ScopeKey) {
            throw 'Scan result does not match the requested scope.'
        }
        $selectedIds = @($publicResult.ControlResults | Where-Object { $_.Status -cne 'NOT_SELECTED' } | ForEach-Object { $_.CheckId })
        Assert-WinSecResultScope -ScopeType $scope.ScopeType -ScopeKey $scope.ScopeKey `
            -ExpectedCheckIds $selectedIds -ControlResults $publicResult.ControlResults `
            -DerivedResults $publicResult.Findings -ExecutionStatus $publicResult.ExecutionStatus
    }
    $scanId = $publicResult.ScanId

    if (
        $scanId -isnot [string] -or
        [string]::IsNullOrWhiteSpace($scanId) -or
        $publicResult.PublicProjection -cne $true -or
        $publicResult.ContainsRawEvidence -cne $false -or
        $publicResult.DeviceId -cne $deviceId -or
        $publicResult.ScoringEligible -cne $false -or
        $null -ne $publicResult.OverallScore -or
        $publicResult.OverallStatus -cne 'NOT_SCORED'
    ) {
        throw 'Scan result failed public security validation.'
    }

    # Never accept raw evidence through this interface.

    if (
        $null -ne $publicResult.PSObject.Properties['Evidence'] -or
        $null -ne $publicResult.PSObject.Properties['RawEvidence']
    ) {
        throw 'Raw evidence detected in public result.'
    }

    # --------------------------------------------------------
    # Publish only after successful validation
    # --------------------------------------------------------

    # Include both identifiers to prevent scan collisions
    # between different devices or executions.

    $sessionKey = '{0}:{1}{2}:{3}' -f `
        $deviceId.Length,
        $deviceId,
        $scanId.Length,
        $scanId

    # Apply the same nested identity/privacy guards as a public read, using
    # temporary maps so a rejection cannot replace the active assessment.
    $null = Get-WinSecCLIActiveAssessment `
        -State ([pscustomobject]@{ SelectedDeviceId = $deviceId }) `
        -Context ([pscustomobject]@{
            ActiveScanByDevice = @{ $deviceId = $scanId }
            PublicScans = @{ $sessionKey = $publicResult }
        })

    if ($Context.PublicScans.Contains($sessionKey)) {
        throw 'A public scan session with this identity already exists.'
    }

    # Prepare the caller's independent response before changing any CLI maps.
    # Copy failure must not leave an assessment partially published.
    $response = Copy-WinSecResultData -Value $publicResult
    $publicationScopeKey = $null
    if ($scope.ScopeType -cne 'DEVICE') { $publicationScopeKey = Get-WinSecCLIScopeKey $deviceId $scope.ScopeType $scope.ScopeKey }
    $Context.PublicScans[$sessionKey] = $publicResult

    if ($scope.ScopeType -ceq 'DEVICE') {
        $Context.ActiveScanByDevice[$deviceId] = $scanId
    }
    else {
        $scopeMap[$publicationScopeKey] = $scanId
        $Context | Add-Member -NotePropertyName ActiveScanByScope -NotePropertyValue $scopeMap -Force
    }

    # --------------------------------------------------------
    # Update display-only message
    # --------------------------------------------------------

    if (
        $publicResult.ExecutionStatus -ceq
            'NO_EXECUTABLE_CHECKS'
    ) {
        $Context.LastScanMessage = (
            'Scan completed: no executable checks. ' +
            'Security score: NOT_SCORED.'
        )
    }
    else {
        $Context.LastScanMessage = (
            'Scan completed. Security score: NOT_SCORED.'
        )
        if ($scope.ScopeType -cne 'DEVICE') {
            $Context.LastScanMessage = '{0} scan completed. Security score: NOT_SCORED.' -f $scope.Label
        }
    }

    # Return only an owned copy of the validated public projection.
    if ($State.Screen -ceq 'Devices') {
        $Context | Add-Member -NotePropertyName LastDeviceMessage -NotePropertyValue $Context.LastScanMessage -Force
    }

    return $response
}

function Get-WinSecCLIDeviceRemovalViewStamp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$State, [Parameter(Mandatory)][psobject]$Context)
    $public=@(foreach ($pair in @($Context.PublicScans.GetEnumerator() | Sort-Object Key)) {
        $key=$pair.Key; $scan=$pair.Value
        if ($scan.DeviceId -isnot [string] -or $scan.ScanId -isnot [string]) { throw 'Invalid public session metadata.' }
        [pscustomobject]@{Key=[string]$key; DeviceId=$scan.DeviceId; ScanId=$scan.ScanId}
    })
    $active=@(foreach ($pair in @($Context.ActiveScanByDevice.GetEnumerator() | Sort-Object Key)) {
        if ($pair.Value -isnot [string]) { throw 'Invalid active session metadata.' }
        [pscustomobject]@{DeviceId=[string]$pair.Key; ScanId=$pair.Value}
    })
    $scopeMap = Get-WinSecCLIValue $Context 'ActiveScanByScope'
    if ($null -ne $scopeMap -and $scopeMap -isnot [hashtable]) { throw 'Invalid scope selection map.' }
    $scoped=@(if ($null -ne $scopeMap) { foreach ($pair in @($scopeMap.GetEnumerator() | Sort-Object Key)) {
        if ($pair.Key -isnot [string] -or $pair.Value -isnot [string]) { throw 'Invalid scoped session metadata.' }
        [pscustomobject]@{Key=$pair.Key;ScanId=$pair.Value}
    } })
    return (ConvertTo-Json -InputObject ([pscustomobject]@{
        Screen=[string]$State.Screen; Index=[int]$State.DeviceIndex; Public=$public; Active=$active; Scoped=$scoped
        Devices=@($Context.Devices | ForEach-Object { [string]$_.DeviceId })
    }) -Depth 5 -Compress)
}

function Invoke-WinSecCLIDeviceRemoval {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$State, [Parameter(Mandatory)][psobject]$Context)
    if ($State.Screen -cne 'Devices' -or $Context.PublicScans -isnot [hashtable] -or
        $Context.ActiveScanByDevice -isnot [hashtable]) { throw 'Invalid device management context.' }
    $devices = @($Context.Devices)
    $index = [int]$State.DeviceIndex
    if ($index -lt 0 -or $index -ge $devices.Count) { throw 'Select a device to remove.' }
    $deviceId = [string]$devices[$index].DeviceId
    $publicKeys = @(
        foreach ($pair in $Context.PublicScans.GetEnumerator()) {
            $key=$pair.Key; $scan = $pair.Value
            if ($scan.DeviceId -isnot [string] -or $scan.ScanId -isnot [string] -or
                $key -cne (Get-WinSecScanSessionKey -DeviceId $scan.DeviceId -ScanId $scan.ScanId)) {
                throw 'Inconsistent public scan ownership.'
            }
            if ([string]::Equals($scan.DeviceId,$deviceId,[StringComparison]::OrdinalIgnoreCase)) { $key }
        }
    )
    $remainingRecords = @{}
    foreach ($field in @('SectionResults','ControlResults','Findings')) {
        $remainingRecords[$field] = @(
            foreach ($record in @(Get-WinSecCLIValue -InputObject $Context -Name $field)) {
                if ($null -eq $record) { continue }
                $owner = Get-WinSecCLIValue -InputObject $record -Name 'DeviceId'
                if ($owner -isnot [string] -or [string]::IsNullOrWhiteSpace($owner)) {
                    if ($devices.Count -eq 1) { continue }
                    throw 'Cannot associate legacy records with one device.'
                }
                if (-not [string]::Equals($owner,$deviceId,[StringComparison]::OrdinalIgnoreCase)) { $record }
            }
        )
    }
    $viewStamp = Get-WinSecCLIDeviceRemovalViewStamp -State $State -Context $Context
    $result = Remove-WinSecManagedDevice -ProjectRoot $Context.ProjectRoot -DeviceId $deviceId `
        -Coordinator $Context.ScanCoordinator -Devices $devices -ConfirmAction {
            param($Request)
            $response = @(Show-WinSecDeviceRemovalConfirmation -Request $Request)
            if ((Get-WinSecCLIDeviceRemovalViewStamp -State $State -Context $Context) -cne $viewStamp) {
                throw 'Device view changed during confirmation.'
            }
            return $response
        }
    if ($null -eq $result) { return $null }
    if ($result.Status -cnotin @('REMOVED','INCOMPLETE') -or $result.DeviceId -isnot [string] -or
        -not [string]::Equals($result.DeviceId,$deviceId,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Invalid device removal result.'
    }
    foreach ($key in $publicKeys) { $Context.PublicScans.Remove($key) }
    foreach ($key in @($Context.ActiveScanByDevice.GetEnumerator() | ForEach-Object { $_.Key })) {
        if ([string]::Equals([string]$key,$deviceId,[StringComparison]::OrdinalIgnoreCase)) { $Context.ActiveScanByDevice.Remove($key) }
    }
    $scopeMap = Get-WinSecCLIValue $Context 'ActiveScanByScope'
    if ($null -ne $scopeMap) {
        $prefix = '{0}:{1}' -f $deviceId.Length,$deviceId
        foreach ($key in @($scopeMap.Keys)) {
            if ($key.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { $scopeMap.Remove($key) }
        }
    }
    foreach ($field in $remainingRecords.Keys) { $Context.$field = @($remainingRecords[$field]) }
    $hasOtherLegacyRecords = $false
    foreach ($field in $remainingRecords.Keys) { if ($remainingRecords[$field].Count -gt 0) { $hasOtherLegacyRecords = $true } }
    if (-not $hasOtherLegacyRecords) { $Context.ScanId = '' }
    if ($result.Status -ceq 'REMOVED') {
        $Context.Devices = @($devices | Where-Object { -not [string]::Equals($_.DeviceId,$deviceId,[StringComparison]::OrdinalIgnoreCase) })
        $Context.LastDeviceMessage = 'Device and its application-owned history were deleted.'
    }
    else {
        $Context.LastDeviceMessage = 'Deletion is incomplete. Some history may already be deleted. Resolve the storage error and confirm a retry.'
    }
    $State.Screen = 'Devices'
    $State.SelectedDeviceId = $null; $State.SelectedDeviceName = $null
    $State.DeviceIndex = [Math]::Max(0,[Math]::Min($index,@($Context.Devices).Count-1))
    $State.SectionIndex = 0; $State.ControlIndex = 0; $State.FindingsOffset = 0
    $State.History.Clear()
    return $result
}

function Invoke-WinSecCLI {
    [CmdletBinding()]
    param(
        [Alias('ProjectPath', 'RootPath')]
        [string]$ProjectRoot = (
            [System.IO.Path]::GetFullPath(
                (Join-Path $PSScriptRoot '..\..')
            )
        ),

        [AllowEmptyCollection()]
        [object[]]$Devices = @(),

        [AllowEmptyCollection()]
        [object[]]$SectionResults = @(),

        [AllowEmptyCollection()]
        [object[]]$ControlResults = @(),

        [AllowEmptyCollection()]
        [object[]]$Findings = @(),

        [string]$ScanId = '',

        [string]$Version = '0.9.0'
    )

    $ProjectRoot = [System.IO.Path]::GetFullPath(
        $ProjectRoot
    )

    # --------------------------------------------------------
    # Load UI components and controllers
    # --------------------------------------------------------

    $modules = @(
        'src/UI/Core/TerminalRenderer.ps1'
        'src/UI/Components/Banner.ps1'
        'src/UI/Components/Table.ps1'
        'src/UI/Components/KeyboardHelp.ps1'
        'src/UI/Core/LayoutManager.ps1'
        'src/UI/Core/KeyboardController.ps1'
        'src/UI/Core/NavigationController.ps1'
        'src/UI/Core/ResizeHandler.ps1'
        'src/UI/Screens/MainMenu.ps1'
        'src/UI/Screens/Results.ps1'
        'src/UI/Screens/Devices.ps1'
        'src/UI/Screens/Findings.ps1'
        'src/UI/Screens/ScanConfirmation.ps1'
        'src/UI/Screens/DeviceRemovalConfirmation.ps1'
        'src/Services/DeviceManagementService.ps1'
        'src/Services/ReportService.ps1'
        'src/Services/ExportService.ps1'
    )

    foreach ($module in $modules) {
        $path = Join-Path `
            -Path $ProjectRoot `
            -ChildPath $module

        if (-not (
            Test-Path -LiteralPath $path -PathType Leaf
        )) {
            throw "Required module not found: $path"
        }

        . $path
    }

    # --------------------------------------------------------
    # Validate required functions
    # --------------------------------------------------------

    $requiredCommands = @(
        'Get-WinSecTerminalSize'
        'Get-WinSecLayout'
        'New-WinSecNavigationState'
        'Invoke-WinSecNavigationAction'
        'New-WinSecResizeState'
        'Read-WinSecResizeAwareKey'
        'Get-WinSecKeyboardAction'
        'ConvertTo-WinSecKeyboardAction'
        'Show-WinSecDevices'
        'Show-WinSecMainMenu'
        'Show-WinSecResults'
        'Show-WinSecFindings'
        'Show-WinSecScanConfirmation'
        'Show-WinSecDeviceRemovalConfirmation'
        'Remove-WinSecManagedDevice'
    )

    foreach ($commandName in $requiredCommands) {
        $command = Get-Command `
            -Name $commandName `
            -CommandType Function `
            -ErrorAction SilentlyContinue

        if ($null -eq $command) {
            throw (
                "Required function unavailable: $commandName"
            )
        }
    }

    # ========================================================
    # WinSec Analyzer v0.9.0
    # ScanCoordinator Initialization
    # ========================================================

    $coordinatorPath = Join-Path `
        -Path $ProjectRoot `
        -ChildPath 'src/Core/ScanCoordinator.ps1'

    if (-not (
        Test-Path -LiteralPath $coordinatorPath -PathType Leaf
    )) {
        throw "ScanCoordinator not found: $coordinatorPath"
    }

    # Load ScanCoordinator into the CLI execution scope.
    # Its functions remain available during this session.

    . $coordinatorPath

    $requiredCoordinatorCommands = @(
        'New-WinSecScanCoordinator'
        'Invoke-WinSecCoordinatedScan'
        'Get-WinSecCoordinatorHistory'
        'Get-WinSecCoordinatorPublicResult'
    )

    foreach ($commandName in $requiredCoordinatorCommands) {
        if (-not (
            Get-Command `
                -Name $commandName `
                -CommandType Function `
                -ErrorAction SilentlyContinue
        )) {
            throw "Required coordinator function unavailable: $commandName"
        }
    }

    # Create an independent coordinator for this CLI session.

    $scanCoordinator = New-WinSecScanCoordinator `
        -ProjectRoot $ProjectRoot

    if ($null -eq $scanCoordinator) {
        throw 'ScanCoordinator initialization returned null.'
    }

    # Production security invariants.

    if (
        $scanCoordinator.ScoringEnabled -ne $false -or
        $scanCoordinator.RemoteExecution -ne $false -or
        $scanCoordinator.AutomaticEvidencePersistence -ne $false
    ) {
        throw 'Unsafe ScanCoordinator configuration detected.'
    }

    # No audit is executed during initialization.

    # --------------------------------------------------------
    # Load device registry
    # --------------------------------------------------------

    
    # ========================================================
    # WinSec Analyzer v0.9.0
    # Persistent Device Inventory Initialization
    # ========================================================

    # --------------------------------------------------------
    # Load configured devices using the existing validated
    # TargetRegistry implementation.
    # --------------------------------------------------------

    $registeredDevices = @(
        Get-WinSecCLIDevices `
            -ProjectRoot $ProjectRoot `
            -Devices $Devices
    )

    # --------------------------------------------------------
    # Detect explicit device input
    # --------------------------------------------------------

    $explicitDevices = @(
        $Devices | Where-Object {
            $null -ne $_
        }
    )

    # Automatic local registration is performed only during
    # normal application startup, without explicit devices.

    if ($explicitDevices.Count -eq 0) {

        # ----------------------------------------------------
        # Load DeviceInventory dependency
        # ----------------------------------------------------

        $inventoryModulePath = Join-Path `
            -Path $ProjectRoot `
            -ChildPath 'src/Core/DeviceInventory.ps1'

        if (-not (
            Test-Path `
                -LiteralPath $inventoryModulePath `
                -PathType Leaf
        )) {
            throw (
                'DeviceInventory module not found: {0}' -f
                $inventoryModulePath
            )
        }

        . $inventoryModulePath

        # ----------------------------------------------------
        # Register or recognize the current local device
        # ----------------------------------------------------

        # This operation saves device identity only.
        # It does not start scans, collect evidence or score.

        $registration = Register-WinSecLocalDevice `
            -ProjectRoot $ProjectRoot `
            -ErrorAction Stop

        if (
            $null -eq $registration -or
            $registration.Status -cnotin @(
                'REGISTERED',
                'ALREADY_REGISTERED'
            )
        ) {
            throw 'Local device registration failed.'
        }

        # ----------------------------------------------------
        # Import validated persistent inventory
        # ----------------------------------------------------

        $savedInventory = Import-WinSecDeviceInventory `
            -ProjectRoot $ProjectRoot `
            -ErrorAction Stop

        # ----------------------------------------------------
        # Preserve explicitly configured devices
        # ----------------------------------------------------

        $mergedDevices = New-Object `
            'System.Collections.Generic.List[object]'

        foreach ($device in $registeredDevices) {

            if ($null -eq $device) {
                continue
            }

            # The temporary fallback is replaced with
            # the actual persistent device registration.

            if ($device.Source -ceq 'LOCAL_FALLBACK') {
                continue
            }

            $mergedDevices.Add($device)
        }

        # ----------------------------------------------------
        # Merge saved devices without duplicates
        # ----------------------------------------------------

        foreach ($savedDevice in $savedInventory.targets) {

            if ($null -eq $savedDevice) {
                continue
            }

            $savedDeviceId = [string]$savedDevice.DeviceId

            $alreadyPresent = $false

            foreach ($existingDevice in $mergedDevices) {

                if (
                    [string]::Equals(
                        [string]$existingDevice.DeviceId,
                        $savedDeviceId,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )
                ) {
                    $alreadyPresent = $true
                    break
                }
            }

            # A device explicitly configured in targets.json
            # takes precedence over a saved inventory entry.
            # This preserves configured Enabled and Mode.

            if (-not $alreadyPresent) {
                $mergedDevices.Add($savedDevice)
            }
        }

        # ----------------------------------------------------
        # Normalize the combined inventory
        # ----------------------------------------------------

        # Reuse the existing TargetRegistry validation.
        # This rejects malformed identities and duplicates.

        $registeredDevices = @(
            Get-WinSecCLIDevices `
                -ProjectRoot $ProjectRoot `
                -Devices $mergedDevices.ToArray()
        )

        # ----------------------------------------------------
        # Verify that the current device is represented
        # ----------------------------------------------------

        $localMatches = @(
            $registeredDevices | Where-Object {
                [string]::Equals($_.DeviceId, $registration.DeviceId, [System.StringComparison]::OrdinalIgnoreCase)
            }
        )

        if ($localMatches.Count -ne 1) {
            throw (
                'Persistent local device could not be ' +
                'resolved in the CLI inventory.'
            )
        }
        # A saved disablement also blocks the backend, including direct calls.
        # Configured permissions remain authoritative; inventory cannot grant any.
        $scanCoordinator.RequireDeviceInventory = $true
    }

    # --------------------------------------------------------
    # Device inventory initialization completed
    # Continue with the existing navigation initialization.
    # --------------------------------------------------------


    # --------------------------------------------------------
    # Initialize navigation and resize state
    # --------------------------------------------------------

    # Saved removals also hide explicit catalog entries, without editing permissions.
    $inventoryForDisplay = Import-WinSecDeviceInventory -ProjectRoot $ProjectRoot
    $registeredDevices = @($registeredDevices | Where-Object {
        -not (Test-WinSecDeviceInventoryRemoval -Inventory $inventoryForDisplay -DeviceId $_.DeviceId)
    })
    $navigationState = New-WinSecNavigationState
    $resizeState = New-WinSecResizeState

    # --------------------------------------------------------
    # Initialize assessment context
    # --------------------------------------------------------

    $context = [PSCustomObject]@{
        ProjectRoot    = $ProjectRoot
        Version        = $Version
        Devices        = $registeredDevices
        SectionResults = @($SectionResults)
        ControlResults = @($ControlResults)
        Findings       = @($Findings)
        ScanId         = $ScanId
        ScanCoordinator = $scanCoordinator
        ActiveScanByDevice = @{}
        ActiveScanByScope = @{}
        PublicScans = @{}
        LastScanMessage = ''
        LastDeviceMessage = ''
    }

    # --------------------------------------------------------
    # Define reusable screen renderer
    # --------------------------------------------------------

    $renderAction = {
        param($CurrentState)

        Show-WinSecCLICurrentScreen `
            -State $CurrentState `
            -Context $context
            
    }

    # --------------------------------------------------------
    # Render initial device selection screen
    # --------------------------------------------------------

    $null = & $renderAction $navigationState

    # --------------------------------------------------------
    # Interactive application loop
    # --------------------------------------------------------

    while (-not $navigationState.ExitRequested) {

        # ----------------------------------------------------
        # Read keyboard input with resize monitoring
        # ----------------------------------------------------

        $keyInfo = Read-WinSecResizeAwareKey `
            -ResizeState $resizeState `
            -RenderAction $renderAction `
            -NavigationState $navigationState

        # ----------------------------------------------------
        # Get action from centralized KeyboardController
        # ----------------------------------------------------

        # ====================================================
        # LOCAL RESCAN AUTHORIZATION
        # ====================================================

        # Validate whether the selected device is authorized
        # to request a local security scan.

        $enableLocalRescan = Test-WinSecCLIRescanEligibility `
            -State $navigationState `
            -Devices $registeredDevices `
            -Coordinator $scanCoordinator

        # ----------------------------------------------------
        # Read centralized keyboard action
        # ----------------------------------------------------

        $keyboardEvent = Get-WinSecKeyboardAction `
            -KeyInfo $keyInfo `
            -Screen $navigationState.Screen `
            -EnableRescan:$enableLocalRescan `
            -EnableExport:(Test-WinSecCLIFindingsExportEligibility -State $navigationState -Context $context)

        # Disabled or unsupported key

        if ($keyboardEvent.Action -eq 'None') {
            continue
        }

        # ----------------------------------------------------
        # Determine navigation boundaries
        # ----------------------------------------------------

        $counts = Get-WinSecCLINavigationCounts `
            -State $navigationState `
            -Context $context

        # ----------------------------------------------------
        # Apply navigation action
        # ----------------------------------------------------

        if ($keyboardEvent.Action -cne 'ExportMD' -and $null -ne $context.PSObject.Properties['LastExportMessage']) {
            $context.LastExportMessage = ''
        }

        $null = Invoke-WinSecNavigationAction `
            -State $navigationState `
            -Action $keyboardEvent.Action `
            -Devices $registeredDevices `
            -SectionCount $counts.SectionCount `
            -ControlCount $counts.ControlCount `
            -FindingCount $counts.FindingCount `
            -SettingsCount $counts.SettingsCount

        # ----------------------------------------------------
        # Handle application lifecycle
        # ----------------------------------------------------

        if ($navigationState.ExitRequested) {
            break
        }

        # ----------------------------------------------------
        # Process device selection
        # ----------------------------------------------------

        if ($navigationState.PendingCommand -eq 'SelectDevice') {

            # The active device is already stored in
            # NavigationState.SelectedDeviceId.
            #
            # Assessment data is filtered dynamically.

            $navigationState.PendingCommand = $null
            $navigationState.PendingScope = $null
        }

        if ($navigationState.PendingCommand -eq 'DeleteDevice') {
            try {
                $null = Invoke-WinSecCLIDeviceRemoval -State $navigationState -Context $context -ErrorAction Stop
                $registeredDevices = @($context.Devices)
            }
            catch { $context.LastDeviceMessage = 'Device deletion failed or was rejected. No successful deletion was confirmed.' }
            finally { $navigationState.PendingCommand = $null; $navigationState.PendingScope = $null }
        }

        # ====================================================
        # PROCESS LOCAL RESCAN COMMAND
        # WinSec Analyzer v0.9.0
        # ====================================================

        if ($navigationState.PendingCommand -eq 'Rescan') {

            try {
                # --------------------------------------------
                # Execute authorized local scan
                # --------------------------------------------

                # Invoke-WinSecCLILocalRescan performs:
                #
                # - Local target authorization
                # - Coordinator safety validation
                # - Real scan execution
                # - Public result validation
                # - Session registration
                # - DeviceId / ScanId association
                #
                # No evidence persistence is requested.
                # No scoring or remote execution is enabled.

                $null = Invoke-WinSecCLILocalRescan `
                    -State $navigationState `
                    -Context $context `
                    -ErrorAction Stop

                # --------------------------------------------
                # Result handling
                # --------------------------------------------

                # The scan function already updates:
                #
                # $context.PublicScans
                # $context.ActiveScanByDevice
                # $context.LastScanMessage
                #
                # No additional mutation is required here.
            }
            catch {
                # --------------------------------------------
                # Safe error handling
                # --------------------------------------------

                # Never display raw collector evidence,
                # internal exception details or sensitive
                # device information through the CLI.

                $context.LastScanMessage = (
                    'Local scan failed or was rejected. ' +
                    'No new result was published to the CLI.'
                )
            }
            finally {
                # --------------------------------------------
                # Reset pending command
                # --------------------------------------------

                # Prevent accidental repeated execution
                # when the terminal redraws or resizes.

                $navigationState.PendingCommand = $null
                $navigationState.PendingScope = $null
            }
        }

        if ($navigationState.PendingCommand -eq 'ExportMD') {
            try { $null=Invoke-WinSecCLIFindingsExport -State $navigationState -Context $context -ErrorAction Stop }
            catch { $context | Add-Member -NotePropertyName LastExportMessage -NotePropertyValue 'Export failed or was rejected.' -Force }
            finally { $navigationState.PendingCommand=$null; $navigationState.PendingScope=$null }
        }

        # ====================================================
        # KEEP UNSUPPORTED OPERATIONS DISABLED
        # ====================================================

        if (
            $navigationState.PendingCommand -in @(
                'ExportTXT',
                'SelectSetting'
            )
        ) {
            # Export and settings editing remain disabled
            # until their implementations are connected.

            $navigationState.PendingCommand = $null
            $navigationState.PendingScope = $null
        }


        # ----------------------------------------------------
        # Redraw using the existing navigation state
        # ----------------------------------------------------

        if ($keyboardEvent.RequiresRedraw) {
            $null = & $renderAction $navigationState
        }
    }

    # --------------------------------------------------------
    # Close interactive session
    # --------------------------------------------------------

    Clear-WinSecScreen

    Write-WinSecText `
        -Text 'WinSec Analyzer session closed.' `
        -Color DarkGray
}
