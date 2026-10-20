
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
    # device without modifying legacy assessment handling.
    # ========================================================

    $activeScanMap = Get-WinSecCLIValue `
        -InputObject $Context `
        -Name 'ActiveScanByDevice'

    $publicScanMap = Get-WinSecCLIValue `
        -InputObject $Context `
        -Name 'PublicScans'

    if (
        $activeScanMap -is [System.Collections.IDictionary] -and
        $activeScanMap.Contains($deviceId)
    ) {
        $activeScanId = [string]$activeScanMap[$deviceId]

        if ([string]::IsNullOrWhiteSpace($activeScanId)) {
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

        # ----------------------------------------------------
        # Validate the public result before rendering
        # ----------------------------------------------------

        if (
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

        if (
            $null -ne
                $publicResult.PSObject.Properties['Evidence'] -or
            $null -ne
                $publicResult.PSObject.Properties['RawEvidence']
        ) {
            throw 'Raw evidence is not allowed in CLI results.'
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
        # Reject scored or raw nested records
        # ----------------------------------------------------

        foreach ($record in @(
            $publicSections + $publicControls + $publicFindings
        )) {
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
        Show-WinSecDevices `
            -NavigationState $State `
            -Devices $Context.Devices `
            -Version $Context.Version

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
            # Resolve ScanCoordinator and registered devices
            # -----------------------------------------------

            $coordinator = Get-WinSecCLIValue `
                -InputObject $Context `
                -Name 'ScanCoordinator'

            $registeredDevices = @(
                Get-WinSecCLIValue `
                    -InputObject $Context `
                    -Name 'Devices'
            )

            # -----------------------------------------------
            # Validate local scan authorization
            # -----------------------------------------------

            $enableRescan = Test-WinSecCLIRescanEligibility `
                -State $State `
                -Devices $registeredDevices `
                -Coordinator $coordinator

            # -----------------------------------------------
            # Render existing main menu
            # -----------------------------------------------

            Show-WinSecMainMenu `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -OverallScore $assessment.OverallScore `
                -OverallStatus $assessment.OverallStatus `
                -Version $Context.Version `
                -EnableRescan:$enableRescan

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
            Show-WinSecResults `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -ControlResults $assessment.ControlResults `
                -Version $Context.Version
        }

        'Results' {
            Show-WinSecResults `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -ControlResults $assessment.ControlResults `
                -Version $Context.Version
        }

        'Findings' {
            Show-WinSecFindings `
                -NavigationState $State `
                -SectionResults $assessment.SectionResults `
                -ControlResults $assessment.ControlResults `
                -Findings $assessment.Findings `
                -ScanId $assessment.ScanId `
                -Version $Context.Version
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

    if ($null -ne $section) {
        $selectedControl = $null

        if (
            $State.FindingsScope -eq 'Control' -and
            $controls.Count -gt 0
        ) {
            $controlIndex = [Math]::Max(
                0,
                [Math]::Min(
                    [int]$State.ControlIndex,
                    $controls.Count - 1
                )
            )

            $selectedControl = $controls[$controlIndex]
        }

        foreach ($finding in $assessment.Findings) {
            $findingSection = [string](
                Get-WinSecCLIValue `
                    -InputObject $finding `
                    -Name 'SectionKey'
            )

            if ($findingSection -ne $section.Key) {
                continue
            }

            if ($null -ne $selectedControl) {
                $findingControl = [string](
                    Get-WinSecCLIValue `
                        -InputObject $finding `
                        -Name 'ControlKey'
                )

                $findingCheck = [string](
                    Get-WinSecCLIValue `
                        -InputObject $finding `
                        -Name 'CheckId'
                )

                $controlMatch = (
                    $findingControl -eq $selectedControl.Key -or
                    (
                        $selectedControl.CheckId -and
                        $findingCheck -eq $selectedControl.CheckId
                    )
                )

                if (-not $controlMatch) {
                    continue
                }
            }

            $findingCount++
        }
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
    # Require a coordinator and the main menu
    # --------------------------------------------------------

    if ($null -eq $Coordinator) {
        return $false
    }

    if ($State.Screen -cne 'MainMenu') {
        return $false
    }

    $selectedId = [string]$State.SelectedDeviceId

    if ([string]::IsNullOrWhiteSpace($selectedId)) {
        return $false
    }

    # --------------------------------------------------------
    # Confirm this computer is the selected target
    # --------------------------------------------------------

    try {
        $localTarget = New-WinSecLocalTarget

        if ($null -eq $localTarget) {
            return $false
        }

        if ($selectedId -cne [string]$localTarget.DeviceId) {
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
    $deviceId = [string]$State.SelectedDeviceId

    if ([string]::IsNullOrWhiteSpace($deviceId)) {
        return $empty
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

    $publicResult = Invoke-WinSecCoordinatedScan `
        -Coordinator $coordinator `
        -DeviceId $deviceId `
        -ErrorAction Stop

    # --------------------------------------------------------
    # Validate public result
    # --------------------------------------------------------

    if ($null -eq $publicResult) {
        throw 'Scan returned no public result.'
    }

    $scanId = [string]$publicResult.ScanId

    if (
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

    $Context.PublicScans[$sessionKey] = $publicResult

    $Context.ActiveScanByDevice[$deviceId] = $scanId

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
    }

    # Return only the validated public projection.

    return $publicResult
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
                $_.DeviceId -ceq $registration.DeviceId
            }
        )

        if ($localMatches.Count -ne 1) {
            throw (
                'Persistent local device could not be ' +
                'resolved in the CLI inventory.'
            )
        }
    }

    # --------------------------------------------------------
    # Device inventory initialization completed
    # Continue with the existing navigation initialization.
    # --------------------------------------------------------


    # --------------------------------------------------------
    # Initialize navigation and resize state
    # --------------------------------------------------------

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
        PublicScans = @{}
        LastScanMessage = ''
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
            -EnableRescan:$enableLocalRescan

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
