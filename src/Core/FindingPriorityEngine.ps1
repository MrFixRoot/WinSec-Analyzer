
# ============================================================
# WinSec Analyzer
# Component : FindingPriorityEngine
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Classifies and prioritizes security findings.
# Supports device-specific assessment results.
#
# Does not modify security configurations.
# Does not calculate the overall security score.
# ============================================================


# ------------------------------------------------------------
# Read finding property
# ------------------------------------------------------------

function Get-WinSecPriorityField {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Finding,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Finding) {
        return $null
    }

    if ($Finding -is [System.Collections.IDictionary]) {

        if ($Finding.Contains($Name)) {
            return $Finding[$Name]
        }

        return $null
    }

    $property = $Finding.PSObject.Properties[$Name]

    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}


# ------------------------------------------------------------
# Normalize finding severity
# ------------------------------------------------------------

function ConvertTo-WinSecSeverity {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Severity
    )

    if ([string]::IsNullOrWhiteSpace($Severity)) {
        return 'UNRATED'
    }

    switch ($Severity.Trim().ToUpperInvariant()) {

        'CRITICAL'      { return 'CRITICAL' }
        'HIGH'          { return 'HIGH' }
        'MEDIUM'        { return 'MEDIUM' }
        'MODERATE'      { return 'MEDIUM' }
        'LOW'           { return 'LOW' }
        'INFO'          { return 'INFO' }
        'INFORMATIONAL' { return 'INFO' }

        default         { return 'UNRATED' }
    }
}


# ------------------------------------------------------------
# Determine finding priority
# ------------------------------------------------------------

function Get-WinSecFindingPriority {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Finding
    )

    $rawSeverity = Get-WinSecPriorityField `
        -Finding $Finding -Name 'Severity'

    $rawPriority = Get-WinSecPriorityField `
        -Finding $Finding -Name 'Priority'

    $severity = ConvertTo-WinSecSeverity `
        -Severity ([string]$rawSeverity)

    $priority = 'UNRATED'
    $rank = 99
    $source = 'Unknown'
    $reason = 'No valid severity or priority provided.'

    # --------------------------------------------------------
    # Respect explicitly assigned priorities
    # --------------------------------------------------------

    $explicitPriority = (
        [string]$rawPriority
    ).Trim().ToUpperInvariant()

    if ($explicitPriority -in @(
        'P1', 'P2', 'P3', 'P4', 'P5'
    )) {

        $priority = $explicitPriority
        $rank = [int]$priority.Substring(1)
        $source = 'Explicit'
        $reason = 'Priority explicitly assigned by assessment.'

    }
    else {

        # ----------------------------------------------------
        # Derive priority from declared severity
        # ----------------------------------------------------

        switch ($severity) {

            'CRITICAL' {
                $priority = 'P1'
                $rank = 1
            }

            'HIGH' {
                $priority = 'P2'
                $rank = 2
            }

            'MEDIUM' {
                $priority = 'P3'
                $rank = 3
            }

            'LOW' {
                $priority = 'P4'
                $rank = 4
            }

            'INFO' {
                $priority = 'P5'
                $rank = 5
            }
        }

        if ($rank -ne 99) {
            $source = 'Severity'
            $reason = "Derived from severity: $severity"
        }
    }

    return [PSCustomObject]@{
        Priority = $priority
        Rank     = $rank
        Severity = $severity
        Source   = $source
        Reason   = $reason
    }
}


# ------------------------------------------------------------
# Get priority display color
# ------------------------------------------------------------

function Get-WinSecPriorityColor {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Priority
    )

    switch (
        ([string]$Priority).Trim().ToUpperInvariant()
    ) {

        'P1' { return 'DarkRed' }
        'P2' { return 'Red' }
        'P3' { return 'Yellow' }
        'P4' { return 'Cyan' }
        'P5' { return 'DarkGray' }

        default { return 'Gray' }
    }
}


# ------------------------------------------------------------
# Prioritize and sort security findings
# ------------------------------------------------------------

function Invoke-WinSecFindingPrioritization {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Findings = @(),

        [AllowNull()]
        [string]$DeviceId = $null,

        [AllowNull()]
        [string]$ScanId = $null
    )

    $items = [System.Collections.Generic.List[object]]::new()

    $index = 0

    foreach ($finding in $Findings) {

        if ($null -eq $finding) {
            continue
        }

        # ----------------------------------------------------
        # Optional device filtering
        # ----------------------------------------------------

        if (-not [string]::IsNullOrWhiteSpace($DeviceId)) {

            $findingDeviceId = Get-WinSecPriorityField `
                -Finding $finding -Name 'DeviceId'

            if ($findingDeviceId -ne $DeviceId) {
                continue
            }
        }

        # ----------------------------------------------------
        # Optional scan filtering
        # ----------------------------------------------------

        if (-not [string]::IsNullOrWhiteSpace($ScanId)) {

            $findingScanId = Get-WinSecPriorityField `
                -Finding $finding -Name 'ScanId'

            if ($findingScanId -ne $ScanId) {
                continue
            }
        }

        # ----------------------------------------------------
        # Resolve finding priority
        # ----------------------------------------------------

        $classification = Get-WinSecFindingPriority `
            -Finding $finding

        # Preserve all original finding properties
        $record = [ordered]@{}

        if ($finding -is [System.Collections.IDictionary]) {

            foreach ($key in $finding.Keys) {
                $record[[string]$key] = $finding[$key]
            }
        }
        else {

            foreach ($property in $finding.PSObject.Properties) {

                if (-not $property.IsGettable) {
                    continue
                }

                $record[$property.Name] = $property.Value
            }
        }

        # Add normalized priority metadata
        $record['Priority'] = $classification.Priority
        $record['PriorityRank'] = $classification.Rank
        $record['SeverityNormalized'] = $classification.Severity
        $record['PrioritySource'] = $classification.Source
        $record['PriorityReason'] = $classification.Reason

        # Preserve original order for equal priorities
        $items.Add(
            [PSCustomObject]@{
                Index   = $index
                Rank    = $classification.Rank
                Finding = [PSCustomObject]$record
            }
        )

        $index++
    }

    # --------------------------------------------------------
    # Sort findings from highest to lowest priority
    # --------------------------------------------------------

    $sorted = @(
        $items | Sort-Object `
            -Property Rank, Index
    )

    foreach ($item in $sorted) {
        $item.Finding
    }
}


# ------------------------------------------------------------
# Summarize findings by priority
# ------------------------------------------------------------

function Get-WinSecFindingPrioritySummary {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Findings = @()
    )

    $counts = @{
        P1      = 0
        P2      = 0
        P3      = 0
        P4      = 0
        P5      = 0
        UNRATED = 0
    }

    $total = 0

    foreach ($finding in $Findings) {

        if ($null -eq $finding) {
            continue
        }

        $classification = Get-WinSecFindingPriority `
            -Finding $finding

        $counts[$classification.Priority]++
        $total++
    }

    return [PSCustomObject]@{
        Total         = $total
        Critical      = $counts.P1
        High          = $counts.P2
        Medium        = $counts.P3
        Low           = $counts.P4
        Informational = $counts.P5
        Unrated       = $counts.UNRATED
    }
}
