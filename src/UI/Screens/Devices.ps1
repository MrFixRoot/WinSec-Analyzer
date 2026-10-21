
# ============================================================
# WinSec Analyzer
# Component : Devices
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Multi-device security assessment interface.
#
# Features:
# - Device selection
# - Explicit NOT_SCORED presentation
# - Inventory metadata separated from scan results
# - Adaptive terminal layout
# - Keyboard navigation
# - Automatic table resizing
# ============================================================


# ------------------------------------------------------------
# Normalize registered device information
# ------------------------------------------------------------

function Get-WinSecDeviceRows {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Devices = @(),
        [object[]]$History = @(),
        [switch]$HistoryLoaded
    )

    # Inventory is not a public scan result. Read only plain identification
    # fields, never assessment metadata or evidence (including their getters).
    # Validate the entire collection before publishing any display rows.
    if ($Devices.Count -gt 10000) { throw 'Too many registered devices.' }
    $displayFields = @('DeviceId','Hostname','Name','DisplayName','Mode')
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $rows = New-Object 'System.Collections.Generic.List[object]'

    foreach ($device in $Devices) {

        if ($null -eq $device) {
            continue
        }

        $fields = @{}
        if ($device -is [System.Collections.IDictionary]) {
            foreach ($key in $device.psbase.Keys) {
                if ($key -isnot [string]) { throw 'Invalid device property name.' }
                if ($key -notin $displayFields) { continue }
                if ($fields.ContainsKey($key)) { throw 'Ambiguous device property.' }
                $fields[$key] = $device[$key]
            }
        }
        elseif ($device -is [pscustomobject]) {
            foreach ($property in $device.PSObject.Properties) {
                if ($property.Name -notin $displayFields) { continue }
                if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty) {
                    throw 'Device display requires plain data properties.'
                }
                $fields[$property.Name] = $property.Value
            }
        }
        else { throw 'Unsupported registered device.' }

        $deviceId = $fields.DeviceId
        if ($deviceId -isnot [string] -or $deviceId.Length -gt 128 -or
            $deviceId -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._:-]*\z') {
            throw 'Invalid device identifier.'
        }
        if (-not $seen.Add($deviceId)) { throw 'Duplicate device identifier.' }

        foreach ($name in @('Hostname','Name')) {
            $value = $fields[$name]
            if ($null -ne $value -and ($value -isnot [string] -or $value.Length -gt 253 -or
                ($value -ne '' -and $value -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._:-]*\z'))) {
                throw 'Invalid device hostname.'
            }
        }
        $hostname = $fields.Hostname
        if ([string]::IsNullOrEmpty($hostname)) { $hostname = $fields.Name }
        if ([string]::IsNullOrEmpty($hostname)) { $hostname = $deviceId }
        $displayName=$fields.DisplayName
        if($null -ne $displayName -and ($displayName -isnot [string] -or $displayName.Length -gt 253 -or
            [string]::IsNullOrWhiteSpace($displayName) -or $displayName -cne $displayName.Trim() -or $displayName -match '[\p{C}\p{Zl}\p{Zp}]')){throw 'Invalid device display name.'}
        if($null -eq $displayName){$displayName=$hostname}

        $inferredMode = 'UNKNOWN'
        foreach ($prefix in @('LOCAL','REMOTE','IMPORTED')) {
            if ($deviceId.StartsWith($prefix + ':', [StringComparison]::OrdinalIgnoreCase)) {
                $inferredMode = $prefix
                break
            }
        }
        $mode = $inferredMode
        if ($null -ne $fields.Mode) {
            if ($fields.Mode -isnot [string]) { throw 'Invalid device mode.' }
            $mode = $fields.Mode.ToUpperInvariant()
            if ($mode -cnotin @('LOCAL','REMOTE','IMPORTED','UNKNOWN') -or
                ($inferredMode -cne 'UNKNOWN' -and $mode -cne $inferredMode)) {
                throw 'Invalid or conflicting device mode.'
            }
        }

        # These are inventory placeholders, never assertions about an audit.
        # Historical dates require verified sessions, not LastScan metadata.
        $rows.Add([PSCustomObject]@{
            Id       = '{0:D2}' -f ($rows.Count + 1)
            DeviceId = $deviceId
            Hostname = $hostname
            Device   = $displayName
            HardwareId = if($deviceId -cmatch '^local:(hw1-[a-f0-9]{64})$'){$Matches[1]}else{'Not recorded'}
            Mode     = $mode
            Score    = 'NOT_SCORED'
            Status   = 'PENDING'
            LastScan = 'Not loaded'
        })
    }
    if($HistoryLoaded){
        if($History.Count -gt 10000){throw 'Excessive device history.'}
        $safeHistory=@(foreach($entry in $History){Copy-WinSecResultData -Value $entry})
        $scanKeys=@{};$byDevice=@{}
        $exactIds=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach($row in $rows){$null=$exactIds.Add($row.DeviceId)}
        foreach($scan in $safeHistory){
            if($scan -isnot [pscustomobject] -or $scan.DeviceId -isnot [string] -or $scan.ScanId -isnot [string] -or
                -not $exactIds.Contains($scan.DeviceId) -or -not (Test-WinSecTargetIdentifier $scan.ScanId) -or
                $scan.ExecutionStatus -isnot [string] -or $scan.ExecutionStatus -cnotin @('COMPLETED','COMPLETED_WITH_ERRORS') -or $null -ne $scan.OverallScore -or
                $scan.OverallStatus -isnot [string] -or $scan.OverallStatus -cne 'NOT_SCORED'){throw 'Invalid device public history.'}
            Assert-WinSecResultScope $scan.ScopeType $scan.ScopeKey
            $key=Get-WinSecScanSessionKey $scan.DeviceId $scan.ScanId
            if($scanKeys.ContainsKey($key)){throw 'Duplicate device scan.'};$scanKeys[$key]=$true
            $null=ConvertTo-WinSecResultUtc -Value $scan.CompletedAtUTC -FieldName CompletedAtUTC
            if(-not $byDevice.ContainsKey($scan.DeviceId)){$byDevice[$scan.DeviceId]=New-Object 'System.Collections.Generic.List[object]'}
            $byDevice[$scan.DeviceId].Add($scan)
        }
        foreach($row in $rows){
            $matching=@($byDevice[$row.DeviceId]|Sort-Object CompletedAtUTC,ScanId)
            $row.LastScan='No saved scan'
            if($matching.Count){$last=$matching[-1];$date=ConvertTo-WinSecResultUtc -Value $last.CompletedAtUTC -FieldName CompletedAtUTC;
                $row.LastScan=($date.UtcDateTime.ToString('yyyy-MM-dd HH:mm')+'Z '+$last.ScopeType)}
            if(@($matching|Where-Object{$_.ScopeType -ceq 'DEVICE'}).Count){$row.Status='NOT_SCORED'}
        }
    }
    return $rows.ToArray()
}


# ------------------------------------------------------------
# Resolve selected device index
# ------------------------------------------------------------

function Get-WinSecSelectedDeviceIndex {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [int]$SelectedIndex = -1,

        [int]$DeviceCount = 0
    )

    if ($DeviceCount -le 0) {
        return -1
    }

    # Use navigation state when an index
    # has not been explicitly provided.

    if ($SelectedIndex -lt 0) {

        $SelectedIndex = 0

        if (
            $null -ne $NavigationState -and
            $null -ne $NavigationState.PSObject.Properties[
                'DeviceIndex'
            ]
        ) {
            $SelectedIndex = [int]$NavigationState.DeviceIndex
        }
    }

    # Keep selection inside valid boundaries
    return [Math]::Max(
        0,
        [Math]::Min(
            $SelectedIndex,
            $DeviceCount - 1
        )
    )
}


# ------------------------------------------------------------
# Render multi-device selection screen
# ------------------------------------------------------------

function Show-WinSecDevices {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [psobject]$NavigationState = $null,

        [AllowEmptyCollection()]
        [object[]]$Devices = @(),

        [int]$SelectedIndex = -1,

        [string]$Version = '0.9.0',

        [string]$Message = '',
        [object[]]$History = @(),
        [switch]$HistoryLoaded,
        [switch]$EnableRescan,
        [ValidateSet('Scan','Rescan')][string]$ScanAction='Scan'
    )

    # --------------------------------------------------------
    # Prepare device information
    # --------------------------------------------------------

    $rows = @(
        Get-WinSecDeviceRows -Devices $Devices -History $History -HistoryLoaded:$HistoryLoaded
    )

    $deviceCount = $rows.Count

    # --------------------------------------------------------
    # Resolve selected device
    # --------------------------------------------------------

    $SelectedIndex = Get-WinSecSelectedDeviceIndex `
        -NavigationState $NavigationState `
        -SelectedIndex $SelectedIndex `
        -DeviceCount $deviceCount

    $selectedDevice = $null

    if ($SelectedIndex -ge 0) {
        $selectedDevice = $rows[$SelectedIndex]
    }

    # --------------------------------------------------------
    # Determine available keyboard commands
    # --------------------------------------------------------

    $hiddenKeys = @()

    if ($deviceCount -eq 0) {

        $hiddenKeys = @(
            'UP/DOWN'
            'ENTER'
            'DEL/SUPR'
            'F2'
        )
    }

    # --------------------------------------------------------
    # Get adaptive terminal layout
    # --------------------------------------------------------

    $layout = Get-WinSecLayout `
        -Screen 'Devices' `
        -HiddenKeys $hiddenKeys

    Clear-WinSecScreen

    # --------------------------------------------------------
    # Validate terminal dimensions
    # --------------------------------------------------------

    if ($layout.IsTooSmall) {

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
            -Text "Minimum: $($layout.MinimumWidth) x $($layout.MinimumHeight)" `
            -Color DarkGray `
            -Align Center

        Write-Host ''

        Write-WinSecText `
            -Text 'Please resize the terminal.' `
            -Color DarkGray `
            -Align Center

        return
    }

    # --------------------------------------------------------
    # Render adaptive project banner
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
            -Text 'mrRoot | Multi-Device Assessment' `
            -Color DarkGray `
            -Align Center
    }

    # --------------------------------------------------------
    # Render screen heading
    # --------------------------------------------------------

    Write-WinSecSectionTitle `
        -Title 'Managed Devices'

    if (-not [string]::IsNullOrWhiteSpace($Message)) { Write-WinSecText -Text $Message -Color Yellow }

    Write-WinSecText `
        -Text "REGISTERED DEVICES: $deviceCount" `
        -Color Cyan

    if ($null -ne $selectedDevice) {

        $selectedText = 'SELECTED: {0} | MODE: {1}' -f `
            $selectedDevice.Device,
            $selectedDevice.Mode

        Write-WinSecText `
            -Text $selectedText `
            -Color Gray
    }
    else {

        Write-WinSecText `
            -Text 'SELECTED: NONE' `
            -Color Yellow
    }

    if ($layout.Height -ge 26) { Write-Host '' }

    # --------------------------------------------------------
    # Define adaptive table columns
    # --------------------------------------------------------

    $columns = @(
        @{
            Key      = 'Id'
            Header   = 'ID'
            Width    = 3
            MinWidth = 2
            MaxWidth = 4
            Priority = 1
            Align    = 'Left'
        }

        @{
            Key      = 'Device'
            Header   = 'Device'
            Width    = 27
            MinWidth = 12
            MaxWidth = 45
            Priority = 1
            Align    = 'Left'
            Expand   = $true
        }

        @{ Key='HardwareId';Header='Hardware ID';Width=22;MinWidth=11;MaxWidth=68;Priority=3;Align='Left' }

        @{
            Key      = 'Score'
            Header   = 'Score'
            Width    = 10
            MinWidth = 10
            MaxWidth = 12
            Priority = 2
            Align    = 'Right'
        }

        @{
            Key      = 'Status'
            Header   = 'Status'
            Width    = 14
            MinWidth = 8
            MaxWidth = 16
            Priority = 3
            Align    = 'Center'
        }

        @{
            Key      = 'Mode'
            Header   = 'Mode'
            Width    = 10
            MinWidth = 6
            MaxWidth = 12
            Priority = 4
            Align    = 'Center'
        }

        @{
            Key      = 'LastScan'
            Header   = 'Last Scan'
            Width    = 20
            MinWidth = 10
            MaxWidth = 24
            Priority = 5
            Align    = 'Left'
        }
    )

    # --------------------------------------------------------
    # Calculate visible table rows
    # --------------------------------------------------------

    $maxRows = [Math]::Max(
        1,
        [int]$layout.MaxTableRows
    )

    # --------------------------------------------------------
    # Render device table
    # --------------------------------------------------------

    Write-WinSecTable `
        -Columns $columns `
        -Rows $rows `
        -SelectedIndex $SelectedIndex `
        -MaxRows $maxRows

    # --------------------------------------------------------
    # Render contextual keyboard help
    # --------------------------------------------------------

    if ($deviceCount -gt 0) {
        $scanText = '[R] {0} Local Device' -f $ScanAction
        if (-not $EnableRescan) { $scanText += ' (unavailable)' }
        Write-WinSecText -Text $scanText -Color Cyan
    }
    Write-WinSecKeyboardHelp `
        -Screen 'Devices' `
        -HiddenKeys $hiddenKeys
}
