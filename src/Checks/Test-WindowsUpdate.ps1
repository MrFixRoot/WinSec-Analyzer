function Test-WindowsUpdate {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 30)]
        [int]$MaxScanAgeDays = 7
    )

    $Results = @()
    $LastScanFresh = $false

    function New-WUResult {
        param([Parameter(Mandatory)][hashtable]$Data)

        [PSCustomObject]@{
            Control        = [string]$Data.Control
            Category       = 'Windows Update'
            Status         = [string]$Data.Status
            Severity       = [string]$Data.Severity
            Score          = [int]$Data.Score
            MaxScore       = [int]$Data.MaxScore
            Evidence       = [string]$Data.Evidence
            Recommendation = [string]$Data.Recommendation
        }
    }

    # 1. Windows Update service (15 points)
    # A stopped, demand-start service is not necessarily insecure.
    try {
        $Service = Get-Service -Name 'wuauserv' -ErrorAction Stop
        $StartType = [string]$Service.StartType
        $ServiceStatus = [string]$Service.Status

        if ($StartType -eq 'Disabled') {
            $Results += New-WUResult @{
                Control = 'Windows Update Service'; Status = 'FAIL'; Severity = 'High'
                Score = 0; MaxScore = 15
                Evidence = "wuauserv: StartType=$StartType; Status=$ServiceStatus"
                Recommendation = 'Review why Windows Update is disabled and restore the approved update mechanism.'
            }
        }
        else {
            $Results += New-WUResult @{
                Control = 'Windows Update Service'; Status = 'PASS'; Severity = 'High'
                Score = 15; MaxScore = 15
                Evidence = "wuauserv: StartType=$StartType; Status=$ServiceStatus"
                Recommendation = 'No action required. Stopped/Manual can be normal for a trigger-start service.'
            }
        }
    }
    catch {
        $Results += New-WUResult @{
            Control = 'Windows Update Service'; Status = 'ERROR'; Severity = 'Unknown'
            Score = 0; MaxScore = 0; Evidence = $_.Exception.Message
            Recommendation = 'Verify access to the Windows Update service.'
        }
    }

    # 2. Automatic Updates configuration (20 points)
    # This checks the explicit disable policy and WUA automatic-update state.
    try {
        $AUPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        $NoAutoUpdate = $null

        if (Test-Path -LiteralPath $AUPath -ErrorAction Stop) {
            $AURegistry = Get-ItemProperty -LiteralPath $AUPath -ErrorAction Stop
            $Setting = $AURegistry.PSObject.Properties['NoAutoUpdate']
            if ($null -ne $Setting) {
                $NoAutoUpdate = [string]$Setting.Value
            }
        }

        if ($null -ne $NoAutoUpdate -and $NoAutoUpdate -notin @('0', '1')) {
            throw "Invalid NoAutoUpdate policy value: $NoAutoUpdate"
        }

        if ($NoAutoUpdate -eq '1') {
            $Results += New-WUResult @{
                Control = 'Automatic Updates Configuration'; Status = 'FAIL'; Severity = 'High'
                Score = 0; MaxScore = 20
                Evidence = 'NoAutoUpdate=1: automatic updates explicitly disabled by policy.'
                Recommendation = 'Review the policy and confirm the device has an approved, effective patching process.'
            }
        }
        else {
            $AutoUpdate = New-Object -ComObject 'Microsoft.Update.AutoUpdate' -ErrorAction Stop
            $ServiceEnabled = [bool]$AutoUpdate.ServiceEnabled
            $NotificationLevel = [int]$AutoUpdate.Settings.NotificationLevel

            if (-not $ServiceEnabled -or $NotificationLevel -eq 1) {
                $Status = 'FAIL'; $Points = 0
            }
            elseif ($NotificationLevel -in @(2, 3)) {
                $Status = 'WARNING'; $Points = 10
            }
            else {
                $Status = 'PASS'; $Points = 20
            }

            $Results += New-WUResult @{
                Control = 'Automatic Updates Configuration'; Status = $Status; Severity = 'High'
                Score = $Points; MaxScore = 20
                Evidence = "NoAutoUpdate=$NoAutoUpdate; ServiceEnabled=$ServiceEnabled; NotificationLevel=$NotificationLevel"
                Recommendation = 'Review automatic update settings and ensure required updates are applied without unnecessary manual delay.'
            }
        }
    }
    catch {
        $Results += New-WUResult @{
            Control = 'Automatic Updates Configuration'; Status = 'ERROR'; Severity = 'Unknown'
            Score = 0; MaxScore = 0; Evidence = $_.Exception.Message
            Recommendation = 'Verify access to Windows Update policy and the Windows Update Agent COM interface.'
        }
    }

    # 3. Last successful automatic update search (20 points)
    # This timestamp is NOT necessarily the last manual scan.
    try {
        $AutoUpdateResults = (New-Object -ComObject 'Microsoft.Update.AutoUpdate' -ErrorAction Stop).Results
        $RawLastScan = $AutoUpdateResults.LastSearchSuccessDate
        $LastScan = $null

        if ($null -ne $RawLastScan) {
            $ParsedLastScan = [datetime]$RawLastScan
            if ($ParsedLastScan.Year -ge 2000) {
                $LastScan = $ParsedLastScan
            }
        }

        if ($null -eq $LastScan) {
            $Results += New-WUResult @{
                Control = 'Recent Automatic Update Scan'; Status = 'WARNING'; Severity = 'High'
                Score = 0; MaxScore = 20
                Evidence = 'Last successful Automatic Updates search timestamp is unavailable.'
                Recommendation = 'Verify that the device scans successfully for Windows updates.'
            }
        }
        else {
            $AgeDays = ((Get-Date) - $LastScan).TotalDays
            $LastScanFresh = ($AgeDays -ge 0 -and $AgeDays -le $MaxScanAgeDays)
            $Status = if ($LastScanFresh) { 'PASS' } else { 'WARNING' }
            $Points = if ($LastScanFresh) { 20 } else { 0 }
            $AgeText = [math]::Round($AgeDays, 1)

            $Results += New-WUResult @{
                Control = 'Recent Automatic Update Scan'; Status = $Status; Severity = 'High'
                Score = $Points; MaxScore = 20
                Evidence = "LastSearchSuccessDate=$LastScan; AgeDays=$AgeText; ThresholdDays=$MaxScanAgeDays"
                Recommendation = 'Investigate outdated or unexpected scan timestamps; confirm Windows Update scanning is functioning.'
            }
        }
    }
    catch {
        $Results += New-WUResult @{
            Control = 'Recent Automatic Update Scan'; Status = 'ERROR'; Severity = 'Unknown'
            Score = 0; MaxScore = 0; Evidence = $_.Exception.Message
            Recommendation = 'Verify Windows Update Agent scan history availability.'
        }
    }

    # 4. Pending applicable software updates (35 points)
    # Offline scan only; NEVER calls Download(), Install(), or DetectNow().
    # Do not interpret an empty cache as PASS without a recent successful scan.
    try {
        $Session = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction Stop
        $Searcher = $Session.CreateUpdateSearcher()
        $Searcher.Online = $false
        $SearchResult = $Searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")

        if ([int]$SearchResult.ResultCode -ne 2) {
            throw "Offline update search was not fully successful. ResultCode=$($SearchResult.ResultCode)"
        }

        $PendingCount = [int]$SearchResult.Updates.Count
        $SecurityCount = 0
        $Examples = @()
        $PriorityCategories = @(
            '0fa1201d-4330-4fa8-8ae9-b877473b6441', # Security Updates
            'e6cf1350-c01b-414d-a61f-263d14d133b4'  # Critical Updates
        )

        for ($Index = 0; $Index -lt $PendingCount; $Index++) {
            $Update = $SearchResult.Updates.Item($Index)
            if ($Examples.Count -lt 5) { $Examples += [string]$Update.Title }
            $SecurityRelated = $false

            for ($CategoryIndex = 0; $CategoryIndex -lt $Update.Categories.Count; $CategoryIndex++) {
                $CategoryID = [string]$Update.Categories.Item($CategoryIndex).CategoryID
                if ($CategoryID.ToLowerInvariant() -in $PriorityCategories) {
                    $SecurityRelated = $true
                    break
                }
            }

            if (-not [string]::IsNullOrWhiteSpace([string]$Update.MsrcSeverity)) {
                $SecurityRelated = $true
            }

            if ($SecurityRelated) { $SecurityCount++ }
        }

        $SampleText = if ($Examples.Count -gt 0) { $Examples -join ' | ' } else { 'None' }
        $Evidence = "OfflineCache=True; Pending=$PendingCount; SecurityOrCritical=$SecurityCount; Examples=$SampleText"

        if ($SecurityCount -gt 0) {
            $Results += New-WUResult @{
                Control = 'Pending Software Updates'; Status = 'FAIL'; Severity = 'High'
                Score = 0; MaxScore = 35; Evidence = $Evidence
                Recommendation = 'Review and prioritize applicable security/critical updates. Validate deployment and reboot requirements.'
            }
        }
        elseif ($PendingCount -gt 0) {
            $Results += New-WUResult @{
                Control = 'Pending Software Updates'; Status = 'WARNING'; Severity = 'Medium'
                Score = 15; MaxScore = 35; Evidence = $Evidence
                Recommendation = 'Review pending applicable software updates and deploy those required by policy.'
            }
        }
        elseif ($LastScanFresh) {
            $Results += New-WUResult @{
                Control = 'Pending Software Updates'; Status = 'PASS'; Severity = 'High'
                Score = 35; MaxScore = 35; Evidence = $Evidence
                Recommendation = 'No currently applicable non-hidden software updates were found in the local WUA metadata.'
            }
        }
        else {
            $Results += New-WUResult @{
                Control = 'Pending Software Updates'; Status = 'ERROR'; Severity = 'Unknown'
                Score = 0; MaxScore = 0
                Evidence = "$Evidence; Cannot confirm a clean state because recent successful automatic scan was not verified."
                Recommendation = 'Verify Windows Update scan freshness before concluding there are no pending updates.'
            }
        }
    }
    catch {
        $Results += New-WUResult @{
            Control = 'Pending Software Updates'; Status = 'ERROR'; Severity = 'Unknown'
            Score = 0; MaxScore = 0; Evidence = $_.Exception.Message
            Recommendation = 'Review Windows Update Agent health and run a separate authorized scan if necessary.'
        }
    }

    # 5. Servicing/Windows Update reboot markers (10 points)
    $RebootPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    )

    try {
        $DetectedPaths = @()
        foreach ($Path in $RebootPaths) {
            if (Test-Path -LiteralPath $Path -ErrorAction Stop) {
                $DetectedPaths += $Path
            }
        }

        if ($DetectedPaths.Count -gt 0) {
            $Results += New-WUResult @{
                Control = 'Pending Reboot'; Status = 'WARNING'; Severity = 'Medium'
                Score = 0; MaxScore = 10
                Evidence = 'Servicing reboot markers detected: ' + ($DetectedPaths -join '; ')
                Recommendation = 'Confirm maintenance requirements and schedule a reboot when appropriate.'
            }
        }
        else {
            $Results += New-WUResult @{
                Control = 'Pending Reboot'; Status = 'PASS'; Severity = 'Medium'
                Score = 10; MaxScore = 10
                Evidence = 'No reboot markers found in the Windows Update and CBS locations checked.'
                Recommendation = 'No action required for the checked markers.'
            }
        }
    }
    catch {
        $Results += New-WUResult @{
            Control = 'Pending Reboot'; Status = 'ERROR'; Severity = 'Unknown'
            Score = 0; MaxScore = 0; Evidence = $_.Exception.Message
            Recommendation = 'Verify access to Windows Update and CBS reboot markers.'
        }
    }

    # Informational: managed WSUS policy. Absence does not mean failure.
    try {
        $WUPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        $AUPath = Join-Path $WUPath 'AU'
        if (Test-Path -LiteralPath $AUPath -ErrorAction Stop) {
            $AUData = Get-ItemProperty -LiteralPath $AUPath -ErrorAction Stop
            if ([string]$AUData.UseWUServer -eq '1') {
                $ServerName = 'Not specified'
                if (Test-Path -LiteralPath $WUPath -ErrorAction Stop) {
                    $WUData = Get-ItemProperty -LiteralPath $WUPath -ErrorAction Stop
                    if ($WUData.WUServer) { $ServerName = [string]$WUData.WUServer }
                }
                $Results += New-WUResult @{
                    Control = 'Managed Update Source'; Status = 'INFO'; Severity = 'Info'
                    Score = 0; MaxScore = 0
                    Evidence = "UseWUServer=1; WSUS=$ServerName"
                    Recommendation = 'Confirm that the managed update service is reachable and approving required updates.'
                }
            }
        }
    }
    catch {
        $Results += New-WUResult @{
            Control = 'Managed Update Source'; Status = 'INFO'; Severity = 'Info'
            Score = 0; MaxScore = 0; Evidence = "Source could not be identified: $($_.Exception.Message)"
            Recommendation = 'Review Windows Update source management if applicable.'
        }
    }

    return $Results
}
