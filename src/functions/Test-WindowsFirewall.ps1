function Test-WindowsFirewall {
    [CmdletBinding()]
    param()

    $Results = @()

    # --------------------------------------------------------
    # Helper function
    # --------------------------------------------------------

    function New-FirewallResult {
        param(
            [string]$Control,
            [string]$Status,
            [string]$Severity,
            [int]$Score,
            [int]$MaxScore,
            [string]$Evidence,
            [string]$Recommendation
        )

        [PSCustomObject]@{
            Control        = $Control
            Category       = 'Windows Firewall'
            Status         = $Status
            Severity       = $Severity
            Score          = $Score
            MaxScore       = $MaxScore
            Evidence       = $Evidence
            Recommendation = $Recommendation
        }
    }

    # ========================================================
    # 1. FIREWALL SERVICE
    # Maximum: 10 points
    # ========================================================

    try {

        $FirewallService = Get-Service -Name 'MpsSvc' -ErrorAction Stop

        if ($FirewallService.Status -eq 'Running') {

            $Results += New-FirewallResult `
                -Control 'Windows Firewall Service' `
                -Status 'PASS' `
                -Severity 'High' `
                -Score 10 `
                -MaxScore 10 `
                -Evidence "MpsSvc status: $($FirewallService.Status)" `
                -Recommendation 'No action required.'
        }
        else {

            $Results += New-FirewallResult `
                -Control 'Windows Firewall Service' `
                -Status 'FAIL' `
                -Severity 'High' `
                -Score 0 `
                -MaxScore 10 `
                -Evidence "MpsSvc status: $($FirewallService.Status)" `
                -Recommendation 'Start the Windows Defender Firewall service.'
        }
    }
    catch {

        $Results += New-FirewallResult `
            -Control 'Windows Firewall Service' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 10 `
            -Evidence $_.Exception.Message `
            -Recommendation 'Verify that the Windows Firewall service is available.'
    }

    # ========================================================
    # 2. FIREWALL PROFILES
    #
    # Each profile:
    # Enabled             = 8 points
    # Default Inbound     = 8 points
    # Logging             = 9 points
    #
    # 25 points x 3 = 75
    # ========================================================

    try {

        try {
            $Profiles = Get-NetFirewallProfile `
                -PolicyStore ActiveStore `
                -ErrorAction Stop
        }
        catch {
            $Profiles = Get-NetFirewallProfile -ErrorAction Stop
        }

        foreach ($Profile in $Profiles) {

            $ProfileName = [string]$Profile.Name

            # ------------------------------------------------
            # Profile enabled
            # ------------------------------------------------

            if ($Profile.Enabled -eq $true) {

                $Results += New-FirewallResult `
                    -Control "$ProfileName Profile Enabled" `
                    -Status 'PASS' `
                    -Severity 'High' `
                    -Score 8 `
                    -MaxScore 8 `
                    -Evidence "$ProfileName firewall profile is enabled." `
                    -Recommendation 'No action required.'
            }
            else {

                $Results += New-FirewallResult `
                    -Control "$ProfileName Profile Enabled" `
                    -Status 'FAIL' `
                    -Severity 'High' `
                    -Score 0 `
                    -MaxScore 8 `
                    -Evidence "$ProfileName firewall profile is disabled." `
                    -Recommendation "Enable the $ProfileName Windows Firewall profile."
            }

            # ------------------------------------------------
            # Default inbound policy
            # ------------------------------------------------

            $InboundAction = [string]$Profile.DefaultInboundAction

            if ($InboundAction -eq 'Block') {

                $Results += New-FirewallResult `
                    -Control "$ProfileName Default Inbound Policy" `
                    -Status 'PASS' `
                    -Severity 'High' `
                    -Score 8 `
                    -MaxScore 8 `
                    -Evidence "Default inbound action: $InboundAction" `
                    -Recommendation 'No action required.'
            }
            elseif ($InboundAction -eq 'Allow') {

                $Results += New-FirewallResult `
                    -Control "$ProfileName Default Inbound Policy" `
                    -Status 'FAIL' `
                    -Severity 'High' `
                    -Score 0 `
                    -MaxScore 8 `
                    -Evidence "Default inbound action: $InboundAction" `
                    -Recommendation "Configure the $ProfileName profile to block unsolicited inbound connections by default."
            }
            else {

                $Results += New-FirewallResult `
                    -Control "$ProfileName Default Inbound Policy" `
                    -Status 'WARNING' `
                    -Severity 'Medium' `
                    -Score 4 `
                    -MaxScore 8 `
                    -Evidence "Default inbound action: $InboundAction" `
                    -Recommendation "Review the effective inbound policy for the $ProfileName profile."
            }

            # ------------------------------------------------
            # Logging
            # ------------------------------------------------

            $LogChecksPassed = 0

            $LogBlocked = ([string]$Profile.LogBlocked -eq 'True')
            $LogAllowed = ([string]$Profile.LogAllowed -eq 'True')

            $LogSize = 0

            if ($null -ne $Profile.LogMaxSizeKilobytes) {
                $LogSize = [int]$Profile.LogMaxSizeKilobytes
            }

            $LogPath = [string]$Profile.LogFileName

            if ($LogBlocked) {
                $LogChecksPassed++
            }

            if ($LogAllowed) {
                $LogChecksPassed++
            }

            if ($LogSize -ge 16384) {
                $LogChecksPassed++
            }

            if (
                -not [string]::IsNullOrWhiteSpace($LogPath) -and
                $LogPath -match '\.log$'
            ) {
                $LogChecksPassed++
            }

            $LoggingScore = [math]::Round(
                9 * ($LogChecksPassed / 4)
            )

            if ($LogChecksPassed -eq 4) {
                $LoggingStatus = 'PASS'
            }
            else {
                $LoggingStatus = 'WARNING'
            }

            $LoggingEvidence = @(
                "Blocked packets logging: $($Profile.LogBlocked)"
                "Allowed connections logging: $($Profile.LogAllowed)"
                "Maximum log size: $LogSize KB"
                "Log file: $LogPath"
            ) -join '; '

            $Results += New-FirewallResult `
                -Control "$ProfileName Firewall Logging" `
                -Status $LoggingStatus `
                -Severity 'Medium' `
                -Score $LoggingScore `
                -MaxScore 9 `
                -Evidence $LoggingEvidence `
                -Recommendation "Enable firewall logging and configure an adequate log file size for the $ProfileName profile."
        }

        # ----------------------------------------------------
        # Outbound policy - informational
        # Does not affect score
        # ----------------------------------------------------

        $OutboundSummary = @(
            $Profiles | ForEach-Object {
                "$($_.Name)=$($_.DefaultOutboundAction)"
            }
        ) -join '; '

        $Results += New-FirewallResult `
            -Control 'Default Outbound Policy' `
            -Status 'INFO' `
            -Severity 'Info' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence $OutboundSummary `
            -Recommendation 'Review outbound filtering requirements according to the security baseline of the environment.'
    }
    catch {

        $Results += New-FirewallResult `
            -Control 'Windows Firewall Profiles' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 75 `
            -Evidence $_.Exception.Message `
            -Recommendation 'Verify privileges and Windows Firewall configuration.'
    }

    # ========================================================
    # 3. Potentially Exposed Sensitive Services
    # Maximum: 15 points
    # ========================================================

    try {

        $SensitivePorts = @{
            '135'  = 'RPC Endpoint Mapper'
            '139'  = 'NetBIOS'
            '445'  = 'SMB'
            '3389' = 'Remote Desktop'
            '5985' = 'WinRM HTTP'
            '5986' = 'WinRM HTTPS'
        }

        $ExposedRules = @()

        try {
            $InboundRules = Get-NetFirewallRule `
                -PolicyStore ActiveStore `
                -Enabled True `
                -Direction Inbound `
                -Action Allow `
                -ErrorAction Stop
        }
        catch {
            $InboundRules = Get-NetFirewallRule `
                -Enabled True `
                -Direction Inbound `
                -Action Allow `
                -ErrorAction Stop
        }

        foreach ($Rule in $InboundRules) {

            try {

                $PortFilters = @(
                    $Rule |
                        Get-NetFirewallPortFilter `
                            -ErrorAction Stop
                )

                $AddressFilters = @(
                    $Rule |
                        Get-NetFirewallAddressFilter `
                            -ErrorAction Stop
                )

                $LocalPorts = @(
                    $PortFilters |
                        ForEach-Object {
                            @($_.LocalPort)
                        }
                ) | ForEach-Object {
                    [string]$_
                }

                $RemoteAddresses = @(
                    $AddressFilters |
                        ForEach-Object {
                            @($_.RemoteAddress)
                        }
                ) | ForEach-Object {
                    [string]$_
                }

                $RemoteIsAny = $false

                foreach ($RemoteAddress in $RemoteAddresses) {

                    if (
                        $RemoteAddress -eq 'Any' -or
                        $RemoteAddress -eq '*' -or
                        $RemoteAddress -eq '0.0.0.0/0' -or
                        $RemoteAddress -eq '::/0'
                    ) {
                        $RemoteIsAny = $true
                    }
                }

                if (-not $RemoteIsAny) {
                    continue
                }

                foreach ($Port in $SensitivePorts.Keys) {

                    if ($LocalPorts -contains $Port) {

                        $ExposedRules += [PSCustomObject]@{
                            RuleName = $Rule.DisplayName
                            Port     = $Port
                            Service  = $SensitivePorts[$Port]
                            Profile  = [string]$Rule.Profile
                        }
                    }
                }
            }
            catch {
                # Ignore individual rules that cannot be inspected.
            }
        }

        if ($ExposedRules.Count -eq 0) {

            $Results += New-FirewallResult `
                -Control 'Potentially Exposed Sensitive Services' `
                -Status 'PASS' `
                -Severity 'High' `
                -Score 15 `
                -MaxScore 15 `
                -Evidence 'No enabled inbound Allow rules exposing selected sensitive ports to Any remote address were detected.' `
                -Recommendation 'No action required.'
        }
        else {

            $PublicExposure = @(
                $ExposedRules |
                    Where-Object {
                        $_.Profile -match 'Public' -or
                        $_.Profile -eq 'Any'
                    }
            )

            $RuleEvidence = @(
                $ExposedRules |
                    ForEach-Object {
                        "$($_.Service) TCP/UDP $($_.Port) | Profile=$($_.Profile) | Rule=$($_.RuleName)"
                    }
            ) -join '; '

            if ($PublicExposure.Count -gt 0) {

                $RuleStatus = 'FAIL'
                $RuleScore = 0
            }
            else {

                $RuleStatus = 'WARNING'
                $RuleScore = 8
            }

            $Results += New-FirewallResult `
                -Control 'Potentially Exposed Sensitive Services' `
                -Status $RuleStatus `
                -Severity 'High' `
                -Score $RuleScore `
                -MaxScore 15 `
                -Evidence $RuleEvidence `
                -Recommendation 'Review these inbound rules. Disable unnecessary rules or restrict their RemoteAddress and firewall profiles.'
        }
    }
    catch {

        $Results += New-FirewallResult `
            -Control 'Potentially Exposed Sensitive Services' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 15 `
            -Evidence $_.Exception.Message `
            -Recommendation 'Review enabled inbound firewall rules manually.'
    }

    return $Results
}