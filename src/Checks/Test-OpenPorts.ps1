function Test-OpenPorts {
    [CmdletBinding()]
    param()

    $Results = @()

    # --------------------------------------------------------
    # Sensitive ports
    # --------------------------------------------------------

    $SensitivePorts = @{
        21   = @{
            Service = 'FTP'
            Severity = 'Medium'
            Recommendation = 'Disable FTP if unnecessary or restrict access to trusted systems.'
        }

        22   = @{
            Service = 'SSH'
            Severity = 'Medium'
            Recommendation = 'Restrict SSH access to trusted management networks.'
        }

        23   = @{
            Service = 'Telnet'
            Severity = 'High'
            Recommendation = 'Disable Telnet and use an encrypted remote administration protocol.'
        }

        80   = @{
            Service = 'HTTP'
            Severity = 'Low'
            Recommendation = 'Verify that the web service is required and properly secured.'
        }

        135  = @{
            Service = 'RPC Endpoint Mapper'
            Severity = 'High'
            Recommendation = 'Restrict RPC access to trusted hosts or management networks.'
        }

        139  = @{
            Service = 'NetBIOS'
            Severity = 'High'
            Recommendation = 'Disable or restrict NetBIOS if it is not required.'
        }

        443  = @{
            Service = 'HTTPS'
            Severity = 'Low'
            Recommendation = 'Verify that the HTTPS service is expected and properly configured.'
        }

        445  = @{
            Service = 'SMB'
            Severity = 'High'
            Recommendation = 'Restrict SMB access to trusted networks and systems.'
        }

        1433 = @{
            Service = 'Microsoft SQL Server'
            Severity = 'High'
            Recommendation = 'Restrict SQL Server access to authorized application and administration hosts.'
        }

        3306 = @{
            Service = 'MySQL'
            Severity = 'High'
            Recommendation = 'Restrict MySQL access to authorized application and administration hosts.'
        }

        3389 = @{
            Service = 'Remote Desktop'
            Severity = 'High'
            Recommendation = 'Restrict RDP access to trusted management networks or VPN connections.'
        }

        5432 = @{
            Service = 'PostgreSQL'
            Severity = 'High'
            Recommendation = 'Restrict PostgreSQL access to authorized systems.'
        }

        5985 = @{
            Service = 'WinRM HTTP'
            Severity = 'High'
            Recommendation = 'Restrict WinRM to trusted management networks and consider HTTPS.'
        }

        5986 = @{
            Service = 'WinRM HTTPS'
            Severity = 'Medium'
            Recommendation = 'Restrict WinRM HTTPS access to trusted management systems.'
        }
    }

    # --------------------------------------------------------
    # Build Windows service map
    # --------------------------------------------------------

    $ServiceMap = @{}

    try {

        $WindowsServices = Get-CimInstance `
            -ClassName Win32_Service `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ProcessId -gt 0
            }

        foreach ($WindowsService in $WindowsServices) {

            $PIDKey = [string]$WindowsService.ProcessId

            if (-not $ServiceMap.ContainsKey($PIDKey)) {
                $ServiceMap[$PIDKey] = @()
            }

            $ServiceMap[$PIDKey] += $WindowsService.Name
        }
    }
    catch {
        # Service information is optional.
    }

    # --------------------------------------------------------
    # Get listening TCP ports
    # --------------------------------------------------------

    try {

        $Connections = Get-NetTCPConnection `
            -State Listen `
            -ErrorAction Stop |
            Sort-Object LocalPort, LocalAddress

        foreach ($Connection in $Connections) {

            $Port = [int]$Connection.LocalPort
            $Address = [string]$Connection.LocalAddress
            $ProcessId = [int]$Connection.OwningProcess

            # ------------------------------------------------
            # Process information
            # ------------------------------------------------

            $ProcessName = 'Unknown'

            try {

                $Process = Get-Process `
                    -Id $ProcessId `
                    -ErrorAction Stop

                $ProcessName = $Process.ProcessName
            }
            catch {
                $ProcessName = 'Unknown'
            }

            # ------------------------------------------------
            # Windows service information
            # ------------------------------------------------

            $WindowsServiceName = '-'

            $PIDKey = [string]$ProcessId

            if ($ServiceMap.ContainsKey($PIDKey)) {

                $WindowsServiceName = (
                    $ServiceMap[$PIDKey] -join ', '
                )
            }

            # ------------------------------------------------
            # Determine exposure
            # ------------------------------------------------

            if (
                $Address -eq '127.0.0.1' -or
                $Address -eq '::1'
            ) {

                $Exposure = 'Localhost'
            }
            elseif (
                $Address -eq '0.0.0.0' -or
                $Address -eq '::'
            ) {

                $Exposure = 'All Interfaces'
            }
            else {

                $Exposure = 'Specific Interface'
            }

            # ------------------------------------------------
            # Sensitive port evaluation
            # ------------------------------------------------

            $KnownService = 'Unknown'
            $Status = 'INFO'
            $Severity = 'Info'
            $Recommendation = 'Verify that this listening port is expected.'

            if ($SensitivePorts.ContainsKey($Port)) {

                $KnownService = $SensitivePorts[$Port].Service
                $Severity = $SensitivePorts[$Port].Severity
                $Recommendation = $SensitivePorts[$Port].Recommendation

                if ($Exposure -eq 'Localhost') {

                    $Status = 'INFO'
                }
                else {

                    $Status = 'WARNING'
                }
            }

            # ------------------------------------------------
            # Build evidence
            # ------------------------------------------------

            $Evidence = (
                "TCP/$Port listening on $Address; " +
                "PID=$ProcessId; " +
                "Process=$ProcessName; " +
                "WindowsService=$WindowsServiceName; " +
                "Exposure=$Exposure"
            )

            # ------------------------------------------------
            # Result
            # ------------------------------------------------

            $Results += [PSCustomObject]@{
                Control        = "TCP Port $Port"
                Category       = 'Open Ports'
                Protocol       = 'TCP'
                LocalAddress   = $Address
                LocalPort      = $Port
                Exposure       = $Exposure
                KnownService   = $KnownService
                ProcessName    = $ProcessName
                ProcessId      = $ProcessId
                WindowsService = $WindowsServiceName
                Status         = $Status
                Severity       = $Severity
                Score          = 0
                MaxScore       = 0
                Evidence       = $Evidence
                Recommendation = $Recommendation
            }
        }
    }
    catch {

        $Results += [PSCustomObject]@{
            Control        = 'Open TCP Ports'
            Category       = 'Open Ports'
            Protocol       = 'TCP'
            LocalAddress   = '-'
            LocalPort      = 0
            Exposure       = '-'
            KnownService   = '-'
            ProcessName    = '-'
            ProcessId      = 0
            WindowsService = '-'
            Status         = 'ERROR'
            Severity       = 'Unknown'
            Score          = 0
            MaxScore       = 0
            Evidence       = $_.Exception.Message
            Recommendation = 'Verify permissions and TCP/IP configuration.'
        }
    }

    return $Results
}