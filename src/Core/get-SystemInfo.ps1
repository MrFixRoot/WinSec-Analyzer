function get-SystemInfo {
    [CmdletBinding()]
    param()

    # ========================================================
    # SYSTEM INFORMATION
    # ========================================================

    try {
        $OS = Get-CimInstance `
            -ClassName Win32_OperatingSystem `
            -ErrorAction Stop

        $ComputerSystem = Get-CimInstance `
            -ClassName Win32_ComputerSystem `
            -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve system information: $($_.Exception.Message)"
    }

    # ========================================================
    # SYSTEM UPTIME
    # ========================================================

    $CurrentDate = Get-Date

    $LastBootTime = $OS.LastBootUpTime

    $Uptime = $null
    $UptimeDays = $null

    if ($LastBootTime) {
        $Uptime = $CurrentDate - $LastBootTime

        $UptimeDays = [math]::Round(
            $Uptime.TotalDays,
            2
        )
    }

    # ========================================================
    # SYSTEM INFORMATION OBJECT
    # ========================================================

    $SystemInfo = [PSCustomObject]@{

        ComputerName = $env:COMPUTERNAME

        UserName = $env:USERNAME

        OperatingSystem = $OS.Caption.Trim()

        OSVersion = $OS.Version

        BuildNumber = $OS.BuildNumber

        Architecture = $OS.OSArchitecture

        Manufacturer = $ComputerSystem.Manufacturer

        Model = $ComputerSystem.Model

        Domain = $ComputerSystem.Domain

        DomainJoined = [bool]$ComputerSystem.PartOfDomain

        TotalMemoryGB = [math]::Round(
            $ComputerSystem.TotalPhysicalMemory / 1GB,
            2
        )

        LastBootTime = $LastBootTime

        UptimeDays = $UptimeDays

        PowerShellVersion = $PSVersionTable.PSVersion.ToString()

        CollectedAt = $CurrentDate
    }

    # ========================================================
    # RETURN RESULTS
    # ========================================================

    return $SystemInfo
}