function Get-SystemInfo {

    [CmdletBinding()]
    param()

    try {

        $OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        $ComputerSystem  = Get-CimInstance -ClassName Win32_ComputerSystem

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Manufacturer = $ComputerSystem.Manufacturer
            Model        = $ComputerSystem.Model
            OS           = $OperatingSystem.Caption
            Version      = $OperatingSystem.Version
            Architecture = $OperatingSystem.OSArchitecture
            LastBoot     = $OperatingSystem.LastBootUpTime
        }

    }
    catch {

        Write-Error "System information could not be retrieved.: $($_.Exception.Message)"

    }

}