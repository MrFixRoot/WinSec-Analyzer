function Get-SystemInfo {
    [CmdletBinding()]
    param()

    try {
        $ComputerSystem  = Get-CimInstance -ClassName Win32_ComputerSystem
        $OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem

        $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)

        $IsAdmin = $Principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )

        [PSCustomObject]@{
            Hostname          = $env:COMPUTERNAME
            OperatingSystem   = $OperatingSystem.Caption
            Version           = $OperatingSystem.Version
            BuildNumber       = $OperatingSystem.BuildNumber
            Architecture      = $OperatingSystem.OSArchitecture
            Domain            = $ComputerSystem.Domain
            Manufacturer      = $ComputerSystem.Manufacturer
            Model             = $ComputerSystem.Model
            CurrentUser       = $Identity.Name
            Administrator     = $IsAdmin
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            LastBootTime      = $OperatingSystem.LastBootUpTime
            AssessmentTime    = Get-Date
        }
    }
    catch {
        Write-Error "Unable to collect system information: $($_.Exception.Message)"
    }
}