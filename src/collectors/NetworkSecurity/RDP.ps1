function Get-WinSecRDPEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.terminal=Get-WinSecRegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' @('fDenyTSConnections','fSingleSessionPerUser')
        $data.rdpTcp=Get-WinSecRegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' @('UserAuthentication','SecurityLayer','MinEncryptionLevel','PortNumber')
        $s=Get-Service -Name TermService -ErrorAction Stop
        $data.service=Select-WinSecProperties $s @('Name','Status','StartType')
    } catch { $warnings.Add('RDP: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Registry:Terminal Server','Get-Service') -Warnings @($warnings.ToArray()) -Status $state)
}
