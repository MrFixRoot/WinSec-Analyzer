function Get-WinSecNetworkAdaptersEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.adapters=@(Get-NetAdapter -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('Name','InterfaceDescription','InterfaceIndex','MacAddress','Status','LinkSpeed','MediaType','Virtual','DriverInformation')
        })
    } catch { $warnings.Add('Adapters: '+$_.Exception.Message) }
    try {
        $data.networkProfiles=@(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('InterfaceIndex','InterfaceAlias','NetworkCategory','IPv4Connectivity','IPv6Connectivity')
        })
    } catch { $warnings.Add('Network profiles: '+$_.Exception.Message) }
    try {
        $data.ipAddresses=@(Get-NetIPAddress -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('InterfaceIndex','AddressFamily','IPAddress','PrefixLength','PrefixOrigin','SuffixOrigin','AddressState')
        })
    } catch { $warnings.Add('IP addresses: '+$_.Exception.Message) }
    try {
        $data.routes=@(Get-NetRoute -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('InterfaceIndex','AddressFamily','DestinationPrefix','NextHop','RouteMetric','PolicyStore')
        })
    } catch { $warnings.Add('Routes: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-NetAdapter','Get-NetIPAddress','Get-NetConnectionProfile','Get-NetRoute') -Warnings @($warnings.ToArray()) -Status $state)
}
