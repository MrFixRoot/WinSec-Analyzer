function Get-WinSecDNSAndProxyEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.dnsServers=@(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('InterfaceIndex','InterfaceAlias','AddressFamily','ServerAddresses')
        })
    } catch { $warnings.Add('DNS server addresses: '+$_.Exception.Message) }
    try {
        $data.dnsClients=@(Get-DnsClient -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('InterfaceIndex','InterfaceAlias','ConnectionSpecificSuffix','RegisterThisConnectionsAddress','UseSuffixWhenRegistering')
        })
    } catch { $warnings.Add('DNS client: '+$_.Exception.Message) }
    try {
        # ProxyServer/PAC URL se excluyen porque pueden incluir credenciales o parametros sensibles.
        $data.proxy=Get-WinSecRegistryValues 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' @('ProxyEnable','AutoDetect')
        $data.proxyPolicy=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' @('ProxySettingsPerUser')
    } catch { $warnings.Add('Proxy policy: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-DnsClientServerAddress','Get-DnsClient','Registry:Internet Settings') -Warnings @($warnings.ToArray()) -Status $state)
}
