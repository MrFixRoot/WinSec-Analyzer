function Get-WinSecWindowsFirewallEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('Name','Enabled','DefaultInboundAction','DefaultOutboundAction','AllowInboundRules','AllowLocalFirewallRules','AllowLocalIPsecRules','NotifyOnListen','LogAllowed','LogBlocked','LogMaxSizeKilobytes','LogFileName')
        })
    } catch { $warnings.Add('Firewall profiles: '+$_.Exception.Message) }
    try {
        $data.rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('Name','DisplayName','Enabled','Direction','Action','Profile','PolicyStoreSourceType','PolicyStoreSource','EdgeTraversalPolicy','PrimaryStatus','EnforcementStatus','RuleGroup','Service')
        })
    } catch { $warnings.Add('Firewall rules: '+$_.Exception.Message) }
    $filters=@(
        [pscustomobject]@{ Key='portFilters'; Cmd='Get-NetFirewallPortFilter'; Fields=@('InstanceID','Protocol','LocalPort','RemotePort','IcmpType','DynamicTarget') },
        [pscustomobject]@{ Key='addressFilters'; Cmd='Get-NetFirewallAddressFilter'; Fields=@('InstanceID','LocalAddress','RemoteAddress') },
        [pscustomobject]@{ Key='applicationFilters'; Cmd='Get-NetFirewallApplicationFilter'; Fields=@('InstanceID','Program','Package') },
        [pscustomobject]@{ Key='serviceFilters'; Cmd='Get-NetFirewallServiceFilter'; Fields=@('InstanceID','Service') }
    )
    foreach ($source in $filters) {
        $key=[string]$source.Key; $cmd=[string]$source.Cmd; $fields=[string[]]$source.Fields
        try { $data[$key]=@(& $cmd -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object { Select-WinSecProperties $_ $fields }) }
        catch { $warnings.Add($cmd+': '+$_.Exception.Message) }
    }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-NetFirewallProfile','Get-NetFirewallRule','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','Get-NetFirewallApplicationFilter','Get-NetFirewallServiceFilter') -Warnings @($warnings.ToArray()) -Status $state)
}
