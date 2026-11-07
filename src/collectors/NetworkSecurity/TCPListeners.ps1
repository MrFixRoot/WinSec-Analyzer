function Get-WinSecTCPListenersEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.tcp=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('LocalAddress','LocalPort','State','OwningProcess','CreationTime','AppliedSetting')
        })
    } catch { $warnings.Add('TCP listeners: '+$_.Exception.Message) }
    try {
        $data.udp=@(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('LocalAddress','LocalPort','OwningProcess')
        })
    } catch { $warnings.Add('UDP endpoints: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-NetTCPConnection','Get-NetUDPEndpoint') -Warnings @($warnings.ToArray()) -Status $state)
}
