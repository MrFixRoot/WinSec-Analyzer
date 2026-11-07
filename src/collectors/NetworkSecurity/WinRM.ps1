function Get-WinSecWinRMEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try { $data.service=Select-WinSecProperties (Get-Service WinRM -ErrorAction Stop) @('Name','Status','StartType') }
    catch { $warnings.Add('WinRM service: '+$_.Exception.Message) }
    try {
        if (Test-Path 'WSMan:\localhost\Listener') {
            $data.listeners=@(Get-ChildItem 'WSMan:\localhost\Listener' -ErrorAction Stop | ForEach-Object {
                Select-WinSecProperties $_ @('Name','PSPath','Keys')
            })
        } else { $data.listeners=@() }
    } catch { $warnings.Add('WinRM listeners: '+$_.Exception.Message) }
    try {
        $data.serviceAuth=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' @('AllowAutoConfig','AllowBasic','AllowUnencryptedTraffic','DisableRunAs')
    } catch { $warnings.Add('WinRM policy: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-Service','WSMan:') -Warnings @($warnings.ToArray()) -Status $state)
}
