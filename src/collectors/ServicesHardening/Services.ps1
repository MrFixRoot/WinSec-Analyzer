function Get-WinSecServicesEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.services=@(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
            # No guardar PathName / StartName para evitar tokens y credenciales incrustadas.
            Select-WinSecProperties $_ @('Name','DisplayName','State','StartMode','ServiceType','Started','ProcessId','DelayedAutoStart','AcceptPause','AcceptStop')
        })
    } catch { $warnings.Add('Win32_Service: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Win32_Service') -Warnings @($warnings.ToArray()) -Status $state)
}
