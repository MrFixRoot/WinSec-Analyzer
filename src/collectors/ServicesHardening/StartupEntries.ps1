function Get-WinSecStartupEntriesEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.entries=@(Get-CimInstance Win32_StartupCommand -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('Name','Location','UserSID')
        })
    } catch { $warnings.Add('Startup entries: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Win32_StartupCommand') -Warnings @($warnings.ToArray()) -Status $state)
}
