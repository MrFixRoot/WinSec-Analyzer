function Get-WinSecSmartScreenEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.explorer=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' @('SmartScreenEnabled')
        $data.policy=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' @('EnableSmartScreen','ShellSmartScreenLevel')
        $data.edge=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' @('SmartScreenEnabled','SmartScreenPuaEnabled')
    } catch { $warnings.Add('SmartScreen registry: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Registry:Explorer','Registry:SmartScreen') -Warnings @($warnings.ToArray()) -Status $state)
}
