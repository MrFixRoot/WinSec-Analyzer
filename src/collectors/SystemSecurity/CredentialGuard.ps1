function Get-WinSecCredentialGuardEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $dg=Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
        $data.deviceGuard=Select-WinSecProperties $dg @('AvailableSecurityProperties','RequiredSecurityProperties','SecurityServicesConfigured','SecurityServicesRunning','VirtualizationBasedSecurityStatus','CodeIntegrityPolicyEnforcementStatus','UsermodeCodeIntegrityPolicyEnforcementStatus')
    } catch { $warnings.Add('Win32_DeviceGuard: '+$_.Exception.Message) }
    try {
        $data.policy=Get-WinSecRegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' @('EnableVirtualizationBasedSecurity','RequirePlatformSecurityFeatures','Locked')
        $data.lsaCfg=Get-WinSecRegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' @('LsaCfgFlags','RunAsPPL')
    } catch { $warnings.Add('DeviceGuard registry: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Win32_DeviceGuard','Registry:DeviceGuard') -Warnings @($warnings.ToArray()) -Status $state)
}
