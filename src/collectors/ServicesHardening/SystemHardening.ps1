function Get-WinSecSystemHardeningEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.lsa=Get-WinSecRegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' @('RunAsPPL','RunAsPPLBoot','LimitBlankPasswordUse','RestrictAnonymous','RestrictAnonymousSAM','NoLMHash','DisableDomainCreds','EveryoneIncludesAnonymous','LmCompatibilityLevel')
        $data.wdigest=Get-WinSecRegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' @('UseLogonCredential')
        $data.autorun=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' @('NoDriveTypeAutoRun','NoAutorun')
        $data.removableStorage=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' @('Deny_All')
        $data.remoteAssistance=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' @('fAllowToGetHelp','fAllowUnsolicited')
    } catch { $warnings.Add('System hardening registry: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Registry:LSA','Registry:Policies') -Warnings @($warnings.ToArray()) -Status $state)
}
