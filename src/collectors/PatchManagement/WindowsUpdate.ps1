function Get-WinSecWindowsUpdateEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.policy=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' @('WUServer','WUStatusServer','DisableWindowsUpdateAccess','DoNotConnectToWindowsUpdateInternetLocations','SetDisableUXWUAccess','TargetReleaseVersion','TargetReleaseVersionInfo','ProductVersion','DeferFeatureUpdates','DeferQualityUpdates','ManagePreviewBuilds')
        # WUServer/WUStatusServer pueden contener endpoints internos: solo guardamos si hay WSUS configurado.
        if ($data.policy.values.Contains('WUServer')) { $data.policy.values['WUServer']='[REDACTED_ENDPOINT]' }
        if ($data.policy.values.Contains('WUStatusServer')) { $data.policy.values['WUStatusServer']='[REDACTED_ENDPOINT]' }
        $data.auPolicy=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' @('AUOptions','NoAutoUpdate','ScheduledInstallDay','ScheduledInstallTime','UseWUServer','DetectionFrequencyEnabled','DetectionFrequency','NoAutoRebootWithLoggedOnUsers')
    } catch { $warnings.Add('Windows Update policy: '+$_.Exception.Message) }
    foreach ($name in @('wuauserv','UsoSvc','BITS')) {
        try { $data[$name]=Select-WinSecProperties (Get-Service $name -ErrorAction Stop) @('Name','Status','StartType') }
        catch { $warnings.Add('Update service '+$name+': '+$_.Exception.Message) }
    }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Registry:WindowsUpdate','Get-Service') -Warnings @($warnings.ToArray()) -Status $state)
}
