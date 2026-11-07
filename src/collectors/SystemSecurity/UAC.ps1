function Get-WinSecUACEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.policies=Get-WinSecRegistryValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' @('EnableLUA','ConsentPromptBehaviorAdmin','ConsentPromptBehaviorUser','PromptOnSecureDesktop','FilterAdministratorToken','EnableInstallerDetection','EnableSecureUIAPaths','EnableVirtualization','ValidateAdminCodeSignatures','LocalAccountTokenFilterPolicy')
    } catch { $warnings.Add('UAC registry: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Registry:HKLM Policies System') -Warnings @($warnings.ToArray()) -Status $state)
}
