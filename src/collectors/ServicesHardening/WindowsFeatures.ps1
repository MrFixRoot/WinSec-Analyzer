function Get-WinSecWindowsFeaturesEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.features=@(Get-WindowsOptionalFeature -Online -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('FeatureName','State','RestartRequired')
        })
    } catch { $warnings.Add('Windows optional features: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-WindowsOptionalFeature') -Warnings @($warnings.ToArray()) -Status $state)
}
