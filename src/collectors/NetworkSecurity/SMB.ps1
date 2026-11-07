function Get-WinSecSMBEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $srv=Get-SmbServerConfiguration -ErrorAction Stop
        $data.server=Select-WinSecProperties $srv @('EnableSMB1Protocol','EnableSMB2Protocol','EncryptData','RejectUnencryptedAccess','RequireSecuritySignature','EnableSecuritySignature','EnableAuthenticateUserSharing','AuditSmb1Access','EnableLeasing')
    } catch { $warnings.Add('SMB Server: '+$_.Exception.Message) }
    try {
        $cli=Get-SmbClientConfiguration -ErrorAction Stop
        $data.client=Select-WinSecProperties $cli @('EnableSecuritySignature','RequireSecuritySignature','EnableInsecureGuestLogons','EnableSMBQUIC','EnableLargeMtu','EnableMultiChannel','EnableBandwidthThrottling','ConnectionCountPerRssNetworkInterface')
    } catch { $warnings.Add('SMB Client: '+$_.Exception.Message) }
    try {
        $feat=Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop
        $data.smb1Feature=Select-WinSecProperties $feat @('FeatureName','State','RestartRequired')
    } catch { $warnings.Add('SMB1 feature: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-SmbServerConfiguration','Get-SmbClientConfiguration','Get-WindowsOptionalFeature') -Warnings @($warnings.ToArray()) -Status $state)
}
