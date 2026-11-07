function Get-WinSecBitLockerEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.volumes=@(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('MountPoint','VolumeType','CapacityGB','VolumeStatus','ProtectionStatus','EncryptionPercentage','EncryptionMethod','AutoUnlockEnabled','AutoUnlockKeyStored')
        })
    } catch { $warnings.Add('Get-BitLockerVolume: '+$_.Exception.Message) }
    # Nunca serializar KeyProtector ni RecoveryPassword.
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-BitLockerVolume') -Warnings @($warnings.ToArray()) -Status $state)
}
