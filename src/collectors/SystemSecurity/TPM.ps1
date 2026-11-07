function Get-WinSecTPMEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $tpm=Get-Tpm -ErrorAction Stop
        $data.tpm=Select-WinSecProperties $tpm @('TpmPresent','TpmReady','TpmEnabled','TpmActivated','TpmOwned','AutoProvisioning','LockedOut','ManagedAuthLevel','ManufacturerIdTxt','ManufacturerVersion','ManufacturerVersionFull20')
    } catch { $warnings.Add('Get-Tpm: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-Tpm') -Warnings @($warnings.ToArray()) -Status $state)
}
