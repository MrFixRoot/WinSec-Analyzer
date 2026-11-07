function Get-WinSecSecureBootEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try { $data.enabled=[bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    catch { $warnings.Add('Secure Boot no disponible/consulta restringida: '+$_.Exception.Message) }
    try {
        $ci=Get-ComputerInfo -Property 'BiosFirmwareType','BiosMode' -ErrorAction Stop
        $data.firmware=Select-WinSecProperties $ci @('BiosFirmwareType','BiosMode')
    } catch { $warnings.Add('Firmware: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Confirm-SecureBootUEFI','Get-ComputerInfo') -Warnings @($warnings.ToArray()) -Status $state)
}
