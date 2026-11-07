function Get-WinSecGuestAccountEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $guests=@(Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -match '-501$' })
        $data.guests=@($guests | ForEach-Object { Select-WinSecProperties $_ @('Name','SID','Enabled','PasswordRequired') })
        if ($guests.Count -ne 1) { $warnings.Add('No se identifico una unica cuenta Guest integrada.') }
    } catch { $warnings.Add('Guest account: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-LocalUser') -Warnings @($warnings.ToArray()) -Status $state)
}
