function Get-WinSecLocalAdministratorsEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $g=Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        $data.administratorGroup=Select-WinSecProperties $g @('Name','SID')
        $data.members=@(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('Name','SID','PrincipalSource','ObjectClass')
        })
    } catch { $warnings.Add('Local administrators: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-LocalGroup','Get-LocalGroupMember') -Warnings @($warnings.ToArray()) -Status $state)
}
