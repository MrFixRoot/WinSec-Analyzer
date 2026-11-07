function Get-WinSecLocalGroupsEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $groups=@(Get-LocalGroup -ErrorAction Stop)
        $data.groups=@($groups | ForEach-Object { Select-WinSecProperties $_ @('Name','SID','PrincipalSource') })
        $members=@()
        foreach ($g in $groups) {
            try {
                $members+=@((Get-LocalGroupMember -Group $g -ErrorAction Stop) | ForEach-Object {
                    [ordered]@{ group=$g.Name; member=(Select-WinSecProperties $_ @('Name','SID','PrincipalSource','ObjectClass')) }
                })
            } catch { $warnings.Add(('Group {0}: {1}' -f $g.Name,$_.Exception.Message)) }
        }
        $data.memberships=$members
    } catch { $warnings.Add('Get-LocalGroup: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-LocalGroup','Get-LocalGroupMember') -Warnings @($warnings.ToArray()) -Status $state)
}
