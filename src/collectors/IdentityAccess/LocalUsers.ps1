function Get-WinSecLocalUsersEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.users=@(Get-LocalUser -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('Name','SID','Enabled','LastLogon','PasswordRequired','PasswordExpires','UserMayChangePassword','AccountExpires','PrincipalSource')
        })
    } catch { $warnings.Add('Get-LocalUser: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-LocalUser') -Warnings @($warnings.ToArray()) -Status $state)
}
