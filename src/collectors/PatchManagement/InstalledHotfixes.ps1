function Get-WinSecInstalledHotfixesEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.hotfixes=@(Get-HotFix -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('HotFixID','Description','InstalledOn','InstalledBy')
        })
        $data.notice='Get-HotFix no representa necesariamente todos los tipos de actualizaciones instaladas.'
    } catch { $warnings.Add('Get-HotFix: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-HotFix') -Warnings @($warnings.ToArray()) -Status $state)
}
