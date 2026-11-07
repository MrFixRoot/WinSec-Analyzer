function Get-WinSecPasswordPolicyEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        # net accounts depende del idioma: preservamos salida, no fingimos que fue interpretada.
        $result=@(& net.exe accounts 2>&1)
        $data.rawOutput=@($result | ForEach-Object { [string]$_ })
        $data.exitCode=$LASTEXITCODE
        if ($LASTEXITCODE -ne 0) { $warnings.Add('net accounts exit code: '+$LASTEXITCODE) }
    } catch { $warnings.Add('net accounts: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('net accounts') -Warnings @($warnings.ToArray()) -Status $state)
}
