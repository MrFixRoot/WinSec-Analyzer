function Get-WinSecAuditPolicyEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $result=@(& auditpol.exe /get /category:* /r 2>&1)
        $data.csvOutput=@($result | ForEach-Object { [string]$_ })
        $data.exitCode=$LASTEXITCODE
        if ($LASTEXITCODE -ne 0) { $warnings.Add('auditpol exit code: '+$LASTEXITCODE) }
    } catch { $warnings.Add('auditpol: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('auditpol /get /category:* /r') -Warnings @($warnings.ToArray()) -Status $state)
}
