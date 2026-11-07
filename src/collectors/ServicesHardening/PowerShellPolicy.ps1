function Get-WinSecPowerShellPolicyEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $data.executionPolicies=@(Get-ExecutionPolicy -List -ErrorAction Stop | ForEach-Object {
            Select-WinSecProperties $_ @('Scope','ExecutionPolicy')
        })
    } catch { $warnings.Add('PowerShell policy: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-ExecutionPolicy') -Warnings @($warnings.ToArray()) -Status $state)
}
