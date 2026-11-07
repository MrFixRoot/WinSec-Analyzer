function Get-WinSecPowerShellLoggingEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    foreach ($hive in @('HKLM:','HKCU:')) {
        foreach ($policy in @('ScriptBlockLogging','ModuleLogging','Transcription')) {
            try {
                $path=$hive+'\SOFTWARE\Policies\Microsoft\Windows\PowerShell\'+$policy
                $data[$hive+'_'+$policy]=Get-WinSecRegistryValues $path @('EnableScriptBlockLogging','EnableScriptBlockInvocationLogging','EnableModuleLogging','EnableTranscripting','EnableInvocationHeader')
            } catch { $warnings.Add($hive+' '+$policy+': '+$_.Exception.Message) }
        }
    }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Registry:PowerShellLogging') -Warnings @($warnings.ToArray()) -Status $state)
}
