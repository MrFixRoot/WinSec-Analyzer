function Get-WinSecEventLogConfigurationEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    $names=@('Security','System','Application','Windows PowerShell','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-Windows Firewall With Advanced Security/Firewall')
    $logs=@()
    foreach ($name in $names) {
        try {
            $log=Get-WinEvent -ListLog $name -ErrorAction Stop
            $logs+=,(Select-WinSecProperties $log @('LogName','IsEnabled','MaximumSizeInBytes','RecordCount','LogMode','LogType','IsClassicLog'))
        } catch { $warnings.Add('Event log '+$name+': '+$_.Exception.Message) }
    }
    $data.logs=@($logs)
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-WinEvent -ListLog') -Warnings @($warnings.ToArray()) -Status $state)
}
