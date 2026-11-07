function Get-WinSecPendingRebootEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $flags=[ordered]@{}
        $flags.windowsUpdateRebootRequired=Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        $flags.componentBasedServicingRebootPending=Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $flags.pendingFileRenameOperations=$false
        $session=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        if ($session.PSObject.Properties['PendingFileRenameOperations']) {
            $flags.pendingFileRenameOperations=(@($session.PendingFileRenameOperations).Count -gt 0)
        }
        $data.indicators=$flags
    } catch { $warnings.Add('Pending reboot: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Registry:WindowsUpdate RebootRequired','Registry:CBS RebootPending') -Warnings @($warnings.ToArray()) -Status $state)
}
