function Get-WinSecInstalledSoftwareEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    $roots=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    $records=@()
    foreach ($root in $roots) {
        try {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            $records+=@(Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object {
                try {
                    $x=Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
                    if ($x.DisplayName) { Select-WinSecProperties $x @('DisplayName','DisplayVersion','Publisher','InstallDate','SystemComponent','WindowsInstaller') }
                } catch { $warnings.Add('Uninstall entry: '+$_.Exception.Message) }
            })
        } catch { $warnings.Add('Uninstall registry: '+$_.Exception.Message) }
    }
    $data.software=@($records | Where-Object { $null -ne $_ })
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Registry:Uninstall') -Warnings @($warnings.ToArray()) -Status $state)
}
