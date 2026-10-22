# Export context only. Choosing a framework never changes a scan or its criteria.
function Get-WinSecExportFrameworkOptions {
    [CmdletBinding()]
    param()
    @(
        [pscustomobject]@{Id='cis-controls';Name='CIS Controls';Benefit='Prioritized safeguards to organize practical security improvements.'}
        [pscustomobject]@{Id='nist-csf';Name='NIST CSF';Benefit='Risk management outcomes to communicate protection and detection needs.'}
        [pscustomobject]@{Id='mitre-attack';Name='MITRE ATT&CK';Benefit='Adversary techniques and defensive context to explain the threat addressed.'}
    )
}

function Show-WinSecExportFrameworkSelection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Selection)
    $copy = Copy-WinSecResultData $Selection
    if ($copy -isnot [pscustomobject] -or -not (Test-WinSecTargetIdentifier $copy.DeviceId) -or
        -not (Test-WinSecTargetIdentifier $copy.ScanId)) { throw 'Invalid export selection identity.' }
    Assert-WinSecResultScope $copy.ScopeType $copy.ScopeKey
    if ($copy.ScopeType -cnotin @('SECTION','CONTROL')) { throw 'Invalid export selection scope.' }
    $options = @(Get-WinSecExportFrameworkOptions)
    $display = [pscustomobject]@{Index=0;CanChoose=$false}
    $render = {
        param($UnusedState)
        $display.CanChoose = $false
        $terminal = Get-WinSecTerminalSize
        $width = [Math]::Max(1,[int]$terminal.ContentWidth)
        Clear-WinSecScreen
        $lines = @('WINSEC ANALYZER - EXPORT FRAMEWORK',
            ('Device: ' + $copy.DeviceId),('Scan: ' + $copy.ScanId),
            ('Selection: {0} / {1}' -f $copy.ScopeType,$copy.ScopeKey),'')
        for ($i=0;$i -lt $options.Count;$i++) {
            $prefix = if ($i -eq $display.Index) {'> '} else {'  '}
            $lines += $prefix + $options[$i].Name
        }
        $lines += ''
        $lines += 'Benefit: ' + $options[$display.Index].Benefit
        $lines += 'Only reviewed mappings can identify a reference control. Missing mappings remain PENDING.'
        $lines += 'Original scan recommendations are retained. References do not certify compliance.'
        $lines += '[Up / Down] Framework | [Enter] Export | [Esc] Cancel'
        $wrapped = @(foreach ($line in $lines) {
            if ($line.Length -eq 0) { ''; continue }
            for ($offset=0;$offset -lt $line.Length;$offset+=$width) {
                $line.Substring($offset,[Math]::Min($width,$line.Length-$offset))
            }
        })
        if ($terminal.Width -lt 40 -or $terminal.Height -lt ($wrapped.Count+1)) {
            $hints = @('Resize to view the export choice.','[Esc] Cancel')
            for ($i=0;$i -lt [Math]::Min($hints.Count,[Math]::Max(0,$terminal.Height-1));$i++) {
                Write-WinSecText -Text $hints[$i].Substring(0,[Math]::Min($width,$hints[$i].Length)) -Color Yellow
            }
            return
        }
        foreach ($line in $wrapped) { Write-WinSecText -Text $line }
        $display.CanChoose = $true
    }
    $resizeState = New-WinSecResizeState
    $null = & $render $null
    while ($true) {
        $key = Read-WinSecResizeAwareKey -ResizeState $resizeState -RenderAction $render
        $null = Invoke-WinSecResizeHandler -ResizeState $resizeState -RenderAction $render
        if ($null -eq $key -or $key.KeyDown -ceq $false -or ([int]$key.ControlKeyState -band 0x0F) -ne 0) { continue }
        if ($key.VirtualKeyCode -eq 27) {
            return [pscustomobject]@{Confirmed=$false;FrameworkId=$null}
        }
        if ($key.VirtualKeyCode -in @(38,40)) {
            $delta = if ($key.VirtualKeyCode -eq 38) {-1} else {1}
            $display.Index = ($display.Index+$delta+$options.Count) % $options.Count
            $null = & $render $null
        }
        elseif ($display.CanChoose -and $key.VirtualKeyCode -eq 13) {
            return [pscustomobject]@{Confirmed=$true;FrameworkId=$options[$display.Index].Id}
        }
    }
}
