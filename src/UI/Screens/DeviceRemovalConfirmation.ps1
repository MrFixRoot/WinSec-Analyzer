# Rendering/input only. Consent applies exclusively to this removal request.
function Show-WinSecDeviceRemovalConfirmation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Request)
    if ($Request.Operation -cne 'DELETE_DEVICE' -or $Request.IncludesHistory -cne $true -or
        $Request.Irreversible -cne $true -or $Request.RegistersAgainOnStartup -isnot [bool] -or
        $Request.DeviceId -isnot [string] -or $Request.Hostname -isnot [string]) {
        throw 'Invalid device removal confirmation.'
    }
    $display = [pscustomobject]@{CanConfirm=$false;Choice=0}
    $render = {
        param($UnusedState)
        $display.CanConfirm = $false
        Clear-WinSecScreen
        $terminal = Get-WinSecTerminalSize
        $width = [Math]::Max(1,[int]$terminal.ContentWidth)
        $lines = @('WINSEC ANALYZER - DELETE DEVICE AND HISTORY',
            ('Device: ' + $Request.Hostname), ('DeviceId: ' + $Request.DeviceId),
            ('Scans in this session: ' + $Request.MemoryScanCount),
            ('Stored history/evidence files: ' + $Request.StoredFileCount),
            'This permanently deletes this device and its application-owned history.',
            'Other devices are preserved. Windows configuration is unchanged.')
        if ($Request.RegistersAgainOnStartup) {
            $lines += 'This computer will register again on next startup, with no history.'
        }
        $lines += @('  [ Accept ]','  [ Cancel ]','[Arrows] Choose | [Enter] Select | [Esc] Cancel')
        $wrapped = @(
            foreach ($line in $lines) {
                for ($offset=0; $offset -lt $line.Length; $offset+=$width) {
                    $line.Substring($offset,[Math]::Min($width,$line.Length-$offset))
                }
            }
        )
        if ($terminal.Width -lt 40 -or $terminal.Height -lt ($wrapped.Count+1)) {
            $hints = @('Resize to view the complete deletion request.','[Esc] Cancel')
            foreach ($hint in @($hints | Select-Object -First ([Math]::Max(0,[int]$terminal.Height-1)))) {
                Write-WinSecText -Text $hint.Substring(0,[Math]::Min($width,$hint.Length)) -Color Yellow
            }
            return
        }
        foreach ($line in $wrapped) {
            $color = if ($line -match '^This permanently deletes|^This computer will register') {'Yellow'} else {'Gray'}
            if (($line -ceq '  [ Accept ]' -and $display.Choice -eq 0) -or
                ($line -ceq '  [ Cancel ]' -and $display.Choice -eq 1)) {
                $line = '> ' + $line.Substring(2);$color='Cyan'
            }
            Write-WinSecText -Text $line -Color $color
        }
        $display.CanConfirm = $true
    }
    $resizeState = New-WinSecResizeState
    $null = & $render $null
    while ($true) {
        $key = Read-WinSecResizeAwareKey -ResizeState $resizeState -RenderAction $render
        $null = Invoke-WinSecResizeHandler -ResizeState $resizeState -RenderAction $render
        if ($null -eq $key -or $key.KeyDown -ceq $false -or ([int]$key.ControlKeyState -band 0x0F) -ne 0) { continue }
        if ($key.VirtualKeyCode -eq 27) { return $false }
        if ($key.VirtualKeyCode -in @(37,38,39,40)) {
            $display.Choice=1-$display.Choice
            $null=& $render $null
            continue
        }
        if ($key.VirtualKeyCode -eq 13 -and $display.Choice -eq 1) { return $false }
        if ($display.CanConfirm -and $key.VirtualKeyCode -eq 13) { return $true }
    }
}
