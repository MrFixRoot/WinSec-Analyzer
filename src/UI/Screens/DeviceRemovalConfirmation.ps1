# Rendering/input only. Consent applies exclusively to this removal request.
function Show-WinSecDeviceRemovalConfirmation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Request)
    if ($Request.Operation -cne 'DELETE_DEVICE' -or $Request.IncludesHistory -cne $true -or
        $Request.Irreversible -cne $true -or $Request.RegistersAgainOnStartup -isnot [bool] -or
        $Request.DeviceId -isnot [string] -or $Request.Hostname -isnot [string]) {
        throw 'Invalid device removal confirmation.'
    }
    $display = [pscustomobject]@{CanConfirm=$false}
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
        $lines += '[Y] Delete device and history | [Esc / N / Enter] Cancel'
        $wrapped = @(
            foreach ($line in $lines) {
                for ($offset=0; $offset -lt $line.Length; $offset+=$width) {
                    $line.Substring($offset,[Math]::Min($width,$line.Length-$offset))
                }
            }
        )
        if ($terminal.Width -lt 40 -or $terminal.Height -lt ($wrapped.Count+1)) {
            Write-WinSecText -Text 'Resize to view the complete deletion request.' -Color Yellow
            Write-WinSecText -Text '[Esc / N / Enter] Cancel'
            return
        }
        foreach ($line in $wrapped) { Write-WinSecText -Text $line }
        $display.CanConfirm = $true
    }
    $resizeState = New-WinSecResizeState
    $null = & $render $null
    while ($true) {
        $key = Read-WinSecResizeAwareKey -ResizeState $resizeState -RenderAction $render
        $null = Invoke-WinSecResizeHandler -ResizeState $resizeState -RenderAction $render
        if ($null -eq $key -or $key.KeyDown -ceq $false -or ([int]$key.ControlKeyState -band 0x0F) -ne 0) { continue }
        if ($key.VirtualKeyCode -in @(27,13) -or [string]$key.Character -ieq 'N') { return $false }
        if ($display.CanConfirm -and [string]$key.Character -ieq 'Y') { return $true }
    }
}
