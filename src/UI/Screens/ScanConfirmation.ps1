# ============================================================
# WinSec Analyzer - Per-operation scan confirmation
# PowerShell 5.1 / 7.x. Rendering and keyboard input only.
# ============================================================

function Show-WinSecScanConfirmation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Request)

    if ($Request.Operation -cne 'SCAN' -or $Request.ReadOnly -cne $true -or
        $Request.Checks -isnot [array] -or
        $Request.SelectionMode -cnotin @('ALL_EXECUTABLE', 'EXPLICIT_CHECKS')) {
        throw 'Invalid scan confirmation request.'
    }

    $display = [pscustomobject]@{ CanConfirm = $false }
    $render = {
        param($UnusedState)
        $display.CanConfirm = $false
        $terminal = Get-WinSecTerminalSize
        Clear-WinSecScreen
        $width = [Math]::Max(1, [int]$terminal.ContentWidth)
        $scope = if ($Request.SelectionMode -ceq 'ALL_EXECUTABLE') {
            'Local device - all executable controls'
        }
        else {
            'Explicit control selection'
        }
        $lines = @(
            'WINSEC ANALYZER - CONFIRM SCAN / RESCAN'
            ('Device: {0}' -f $Request.Hostname)
            ('DeviceId: {0}' -f $Request.DeviceId)
            ('Scope: {0}' -f $scope)
            'Mode: READ ONLY - no Windows configuration changes'
            'Raw evidence storage: NOT REQUESTED'
            ('Executable controls: {0}' -f @($Request.Checks).Count)
        )
        foreach ($check in $Request.Checks) {
            $lines += '{0} | {1} | {2}' -f $check.CheckId, $check.SectionKey, $check.Name
        }
        $hasChecks = @($Request.Checks).Count -gt 0
        if (-not $hasChecks) {
            $lines += 'NO_EXECUTABLE_CHECKS - no audit will be started. NOT_SCORED.'
        }
        $lines += if ($hasChecks) {
            '[Y] Confirm this operation | [Esc / N / Enter] Cancel'
        }
        else {
            '[Esc / N / Enter] Back'
        }

        # Wrap every field completely; do not approve truncated requests.
        $wrapped = @(
            foreach ($line in $lines) {
                for ($offset = 0; $offset -lt $line.Length; $offset += $width) {
                    $line.Substring($offset, [Math]::Min($width, $line.Length - $offset))
                }
            }
        )
        if ($terminal.Width -lt 40 -or $terminal.Height -lt ($wrapped.Count + 1)) {
            Write-WinSecText -Text 'Resize to view the complete scan request.' -Color Yellow
            Write-WinSecText -Text ('Required height at this width: {0}' -f ($wrapped.Count + 1))
            Write-WinSecText -Text '[Esc / N / Enter] Cancel'
            return
        }
        foreach ($line in $wrapped) { Write-WinSecText -Text $line }
        $display.CanConfirm = $hasChecks
    }

    $resizeState = New-WinSecResizeState
    $null = & $render $null
    while ($true) {
        $key = Read-WinSecResizeAwareKey -ResizeState $resizeState -RenderAction $render
        $null = Invoke-WinSecResizeHandler -ResizeState $resizeState -RenderAction $render
        if ($null -eq $key -or $key.KeyDown -ceq $false -or
            ([int]$key.ControlKeyState -band 0x0F) -ne 0) { continue }
        if ($key.VirtualKeyCode -in @(27, 13) -or [string]$key.Character -ieq 'N') {
            return $false
        }
        if ($display.CanConfirm -and [string]$key.Character -ieq 'Y') {
            return $true
        }
    }
}
