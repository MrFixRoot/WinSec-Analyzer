# Real control-count progress. No timers, collection or persistence in the UI.
function New-WinSecScanProgressState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DeviceId,
        [Parameter(Mandatory)][string]$ScopeLabel,
        [ValidateSet('Scan','Rescan')][string]$ScanAction = 'Scan'
    )
    foreach ($value in @($DeviceId, $ScopeLabel)) {
        if ([string]::IsNullOrWhiteSpace($value) -or $value -match '[\x00-\x1f\x7f]') {
            throw 'Invalid scan progress context.'
        }
    }
    [pscustomobject]@{
        DeviceId = $DeviceId; ScopeLabel = $ScopeLabel; ScanAction = $ScanAction
        ScanId = ''; CancelRequested = $false; LastProgress = $null
        Width = 0; Height = 0
    }
}

function Show-WinSecScanProgress {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$State, [Parameter(Mandatory)][object]$Progress)
    $event = Copy-WinSecResultData $Progress
    $fields = @('SchemaVersion','DeviceId','ScanId','Phase','CompletedChecks','TotalChecks','CheckId')
    if($event.SchemaVersion -ceq '2.0.0'){$fields+=@('Stage','CompletedSteps','TotalSteps')}
    if (@($event.PSObject.Properties).Count -ne $fields.Count -or
        @($event.PSObject.Properties | Where-Object { $_.Name -cnotin $fields }).Count -gt 0) {
        throw 'Scan progress contains unsupported fields.'
    }
    if ($event.SchemaVersion -cnotin @('1.0.0','2.0.0') -or $event.DeviceId -cne $State.DeviceId -or
        $event.ScanId -isnot [string] -or $event.ScanId -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z' -or
        $event.Phase -isnot [string] -or
        $event.Phase -cnotin @('READING','CHECK_COMPLETED','FINALIZING','COMPLETED','COMPLETED_WITH_ERRORS','CANCELLED') -or
        $event.CompletedChecks -isnot [int] -or $event.TotalChecks -isnot [int] -or
        $event.TotalChecks -lt 1 -or $event.CompletedChecks -lt 0 -or $event.CompletedChecks -gt $event.TotalChecks -or
        $event.CheckId -isnot [string] -or
        ($event.CheckId -ne '' -and $event.CheckId -cnotmatch '\AWSA-[A-Z]{3}-[0-9]{3}\z')) {
        throw 'Invalid scan progress event.'
    }
    if (($State.ScanId -ne '' -and $State.ScanId -cne $event.ScanId) -or
        ($null -ne $State.LastProgress -and ($State.LastProgress.TotalChecks -ne $event.TotalChecks -or
            $State.LastProgress.CompletedChecks -gt $event.CompletedChecks))) {
        throw 'Scan progress identity or counts changed.'
    }
    $finished = $event.Phase -cin @('COMPLETED','COMPLETED_WITH_ERRORS')
    $fraction=0.0
    if($event.SchemaVersion -ceq '2.0.0') {
        if($event.Phase -cne 'READING' -or $event.CheckId -cnotin @('WSA-NET-001','WSA-NET-002','WSA-NET-003','WSA-NET-004') -or $event.Stage -isnot [string] -or
            $event.Stage -cnotmatch '\A[A-Z]{1,40}\z' -or $event.CompletedSteps -isnot [int] -or $event.TotalSteps -isnot [int] -or
            $event.TotalSteps -lt 1 -or $event.CompletedSteps -lt 0 -or $event.CompletedSteps -gt $event.TotalSteps){throw 'Invalid collector progress detail.'}
        $fraction=[double]$event.CompletedSteps/$event.TotalSteps
    }
    if (($finished -or $event.Phase -ceq 'FINALIZING') -and $event.CompletedChecks -ne $event.TotalChecks) {
        throw 'Scan progress cannot finish before every selected control returns.'
    }
    $percent = if ($finished) { 100 } else {
        [Math]::Min(99, [int][Math]::Floor(100.0 * ($event.CompletedChecks+$fraction) / $event.TotalChecks))
    }
    $terminal = Get-WinSecTerminalSize
    if($null -ne $State.LastProgress -and $terminal.Width -eq $State.Width -and $terminal.Height -eq $State.Height -and
        (ConvertTo-Json -InputObject $event -Compress -Depth 5) -ceq (ConvertTo-Json -InputObject $State.LastProgress -Compress -Depth 5)){return}
    $width = [Math]::Max(1, [int]$terminal.ContentWidth)
    $barWidth = [Math]::Max(1, [Math]::Min(30, $width - 9))
    $filled = [int][Math]::Floor($barWidth * $percent / 100.0)
    $bar = (([string][char]0x2588) * $filled) + (([string][char]0x2591) * ($barWidth - $filled))
    $message = switch ($event.Phase) {
        'READING' { 'Reading control: ' + $event.CheckId }
        'CHECK_COMPLETED' { 'Control finished: ' + $event.CheckId }
        'FINALIZING' { 'Validating / saving public results...' }
        'COMPLETED' { 'Scan COMPLETE. Saved readings are ready for framework review.' }
        'COMPLETED_WITH_ERRORS' { 'Scan PARTIAL. Collection issues were recorded.' }
        'CANCELLED' { 'Cancelled. No new scan saved.' }
    }
    if($event.SchemaVersion -ceq '2.0.0'){$name=if($event.CheckId -ceq 'WSA-NET-001'){'Firewall'}elseif($event.CheckId -ceq 'WSA-NET-002'){'SMBv1'}elseif($event.CheckId -ceq 'WSA-NET-004'){'Open Ports'}else{'Remote Desktop'};$message=$name+': '+$event.Stage+' ('+$event.CompletedSteps+'/'+$event.TotalSteps+')'}
    $hint = if ($event.Phase -cin @('READING','CHECK_COMPLETED')) {
        if($event.CheckId -ceq 'WSA-NET-001'){'Esc: cancel Firewall collection'}elseif($event.CheckId -ceq 'WSA-NET-002'){'Esc: cancel SMBv1 collection'}elseif($event.CheckId -ceq 'WSA-NET-003'){'Esc: cancel RDP collection'}elseif($event.CheckId -ceq 'WSA-NET-004'){'Esc: cancel endpoint collection'}else{'Esc: stop after current control'}
    } elseif ($event.Phase -ceq 'FINALIZING') { 'Finishing; please wait.' } else { '' }
    $lines = @(
        ('WINSEC - ' + $State.ScanAction.ToUpperInvariant() + ' - READ ONLY'),
        $message,
        ('[{0}] {1,3}%' -f $bar, $percent),
        ('Controls completed: {0}/{1}' -f $event.CompletedChecks, $event.TotalChecks),
        ('Scope: ' + $State.ScopeLabel),
        ('Device: ' + $State.DeviceId),
        $hint
    )
    $State.ScanId = $event.ScanId
    $State.LastProgress = $event
    $State.Width = $terminal.Width; $State.Height = $terminal.Height
    Clear-WinSecScreen
    $color = if ($event.Phase -cin @('CANCELLED','COMPLETED_WITH_ERRORS')) {'Yellow'} else {'Cyan'}
    foreach ($line in @($lines | Select-Object -First ([Math]::Max(0, [int]$terminal.Height - 1)))) {
        Write-WinSecText -Text $line.Substring(0, [Math]::Min($line.Length, $width)) -Color $color
    }
}

function Test-WinSecScanProgressCancellation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$State)
    for ($i = 0; $i -lt 32; $i++) {
        $key = Read-WinSecPendingKey
        if ($null -eq $key) { break }
        if ($key.KeyDown -ceq $false -or ([int]$key.ControlKeyState -band 0x0F) -ne 0) { continue }
        if ($key.VirtualKeyCode -eq 27) { $State.CancelRequested = $true; break }
    }
    if ($null -ne $State.LastProgress) {
        $terminal = Get-WinSecTerminalSize
        if ($terminal.Width -ne $State.Width -or $terminal.Height -ne $State.Height) {
            Show-WinSecScanProgress -State $State -Progress $State.LastProgress
        }
    }
    return [bool]$State.CancelRequested
}
