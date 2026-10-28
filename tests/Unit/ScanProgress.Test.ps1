# Control-count progress and cooperative cancellation; all collectors and input are synthetic.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/AuditEngine.ps1')
. (Join-Path $root 'src/Core/ResultModel.ps1')
. (Join-Path $root 'src/UI/Screens/ScanProgress.ps1')
$script:passed = 0; $script:failed = 0
function Assert-WinSecProgress {
    param([bool]$Condition)
    if (-not $Condition) { throw 'Progress assertion failed.' }
}
function Test-WinSecProgress {
    param([string]$Name, [scriptblock]$Action)
    $script:collected = 0
    $script:events = New-Object 'System.Collections.Generic.List[object]'
    $script:keys = New-Object 'System.Collections.Generic.Queue[object]'
    $script:lines = New-Object 'System.Collections.Generic.List[string]'
    $script:colors = New-Object 'System.Collections.Generic.List[string]'
    $script:terminal = [pscustomobject]@{Width=80;ContentWidth=79;Height=25}
    $script:display = New-WinSecScanProgressState -DeviceId 'local:PROGRESS-FIXTURE' -ScopeLabel 'Control'
    try { $null = & $Action; $script:passed++; Write-Host ('[PASS] ' + $Name) }
    catch { $script:failed++; Write-Host ('[FAIL] ' + $Name + ' : ' + $_.Exception.Message); Write-Host $_.ScriptStackTrace }
}
function Import-WinSecAuditDependencies { param([switch]$SkipScoring); Assert-WinSecProgress ([bool]$SkipScoring) }
function New-WinSecLocalTarget { [pscustomobject]@{DeviceId='local:PROGRESS-FIXTURE'} }
function Invoke-WinSecAuditCheck {
    param($Check, $DeviceId, $ScanId)
    $script:collected++
    New-WinSecAuditRecord -Check $Check -DeviceId $DeviceId -ScanId $ScanId `
        -Status INFORMATIONAL -ObservedStatus INFORMATIONAL -Evidence @{Secret='PRIVATE-PROGRESS-MARKER'}
}
function Get-WinSecTerminalSize { $script:terminal }
function Clear-WinSecScreen { $script:lines.Clear();$script:colors.Clear() }
function Write-WinSecText { param($Text,$Color); $script:lines.Add([string]$Text);$script:colors.Add([string]$Color) }
function Read-WinSecPendingKey { if ($script:keys.Count) { return $script:keys.Dequeue() }; return $null }
function New-WinSecProgressEvent {
    param([string]$Phase='READING', [int]$Completed=0, [int]$Total=2)
    [pscustomobject]@{SchemaVersion='1.0.0';DeviceId='local:PROGRESS-FIXTURE';ScanId='progress-1';
        Phase=$Phase;CompletedChecks=$Completed;TotalChecks=$Total;CheckId='WSA-SYS-001'}
}
$script:registry = [pscustomobject]@{
    CatalogVersion='0.9.0';Sections=@();Checks=@(
        [pscustomobject]@{CheckId='WSA-SYS-001';ExecutionEnabled=$true;ExecutionReady=$true;ImplementationStatus='VALIDATED'},
        [pscustomobject]@{CheckId='WSA-SYS-002';ExecutionEnabled=$true;ExecutionReady=$true;ImplementationStatus='VALIDATED'},
        [pscustomobject]@{CheckId='WSA-NET-001';ExecutionEnabled=$false;ExecutionReady=$false;ImplementationStatus='PLANNED'}
    )
}
$notify = { param($event); $script:events.Add((Copy-WinSecResultData $event)) }

Test-WinSecProgress 'Counts advance only after selected collectors return' {
    $result = @(Invoke-WinSecAudit -Registry $script:registry -SkipScoring -ProgressCallback $notify)
    Assert-WinSecProgress ($result.Count -eq 1 -and $script:collected -eq 2 -and $script:events.Count -eq 4)
    Assert-WinSecProgress (($script:events.Phase -join ',') -ceq 'READING,CHECK_COMPLETED,READING,CHECK_COMPLETED')
    Assert-WinSecProgress (($script:events.CompletedChecks -join ',') -ceq '0,1,1,2')
    Assert-WinSecProgress (@($script:events | Where-Object TotalChecks -NE 2).Count -eq 0)
    Assert-WinSecProgress (($script:events | ConvertTo-Json -Depth 8) -notmatch 'PRIVATE-PROGRESS-MARKER|Evidence')
}
Test-WinSecProgress 'Progress output and event mutation cannot alter the audit result' {
    $result = @(Invoke-WinSecAudit -Registry $script:registry -SkipScoring -ProgressCallback {
        param($event); $event.CheckId='FOREIGN'; $event.CompletedChecks=900; 'Unwanted callback output'
    })
    Assert-WinSecProgress ($result.Count -eq 1 -and $result[0].ExecutedChecks -eq 2)
    Assert-WinSecProgress ($result[0].ControlResults[0].CheckId -ceq 'WSA-SYS-001')
}
Test-WinSecProgress 'Display errors do not change collector execution' {
    $result = Invoke-WinSecAudit -Registry $script:registry -SkipScoring -ProgressCallback { throw 'PRIVATE-DISPLAY-ERROR' }
    Assert-WinSecProgress ($result.ExecutedChecks -eq 2)
}
Test-WinSecProgress 'Cancellation before the first control executes nothing' {
    $caught=$false
    try { $null=Invoke-WinSecAudit -Registry $script:registry -SkipScoring -ProgressCallback $notify -CancellationAction {$true} }
    catch [OperationCanceledException] { $caught=$true }
    Assert-WinSecProgress ($caught -and $script:collected -eq 0 -and $script:events[0].Phase -ceq 'CANCELLED')
}
Test-WinSecProgress 'Cancellation after one control prevents the next control' {
    $caught=$false
    try { $null=Invoke-WinSecAudit -Registry $script:registry -SkipScoring -ProgressCallback $notify -CancellationAction {$script:collected -ge 1} }
    catch [OperationCanceledException] { $caught=$true }
    Assert-WinSecProgress ($caught -and $script:collected -eq 1 -and $script:events[-1].Phase -ceq 'CANCELLED')
    Assert-WinSecProgress ($script:events[-1].CompletedChecks -eq 1)
}
foreach ($badDecision in @({ 'true' }, { @($true,$false) }, { throw 'PRIVATE-CANCEL-ERROR' })) {
    Test-WinSecProgress 'Ambiguous or failed cancellation input aborts safely' {
        $caught=$false
        try { $null=Invoke-WinSecAudit -Registry $script:registry -SkipScoring -CancellationAction $badDecision }
        catch { $caught=$true; Assert-WinSecProgress ($_.Exception.Message -notmatch 'PRIVATE-CANCEL-ERROR') }
        Assert-WinSecProgress ($caught -and $script:collected -eq 0)
    }
}
Test-WinSecProgress 'Reading is 0 percent and finalizing cannot claim 100 percent' {
    Show-WinSecScanProgress $script:display (New-WinSecProgressEvent)
    Assert-WinSecProgress (($script:lines -join '|') -match '\b0%' -and ($script:lines -join '|') -match 'Reading control')
    Show-WinSecScanProgress $script:display (New-WinSecProgressEvent FINALIZING 2)
    Assert-WinSecProgress (($script:lines -join '|') -match '99%' -and ($script:lines -join '|') -notmatch '100%')
    Show-WinSecScanProgress $script:display (New-WinSecProgressEvent COMPLETED 2)
    Assert-WinSecProgress (($script:lines -join '|') -match '100%' -and ($script:lines -join '|') -match 'Scan COMPLETE' -and ($script:lines -join '|') -notmatch 'NOT_SCORED')
}
Test-WinSecProgress 'Cancellation and technical warnings are yellow; normal progress retains cyan' {
    Show-WinSecScanProgress $script:display (New-WinSecProgressEvent)
    Assert-WinSecProgress (@($script:colors|Where-Object {$_ -cne 'Cyan'}).Count -eq 0)
    Show-WinSecScanProgress $script:display (New-WinSecProgressEvent CANCELLED)
    Assert-WinSecProgress (@($script:colors|Where-Object {$_ -cne 'Yellow'}).Count -eq 0 -and
        ($script:lines -join '|') -match 'No new scan saved')
    Show-WinSecScanProgress $script:display (New-WinSecProgressEvent COMPLETED_WITH_ERRORS 2)
    Assert-WinSecProgress (@($script:colors|Where-Object {$_ -cne 'Yellow'}).Count -eq 0)
}
Test-WinSecProgress 'Half the selected controls produces 50 percent' {
    Show-WinSecScanProgress $script:display (New-WinSecProgressEvent CHECK_COMPLETED 1)
    Assert-WinSecProgress (($script:lines -join '|') -match '50%')
}
Test-WinSecProgress 'Small terminals and resize fit without advancing counts or collecting' {
    Show-WinSecScanProgress $script:display (New-WinSecProgressEvent CHECK_COMPLETED 1)
    foreach ($size in @(@{W=40;H=10},@{W=16;H=5},@{W=1;H=1},@{W=100;H=30})) {
        $script:terminal=[pscustomobject]@{Width=$size.W;ContentWidth=[Math]::Max(1,$size.W-1);Height=$size.H}
        $null=Test-WinSecScanProgressCancellation $script:display
        Assert-WinSecProgress (@($script:lines|Where-Object {$_.Length -gt $script:terminal.ContentWidth}).Count -eq 0)
        Assert-WinSecProgress ($script:lines.Count -le $size.H-1 -and $script:display.LastProgress.CompletedChecks -eq 1)
    }
    Assert-WinSecProgress ($script:collected -eq 0)
}
Test-WinSecProgress 'Escape requests cancellation but modifiers and key releases do not' {
    foreach ($key in @(
        @{VirtualKeyCode=27;KeyDown=$true;ControlKeyState=8},
        @{VirtualKeyCode=27;KeyDown=$false;ControlKeyState=0}
    )) { $script:keys.Enqueue([pscustomobject]$key) }
    Assert-WinSecProgress (-not (Test-WinSecScanProgressCancellation $script:display))
    $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=27;KeyDown=$true;ControlKeyState=0})
    Assert-WinSecProgress (Test-WinSecScanProgressCancellation $script:display)
}
foreach ($mutation in @(
    {param($e);$e.DeviceId='local:FOREIGN'}, {param($e);$e.ScanId='foreign-scan'},
    {param($e);$e.CompletedChecks=3}, {param($e);$e.Phase='COMPLETED'},
    {param($e);$e|Add-Member -NotePropertyName Evidence -NotePropertyValue @{Secret='PRIVATE'} }
)) {
    Test-WinSecProgress 'Invalid, foreign or private progress cannot overwrite the display' {
        Show-WinSecScanProgress $script:display (New-WinSecProgressEvent)
        $before=$script:lines -join '|';$event=New-WinSecProgressEvent;$null=& $mutation $event;$caught=$false
        try {Show-WinSecScanProgress $script:display $event} catch {$caught=$true}
        Assert-WinSecProgress ($caught -and ($script:lines -join '|') -ceq $before)
    }
}
Test-WinSecProgress 'Firewall stages advance within the control and repeated heartbeats do not redraw' {
    $event=New-WinSecProgressEvent;$event.SchemaVersion='2.0.0';$event.CheckId='WSA-NET-001';$event.TotalChecks=1
    $event|Add-Member Stage 'RULESACTIVE';$event|Add-Member CompletedSteps 7;$event|Add-Member TotalSteps 28
    Show-WinSecScanProgress $script:display $event
    Assert-WinSecProgress (($script:lines -join '|') -match '25%' -and ($script:lines -join '|') -match 'RULESACTIVE' -and ($script:lines -join '|') -match 'Esc: cancel Firewall')
    $before=$script:lines -join '|';$script:lines.Add('REDRAW-GUARD')
    Show-WinSecScanProgress $script:display $event
    Assert-WinSecProgress ($script:lines[-1] -ceq 'REDRAW-GUARD')
    $script:terminal=[pscustomobject]@{Width=16;ContentWidth=15;Height=5}
    Show-WinSecScanProgress $script:display $event
    Assert-WinSecProgress (@($script:lines|Where-Object {$_.Length -gt 15}).Count -eq 0 -and $script:display.LastProgress.CompletedSteps -eq 7)
}
Write-Host ('Scan progress: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if ($script:failed) { throw 'Scan progress unit tests failed.' }
