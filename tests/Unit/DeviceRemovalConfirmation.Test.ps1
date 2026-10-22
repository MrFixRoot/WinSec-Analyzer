[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../src/UI/Screens/DeviceRemovalConfirmation.ps1')
$script:passed=0; $script:failed=0
function Get-WinSecTerminalSize { return $script:terminal }
function Clear-WinSecScreen { $script:lines=@() }
function Write-WinSecText { param($Text,$Color) $script:lines+= [string]$Text;$script:colors+=[string]$Color }
function New-WinSecResizeState { return [pscustomobject]@{} }
function Invoke-WinSecResizeHandler { param($ResizeState,$RenderAction) }
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    while ($script:keys.Count -gt 0) {
        $event=$script:keys.Dequeue()
        if ($event -is [scriptblock]) { $null=& $event; $null=& $RenderAction $null; continue }
        return $event
    }
    throw 'Unexpected extra keyboard read.'
}
function Add-WinSecRemovalKey {
    param([string]$Character,[int]$Code=0,[int]$Modifiers=0,[bool]$Down=$true)
    $script:keys.Enqueue([pscustomobject]@{Character=$Character; VirtualKeyCode=$Code; ControlKeyState=$Modifiers; KeyDown=$Down})
}
function Assert-WinSecDialog { param([bool]$Value) if (-not $Value) { throw 'Deletion dialog assertion failed.' } }
function Test-WinSecDialog {
    param([string]$Name,[scriptblock]$Action)
    $script:terminal=[pscustomobject]@{Width=80; ContentWidth=79; Height=40}
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    $script:colors=@()
    $script:request=[pscustomobject]@{Operation='DELETE_DEVICE'; DeviceId=('local:hw1-'+('a'*64)); Hostname='FIXTURE';
        MemoryScanCount=2; StoredFileCount=3; IncludesHistory=$true; Irreversible=$true; RegistersAgainOnStartup=$true}
    try { $null=& $Action; $script:passed++; Write-Host "[PASS] $Name" }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}
Test-WinSecDialog 'Explicit Y approves after rendering the complete identity and irreversible scope' {
    Add-WinSecRemovalKey Y
    Assert-WinSecDialog (Show-WinSecDeviceRemovalConfirmation $script:request)
    $text=$script:lines -join ' '
    Assert-WinSecDialog ($text -match 'permanently deletes' -and $text -match 'register again' -and
        $text -match 'Scans in this session: 2' -and $text -match 'files: 3' -and $text -match 'FIXTURE')
}
foreach ($key in @(@{C='';V=27},@{C='N';V=78})) {
    Test-WinSecDialog 'Esc and N cancel' {
        Add-WinSecRemovalKey $key.C $key.V
        Assert-WinSecDialog (-not (Show-WinSecDeviceRemovalConfirmation $script:request))
    }
}
Test-WinSecDialog 'Enter confirms only the fully visible deletion request' {
    Add-WinSecRemovalKey '' 13
    Assert-WinSecDialog (Show-WinSecDeviceRemovalConfirmation $script:request)
    Assert-WinSecDialog (($script:lines -join ' ') -match '\[Y\] Accept' -and
        ($script:lines -join ' ') -match '\[N / Esc\]')
}
Test-WinSecDialog 'Enter cannot approve a deletion on a truncated terminal' {
    $script:terminal.Height=4
    Add-WinSecRemovalKey '' 13; Add-WinSecRemovalKey N
    Assert-WinSecDialog (-not (Show-WinSecDeviceRemovalConfirmation $script:request))
}
Test-WinSecDialog 'Modified and release Enter events cannot approve deletion' {
    Add-WinSecRemovalKey '' 13 4;Add-WinSecRemovalKey '' 13 0 $false;Add-WinSecRemovalKey N
    Assert-WinSecDialog (-not (Show-WinSecDeviceRemovalConfirmation $script:request))
}
Test-WinSecDialog 'Small terminal cannot approve a truncated deletion request' {
    $script:terminal.Height=4
    Add-WinSecRemovalKey Y; Add-WinSecRemovalKey N
    Assert-WinSecDialog (-not (Show-WinSecDeviceRemovalConfirmation $script:request))
}
Test-WinSecDialog 'Resizing requires a new explicit Y after the full request becomes visible' {
    $script:terminal.Height=4
    Add-WinSecRemovalKey Y
    $script:keys.Enqueue({$script:terminal.Height=40})
    Add-WinSecRemovalKey Y
    Assert-WinSecDialog (Show-WinSecDeviceRemovalConfirmation $script:request)
}
Test-WinSecDialog 'Shrinking the terminal revokes prior display eligibility' {
    $script:keys.Enqueue({$script:terminal.Height=4})
    Add-WinSecRemovalKey Y; Add-WinSecRemovalKey N
    Assert-WinSecDialog (-not (Show-WinSecDeviceRemovalConfirmation $script:request))
}
Test-WinSecDialog 'Modifier and key release Y events cannot approve' {
    Add-WinSecRemovalKey Y 89 4; Add-WinSecRemovalKey Y 89 0 $false; Add-WinSecRemovalKey N
    Assert-WinSecDialog (-not (Show-WinSecDeviceRemovalConfirmation $script:request))
}
Test-WinSecDialog 'A scan request cannot authorize a deletion' {
    $script:request.Operation='SCAN'; $caught=$false
    try { $null=Show-WinSecDeviceRemovalConfirmation $script:request } catch { $caught=$true }
    Assert-WinSecDialog $caught
}
foreach($arrow in @(37,38,39,40)) {
    Test-WinSecDialog ('Arrow then Enter selects Cancel instead of deleting: '+$arrow) {
        Add-WinSecRemovalKey '' $arrow;Add-WinSecRemovalKey '' 13
        Assert-WinSecDialog (-not(Show-WinSecDeviceRemovalConfirmation $script:request) -and
            ($script:lines -join '|').Contains('> [ Cancel ]') -and $script:colors -contains 'Cyan')
    }
}
Test-WinSecDialog 'Accept can be selected again; irreversible-deletion warning is yellow' {
    Add-WinSecRemovalKey '' 39;Add-WinSecRemovalKey '' 37;Add-WinSecRemovalKey '' 13
    Assert-WinSecDialog ((Show-WinSecDeviceRemovalConfirmation $script:request) -and
        ($script:lines -join '|').Contains('> [ Accept ]') -and $script:colors -contains 'Yellow')
}
Test-WinSecDialog 'The selected Cancel survives resizing and still requires Enter' {
    Add-WinSecRemovalKey '' 40
    $script:keys.Enqueue({$script:terminal.Width=120;$script:terminal.ContentWidth=119})
    Add-WinSecRemovalKey '' 13
    Assert-WinSecDialog (-not(Show-WinSecDeviceRemovalConfirmation $script:request) -and $script:keys.Count -eq 0)
}
Test-WinSecDialog 'Deletion warnings fit a one-cell terminal and cannot accept' {
    $script:terminal=[pscustomobject]@{Width=1;ContentWidth=1;Height=1}
    Add-WinSecRemovalKey '' 13;Add-WinSecRemovalKey '' 27
    Assert-WinSecDialog (-not(Show-WinSecDeviceRemovalConfirmation $script:request) -and $script:lines.Count -eq 0)
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if ($script:failed -gt 0) { throw 'Deletion confirmation tests failed.' }
