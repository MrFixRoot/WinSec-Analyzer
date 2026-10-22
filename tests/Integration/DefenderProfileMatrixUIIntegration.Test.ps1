# Descubrimiento y selector reales con 101 perfiles; teclado y terminal sintéticos.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/UI/Screens/AssessmentProfileSelection.ps1')
function Get-CimInstance {throw 'Unexpected Windows query in profile UI integration.'}
function Get-MpComputerStatus {throw 'Unexpected Defender query in profile UI integration.'}
function Get-MpPreference {throw 'Unexpected Defender query in profile UI integration.'}
$profiles=@(Get-WinSecAssessmentProfileOptions $root @('WSA-SYS-001'))
$editionNames=@((Get-WinSecDefenderProfileMatrix $root).Matrix.Editions | Sort-Object Name | ForEach-Object {$_.Name})
$request=[pscustomobject]@{Operation='SCAN';ReadOnly=$true;DeviceId='local:PROFILE-MATRIX';Hostname='SYNTHETIC';
    ScopeType='CONTROL';ScopeKey='WSA-SYS-001';Checks=@([pscustomobject]@{CheckId='WSA-SYS-001';SectionKey='SystemSecurity'})}
$script:passed=0;$script:failed=0
function Assert-WinSecMatrixUI {param([bool]$Value);if(-not $Value){throw 'Profile matrix UI assertion failed.'}}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear()}
function Write-WinSecText {param($Text,$Color);$script:lines.Add([string]$Text)}
function New-WinSecResizeState {[pscustomobject]@{}}
function Invoke-WinSecResizeHandler {param($ResizeState,$RenderAction);return $false}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if($script:keys.Count -eq 0){throw 'Synthetic profile key queue exhausted.'}
    $key=$script:keys.Dequeue()
    if($null -ne $key.Terminal){$script:terminal=$key.Terminal;$null=& $RenderAction $null}
    if($null -ne $key.Hook){$null=& $key.Hook ($script:lines.ToArray())}
    $key
}
function Add-WinSecMatrixUIKey {
    param([int]$Code,[string]$Character='',[object]$Terminal=$null,[scriptblock]$Hook=$null)
    $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$Code;Character=$Character;Terminal=$Terminal;Hook=$Hook;KeyDown=$true;ControlKeyState=0})
}
function Add-WinSecMatrixOperatingSystem {
    param([string]$Name)
    $index=[array]::IndexOf($editionNames,$Name)
    if($index -lt 0){throw 'Unknown fixture operating system.'}
    for($i=0;$i -le $index;$i++){Add-WinSecMatrixUIKey 40}
    Add-WinSecMatrixUIKey 13
}
function Test-WinSecMatrixUI {
    param([string]$Name,[scriptblock]$Action)
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=50}
    $script:lines=New-Object 'System.Collections.Generic.List[string]'
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
Test-WinSecMatrixUI 'The last operating system opens its reviewed build with exact provenance and unchanged caller data' {
    $before=Get-WinSecPublicHistoryJson $profiles
    Add-WinSecMatrixUIKey 38;Add-WinSecMatrixUIKey 13;Add-WinSecMatrixUIKey 13
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    $plan=Get-WinSecAssessmentProfilePlan $root @('WSA-SYS-001') $answer.Selection.Profile
    Assert-WinSecMatrixUI ($profiles.Count -eq 101 -and $answer.Confirmed -ceq $true -and
        $answer.Selection.Profile -ceq 'WSA-W11-21H2-PRO-N-DEF-BASE' -and
        $answer.Selection.Policies[0].CatalogSha256 -ceq $plan.Preview.Policies[0].CatalogSha256 -and
        $before -ceq (Get-WinSecPublicHistoryJson $profiles) -and ($script:lines -join '|').Contains('Choice 1 / 7') -and
        ($script:lines -join '|').Contains('Windows 11 / Pro N') -and ($script:lines -join '|').Contains('21H2 | build 22000'))
}
Test-WinSecMatrixUI 'All 17 operating systems wrap back to collection only without implicit selection' {
    for($i=0;$i -lt 18;$i++){Add-WinSecMatrixUIKey 40}
    Add-WinSecMatrixUIKey 13
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI ($answer.Confirmed -ceq $true -and $null -eq $answer.Selection -and $script:keys.Count -eq 0)
}
foreach($code in @(78,27)) {
    Test-WinSecMatrixUI 'Esc cancels after navigation; N cannot decide' {
        Add-WinSecMatrixUIKey 38;Add-WinSecMatrixUIKey $code $(if($code -eq 78){'n'}else{''})
        if($code -eq 78){Add-WinSecMatrixUIKey 27}
        $answer=Show-WinSecAssessmentProfileSelection $request $profiles
        Assert-WinSecMatrixUI ($answer.Confirmed -ceq $false -and $null -eq $answer.Selection -and $script:keys.Count -eq 0)
    }
}
Test-WinSecMatrixUI 'Tiny terminal cannot confirm a hidden profile and remains bounded' {
    $script:terminal=[pscustomobject]@{Width=16;ContentWidth=15;Height=5}
    Add-WinSecMatrixUIKey 38;Add-WinSecMatrixUIKey 13;Add-WinSecMatrixUIKey 27
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI (-not $answer.Confirmed -and $script:lines.Count -lt 5 -and @($script:lines|Where-Object Length -GT 15).Count -eq 0)
}
Test-WinSecMatrixUI 'Resizing preserves the expanded choice and still requires fresh Enter' {
    $script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=10}
    Add-WinSecMatrixUIKey 38;Add-WinSecMatrixUIKey 13
    Add-WinSecMatrixUIKey 0 '' ([pscustomobject]@{Width=120;ContentWidth=119;Height=50})
    Add-WinSecMatrixUIKey 13;Add-WinSecMatrixUIKey 13
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI ($answer.Confirmed -ceq $true -and $answer.Selection.Profile -ceq 'WSA-W11-21H2-PRO-N-DEF-BASE' -and $script:keys.Count -eq 0)
}
Test-WinSecMatrixUI 'Windows 11 Pro then 23H2 build 22631 returns exactly the offered profile' {
    Add-WinSecMatrixOperatingSystem Pro
    Add-WinSecMatrixUIKey 40;Add-WinSecMatrixUIKey 40;Add-WinSecMatrixUIKey 13
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI ($answer.Selection.Profile -ceq 'WSA-W11-23H2-PRO-DEF-BASE' -and
        $answer.Selection.Policies[0].Edition -ceq 'SKU:48' -and
        ($script:lines -join '|').Contains('23H2 | build 22631'))
}
Test-WinSecMatrixUI 'Build arrows wrap only within the selected edition' {
    Add-WinSecMatrixOperatingSystem Pro
    Add-WinSecMatrixUIKey 38;Add-WinSecMatrixUIKey 13
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI ($answer.Selection.Profile -ceq 'WSA-W11-26H2-PRO-DEF-BASE' -and
        ($script:lines -join '|').Contains('Choice 7 / 7'))
}
Test-WinSecMatrixUI 'Escape from builds restores the operating system selection; a second Escape exits' {
    Add-WinSecMatrixOperatingSystem Pro
    Add-WinSecMatrixUIKey 27 -Hook {Assert-WinSecMatrixUI (($script:lines -join '|').Contains('VERSION / BUILD'))}
    Add-WinSecMatrixUIKey 27 -Hook {Assert-WinSecMatrixUI (($script:lines -join '|').Contains('OPERATING SYSTEM / EDITION') -and
        ($script:lines -join '|').Contains('Selected: Windows 11 / Pro'))}
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI (-not $answer.Confirmed -and $null -eq $answer.Selection -and $script:keys.Count -eq 0)
}
Test-WinSecMatrixUI 'Y and N cannot decide in the build list; Esc returns and exits by level' {
    Add-WinSecMatrixOperatingSystem Pro
    Add-WinSecMatrixUIKey 89 'y';Add-WinSecMatrixUIKey 78 'n';Add-WinSecMatrixUIKey 27;Add-WinSecMatrixUIKey 27
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI (-not $answer.Confirmed -and $null -eq $answer.Selection -and $script:keys.Count -eq 0)
}
Test-WinSecMatrixUI 'A tiny build screen cannot confirm; resizing preserves the build and requires fresh Enter' {
    Add-WinSecMatrixOperatingSystem Pro
    Add-WinSecMatrixUIKey 40
    Add-WinSecMatrixUIKey 13 '' ([pscustomobject]@{Width=16;ContentWidth=15;Height=5})
    Add-WinSecMatrixUIKey 0 '' ([pscustomobject]@{Width=120;ContentWidth=119;Height=50})
    Add-WinSecMatrixUIKey 13
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles
    Assert-WinSecMatrixUI ($answer.Selection.Profile -ceq 'WSA-W11-22H2-PRO-DEF-BASE' -and $script:keys.Count -eq 0)
}
Test-WinSecMatrixUI 'All 101 profiles remain reachable through their operating system and ordered builds' {
    $matrix=(Get-WinSecDefenderProfileMatrix $root).Matrix
    $systemIndex=0
    foreach($edition in @($matrix.Editions|Sort-Object Name)){
        $systemIndex++
        $releases=@($matrix.Releases|Where-Object {$_.Name -cin $edition.Releases})
        for($buildIndex=0;$buildIndex -lt $releases.Count;$buildIndex++){
            for($i=0;$i -lt $systemIndex;$i++){Add-WinSecMatrixUIKey 40}
            Add-WinSecMatrixUIKey 13
            for($i=0;$i -lt $buildIndex;$i++){Add-WinSecMatrixUIKey 40}
            Add-WinSecMatrixUIKey 13
            $answer=Show-WinSecAssessmentProfileSelection $request $profiles
            Assert-WinSecMatrixUI ($answer.Confirmed -and $answer.Selection.Profile -ceq ('WSA-W11-{0}-{1}-DEF-BASE' -f $releases[$buildIndex].Name,$edition.Key))
        }
    }
}
Test-WinSecMatrixUI 'Operating systems are alphabetical while collection only remains the first explicit choice' {
    foreach($name in $editionNames){
        Add-WinSecMatrixUIKey 40
        $expected=$name
        Add-WinSecMatrixUIKey 0 -Hook ({param($Lines);Assert-WinSecMatrixUI (($Lines -join '|').Contains('Selected: Windows 11 / '+$expected))}.GetNewClosure())
    }
    Add-WinSecMatrixUIKey 27
    Assert-WinSecMatrixUI (-not(Show-WinSecAssessmentProfileSelection $request $profiles).Confirmed)
}
Test-WinSecMatrixUI 'The observed local OS is informational and does not preselect or approve a profile' {
    Add-WinSecMatrixUIKey 27
    $answer=Show-WinSecAssessmentProfileSelection $request $profiles -CurrentSystemLabel 'Pro 22H2 | build: 22621'
    Assert-WinSecMatrixUI (-not $answer.Confirmed -and ($script:lines -join '|').Contains('Current OS: Pro 22H2 | build: 22621') -and
        ($script:lines -join '|').Contains('Selected: Collection only'))
}
[Console]::WriteLine(('Profile matrix UI integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Profile matrix UI integration failed.'}
