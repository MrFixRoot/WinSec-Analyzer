# Real confirmation screen, synthetic requests/keyboard/terminal; no provider calls.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/UI/Screens/ScanConfirmation.ps1')
$script:passed=0;$script:failed=0
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines=@();$script:colors=@()}
function Write-WinSecText {param($Text,$Color);$script:lines+=[string]$Text;$script:colors+=[string]$Color}
function New-WinSecResizeState {[pscustomobject]@{}}
function Invoke-WinSecResizeHandler {param($ResizeState,$RenderAction)}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if($script:keys.Count -eq 0){throw 'Synthetic confirmation input exhausted.'}
    $key=$script:keys.Dequeue()
    if($null -ne $key.PSObject.Properties['Terminal']){$script:terminal=$key.Terminal;$null=& $RenderAction $null}
    return $key
}
function Add-WinSecScoringKey {
    param([int]$Code,[int]$Modifiers=0,[bool]$Down=$true,[object]$Terminal=$null)
    $key=[pscustomobject]@{VirtualKeyCode=$Code;Character='';ControlKeyState=$Modifiers;KeyDown=$Down}
    if($null -ne $Terminal){$key|Add-Member Terminal $Terminal}
    $script:keys.Enqueue($key)
}
function Assert-WinSecScoringDialog {param([bool]$Value);if(-not $Value){throw 'Scoring confirmation assertion failed.'}}
function Test-WinSecScoringDialog {
    param([string]$Name,[scriptblock]$Action)
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55}
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    $script:request=[pscustomobject]@{Operation='SCAN';ReadOnly=$true;DeviceId=('local:hw1-'+('a'*64));Hostname='SYNTHETIC'
        SelectionMode='EXPLICIT_CHECKS';ScopeType='CONTROL';ScopeKey='WSA-SYS-001';ScanAction='Scan'
        Checks=@([pscustomobject]@{CheckId='WSA-SYS-001';SectionKey='SystemSecurity';Name='Synthetic control'})
        EvaluationProfile=[pscustomobject]@{Profile='SYNTHETIC-PROFILE';Policies=@([pscustomobject]@{
            CheckId='WSA-SYS-001';CatalogId='SYNTHETIC-CATALOG';CatalogVersion='1.0.0';CatalogSha256=('A'*64)
            OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='SKU:48'})}
        ConfigurationScoring=[pscustomobject]@{MethodologyId='WSA_CONTROL_CRITERIA_MEAN';MethodologyVersion='1.2.0';PolicySha256=('B'*64)}}
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
foreach($version in @('1.0.0','1.1.0','1.2.0')) {
    Test-WinSecScoringDialog ('Explicit Enter accepts and describes the supported method: '+$version) {
        $script:request.ConfigurationScoring.MethodologyVersion=$version;Add-WinSecScoringKey 13
        Assert-WinSecScoringDialog (Show-WinSecScanConfirmation $script:request)
        $text=$script:lines -join '|'
        Assert-WinSecScoringDialog ($text.Contains('WSA_CONTROL_CRITERIA_MEAN / '+$version) -and
            $text.Contains('B'*64) -and $text.Contains('READ ONLY') -and
            $text.Contains('weighted verified') -eq ($version -ceq '1.2.0'))
    }
}
foreach($cancel in @('Escape','ArrowEnter','Letters','ModifiedEnter','ReleasedEnter')) {
    Test-WinSecScoringDialog ('Weighted confirmation can be safely cancelled: '+$cancel) {
        switch($cancel) {
            Escape {Add-WinSecScoringKey 27}
            ArrowEnter {Add-WinSecScoringKey 39;Add-WinSecScoringKey 13}
            Letters {Add-WinSecScoringKey 89;Add-WinSecScoringKey 78;Add-WinSecScoringKey 27}
            ModifiedEnter {Add-WinSecScoringKey 13 -Modifiers 8;Add-WinSecScoringKey 27}
            ReleasedEnter {Add-WinSecScoringKey 13 -Down $false;Add-WinSecScoringKey 27}
        }
        Assert-WinSecScoringDialog (-not (Show-WinSecScanConfirmation $script:request))
    }
}
foreach($size in @(@{W=16;H=5},@{W=40;H=10},@{W=80;H=12})) {
    Test-WinSecScoringDialog ('A truncated weighted request cannot be approved: '+$size.W+'x'+$size.H) {
        $script:terminal=[pscustomobject]@{Width=$size.W;ContentWidth=($size.W-1);Height=$size.H}
        Add-WinSecScoringKey 13;Add-WinSecScoringKey 27
        Assert-WinSecScoringDialog (-not (Show-WinSecScanConfirmation $script:request) -and
            $script:colors -contains 'Yellow' -and @($script:lines|Where-Object {$_.Length -ge $size.W}).Count -eq 0)
    }
}
Test-WinSecScoringDialog 'Resize requires a subsequent explicit Enter after the complete request becomes visible' {
    $full=$script:terminal;$script:terminal=[pscustomobject]@{Width=16;ContentWidth=15;Height=5}
    Add-WinSecScoringKey 13;Add-WinSecScoringKey 0 -Terminal $full;Add-WinSecScoringKey 13
    Assert-WinSecScoringDialog (Show-WinSecScanConfirmation $script:request)
}
foreach($version in @('9.0.0','1.2','',@('1.1.0','1.2.0'),1)) {
    Test-WinSecScoringDialog 'Unknown or nonscalar methods cannot enter the confirmation dialog' {
        $script:request.ConfigurationScoring.MethodologyVersion=$version
        $caught=$false;try{$null=Show-WinSecScanConfirmation $script:request}catch{$caught=$true}
        Assert-WinSecScoringDialog $caught
    }
}
Test-WinSecScoringDialog 'Weighted scoring requires the profile and a valid policy hash' {
    $script:request.ConfigurationScoring.PolicySha256='not-a-hash'
    $caught=$false;try{$null=Show-WinSecScanConfirmation $script:request}catch{$caught=$true}
    Assert-WinSecScoringDialog $caught
    $script:request.ConfigurationScoring.PolicySha256='B'*64;$script:request.PSObject.Properties.Remove('EvaluationProfile')
    $caught=$false;try{$null=Show-WinSecScanConfirmation $script:request}catch{$caught=$true}
    Assert-WinSecScoringDialog $caught
}
[Console]::WriteLine(('Scoring confirmation: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Scoring confirmation tests failed.'}
