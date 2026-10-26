# Real discovery/picker/profile-plan with a synthetic keyboard and terminal.
# No coordinator execution, provider queries, inventory/history or report writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/UI/Screens/AssessmentProfileSelection.ps1')
$script:providerCalls=0;$script:scanCalls=0
function Get-CimInstance {$script:providerCalls++;throw 'Unexpected Windows query.'}
function Invoke-WinSecCoordinatedScan {$script:scanCalls++;throw 'Unexpected scan.'}
function Save-WinSecPublicHistory {throw 'Unexpected history write.'}
function Get-WinSecTerminalSize {return $script:terminal}
function Clear-WinSecScreen {$script:lines.Clear()}
function Write-WinSecText {param($Text,$Color);$script:lines.Add([string]$Text)}
function New-WinSecResizeState {[pscustomobject]@{}}
function Invoke-WinSecResizeHandler {param($ResizeState,$RenderAction);return $false}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if(-not $script:keys.Count){throw 'Synthetic key queue exhausted.'}
    $key=$script:keys.Dequeue()
    if($null -ne $key.Terminal){$script:terminal=$key.Terminal;$null=& $RenderAction $null}
    return $key
}
function Add-WinSecVariantKey {
    param([int]$Code,[object]$Terminal=$null)
    $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$Code;Character='';ControlKeyState=0;KeyDown=$true;Terminal=$Terminal})
}
$options=@(Get-WinSecAssessmentProfileOptions $root @('WSA-SYS-003'))
$script:passed=0;$script:failed=0
function Assert-WinSecVariantSelection {param([bool]$Value);if(-not $Value){throw 'Variant selection integration assertion failed.'}}
function Test-WinSecVariantSelection {
    param([string]$Name,[scriptblock]$Action)
    $script:terminal=[pscustomobject]@{Width=140;ContentWidth=139;Height=60}
    $script:lines=New-Object 'System.Collections.Generic.List[string]'
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    try{$null=& $Action;Assert-WinSecVariantSelection ($script:scanCalls -eq 0 -and $script:providerCalls -eq 0);$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
$request=[pscustomobject]@{Operation='SCAN';ReadOnly=$true;DeviceId='local:VARIANT-FIXTURE';Hostname='SYNTHETIC';
    ScopeType='CONTROL';ScopeKey='WSA-SYS-003';Checks=@([pscustomobject]@{CheckId='WSA-SYS-003';SectionKey='SystemSecurity'})}
$cases=@(
    @{Profile='WSA-W11-21H2-PRO-DEF-BASE';Label='Pro / GPO and MDM';Model='legacy deadline'},
    @{Profile='WSA-W11-22H2-PRO-WORKSTATION-N-DEF-BASE';Label='Pro / GPO and MDM';Model='separate quality'},
    @{Profile='WSA-W11-25H2-HOME-DEF-BASE';Label='Home / consumer updates';Model='Consumer policy source required'},
    @{Profile='WSA-W11-24H2-EDU-DEF-BASE';Label='Enterprise-Education / GPO and MDM';Model='separate quality'},
    @{Profile='WSA-W11-24H2-ENT-LTSC-DEF-BASE';Label='Enterprise LTSC / GPO and MDM';Model='separate quality'},
    @{Profile='WSA-W11-24H2-IOT-ENT-LTSC-DEF-BASE';Label='IoT Enterprise LTSC / GPO and MDM';Model='separate quality'},
    @{Profile='WSA-W11-26H1-PRO-DEF-BASE';Label='Pro / GPO and MDM';Model='separate quality'}
)
foreach($case in $cases) {
    Test-WinSecVariantSelection ('Selected variant remains the exact approved Windows context: '+$case.Profile) {
        $offered=@($options|Where-Object Profile -CEQ $case.Profile)
        Assert-WinSecVariantSelection ($offered.Count -eq 1)
        $before=ConvertTo-Json -InputObject $offered[0] -Depth 6 -Compress
        Add-WinSecVariantKey 40;Add-WinSecVariantKey 13;Add-WinSecVariantKey 13
        $answer=Show-WinSecAssessmentProfileSelection $request $offered
        $text=$script:lines -join '|'
        Assert-WinSecVariantSelection ($answer.Confirmed -and $answer.Selection.Profile -ceq $case.Profile -and
            $before -ceq (ConvertTo-Json $answer.Selection -Depth 6 -Compress) -and
            $text.Contains('Windows Update variant: '+$case.Label) -and $text.Contains($case.Model) -and
            $text.Contains('Criteria weights: 15/35/50.') -and $script:keys.Count -eq 0)
        $plan=Get-WinSecAssessmentProfilePlan $root @('WSA-SYS-003') $answer.Selection.Profile
        Assert-WinSecVariantSelection ($before -ceq (ConvertTo-Json $plan.Preview -Depth 6 -Compress) -and
            ($plan.Catalogs['WSA-SYS-003'].Catalog.Criteria.Weight -join '|') -ceq '15|35|50')
    }
}
Test-WinSecVariantSelection 'All 101 contexts remain available without adding duplicate or user-declared capability choices' {
    Assert-WinSecVariantSelection ($options.Count -eq 101 -and @($options.Profile|Sort-Object -Unique).Count -eq 101)
}
Test-WinSecVariantSelection 'Escape from version returns to editions; a second Escape cancels without a scan' {
    $offered=@($options|Where-Object Profile -CEQ 'WSA-W11-25H2-HOME-DEF-BASE')
    Add-WinSecVariantKey 40;Add-WinSecVariantKey 13;Add-WinSecVariantKey 27;Add-WinSecVariantKey 27
    $answer=Show-WinSecAssessmentProfileSelection $request $offered
    Assert-WinSecVariantSelection (-not $answer.Confirmed -and $null -eq $answer.Selection -and
        ($script:lines -join '|').Contains('OPERATING SYSTEM / EDITION') -and $script:keys.Count -eq 0)
}
Test-WinSecVariantSelection 'Small and resized terminals require a complete visible variant and a fresh Enter' {
    $offered=@($options|Where-Object Profile -CEQ 'WSA-W11-24H2-ENT-LTSC-DEF-BASE')
    Add-WinSecVariantKey 40;Add-WinSecVariantKey 13
    Add-WinSecVariantKey 0 ([pscustomobject]@{Width=40;ContentWidth=39;Height=10})
    Add-WinSecVariantKey 13
    Add-WinSecVariantKey 0 ([pscustomobject]@{Width=140;ContentWidth=139;Height=60})
    Add-WinSecVariantKey 13
    $answer=Show-WinSecAssessmentProfileSelection $request $offered
    Assert-WinSecVariantSelection ($answer.Confirmed -and $script:keys.Count -eq 0)
}
Test-WinSecVariantSelection 'A tiny terminal cannot confirm an unseen selection' {
    $script:terminal=[pscustomobject]@{Width=16;ContentWidth=15;Height=5}
    Add-WinSecVariantKey 13;Add-WinSecVariantKey 27
    $answer=Show-WinSecAssessmentProfileSelection $request @($options[0])
    Assert-WinSecVariantSelection (-not $answer.Confirmed -and @($script:lines|Where-Object Length -GT 15).Count -eq 0)
}
Write-Host ('Windows Update variant selection: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Windows Update variant selection integration tests failed.'}
