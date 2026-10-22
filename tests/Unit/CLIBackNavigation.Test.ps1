# Escape must not depend on scan/export eligibility or result validation.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($path in @('src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/KeyboardController.ps1','src/UI/Core/NavigationController.ps1')){. (Join-Path $root $path)}
$script:passed=0;$script:failed=0
function Assert-WinSecBack {param([bool]$Value);if(-not $Value){throw 'CLI Back assertion failed.'}}
function Test-WinSecCLIRescanEligibility {throw 'Back queried scan authorization.'}
function Test-WinSecCLIFindingsExportEligibility {throw 'Back queried export authorization.'}
function Get-WinSecCLINavigationCounts {throw 'Back queried finding data.'}
function Test-WinSecBack {
    param([string]$Name,[scriptblock]$Action)
    $script:state=New-WinSecNavigationState
    $script:state.Screen='Section';$script:state.SectionIndex=2;$script:state.ControlIndex=1
    $script:state.SelectedDeviceId='local:BACK-FIXTURE';$script:state.SelectedDeviceName='SYNTHETIC'
    $null=Set-WinSecNavigationScreen $script:state Findings
    $script:key=[pscustomobject]@{VirtualKeyCode=27;Character=[char]27;KeyDown=$true;ControlKeyState=0}
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
Test-WinSecBack 'Escape returns from Findings without consulting permissions or result data' {
    Assert-WinSecBack ((Invoke-WinSecCLIBackNavigation $script:key $script:state) -and $script:state.Screen -ceq 'Section' -and
        $script:state.SectionIndex -eq 2 -and $script:state.ControlIndex -eq 1 -and
        $script:state.SelectedDeviceId -ceq 'local:BACK-FIXTURE' -and $script:state.History.Count -eq 0 -and $null -eq $script:state.PendingCommand)
}
foreach($origin in @('MainMenu','Results')){
    Test-WinSecBack ('Findings restores its actual origin: '+$origin) {
        $script:state=New-WinSecNavigationState;$script:state.Screen=$origin
        $null=Set-WinSecNavigationScreen $script:state Findings
        Assert-WinSecBack ((Invoke-WinSecCLIBackNavigation $script:key $script:state) -and $script:state.Screen -ceq $origin)
    }
}
foreach($mutation in @({$script:key.KeyDown=$false},{$script:key.ControlKeyState=4},{$script:key.VirtualKeyCode=40})){
    Test-WinSecBack 'Release modifier and unrelated keys cannot restore or authorize navigation' {
        $null=& $mutation
        Assert-WinSecBack (-not(Invoke-WinSecCLIBackNavigation $script:key $script:state) -and $script:state.Screen -ceq 'Findings')
    }
}
Test-WinSecBack 'Findings with no navigation history still has a safe return' {
    $script:state.History.Clear()
    Assert-WinSecBack ((Invoke-WinSecCLIBackNavigation $script:key $script:state) -and $script:state.Screen -ceq 'MainMenu')
}
Test-WinSecBack 'The actual CLI routes Back before scan export or finding-count gates' {
    $tokens=$null;$errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1'),[ref]$tokens,[ref]$errors)
    $cli=$ast.Find({param($node);$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-WinSecCLI'},$true)
    $commands=@($cli.Body.FindAll({param($node);$node -is [System.Management.Automation.Language.CommandAst]},$true))
    $back=@($commands|Where-Object {$_.GetCommandName() -ceq 'Invoke-WinSecCLIBackNavigation'})
    $gates=@($commands|Where-Object {$_.GetCommandName() -cin @('Test-WinSecCLIRescanEligibility','Test-WinSecCLIFindingsExportEligibility','Get-WinSecCLINavigationCounts')})
    Assert-WinSecBack ($errors.Count -eq 0 -and $back.Count -eq 1 -and $gates.Count -eq 3 -and
        @($gates|Where-Object {$_.Extent.StartLineNumber -lt $back[0].Extent.StartLineNumber}).Count -eq 0)
}
[Console]::WriteLine(('CLI Back navigation: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'CLI Back navigation tests failed.'}
