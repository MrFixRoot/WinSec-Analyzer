# Startup token and process boundaries are synthetic. No UAC, scans or writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$helper=Join-Path $root 'src/Core/StartupElevation.ps1'
. $helper
$script:passed=0;$script:failed=0
function Assert-WinSecStartup {param([bool]$Condition);if(-not $Condition){throw 'Startup elevation assertion failed.'}}
function Test-WinSecStartupCase {
    param([string]$Name,[scriptblock]$Action)
    $script:decision=$false;$script:tokenError=$false;$script:tokenCalls=0;$script:processCalls=0
    $script:mode='OK';$script:missing='';$script:launch=$null
    try {$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch {$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
function Test-WinSecAdministrator {
    $script:tokenCalls++
    if($script:tokenError){throw 'PRIVATE_STARTUP_TOKEN'}
    $script:decision
}
function Test-Path {
    [CmdletBinding()]param($LiteralPath,$PathType)
    return ($LiteralPath -cne $script:missing)
}
function Start-Process {
    [CmdletBinding()]
    param($FilePath,$Verb,[string[]]$ArgumentList,$WorkingDirectory,$WindowStyle)
    $script:processCalls++
    $script:launch=[pscustomobject]@{FilePath=$FilePath;Verb=$Verb;Arguments=$ArgumentList;Directory=$WorkingDirectory;Window=$WindowStyle}
    switch($script:mode){
        CANCEL {throw [ComponentModel.Win32Exception]::new(1223)}
        WRAPPED {throw [InvalidOperationException]::new('PRIVATE_STARTUP_WRAPPER',[ComponentModel.Win32Exception]::new(1223))}
        ERROR {throw 'PRIVATE_STARTUP_PROCESS 1223'}
    }
    'UNEXPECTED_PROCESS_OUTPUT'
}
$launcher=Join-Path $root 'Start-WinSec.ps1'
Test-WinSecStartupCase 'Importing the helper never probes a token or starts a process' {
    . $helper
    Assert-WinSecStartup ($script:tokenCalls -eq 0 -and $script:processCalls -eq 0)
}
Test-WinSecStartupCase 'An administrative token continues in the existing process' {
    $script:decision=$true
    $result=Invoke-WinSecStartupElevation $launcher '0.9.0'
    Assert-WinSecStartup ($result.Status -ceq 'READY' -and $script:tokenCalls -eq 1 -and $script:processCalls -eq 0)
}
Test-WinSecStartupCase 'A nonadministrative token requests RunAs with the current absolute runtime' {
    $result=@(Invoke-WinSecStartupElevation $launcher '0.9.0')
    $exe=if($PSVersionTable.PSEdition -ceq 'Core'){'pwsh.exe'}else{'powershell.exe'}
    Assert-WinSecStartup ($result.Count -eq 1 -and $result[0].Status -ceq 'RELAUNCHED' -and $script:processCalls -eq 1 -and
        $script:launch.FilePath -ceq (Join-Path $PSHOME $exe) -and $script:launch.Verb -ceq 'RunAs' -and
        $script:launch.Directory -ceq $root -and $script:launch.Window -ceq 'Normal' -and $script:launch.Arguments.Count -eq 1)
}
foreach($sample in @(@{Directory="C:\WinSec O'Neil & literal";Version="0.9.0'; throw 'INJECTED"},
    @{Directory=('C:\WinSec '+[char]0x2019+' literal');Version=('0.9.0'+[char]0x2018+'; $(INJECTED)')})) {
    Test-WinSecStartupCase 'Paths and versions survive as literals without executing injected commands' {
        $path=Join-Path $sample.Directory 'Start-WinSec.ps1'
        $result=Invoke-WinSecStartupElevation $path $sample.Version
        Assert-WinSecStartup ($result.Status -ceq 'RELAUNCHED')
        $arguments=$script:launch.Arguments[0]
        Assert-WinSecStartup ($arguments -cmatch '\A-NoLogo -NoProfile -EncodedCommand ([A-Za-z0-9+/=]+)\z')
        $decoded=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))
        $tokens=$null;$errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput($decoded,[ref]$tokens,[ref]$errors)
        $command=$ast.EndBlock.Statements[0].PipelineElements[0]
        Assert-WinSecStartup ($errors.Count -eq 0 -and $ast.EndBlock.Statements.Count -eq 1 -and
            $command.CommandElements.Count -eq 4 -and $command.CommandElements[0].Value -ceq $path -and
            $command.CommandElements[1].ParameterName -ceq 'Version' -and $command.CommandElements[2].Value -ceq $sample.Version -and
            $command.CommandElements[3].ParameterName -ceq 'ElevationAttempted')
    }
}
Test-WinSecStartupCase 'A child without elevation cannot request UAC repeatedly' {
    $result=Invoke-WinSecStartupElevation $launcher '0.9.0' -ElevationAttempted
    Assert-WinSecStartup ($result.Status -ceq 'FAILED' -and $script:processCalls -eq 0)
}
Test-WinSecStartupCase 'An elevated child passes the retry guard' {
    $script:decision=$true
    $result=Invoke-WinSecStartupElevation $launcher '0.9.0' -ElevationAttempted
    Assert-WinSecStartup ($result.Status -ceq 'READY' -and $script:processCalls -eq 0)
}
foreach($caseMode in @('CANCEL','WRAPPED')) {
    Test-WinSecStartupCase ('Typed UAC cancellation returns a safe bounded message: '+$caseMode) {
        $script:mode=$caseMode
        $result=Invoke-WinSecStartupElevation $launcher '0.9.0'
        Assert-WinSecStartup ($result.Status -ceq 'CANCELLED' -and $script:processCalls -eq 1 -and $result.Message -notmatch 'PRIVATE|Exception')
    }
}
Test-WinSecStartupCase 'A generic launch failure is not inferred to be cancellation from its text' {
    $script:mode='ERROR'
    $result=Invoke-WinSecStartupElevation $launcher '0.9.0'
    Assert-WinSecStartup ($result.Status -ceq 'FAILED' -and $result.Message -notmatch 'PRIVATE|1223')
}
foreach($decision in @(@{Value='True'},@{Value=@($true,$false)},@{Value=$null})) {
    Test-WinSecStartupCase 'Ambiguous token results cannot start a process or the application' {
        $script:decision=$decision.Value
        $result=Invoke-WinSecStartupElevation $launcher '0.9.0'
        Assert-WinSecStartup ($result.Status -ceq 'FAILED' -and $script:processCalls -eq 0)
    }
}
Test-WinSecStartupCase 'Token query failures cannot start a process' {
    $script:tokenError=$true
    $result=Invoke-WinSecStartupElevation $launcher '0.9.0'
    Assert-WinSecStartup ($result.Status -ceq 'FAILED' -and $script:processCalls -eq 0 -and $result.Message -notmatch 'PRIVATE')
}
foreach($path in @('Start-WinSec.ps1',(Join-Path $root 'Other.ps1'))) {
    Test-WinSecStartupCase 'An unexpected launcher cannot be elevated' {
        $result=Invoke-WinSecStartupElevation $path '0.9.0'
        Assert-WinSecStartup ($result.Status -ceq 'FAILED' -and $script:processCalls -eq 0)
    }
}
foreach($missingPath in @($launcher,(Join-Path $PSHOME $(if($PSVersionTable.PSEdition -ceq 'Core'){'pwsh.exe'}else{'powershell.exe'})))) {
    Test-WinSecStartupCase 'Missing launcher or runtime cannot start a process' {
        $script:missing=$missingPath
        $result=Invoke-WinSecStartupElevation $launcher '0.9.0'
        Assert-WinSecStartup ($result.Status -ceq 'FAILED' -and $script:processCalls -eq 0)
    }
}
Write-Host ('Startup elevation unit: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Startup elevation unit tests failed.'}
