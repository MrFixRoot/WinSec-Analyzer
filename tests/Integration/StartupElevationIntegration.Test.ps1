# Executes the real launcher and elevation helper with alias-bound token,
# Start-Process and CLI boundaries. No UAC, native audit, inventory or file writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$launcher=Join-Path $root 'Start-WinSec.ps1'
$script:passed=0;$script:failed=0
$global:WinSecStartupIntegration=@{}
function Assert-WinSecStartupIntegration {param([bool]$Condition);if(-not $Condition){throw 'Startup integration assertion failed.'}}
function Get-WinSecStartupTestToken {$global:WinSecStartupIntegration.Admin}
function Invoke-WinSecStartupTestProcess {
    [CmdletBinding()]
    param($FilePath,$Verb,$ArgumentList,$WorkingDirectory,$WindowStyle)
    $global:WinSecStartupIntegration.ProcessCalls++
    $global:WinSecStartupIntegration.Process=[pscustomobject]@{
        FilePath=$FilePath;Verb=$Verb;Arguments=$ArgumentList;Directory=$WorkingDirectory;Window=$WindowStyle
    }
    switch($global:WinSecStartupIntegration.ProcessError){
        CANCEL {throw [ComponentModel.Win32Exception]::new(1223)}
        ERROR {throw 'PRIVATE_STARTUP_INTEGRATION'}
    }
}
function Invoke-WinSecStartupTestCLI {
    param([string]$Version)
    $global:WinSecStartupIntegration.CliCalls++
    $global:WinSecStartupIntegration.Version=$Version
}
function Deny-WinSecStartupSideEffect {
    $global:WinSecStartupIntegration.UnexpectedCalls++
    throw 'Unexpected startup collection or persistence.'
}
function Write-Host {
    param([object[]]$Object,$ForegroundColor,[switch]$NoNewline)
    $global:WinSecStartupIntegration.Messages.Add([pscustomobject]@{Text=($Object -join ' ');Color=[string]$ForegroundColor})
}
$aliases=@{
    'Test-WinSecAdministrator'='Get-WinSecStartupTestToken'
    'Start-Process'='Invoke-WinSecStartupTestProcess'
    'Invoke-WinSecCLI'='Invoke-WinSecStartupTestCLI'
    'Get-CimInstance'='Deny-WinSecStartupSideEffect'
    'Invoke-CimMethod'='Deny-WinSecStartupSideEffect'
    'Invoke-WinSecAudit'='Deny-WinSecStartupSideEffect'
    'Save-WinSecPublicHistory'='Deny-WinSecStartupSideEffect'
    'Initialize-WinSecDeviceInventory'='Deny-WinSecStartupSideEffect'
}
function Test-WinSecStartupIntegrationCase {
    param([string]$Name,[scriptblock]$Action)
    $global:WinSecStartupIntegration=@{Admin=$false;ProcessCalls=0;CliCalls=0;UnexpectedCalls=0;Version='';ProcessError='';Process=$null;
        Messages=(New-Object 'System.Collections.Generic.List[object]')}
    try {
        $null=& $Action
        Assert-WinSecStartupIntegration ($global:WinSecStartupIntegration.UnexpectedCalls -eq 0)
        $script:passed++;[Console]::WriteLine('[PASS] '+$Name)
    }
    catch {$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
try {
    foreach($name in $aliases.Keys){Set-Alias -Name $name -Value $aliases[$name] -Scope Script}
    foreach($name in $aliases.Keys){Assert-WinSecStartupIntegration ((Get-Command $name).CommandType -eq 'Alias')}
    Test-WinSecStartupIntegrationCase 'Already elevated startup enters the CLI once without launching a process' {
        $global:WinSecStartupIntegration.Admin=$true
        & $launcher -Version '0.9.0-test'
        Assert-WinSecStartupIntegration ($global:WinSecStartupIntegration.CliCalls -eq 1 -and
            $global:WinSecStartupIntegration.Version -ceq '0.9.0-test' -and $global:WinSecStartupIntegration.ProcessCalls -eq 0)
    }
    Test-WinSecStartupIntegrationCase 'Unelevated startup requests one interactive relaunch and stops the original instance' {
        & $launcher
        $process=$global:WinSecStartupIntegration.Process
        Assert-WinSecStartupIntegration ($global:WinSecStartupIntegration.CliCalls -eq 0 -and
            $global:WinSecStartupIntegration.ProcessCalls -eq 1 -and $process.Verb -ceq 'RunAs' -and $process.Window -ceq 'Normal')
    }
    Test-WinSecStartupIntegrationCase 'UAC cancellation stops before the CLI and displays a yellow notice' {
        $global:WinSecStartupIntegration.ProcessError='CANCEL'
        & $launcher
        $messages=$global:WinSecStartupIntegration.Messages
        Assert-WinSecStartupIntegration ($global:WinSecStartupIntegration.CliCalls -eq 0 -and
            $global:WinSecStartupIntegration.ProcessCalls -eq 1 -and $messages.Count -eq 1 -and
            $messages[0].Color -ceq 'Yellow' -and $messages[0].Text -match 'cancelled')
    }
    Test-WinSecStartupIntegrationCase 'Unexpected elevation failures never open the CLI or expose raw errors' {
        $global:WinSecStartupIntegration.ProcessError='ERROR'
        & $launcher
        $messages=$global:WinSecStartupIntegration.Messages
        Assert-WinSecStartupIntegration ($global:WinSecStartupIntegration.CliCalls -eq 0 -and
            $messages.Count -eq 1 -and $messages[0].Color -ceq 'Yellow' -and $messages[0].Text -notmatch 'PRIVATE')
    }
    Test-WinSecStartupIntegrationCase 'An unelevated child stops without another UAC attempt' {
        & $launcher -ElevationAttempted
        Assert-WinSecStartupIntegration ($global:WinSecStartupIntegration.CliCalls -eq 0 -and
            $global:WinSecStartupIntegration.ProcessCalls -eq 0 -and $global:WinSecStartupIntegration.Messages.Count -eq 1)
    }
    Test-WinSecStartupIntegrationCase 'Successful relaunch simulation opens only the elevated instance' {
        & $launcher -Version '0.9.0-test'
        $global:WinSecStartupIntegration.Admin=$true
        & $launcher -Version '0.9.0-test' -ElevationAttempted
        Assert-WinSecStartupIntegration ($global:WinSecStartupIntegration.ProcessCalls -eq 1 -and
            $global:WinSecStartupIntegration.CliCalls -eq 1 -and $global:WinSecStartupIntegration.Version -ceq '0.9.0-test')
    }
    Test-WinSecStartupIntegrationCase 'An invalid token result cannot reach the CLI or start a process' {
        $global:WinSecStartupIntegration.Admin=@($true,$false)
        & $launcher
        Assert-WinSecStartupIntegration ($global:WinSecStartupIntegration.CliCalls -eq 0 -and
            $global:WinSecStartupIntegration.ProcessCalls -eq 0)
    }
}
finally {
    foreach($name in $aliases.Keys){Remove-Item -LiteralPath ('Alias:'+ $name) -Force -ErrorAction SilentlyContinue}
    Remove-Variable -Name WinSecStartupIntegration -Scope Global
}
[Console]::WriteLine(('Startup elevation integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Startup elevation integration tests failed.'}
