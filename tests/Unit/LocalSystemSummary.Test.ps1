# Informational OS metadata only, with local identity and CIM simulated.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$script:reads=0
function Get-CimInstance {$script:reads++;throw 'Unexpected Windows query during import.'}
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1')
$script:importReads=$script:reads
$script:device='local:hw1-'+('a'*64)
$script:passed=0;$script:failed=0
function Assert-WinSecSystemSummary {param([bool]$Value);if(-not $Value){throw 'System summary assertion failed.'}}
function Get-WinSecLocalHardwareDeviceId {$script:device}
function Get-CimInstance {
    [CmdletBinding()]
    param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    $script:reads++
    Assert-WinSecSystemSummary ($Namespace -ceq 'root/cimv2' -and $ClassName -ceq 'Win32_OperatingSystem' -and
        ($Property -join ',') -ceq 'Caption,Version,BuildNumber,OperatingSystemSKU,ProductType' -and $OperationTimeoutSec -eq 10)
    if($script:providerFails){throw 'PRIVATE-OS-ERROR'}
    $script:systems
}
function Test-WinSecSystemSummary {
    param([string]$Name,[scriptblock]$Action)
    $script:reads=0;$script:providerFails=$false
    $script:systems=@([pscustomobject]@{Caption='Microsoft Windows 11 Pro';Version='10.0.22621';BuildNumber='22621';
        OperatingSystemSKU=[uint32]48;ProductType=[uint32]1})
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
Test-WinSecSystemSummary 'Importing services never queries Windows' {Assert-WinSecSystemSummary ($script:importReads -eq 0)}
Test-WinSecSystemSummary 'Edition release and build come from observed local metadata and the validated matrix' {
    $info=Get-WinSecLocalSystemSummary $script:device $root
    Assert-WinSecSystemSummary ($info.DeviceId -ceq $script:device -and $info.Label -ceq 'Pro 22H2 | build: 22621' -and
        $script:reads -eq 1 -and @($info.PSObject.Properties).Count -eq 2)
}
Test-WinSecSystemSummary 'The observed SKU distinguishes edition variants without trusting the caption edition' {
    $script:systems[0].OperatingSystemSKU=[uint32]162
    Assert-WinSecSystemSummary ((Get-WinSecLocalSystemSummary $script:device $root).Label -ceq 'Pro for Workstations N 22H2 | build: 22621')
}
foreach($mutation in @(
    {$script:systems[0].BuildNumber='26100'},
    {$script:systems[0].Caption="Windows 11`nPRIVATE"},
    {$script:systems[0].Caption='Microsoft Windows Server'},
    {$script:systems[0].ProductType=[uint32]3},
    {$script:systems[0].OperatingSystemSKU='48'},
    {$script:systems=@()},
    {$script:systems=@($script:systems[0],$script:systems[0])},
    {$script:providerFails=$true}
)){
    Test-WinSecSystemSummary 'Invalid unavailable or ambiguous OS metadata is not presented as a detected version' {
        $null=& $mutation
        Assert-WinSecSystemSummary ((Get-WinSecLocalSystemSummary $script:device $root).Label -ceq 'Unavailable')
    }
}
Test-WinSecSystemSummary 'Unknown builds and editions remain explicitly unknown' {
    $script:systems[0].Version='10.0.29999';$script:systems[0].BuildNumber='29999';$script:systems[0].OperatingSystemSKU=[uint32]999
    Assert-WinSecSystemSummary ((Get-WinSecLocalSystemSummary $script:device $root).Label -ceq 'Edition unknown (SKU:999) Version unknown | build: 29999')
}
Test-WinSecSystemSummary 'Foreign hardware is rejected before querying the OS' {
    $caught=$false
    try{$null=Get-WinSecLocalSystemSummary ('local:hw1-'+('b'*64)) $root}catch{$caught=$true}
    Assert-WinSecSystemSummary ($caught -and $script:reads -eq 0)
}
Test-WinSecSystemSummary 'Cached information is shown only for the matching device without querying Windows again' {
    $context=[pscustomobject]@{LocalSystemInfo=Get-WinSecLocalSystemSummary $script:device $root}
    $state=[pscustomobject]@{SelectedDeviceId=$script:device}
    1..3|ForEach-Object {Assert-WinSecSystemSummary ((Get-WinSecCLISystemLabel $state $context) -ceq 'Pro 22H2 | build: 22621')}
    $state.SelectedDeviceId='local:hw1-'+('b'*64)
    Assert-WinSecSystemSummary ((Get-WinSecCLISystemLabel $state $context) -ceq '' -and $script:reads -eq 1)
}
Test-WinSecSystemSummary 'Malformed or private display metadata cannot reach the header' {
    $state=[pscustomobject]@{SelectedDeviceId=$script:device}
    foreach($bad in @([pscustomobject]@{DeviceId=$script:device;Label="Pro`nPRIVATE"},
        [pscustomobject]@{DeviceId=$script:device;Label='Pro';Evidence='PRIVATE'})){
        Assert-WinSecSystemSummary ((Get-WinSecCLISystemLabel $state ([pscustomobject]@{LocalSystemInfo=$bad})) -ceq '')
    }
}
[Console]::WriteLine(('Local system summary: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Local system summary tests failed.'}
