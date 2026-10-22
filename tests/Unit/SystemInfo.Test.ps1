# Synthetic OS metadata only; no native CIM, storage, registry or Windows audit.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/TargetRegistry.ps1')
$script:reads = 0
function Get-CimInstance {
    [CmdletBinding()]
    param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    $script:reads++
    if ($Namespace -cne 'root/cimv2' -or $ClassName -cne 'Win32_OperatingSystem' -or
        ($Property -join ',') -cne 'Caption,Version,BuildNumber,OperatingSystemSKU,ProductType' -or
        $OperationTimeoutSec -ne 10) { throw 'Unexpected OS query.' }
    if ($script:readError) { throw 'PRIVATE-SYSTEM-INFO-ERROR' }
    return $script:os
}
. (Join-Path $root 'src/Services/SystemInfoService.ps1')
if ($script:reads -ne 0) { throw 'Import must not query Windows.' }
$script:device = 'local:hw1-' + ('a' * 64)
function Get-WinSecLocalHardwareDeviceId {
    [CmdletBinding()]param()
    if ($script:identityError) { throw 'PRIVATE-IDENTITY-ERROR' }
    return $script:localIds
}
$script:passed = 0; $script:failed = 0
function Assert-WinSecSystemInfo {param([bool]$Value); if (-not $Value) { throw 'SystemInfo assertion failed.' }}
function Invoke-WinSecSystemInfoFixture { Get-WinSecLocalAssessmentContext -DeviceId $script:device -ScanId 'scan-system-info' }
function Test-WinSecSystemInfo {
    param([string]$Name,[scriptblock]$Action)
    $script:reads=0; $script:readError=$false; $script:identityError=$false; $script:localIds=@($script:device)
    $script:os=[pscustomobject]@{Caption='Microsoft Windows 11 Pro';Version='10.0.26100';BuildNumber='26100';
        OperatingSystemSKU=[uint32]48;ProductType=[uint32]1;RegisteredUser='PRIVATE-OS-USER';SerialNumber='PRIVATE-OS-KEY'}
    try { $null=& $Action; $script:passed++; Write-Host ('[PASS] '+$Name) }
    catch { $script:failed++; Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message); Write-Host $_.ScriptStackTrace }
}
Test-WinSecSystemInfo 'Exact Windows version and native SKU with an unresolved policy profile' {
    $r=Invoke-WinSecSystemInfoFixture
    Assert-WinSecSystemInfo ($r.DeviceId -ceq $script:device -and $r.ScanId -ceq 'scan-system-info' -and
        $r.OSFamily -ceq 'Windows' -and $r.OSRelease -ceq 'Windows 11 10.0.26100' -and
        $r.Edition -ceq 'SKU:48' -and $r.Profile -ceq 'UNRESOLVED' -and $script:reads -eq 1)
    Assert-WinSecSystemInfo (@($r.PSObject.Properties).Count -eq 6 -and
        ($r|ConvertTo-Json -Compress) -notmatch 'PRIVATE-|RegisteredUser|SerialNumber|24H2')
}
Test-WinSecSystemInfo 'Localized edition captions and trailing spaces do not select a policy' {
    $script:os.Caption='Microsoft Windows 11 Professionnel '
    $r=Invoke-WinSecSystemInfoFixture
    Assert-WinSecSystemInfo ($r.OSRelease -ceq 'Windows 11 10.0.26100' -and $r.Profile -ceq 'UNRESOLVED')
}
foreach ($case in @(
    @{Caption='Microsoft Windows 10 Pro'}, @{Caption='Microsoft Windows Server 2025'},
    @{Caption='Microsoft Windows 12 Pro'}, @{Caption="Microsoft Windows 11 Pro`e[0m"},
    @{Caption=@('Microsoft Windows 11 Pro')}, @{ProductType=3}, @{ProductType=2},
    @{ProductType='1'}, @{ProductType=$true}, @{Version='10.0.19045';BuildNumber='19045'},
    @{Version='10.0.26100';BuildNumber='22631'}, @{Version='10.0.26100.1234'},
    @{Version='11.0.26100'}, @{BuildNumber='026100'}, @{BuildNumber=26100},
    @{BuildNumber='999999999999999999999999'}, @{Version=$null}, @{Caption=$null}
)) {
    Test-WinSecSystemInfo ('Unsupported or inconsistent OS stays unresolved: '+($case|ConvertTo-Json -Compress)) {
        foreach ($key in $case.Keys) { $script:os.$key=$case[$key] }
        $r=Invoke-WinSecSystemInfoFixture
        Assert-WinSecSystemInfo ($r.OSRelease -ceq 'UNRESOLVED' -and $r.Edition -ceq 'UNRESOLVED' -and
            $r.Profile -ceq 'UNRESOLVED' -and $script:reads -eq 1)
    }
}
foreach ($sku in @($null,0,-1,'48',$true,@(48))) {
    Test-WinSecSystemInfo 'Unknown or nonnumeric SKU cannot imply an edition' {
        $script:os.OperatingSystemSKU=$sku
        $r=Invoke-WinSecSystemInfoFixture
        Assert-WinSecSystemInfo ($r.OSRelease -ceq 'Windows 11 10.0.26100' -and $r.Edition -ceq 'UNRESOLVED')
    }
}
Test-WinSecSystemInfo 'OS read failures return no private exception details' {
    $script:readError=$true; $r=Invoke-WinSecSystemInfoFixture
    Assert-WinSecSystemInfo ($r.OSRelease -ceq 'UNRESOLVED' -and ($r|ConvertTo-Json -Compress) -notmatch 'PRIVATE-')
}
Test-WinSecSystemInfo 'Missing or multiple singleton instances remain unresolved' {
    foreach ($instances in @(@(),@($script:os,$script:os))) {
        $script:os=$instances; $r=Invoke-WinSecSystemInfoFixture
        Assert-WinSecSystemInfo ($r.OSRelease -ceq 'UNRESOLVED' -and $r.Profile -ceq 'UNRESOLVED')
    }
}
Test-WinSecSystemInfo 'Output is isolated from the native object and earlier results' {
    $before=$script:os|ConvertTo-Json -Compress
    $r=Invoke-WinSecSystemInfoFixture; $r.OSRelease='CHANGED'
    $again=Invoke-WinSecSystemInfoFixture
    Assert-WinSecSystemInfo (($script:os|ConvertTo-Json -Compress) -ceq $before -and $again.OSRelease -ceq 'Windows 11 10.0.26100')
}
foreach ($ids in @(@(),@('local:FOREIGN'),@(('local:hw1-'+('b'*64))),@($script:device,$script:device))) {
    Test-WinSecSystemInfo 'Unresolved or foreign local identity aborts before OS collection' {
        $script:localIds=$ids; $caught=$false
        try { $null=Invoke-WinSecSystemInfoFixture } catch { $caught=$true }
        Assert-WinSecSystemInfo ($caught -and $script:reads -eq 0)
    }
}
Test-WinSecSystemInfo 'Hardware provider failure is not treated as unknown applicability' {
    $script:identityError=$true; $message=''
    try { $null=Invoke-WinSecSystemInfoFixture } catch { $message=$_.Exception.Message }
    Assert-WinSecSystemInfo ($message -and $message -notmatch 'PRIVATE-' -and $script:reads -eq 0)
}
foreach ($identity in @(@{Device='local:HOST';Scan='scan-valid'},@{Device=$script:device;Scan='../bad'},
    @{Device=$script:device.ToUpperInvariant();Scan='scan-valid'})) {
    Test-WinSecSystemInfo 'Invalid or noncanonical identity is rejected before collection' {
        $caught=$false
        try { $null=Get-WinSecLocalAssessmentContext -DeviceId $identity.Device -ScanId $identity.Scan } catch { $caught=$true }
        Assert-WinSecSystemInfo ($caught -and $script:reads -eq 0)
    }
}
Write-Host ('SystemInfo: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if ($script:failed) { throw 'SystemInfo unit tests failed.' }
