# Inventory presentation only: synthetic data, no startup or persistence.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../src/UI/Components/Table.ps1')
. (Join-Path $PSScriptRoot '../../src/UI/Screens/Devices.ps1')
$script:passed=0; $script:failed=0
function Assert-WinSecDevices {param([bool]$Condition); if(-not $Condition){throw 'Devices public contract assertion failed.'}}
function Test-WinSecDevices {
    param([string]$Name,[scriptblock]$Action)
    try {$null=& $Action; $script:passed++; Write-Host "[PASS] $Name"}
    catch {$script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function Assert-WinSecDevicesRejected {
    param([scriptblock]$Action)
    $caught=$null; $published=New-Object 'System.Collections.Generic.List[object]'
    try {& $Action | ForEach-Object {$published.Add($_)}} catch {$caught=$_}
    Assert-WinSecDevices ($null -ne $caught -and $published.Count -eq 0 -and
        $caught.Exception.Message -notlike '*SYNTHETIC-DEVICES-PRIVATE*')
}
Test-WinSecDevices 'Empty inventory emits no rows' {
    Assert-WinSecDevices (@(Get-WinSecDeviceRows).Count -eq 0)
}
foreach($value in @(0,100,'90/100','--/100',$false,@{Private='SYNTHETIC-DEVICES-PRIVATE'})) {
    Test-WinSecDevices ('Inventory cannot authorize a score or assessment: '+$value.GetType().Name) {
        $row=@(Get-WinSecDeviceRows -Devices @(@{DeviceId='local:FIXTURE';Hostname='FIXTURE';Mode='LOCAL';
            Score=$value;Status='PASS';LastScan='SYNTHETIC-DEVICES-PRIVATE';ScanId='foreign'}))[0]
        Assert-WinSecDevices ($row.Score -ceq 'NOT_SCORED' -and $row.Status -ceq 'PENDING' -and
            $row.LastScan -ceq 'Not loaded' -and $null -eq $row.PSObject.Properties['ScanId'])
    }
}
foreach($field in @('Score','Status','LastScan','ScanId','Evidence','Metadata')) {
    Test-WinSecDevices ("Untrusted assessment and private getters are never read: $field") {
        $script:getterCalls=0
        $device=[pscustomobject]@{DeviceId='local:FIXTURE';Hostname='FIXTURE';Mode='LOCAL'}
        $device|Add-Member -MemberType ScriptProperty -Name $field -Value {$script:getterCalls++;throw 'SYNTHETIC-DEVICES-PRIVATE'}
        $row=@(Get-WinSecDeviceRows -Devices @($device))[0]
        Assert-WinSecDevices ($script:getterCalls -eq 0 -and $row.Score -ceq 'NOT_SCORED')
    }
}
foreach($field in @('DeviceId','Hostname','Name','Mode')) {
    Test-WinSecDevices ("Calculated identity fields fail before execution or partial rows: $field") {
        $script:getterCalls=0
        $device=[pscustomobject]@{DeviceId='local:SECOND';Hostname='SECOND';Mode='LOCAL'}
        $device.PSObject.Properties.Remove($field)
        $device|Add-Member -MemberType ScriptProperty -Name $field -Value {$script:getterCalls++;'SYNTHETIC-DEVICES-PRIVATE'}
        Assert-WinSecDevicesRejected {Get-WinSecDeviceRows -Devices @(@{DeviceId='local:FIRST'},$device)}
        Assert-WinSecDevices ($script:getterCalls -eq 0)
    }
}
foreach($invalid in @(
    @{Hostname='FIXTURE'}, @{DeviceId=''}, @{DeviceId=@('local:FIXTURE')},
    @{DeviceId='../SYNTHETIC-DEVICES-PRIVATE'}, @{DeviceId=('x'*129)},
    @{DeviceId="local:FIXTURE`nPASS"}, @{DeviceId="local:FIXTURE`n"},
    @{DeviceId='local:FIXTURE';Hostname="FIXTURE`n"}, @{DeviceId='local:FIXTURE';Hostname=@('FIXTURE')},
    @{DeviceId='local:FIXTURE';Hostname="FIXTURE$([char]27)[2J"},
    @{DeviceId='local:FIXTURE';Name=@{Private='SYNTHETIC-DEVICES-PRIVATE'}},
    @{DeviceId='local:FIXTURE';Hostname=('x'*254)},
    @{DeviceId='local:FIXTURE';Mode='REMOTE'}, @{DeviceId='remote:FIXTURE';Mode='LOCAL'},
    @{DeviceId='local:FIXTURE';Mode=@('LOCAL')}, @{DeviceId='local:FIXTURE';Mode='INVALID'},
    'SYNTHETIC-DEVICES-PRIVATE', 42
)) {
    Test-WinSecDevices 'Invalid identity data fails without publishing previous valid rows' {
        Assert-WinSecDevicesRejected {Get-WinSecDeviceRows -Devices @(@{DeviceId='local:FIRST'},$invalid)}
    }
}
foreach($id in @('local:FIRST','LOCAL:first')) {
    Test-WinSecDevices 'Duplicate identity fails closed, including casing variants' {
        Assert-WinSecDevicesRejected {Get-WinSecDeviceRows -Devices @(@{DeviceId='local:FIRST'},@{DeviceId=$id})}
    }
}
Test-WinSecDevices 'Case-ambiguous dictionary field names fail closed' {
    $device=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $device.Add('DeviceId','local:FIRST');$device.Add('deviceid','local:SECOND')
    Assert-WinSecDevicesRejected {Get-WinSecDeviceRows -Devices @($device)}
}
Test-WinSecDevices 'Dictionary members cannot shadow data enumeration' {
    $device=@{DeviceId='local:FIXTURE';Hostname='FIXTURE';Keys=@('SYNTHETIC-DEVICES-PRIVATE');Count=100}
    $row=@(Get-WinSecDeviceRows -Devices @($device))[0]
    Assert-WinSecDevices ($row.DeviceId -ceq 'local:FIXTURE' -and $row.Score -ceq 'NOT_SCORED')
}
Test-WinSecDevices 'Rows retain order, safe identity aliases and modes without authorizing remote scans' {
    $rows=@(Get-WinSecDeviceRows -Devices @(
        [pscustomobject]@{DeviceId='local:FIRST';Name='FIRST';Mode='local'},
        @{DeviceId='remote:SECOND';Hostname='SECOND';Mode='REMOTE'},
        [ordered]@{DeviceId='imported:THIRD'}, @{DeviceId='FOURTH'}))
    Assert-WinSecDevices ($rows.Count -eq 4 -and $rows[0].Id -ceq '01' -and
        $rows[0].Hostname -ceq 'FIRST' -and $rows[0].Mode -ceq 'LOCAL' -and
        $rows[1].Mode -ceq 'REMOTE' -and $rows[2].Mode -ceq 'IMPORTED' -and
        $rows[3].Hostname -ceq 'FOURTH' -and $rows[3].Mode -ceq 'UNKNOWN')
}
Test-WinSecDevices 'Detached scalar rows never expose private metadata or mutate the inventory' {
    $device=[pscustomobject]@{DeviceId='local:FIXTURE';Hostname='FIXTURE';Mode='LOCAL';Score=100;
        Status='FAIL';Evidence=@{Secret='SYNTHETIC-DEVICES-PRIVATE'}}
    $before=ConvertTo-Json -InputObject $device -Depth 5 -Compress
    $row=@(Get-WinSecDeviceRows -Devices @($device))[0]
    Assert-WinSecDevices (@($row.PSObject.Properties).Count -eq 9 -and $row.Device -ceq 'FIXTURE' -and $row.HardwareId -ceq 'Not recorded' -and
        (ConvertTo-Json -InputObject $row -Compress) -notlike '*SYNTHETIC-DEVICES-PRIVATE*')
    $row.Hostname='changed'
    Assert-WinSecDevices ($before -ceq (ConvertTo-Json -InputObject $device -Depth 5 -Compress))
}
Test-WinSecDevices 'Collection limit rejects before publishing any row' {
    Assert-WinSecDevicesRejected {Get-WinSecDeviceRows -Devices (@(@{DeviceId='local:FIXTURE'})*10001)}
}
Test-WinSecDevices 'Selection retains navigation state and clamps to available devices' {
    $state=[pscustomobject]@{DeviceIndex=5}
    Assert-WinSecDevices ((Get-WinSecSelectedDeviceIndex -NavigationState $state -DeviceCount 2) -eq 1 -and
        (Get-WinSecSelectedDeviceIndex -DeviceCount 0) -eq -1 -and $state.DeviceIndex -eq 5)
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if($script:failed -gt 0){throw "$script:failed Devices public contract test(s) failed."}
