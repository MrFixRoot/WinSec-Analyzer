# Providers for Windows Update tests only. No native Windows queries or writes.
function Reset-WinSecWindowsUpdateFixture {
    $script:WU=@{
        DeviceId=('local:hw1-'+('a'*64));LocalIds=@('local:hw1-'+('a'*64));IdentityFails=$false
        IdentityReads=0;CimReads=0;KeyReads=0;FailClasses=@();FailKeys=@();MissingKeys=@()
        FailValues=@();FailClose=@();Closed=@();ValueReads=@();Kinds=@{}
        VersionReads=0;VersionValueReads=@();VersionClosed=0;VersionKeyFails=$false;VersionKeyMissing=$false;VersionCloseFails=$false
        VersionValues=@{CurrentBuildNumber='26100';UBR=9711;RegisteredOwner='PRIVATE-WU-OWNER'}
        RebootReads=0;RebootFails=$false;RebootValue=$false
        Systems=@([pscustomobject]@{Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1;Caption='PRIVATE-WU-CAPTION'})
        Services=@([pscustomobject]@{Name='wuauserv';State='Stopped';StartMode='Manual';StartName='PRIVATE-WU-ACCOUNT';PathName='PRIVATE-WU-PATH'})
        Values=@{
            AutomaticUpdates=@{NoAutoUpdate=0;AUOptions=4;UseWUServer=0}
            WindowsUpdate=@{DeferQualityUpdates=1;DeferQualityUpdatesPeriodInDays=7;SetDisableUXWUAccess=0
                DoNotConnectToWindowsUpdateInternetLocations=0;SetPolicyDrivenUpdateSourceForQualityUpdates=0}
        }
    }
}
function Get-WinSecLocalHardwareDeviceId {
    [CmdletBinding()]param()
    $script:WU.IdentityReads++
    if($script:WU.IdentityFails){throw 'PRIVATE-WU-IDENTITY'}
    $script:WU.LocalIds
}
function Get-CimInstance {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
    $script:WU.CimReads++
    if($Namespace -cne 'root/cimv2' -or $OperationTimeoutSec -ne 10){throw 'Unexpected CIM scope.'}
    if($script:WU.FailClasses -ccontains $ClassName){throw 'PRIVATE-WU-PROVIDER'}
    switch -CaseSensitive ($ClassName) {
        'Win32_OperatingSystem' {
            if(($Property -join ',') -cne 'Version,BuildNumber,OperatingSystemSKU,ProductType' -or $Filter){throw 'Unexpected OS query.'}
            return $script:WU.Systems
        }
        'Win32_Service' {
            if(($Property -join ',') -cne 'Name,State,StartMode' -or $Filter -cne "Name = 'wuauserv'"){throw 'Unexpected service query.'}
            return $script:WU.Services
        }
        default {throw 'Unexpected Windows query.'}
    }
}
function Open-WinSecWindowsUpdatePolicyKey {
    [CmdletBinding()]param([string]$SubKey)
    $area=switch -CaseSensitive ($SubKey) {
        'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' {'AutomaticUpdates'}
        'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' {'WindowsUpdate'}
        default {throw 'Unexpected registry scope.'}
    }
    $script:WU.KeyReads++
    if($script:WU.FailKeys -ccontains $area){throw 'PRIVATE-WU-REGISTRY'}
    if($script:WU.MissingKeys -ccontains $area){return $null}
    $key=[pscustomobject]@{Area=$area}
    $key|Add-Member -MemberType ScriptMethod -Name GetValue -Value {
        param($Name,$Default,$Options)
        if($Options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames -or $null -ne $Default){throw 'Unexpected registry options.'}
        $allowed=if($this.Area -ceq 'AutomaticUpdates'){@('NoAutoUpdate','AUOptions','UseWUServer')}
            else{@('DeferQualityUpdates','DeferQualityUpdatesPeriodInDays','SetDisableUXWUAccess',
                'DoNotConnectToWindowsUpdateInternetLocations','SetPolicyDrivenUpdateSourceForQualityUpdates')}
        if($Name -cnotin $allowed){throw 'Forbidden registry value.'}
        $id=$this.Area+'.'+$Name;$script:WU.ValueReads+=,$id
        if($script:WU.FailValues -ccontains $id){throw 'PRIVATE-WU-VALUE'}
        return ,$script:WU.Values[$this.Area][$Name]
    }
    $key|Add-Member -MemberType ScriptMethod -Name GetValueKind -Value {
        param($Name)
        $id=$this.Area+'.'+$Name
        if($script:WU.Kinds.ContainsKey($id)){return $script:WU.Kinds[$id]}
        return [Microsoft.Win32.RegistryValueKind]::DWord
    }
    $key|Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $script:WU.Closed+=,$this.Area
        if($script:WU.FailClose -ccontains $this.Area){throw 'PRIVATE-WU-CLOSE'}
    }
    return $key
}

function Open-WinSecWindowsUpdateVersionKey {
    [CmdletBinding()]param()
    $script:WU.VersionReads++
    if($script:WU.VersionKeyFails){throw 'PRIVATE-WU-VERSION-KEY'}
    if($script:WU.VersionKeyMissing){return $null}
    $key=[pscustomobject]@{Area='Version'}
    $key|Add-Member ScriptMethod GetValue {
        param($Name,$Default,$Options)
        if($Name -cnotin @('CurrentBuildNumber','UBR') -or $null -ne $Default -or
            $Options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames){throw 'Forbidden version value.'}
        $script:WU.VersionValueReads+=,$Name
        if($script:WU.FailValues -ccontains ('Version.'+$Name)){throw 'PRIVATE-WU-VERSION-VALUE'}
        return ,$script:WU.VersionValues[$Name]
    }
    $key|Add-Member ScriptMethod GetValueKind {
        param($Name)
        if($script:WU.Kinds.ContainsKey('Version.'+$Name)){return $script:WU.Kinds['Version.'+$Name]}
        if($Name -ceq 'CurrentBuildNumber'){return [Microsoft.Win32.RegistryValueKind]::String}
        return [Microsoft.Win32.RegistryValueKind]::DWord
    }
    $key|Add-Member ScriptMethod Dispose {
        $script:WU.VersionClosed++
        if($script:WU.VersionCloseFails){throw 'PRIVATE-WU-VERSION-CLOSE'}
    }
    return $key
}

function Get-WinSecWindowsUpdateRebootRequired {
    [CmdletBinding()]param()
    $script:WU.RebootReads++
    if($script:WU.RebootFails){throw 'PRIVATE-WU-REBOOT'}
    return ,$script:WU.RebootValue
}
