# Reviewed local RDP configuration projection. Importing this file performs no queries.
function Get-WinSecRdpClasses {
    $spec=@(
        'Global|Win32_TerminalServiceSetting|AllowTSConnections,PolicySourceAllowTSConnections,SingleSession,TerminalServerMode,DeleteTempFolders,PolicySourceDeleteTempFolders,UseTempFolders,PolicySourceUseTempFolders,UserPermission'
        'General|Win32_TSGeneralSetting|MinEncryptionLevel,PolicySourceMinEncryptionLevel,SecurityLayer,PolicySourceSecurityLayer,UserAuthenticationRequired,PolicySourceUserAuthenticationRequired,WindowsAuthentication,SSLCertificateSHA1HashType'
        'Logon|Win32_TSLogonSetting|ClientLogonInfoPolicy,PromptForPassword,PolicySourcePromptForPassword'
        'Session|Win32_TSSessionSetting|ActiveSessionLimit,BrokenConnectionAction,BrokenConnectionPolicy,DisconnectedSessionLimit,IdleSessionLimit,PolicySourceActiveSessionLimit,PolicySourceBrokenConnectionAction,PolicySourceDisconnectedSessionLimit,PolicySourceIdleSessionLimit,PolicySourceReconnectionPolicy,ReconnectionPolicy,TimeLimitPolicy,EnableTimeoutWarning'
        'Redirection|Win32_TSClientSetting|ConnectionPolicy,ConnectClientDrivesAtLogon,ConnectPrinterAtLogon,DefaultToClientPrinter,PolicySourceDefaultToClientPrinter,WindowsPrinterMapping,PolicySourceWindowsPrinterMapping,LPTPortMapping,PolicySourceLPTPortMapping,COMPortMapping,PolicySourceCOMPortMapping,DriveMapping,PolicySourceDriveMapping,AudioMapping,PolicySourceAudioMapping,ClipboardMapping,PolicySourceClipboardMapping,ColorDepthPolicy,PolicySourceColorDepthPolicy,ColorDepth,PolicySourceColorDepth,MaxMonitors,MaxXResolution,MaxYResolution,PolicySourceMaxMonitors,PolicySourceMaxResolution,PNPRedirection,PolicySourcePNPRedirection,AudioCaptureRedir,PolicySourceAudioCaptureRedir,VideoPlaybackRedir,PolicySourceVideoPlaybackRedir,AllowDwm,PolicySourceAllowDwm,PolicyAdvancedRemoteAppGraphics,AdvancedRemoteAppGraphics,RemoteSessionProfile,PolicySourceRemoteSessionProfile,AVC444ModePreferred,PolicySourceAvc444ModePreferred,EncodeImageQuality,PolicySourceEncodeImageQuality,HardwareGraphicsAdapter,PolicySourceHardwareGraphicsAdapter,SelectTransport,PolicySourceSelectTransport,SelectNetworkDetect,PolicySourceSelectNetworkDetect'
        'Network|Win32_TSNetworkAdapterSetting|MaximumConnections,NetworkAdapterLanaID,PolicySourceMaximumConnections'
        'Permissions|Win32_TSPermissionsSetting|DenyAdminPermissionForCustomization,PolicySourceDenyAdminPermissionForCustomization'
    )
    foreach($s in $spec){$p=$s.Split('|');[pscustomobject]@{Id=$p[0];Class=$p[1];Fields=@($p[2].Split(','));Singleton=($p[0] -ceq 'Global')}}
}
function Get-WinSecRdpRegistryDefinitions {
    $hostKey='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $spec=@(
        @{Id='LocalDenyConnections';Key='SYSTEM\CurrentControlSet\Control\Terminal Server';Name='fDenyTSConnections';Max=1}
        @{Id='LocalSingleSession';Key='SYSTEM\CurrentControlSet\Control\Terminal Server';Name='fSingleSessionPerUser';Max=1}
        @{Id='ListenerPort';Key='SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';Name='PortNumber';Max=65535}
        @{Id='ListenerNLA';Key='SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';Name='UserAuthentication';Max=1}
        @{Id='ListenerSecurityLayer';Key='SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';Name='SecurityLayer';Max=2}
        @{Id='ListenerEncryption';Key='SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';Name='MinEncryptionLevel';Max=4}
    )
    foreach($name in @('fDenyTSConnections','UserAuthentication','SecurityLayer','MinEncryptionLevel','fPromptForPassword','fDisableCdm',
        'fDisableClip','fDisableCpm','fDisableCcm','fDisableLPT','fDisablePNPRedir','fDisableAudioCapture','fDisableCam','fDisableCameraRedir',
        'fSingleSessionPerUser','fResetBroken','fReconnectSame','MaxIdleTime','MaxDisconnectionTime',
        'MaxConnectionTime','MaxInstanceCount','DeleteTempDirsOnExit','PerSessionTempDir','fDisableAutoReconnect',
        'fEncryptRPCTraffic','fDisableWebAuthn','DisablePasswordSaving','AllowSignedFiles','AllowUnsignedFiles',
        'fEnableSmartCard','fEnableTimeZoneRedirection','fWritableTSCCPermTab','EnableUiaRedirection',
        'fForceClientLptDef','bEnumerateHWBeforeSW','UseUniversalPrinterDriverFirst','AVCHardwareEncodePreferred','AVC444ModePreferred')){
        $max=switch($name){SecurityLayer {2};MinEncryptionLevel {4};{$_ -cin @('MaxIdleTime','MaxDisconnectionTime','MaxConnectionTime','MaxInstanceCount')} {4294967295};default {1}}
        $spec+=@{Id=('Policy_'+$name);Key=$hostKey;Name=$name;Max=$max}
    }
    foreach($name in @('fClientDisableUDP','EnableHardwareMode')){
        if(@($spec|Where-Object Id -CEQ ('Client_'+$name)).Count){continue}
        $spec+=@{Id=('Client_'+$name);Key=($hostKey+'\Client');Name=$name;Max=1}
    }
    foreach($d in $spec){[pscustomobject]$d}
}
function Get-WinSecRdpHostSupport {
    param($Build,$Sku,$ProductType)
    if($Build -isnot [int] -and $Build -isnot [long]){return 'UNKNOWN'}
    if($Build -lt 22000 -or $ProductType -ne 1 -or $null -eq $Sku){return 'UNKNOWN'}
    if($Sku -cin @(98,99,100,101)){return 'UNSUPPORTED_HOME'}
    if($Sku -cin @(4,27,48,49,121,122,125,126,161,162,164,165,188,191)){return 'SUPPORTED'}
    return 'UNKNOWN'
}
function Get-WinSecRdpIssueCodes {
    @('PLATFORM_UNAVAILABLE','HOST_EDITION_UNRESOLVED','SERVICES_UNAVAILABLE','CONFIGURATION_FIELDS_UNAVAILABLE','HOST_STATE_CONFLICT')
    foreach($c in Get-WinSecRdpClasses){'PROVIDER_'+$c.Id.ToUpperInvariant()+'_UNAVAILABLE'}
    foreach($d in Get-WinSecRdpRegistryDefinitions){'REGISTRY_'+$d.Id.ToUpperInvariant()+'_UNAVAILABLE'}
}
function Get-WinSecRdpRequiredFields {
    param([string]$ClassId)
    switch($ClassId){Global {@('AllowTSConnections')};General {@('UserAuthenticationRequired','SecurityLayer','MinEncryptionLevel')}}
}
function Get-WinSecRdpNotApplicableFields {
    param([string]$ClassId,[AllowNull()][object]$Platform)
    # Documented retired desktop-composition fields, not arbitrary provider nulls.
    if($ClassId -ceq 'Redirection' -and $null -ne $Platform -and $Platform.ProductType -eq 1 -and
        $Platform.BuildNumber -cin @(22000,22621,22631,26100,26200,28000)){
        @('AllowDwm','PolicySourceAllowDwm')
    }
}
function Get-WinSecRdpTechnicalDefinitions {
    param([switch]$Legacy)
    $spec=@('CollectionSuccessful|Collection|bool|Collector|','CollectionComplete|Collection|bool|Collector|',
        'CollectionIssueCount|Collection|number|Collector|','CollectionIssueCodes|Collection|rdpIssues|Collector|',
        'UnknownFieldCount|Collection|number|Collector|','HostSupport|Windows context|rdpSupport|Observed Windows|',
        'HostEnabled|Effective host configuration|bool|CIM:Win32_TerminalServiceSetting|HostState',
        'Platform.BuildNumber|Windows context|number|CIM:Win32_OperatingSystem|',
        'Platform.OperatingSystemSKU|Windows context|number|CIM:Win32_OperatingSystem|',
        'Platform.ProductType|Windows context|number|CIM:Win32_OperatingSystem|')
    if(-not $Legacy){$spec+=@('CoverageComplete|Collection coverage|bool|Collector|',
        'InformationalUnknownFieldCount|Collection coverage|number|Collector|','RequiredUnknownFieldCount|Collection coverage|number|Collector|',
        'NotApplicableFieldCount|Collection coverage|number|Collector|')}
    foreach($name in @('TermService','UmRdpService','SessionEnv')){
        foreach($field in @('State','StartMode')){$spec+=('Services.'+$name+'.'+$field+'|RDP services|mode|CIM:Win32_Service|')}
    }
    foreach($c in Get-WinSecRdpClasses){$spec+=('Inventory.'+$c.Id+'|RDP '+$c.Id+' configuration|rdpInventory|CIM:'+$c.Class+'|Availability.'+$c.Id)}
    foreach($d in Get-WinSecRdpRegistryDefinitions){
        $spec+=('Registry.'+$d.Id+'.State|Local and policy registry configuration|mode|Registry:HKLM|')
        $spec+=('Registry.'+$d.Id+'.Value|Local and policy registry configuration|number|Registry:HKLM|Registry.'+$d.Id+'.State')
    }
    foreach($s in $spec){$p=$s.Split('|');[pscustomobject]@{Id=$p[0];Group=$p[1];Kind=$p[2];Source=$p[3];StatePath=$p[4]}}
}
function ConvertTo-WinSecRdpNumber {
    param([AllowNull()][object]$Value)
    if($null -ne $Value -and $Value.GetType() -in @([byte],[uint16],[int16],[int],[uint32],[long],[uint64]) -and
        [decimal]$Value -ge 0 -and [decimal]$Value -le 4294967295){return [long]$Value}
    return $null
}
function ConvertTo-WinSecRdpInventory {
    param([string]$Json)
    if($Json.Length -gt 300000){throw 'RDP inventory exceeds the reviewed limit.'}
    $b=ConvertFrom-WinSecStoredJson $Json
    $modern=($null -ne $b.PSObject.Properties['SchemaVersion'])
    if($modern){
        Assert-WinSecConfigurationFields $b @('SchemaVersion','Class','NotApplicableFields','Items')
        if($b.SchemaVersion -cne '1.1.0' -or $b.NotApplicableFields -isnot [array] -or $b.NotApplicableFields.Count -gt 2 -or
            @($b.NotApplicableFields|Select-Object -Unique).Count -ne $b.NotApplicableFields.Count -or
            @($b.NotApplicableFields|Where-Object {$_ -isnot [string] -or $_ -cnotin @('AllowDwm','PolicySourceAllowDwm') -or $b.Class -cne 'Redirection'}).Count){throw 'Invalid RDP field exclusions.'}
    } else {Assert-WinSecConfigurationFields $b @('Class','Items')}
    $defs=@(Get-WinSecRdpClasses|Where-Object Id -CEQ $b.Class)
    if($defs.Count -ne 1 -or $b.Items -isnot [array] -or $b.Items.Count -gt 64 -or ($defs[0].Singleton -and $b.Items.Count -ne 1)){throw 'Invalid RDP inventory.'}
    $seen=@{}
    foreach($item in $b.Items){
        Assert-WinSecConfigurationFields $item @('Id','Values')
        if($item.Id -isnot [string] -or $item.Id -cnotmatch '\A(?:GLOBAL|RDP_TCP|[a-f0-9]{64})\z' -or $seen.ContainsKey($item.Id) -or
            ($defs[0].Singleton -ne ($item.Id -ceq 'GLOBAL'))){throw 'Invalid RDP listener identity.'}
        $seen[$item.Id]=$true
        Assert-WinSecConfigurationFields $item.Values $defs[0].Fields
        foreach($name in $defs[0].Fields){
            if($modern -and $name -cin $b.NotApplicableFields -and $null -ne $item.Values.$name){throw 'Excluded RDP field cannot supply a value.'}
            if($null -ne $item.Values.$name -and $null -eq (ConvertTo-WinSecRdpNumber $item.Values.$name)){throw 'Unsafe RDP configuration value.'}
            if($modern -and $null -ne $item.Values.$name -and $null -eq (ConvertTo-WinSecRdpConfigurationValue $b.Class $name $item.Values.$name)){throw 'Invalid principal RDP configuration value.'}
        }
    }
    return $b
}
function ConvertTo-WinSecRdpConfigurationValue {
    param([string]$ClassId,[string]$Field,[AllowNull()][object]$Value)
    $v=ConvertTo-WinSecRdpNumber $Value
    if($null -eq $v){return $null}
    if(($ClassId -ceq 'Global' -and $Field -ceq 'AllowTSConnections' -and $v -notin @(0,1)) -or
        ($ClassId -ceq 'General' -and $Field -ceq 'UserAuthenticationRequired' -and $v -notin @(0,1)) -or
        ($ClassId -ceq 'General' -and $Field -ceq 'MinEncryptionLevel' -and $v -notin @(1,2,3,4)) -or
        ($ClassId -ceq 'General' -and $Field -ceq 'SecurityLayer' -and $v -notin @(0,1,2,3,4))){return $null}
    return $v
}
