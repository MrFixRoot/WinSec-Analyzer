# Closed SMB configuration projection. Importing this file performs no collection.
function Get-WinSecSmbConfigurationFields {
    param([ValidateSet('Server','Client')][string]$Role)
    $bool=if($Role -ceq 'Server') {
        @('EnableSMB1Protocol','EnableSMB2Protocol','AuditSmb1Access','EnableSecuritySignature','RequireSecuritySignature',
          'EncryptData','RejectUnencryptedAccess','EnableAuthenticateUserSharing','EnableForcedLogoff','EnableStrictNameChecking',
          'EnableMultiChannel','EnableLeasing','EnableOplocks','AnnounceServer','AutoShareServer','AutoShareWorkstation',
          'EnableDownlevelTimewarp','ServerHidden','TreatHostAsStableStorage','ValidateAliasNotCircular','ValidateShareScope',
          'ValidateShareScopeNotAliased','ValidateTargetName','DisableSmbEncryptionOnSecureConnection','EnableSMBQUIC',
          'RestrictNamedpipeAccessViaQuic','AuditClientDoesNotSupportEncryption','AuditClientDoesNotSupportSigning',
          'EnableMailslots')
    } else {
        @('EnableSecuritySignature','RequireSecuritySignature','EnableInsecureGuestLogons','EnableBandwidthThrottling',
          'EnableByteRangeLockingOnReadOnlyFiles','EnableLargeMtu','EnableLoadBalanceScaleOut','EnableMultiChannel',
          'OplocksDisabled','UseOpportunisticLocking','ForceSMBEncryptionOverQuic','SkipCertificateCheck',
          'RequireEncryption','AuditServerDoesNotSupportEncryption','AuditServerDoesNotSupportSigning',
          'AuditInsecureGuestLogon','BlockNTLM','EnableMailslots')
    }
    # Dialects are not booleans; unknown enumeration values are not published.
    foreach($name in @($bool|Select-Object -Unique|Where-Object {$_ -notlike '*Dialect*'})) {
        [pscustomobject]@{Name=$name;Kind='bool';Modern=($name -cin @('AuditClientDoesNotSupportEncryption','AuditClientDoesNotSupportSigning',
            'AuditServerDoesNotSupportEncryption','AuditServerDoesNotSupportSigning','AuditInsecureGuestLogon'))}
    }
    $numbers=if($Role -ceq 'Server') {
        @('AsynchronousCredits','AutoDisconnectTimeout','CachedOpenLimit','DurableHandleV2TimeoutInSeconds','IrpStackSize',
          'KeepAliveTime','MaxChannelPerSession','MaxMpxCount','MaxSessionPerConnection','MaxThreadsPerQueue','MaxWorkItems',
          'OplockBreakWait','PendingClientTimeoutInSeconds','Smb2CreditsMax','Smb2CreditsMin','SmbServerNameHardeningLevel')
    } else {
        @('ConnectionCountPerRssNetworkInterface','DirectoryCacheEntriesMax','DirectoryCacheEntrySizeMax','DirectoryCacheLifetime',
          'DormantFileLimit','ExtendedSessionTimeout','FileInfoCacheEntriesMax','FileInfoCacheLifetime','FileNotFoundCacheEntriesMax',
          'FileNotFoundCacheLifetime','KeepConn','MaxCmds','MaximumConnectionCountPerServer','SessionTimeout','WindowSizeThreshold')
    }
    foreach($name in $numbers){[pscustomobject]@{Name=$name;Kind='number';Modern=$false}}
    foreach($name in @('EncryptionCiphers','Smb2DialectMin','Smb2DialectMax')){
        [pscustomobject]@{Name=$name;Kind=if($name -ceq 'EncryptionCiphers'){'smbCiphers'}else{'smbDialect'};Modern=$false}
    }
    if($Role -ceq 'Server') {
        foreach($name in @('NullSessionPipes','NullSessionShares')){[pscustomobject]@{Name=($name+'Count');Kind='number';Modern=$false}}
    }
}
function Get-WinSecSmbRegistryDefinitions {
    @(
        @{Id='ServerSMB1';Key='SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';Name='SMB1';Kind='DWord'}
        @{Id='ServerAuditSMB1';Key='SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';Name='AuditSmb1Access';Kind='DWord'}
        @{Id='ClientDriverStart';Key='SYSTEM\CurrentControlSet\Services\mrxsmb10';Name='Start';Kind='DWord'}
        @{Id='ServerDriverStart';Key='SYSTEM\CurrentControlSet\Services\srv';Name='Start';Kind='DWord'}
        @{Id='ModernClientDriverStart';Key='SYSTEM\CurrentControlSet\Services\mrxsmb20';Name='Start';Kind='DWord'}
        @{Id='ModernServerDriverStart';Key='SYSTEM\CurrentControlSet\Services\srv2';Name='Start';Kind='DWord'}
        @{Id='ClientDependsOnSMB1';Key='SYSTEM\CurrentControlSet\Services\LanmanWorkstation';Name='DependOnService';Kind='MultiString'}
        @{Id='GuestPolicy';Key='SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation';Name='AllowInsecureGuestAuth';Kind='DWord'}
    )|ForEach-Object {[pscustomobject]$_}
}
function Get-WinSecSmbIssueCodes {
    @('PLATFORM_UNAVAILABLE','SERVER_UNAVAILABLE','CLIENT_UNAVAILABLE','FEATURES_UNAVAILABLE','SERVICES_UNAVAILABLE',
      'FEATURE_IDENTITY_INVALID','SERVICE_IDENTITY_INVALID','SERVER_REQUIRED_FIELDS_UNAVAILABLE','CLIENT_REQUIRED_FIELDS_UNAVAILABLE')
    foreach($name in @('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server','SMB1Protocol-Deprecation')){'FEATURE_'+($name.Replace('-','_'))+'_UNAVAILABLE'}
    foreach($d in Get-WinSecSmbRegistryDefinitions){'REGISTRY_'+$d.Id.ToUpperInvariant()+'_UNAVAILABLE'}
}
function Get-WinSecSmbTechnicalDefinitions {
    $spec=@('CollectionSuccessful|Collection|bool|Collector|','CollectionComplete|Collection|bool|Collector|',
        'CollectionIssueCount|Collection|number|Collector|','CollectionIssueCodes|Collection|smbIssues|Collector|',
        'Platform.BuildNumber|Windows context|number|CIM:Win32_OperatingSystem|',
        'Platform.OperatingSystemSKU|Windows context|number|CIM:Win32_OperatingSystem|',
        'Platform.ProductType|Windows context|number|CIM:Win32_OperatingSystem|')
    foreach($role in @('Server','Client')) {
        foreach($f in Get-WinSecSmbConfigurationFields $role){$state=if($f.Modern){'Availability.'+$role+'.'+$f.Name}else{''};$spec+=($role+'.'+$f.Name+'|SMB '+$role+' configuration|'+$f.Kind+'|Get-Smb'+$role+'Configuration|'+$state)}
    }
    foreach($name in @('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server','SMB1Protocol-Deprecation')){
        $spec+=('Features.'+$name+'|SMBv1 optional features|smbFeature|CIM:Win32_OptionalFeature|')
    }
    foreach($name in @('LanmanServer','LanmanWorkstation')){
        $spec+=('Services.'+$name+'.State|SMB services|mode|CIM:Win32_Service|')
        $spec+=('Services.'+$name+'.StartMode|SMB services|mode|CIM:Win32_Service|')
    }
    foreach($d in Get-WinSecSmbRegistryDefinitions){
        $spec+=('Registry.'+$d.Id+'.State|SMBv1 registry configuration|mode|Registry:HKLM|')
        $kind=if($d.Kind -ceq 'MultiString'){'bool'}else{'number'}
        $spec+=('Registry.'+$d.Id+'.Value|SMBv1 registry configuration|'+$kind+'|Registry:HKLM|Registry.'+$d.Id+'.State')
    }
    foreach($line in $spec){$p=$line.Split('|');[pscustomobject]@{Id=$p[0];Group=$p[1];Kind=$p[2];Source=$p[3];StatePath=$p[4]}}
}
function ConvertTo-WinSecSmbValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    if($null -eq $Value){return $null}
    switch($Kind) {
        bool {if($Value -is [bool]){return $Value}}
        number {
            if($Value.GetType() -in @([byte],[uint16],[int16],[uint32],[int],[long],[uint64]) -and
                [decimal]$Value -ge 0 -and [decimal]$Value -le 4294967295){return [long]$Value}
        }
        smbFeature {if($Value -is [string] -and $Value -cin @('ENABLED','DISABLED','ABSENT','UNKNOWN')){return $Value}}
        smbDialect {if($Value -is [string] -and $Value -cin @('None','SMB202','SMB210','SMB300','SMB302','SMB311')){return $Value}}
        smbCiphers {
            if($Value -is [string] -and $Value.Length -le 160){
                $tokens=@($Value.Split(',')|ForEach-Object {$_.Trim()})
                if($tokens.Count -ge 1 -and $tokens.Count -le 4 -and
                    @($tokens|Where-Object {$_ -cnotin @('AES_128_GCM','AES_128_CCM','AES_256_GCM','AES_256_CCM')}).Count -eq 0 -and
                    @($tokens|Select-Object -Unique).Count -eq $tokens.Count){return ($tokens -join ',')}
            }
        }
    }
    return $null
}
