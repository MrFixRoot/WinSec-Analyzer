# Isolated SMB configuration candidate. Importing the catalog performs no Windows queries.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecSmbCandidateRegistry {
    [CmdletBinding()]param()
    foreach($spec in @(
        'ServerSMB1|SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1|DWord',
        'ServerAuditSMB1|SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|AuditSmb1Access|DWord',
        'ClientDriverStart|SYSTEM\CurrentControlSet\Services\mrxsmb10|Start|DWord',
        'ServerDriverStart|SYSTEM\CurrentControlSet\Services\srv|Start|DWord',
        'ModernClientDriverStart|SYSTEM\CurrentControlSet\Services\mrxsmb20|Start|DWord',
        'ModernServerDriverStart|SYSTEM\CurrentControlSet\Services\srv2|Start|DWord',
        'ClientDependencies|SYSTEM\CurrentControlSet\Services\LanmanWorkstation|DependOnService|MultiString',
        'GuestPolicy|SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation|AllowInsecureGuestAuth|DWord')){
        $p=$spec.Split('|');[pscustomobject]@{Id=$p[0];Key=$p[1];Name=$p[2];Kind=$p[3]}
    }
}

function Get-WinSecSmbCandidateAreas {
    [CmdletBinding()]param()
    foreach($spec in @(
        'Platform|CIM|LOCAL|https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem',
        'Server|CMDLET|LOCAL|https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbserverconfiguration',
        'Client|CMDLET|LOCAL|https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbclientconfiguration',
        'Features|CIM|LOCAL|https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-optionalfeature',
        'Services|CIM|LOCAL|https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service',
        'Registry|REGISTRY|HKLM_REGISTRY64|https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3')){
        $p=$spec.Split('|');[pscustomobject]@{Id=$p[0];Provider=$p[1];Location=$p[2];ReferenceUrl=$p[3]}
    }
}

function Get-WinSecSmbCandidateFields {
    [CmdletBinding()]param()
    foreach($area in Get-WinSecSmbCandidateAreas){
        $groups=switch -CaseSensitive ($area.Id){
            Platform {'Version|Version';'Build|BuildNumber';'UInt32|OperatingSystemSKU,ProductType'}
            Server {
                'Boolean|EnableSMB1Protocol,EnableSMB2Protocol,AuditSmb1Access,EnableSecuritySignature,RequireSecuritySignature,EncryptData,RejectUnencryptedAccess,EnableAuthenticateUserSharing,EnableForcedLogoff,EnableStrictNameChecking,EnableMultiChannel,EnableLeasing,EnableOplocks,AnnounceServer,AutoShareServer,AutoShareWorkstation,EnableDownlevelTimewarp,ServerHidden,TreatHostAsStableStorage,ValidateAliasNotCircular,ValidateShareScope,ValidateShareScopeNotAliased,ValidateTargetName,DisableSmbEncryptionOnSecureConnection,EnableSMBQUIC,RestrictNamedpipeAccessViaQuic,AuditClientDoesNotSupportEncryption,AuditClientDoesNotSupportSigning,EnableMailslots,AuditClientCertificateAccess,AuditInsecureGuestLogon,DisableCompression,RequestCompression,EnableDirectoryHandleLeasing'
                'UInt32|AsynchronousCredits,AutoDisconnectTimeout,CachedOpenLimit,DurableHandleV2TimeoutInSeconds,IrpStackSize,KeepAliveTime,MaxChannelPerSession,MaxMpxCount,MaxSessionPerConnection,MaxThreadsPerQueue,MaxWorkItems,OplockBreakWait,PendingClientTimeoutInSeconds,Smb2CreditsMax,Smb2CreditsMin,SmbServerNameHardeningLevel,AutoDisconnectTimeoutInMinutesV1,AutoDisconnectTimeoutInSecondsV2,InvalidAuthenticationDelayTimeInMs'
                'Ciphers|EncryptionCiphers';'Dialect|Smb2DialectMin,Smb2DialectMax'
            }
            Client {
                'Boolean|EnableSecuritySignature,RequireSecuritySignature,EnableInsecureGuestLogons,EnableBandwidthThrottling,EnableByteRangeLockingOnReadOnlyFiles,EnableLargeMtu,EnableLoadBalanceScaleOut,EnableMultiChannel,OplocksDisabled,UseOpportunisticLocking,ForceSMBEncryptionOverQuic,SkipCertificateCheck,RequireEncryption,AuditServerDoesNotSupportEncryption,AuditServerDoesNotSupportSigning,AuditInsecureGuestLogon,BlockNTLM,EnableMailslots,DisableCompression,EnableCompressibilitySampling,EnableSMBQUIC,RequestCompression'
                'UInt32|ConnectionCountPerRssNetworkInterface,DirectoryCacheEntriesMax,DirectoryCacheEntrySizeMax,DirectoryCacheLifetime,DormantFileLimit,ExtendedSessionTimeout,FileInfoCacheEntriesMax,FileInfoCacheLifetime,FileNotFoundCacheEntriesMax,FileNotFoundCacheLifetime,KeepConn,MaxCmds,MaximumConnectionCountPerServer,SessionTimeout,WindowSizeThreshold,InvalidAuthenticationCacheLifetime'
                'Ciphers|EncryptionCiphers';'Dialect|Smb2DialectMin,Smb2DialectMax';'UInt64Text|CompressibilitySamplingSize,CompressibleThreshold'
            }
            Features {'FeatureName|Name';'UInt32|InstallState';'Installation|InstallationState';'Status|Status';'Utc|InstallDate'}
            Services {'ServiceName|Name';'ServiceState|State';'StartMode|StartMode';'Boolean|Started,DelayedAutoStart';'UInt32|ExitCode,ServiceSpecificExitCode,CheckPoint,WaitHint';'ErrorControl|ErrorControl'}
            Registry {
                'RegistryDWord|ServerSMB1,ServerAuditSMB1,ClientDriverStart,ServerDriverStart,ModernClientDriverStart,ModernServerDriverStart,GuestPolicy'
                'Dependencies|ClientDependencies';'DependencyCount|ClientDependencies'
            }
        }
        foreach($spec in $groups){$p=$spec.Split('|');foreach($name in $p[1].Split(',')){
            $suffix=if($p[0] -ceq 'DependencyCount'){'ReportedCount'}else{''}
            $type=switch($p[0]){Boolean {'Boolean'};{$_ -cin @('Build','UInt32','RegistryDWord','DependencyCount')} {'UInt32'};Dependencies {'StringArray'};default {'String'}}
            $required=($area.Id -cin @('Platform','Registry') -or $p[0] -cin @('FeatureName','ServiceName') -or
                ($area.Id -ceq 'Server' -and $name -cin @('EnableSMB1Protocol','EnableSMB2Protocol','AuditSmb1Access','RequireSecuritySignature')) -or
                ($area.Id -ceq 'Client' -and $name -cin @('RequireSecuritySignature','EnableInsecureGuestLogons')) -or
                ($area.Id -ceq 'Features' -and $name -cin @('InstallState','InstallationState')) -or
                ($area.Id -ceq 'Services' -and $name -cin @('State','StartMode')))
            [pscustomobject]@{Id=($area.Id+'.'+$name+$suffix);Inventory=$area.Id;Property=$name;Kind=$p[0];Type=$type;Required=$required;
                Exposure=$(if($p[0] -ceq 'Dependencies'){'IDENTIFIABLE'}else{'CONFIGURATION'})}
        }}
    }
    foreach($area in Get-WinSecSmbCandidateAreas){foreach($kind in @('Time','SourceState','Location')){
        [pscustomobject]@{Id=('Capture.'+$area.Id+$kind);Inventory='Capture';Property=($area.Id+$kind);Kind=$kind;Type='String';Required=$true;Exposure='CONFIGURATION'}
    }}
    [pscustomobject]@{Id='Capture.Scope';Inventory='Capture';Property='Scope';Kind='Scope';Type='String';Required=$true;Exposure='CONFIGURATION'}
}

function Get-WinSecSmbCandidateCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecSmbCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider=$_.Provider;ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbserverconfiguration'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=($_.Id -cnotin @('Features','Services'));Applicability=$rule}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=$rule}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.SMB.Candidate';CatalogVersion='1.0.0';CheckId='WSA-NET-002';
        Sources=$sources;Inventories=$inventories;Fields=@(Get-WinSecSmbCandidateFields|ForEach-Object {
            [pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit=$(if($_.Kind -ceq 'DependencyCount'){'count'}else{'none'});Required=$_.Required;Exposure=$_.Exposure;Applicability=$rule}})}
}
