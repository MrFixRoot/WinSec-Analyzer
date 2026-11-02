# Candidate only: reviewed field definitions, not an execution permission or native query.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecDefenderTechnicalFields {
    [CmdletBinding()]param()
    $groups=@(
        @('Platform','Build','BuildNumber'),
        @('Platform','PlatformVersion','Version'),
        @('Platform','UInt32','OperatingSystemSKU,ProductType'),
        @('Status','Boolean','AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,DefenderSignaturesOutOfDate,IsTamperProtected,IsVirtualMachine,RebootRequired,FullScanOverdue,FullScanRequired,QuickScanOverdue'),
        @('Status','UInt32','AntispywareSignatureAge,AntivirusSignatureAge,NISSignatureAge,QuickScanAge,FullScanAge,ComputerState,LastFullScanSource,LastQuickScanSource,RealTimeScanDirection,ProductStatus'),
        @('Status','Version','AMEngineVersion,AMProductVersion,AMServiceVersion,AntispywareSignatureVersion,AntivirusSignatureVersion,NISEngineVersion,NISSignatureVersion,FullScanSignatureVersion,QuickScanSignatureVersion'),
        @('Status','Utc','AntispywareSignatureLastUpdated,AntivirusSignatureLastUpdated,NISSignatureLastUpdated,QuickScanStartTime,QuickScanEndTime,FullScanStartTime,FullScanEndTime'),
        @('Status','RunningMode','AMRunningMode'),
        @('Preferences','Boolean','CheckForSignaturesBeforeRunningScan,ScanOnlyIfIdleEnabled,SignatureDisableUpdateOnStartupWithoutEngine,MeteredConnectionUpdates,AllowNetworkProtectionOnWinServer,DisableDatagramProcessing,DisableCpuThrottleOnIdleScans,DisableAutoExclusions,DisablePrivacyMode,RandomizeScheduleTaskTimes,DisableBehaviorMonitoring,DisableRealtimeMonitoring,DisableScriptScanning,DisableArchiveScanning,DisableCatchupFullScan,DisableCatchupQuickScan,DisableEmailScanning,DisableRemovableDriveScanning,DisableRestorePoint,DisableScanningMappedNetworkDrivesForFullScan,DisableScanningNetworkFiles,DisableIOAVProtection,AllowSwitchToAsyncInspection,UILockdown,DisableBlockAtFirstSeen,DisableGradualRelease,EnableLowCpuPriority,EnableFileHashComputation,EnableFullScanOnBatteryPower,ForceUseProxyOnly,OobeEnableRtpAndSigUpdate,DisableTlsParsing,DisableHttpParsing,DisableDnsParsing,DisableFtpParsing,DisableSmtpParsing,DisableDnsOverTcpParsing,DisableSshParsing,DisableNetworkProtectionPerfTelemetry,AllowNetworkProtectionDownLevel,AllowDatagramProcessingOnWinServer,EnableDnsSinkhole,DisableInboundConnectionFiltering,DisableIntrusionPreventionSystem,DisableRdpParsing'),
        @('Preferences','UInt32','RealTimeScanDirection,IntelTDTEnabled,RemediationScheduleDay,ScanParameters,ScanScheduleDay,MAPSReporting,SubmitSamplesConsent,UnknownThreatDefaultAction,LowThreatDefaultAction,ModerateThreatDefaultAction,HighThreatDefaultAction,SevereThreatDefaultAction,DefinitionUpdatesChannel,EngineUpdatesChannel,PlatformUpdatesChannel,SignaturesUpdatesChannel,CloudBlockLevel,CloudExtendedTimeout,EnableNetworkProtection,EnableControlledFolderAccess,PUAProtection,SignatureUpdateInterval'),
        @('Preferences','Percent','ScanAvgCPULoadFactor'),
        @('ExclusionCounts','Count','ExclusionPath,ExclusionProcess,ExclusionExtension,AttackSurfaceReductionOnlyExclusions,ControlledFolderAccessAllowedApplications,ControlledFolderAccessProtectedFolders'),
        @('ASR','Guid','RuleId'),@('ASR','UInt32','Action')
    )
    foreach($group in $groups){foreach($property in $group[2].Split(',')){
        $suffix=if($group[0] -ceq 'Status' -and $property.EndsWith('Age',[StringComparison]::Ordinal)){'Days'}elseif($group[1] -ceq 'Count'){'Count'}elseif($property -ceq 'SignatureUpdateInterval'){'Hours'}else{''}
        $type=switch($group[1]){Boolean {'Boolean'};{$_ -cin @('UInt32','Build','Count','Percent')} {'UInt32'};default {'String'}}
        $unit=if($group[1] -ceq 'Count'){'count'}elseif($group[1] -ceq 'Percent'){'percent'}elseif($property -ceq 'CloudExtendedTimeout'){'seconds'}else{'none'}
        $required=($group[0] -ceq 'Platform' -or ($group[0] -ceq 'Status' -and $property -cin @('AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled')) -or
            ($group[0] -ceq 'Preferences' -and $property -ceq 'DisableRealtimeMonitoring') -or $group[0] -ceq 'ASR')
        [pscustomobject]@{Id=($group[0]+'.'+$property+$suffix);Inventory=$group[0];Property=$property;Kind=$group[1];Type=$type;Unit=$unit;Required=$required}
    }}
}

function Get-WinSecDefenderTechnicalCatalog {
    [CmdletBinding()]param([ValidateSet('1.0.0','1.1.0')][string]$CatalogVersion='1.0.0')
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()}
    $inventories=@(foreach($name in @('Platform','Status','Preferences','ExclusionCounts','ASR')){
        [pscustomobject]@{Id=$name;SourceId=$(if($name -cin @('ASR','ExclusionCounts')){'Preferences'}else{$name});Required=($name -cne 'ExclusionCounts');Singleton=($name -cne 'ASR');Applicability=$rule}
    })
    $fields=@(Get-WinSecDefenderTechnicalFields|ForEach-Object {
        [pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit=$_.Unit;Required=$_.Required;Exposure='CONFIGURATION';Applicability=$rule}
    })
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.Defender.Candidate';CatalogVersion=$CatalogVersion;CheckId='WSA-SYS-001';
        Sources=@(
            [pscustomobject]@{Id='Platform';Provider='CIM';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem'},
            [pscustomobject]@{Id='Status';Provider='CMDLET';ReferenceUrl='https://learn.microsoft.com/ca-es/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2022-ps'},
            $(if($CatalogVersion -ceq '1.1.0'){
                [pscustomobject]@{Id='Preferences';Provider='CIM';ReferenceUrl='https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mppreference'}
            }else{[pscustomobject]@{Id='Preferences';Provider='CMDLET';ReferenceUrl='https://learn.microsoft.com/en-us/powershell/module/defender/get-mppreference?view=windowsserver2025-ps'}}),
            [pscustomobject]@{Id='PreferenceSchema';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2025-ps'},
            [pscustomobject]@{Id='ASRReference';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference'});
        Inventories=$inventories;Fields=$fields}
}
