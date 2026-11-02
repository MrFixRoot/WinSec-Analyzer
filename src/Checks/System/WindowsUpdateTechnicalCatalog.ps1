# Candidate field contract only. No provider access or production registration.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecWindowsUpdateTechnicalServices {
    [CmdletBinding()]param()
    @('wuauserv','BITS','UsoSvc','WaaSMedicSvc','DoSvc','TrustedInstaller')
}

function Get-WinSecWindowsUpdateTechnicalAreas {
    [CmdletBinding()]param()
    foreach($row in @('Platform|CIM|https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem',
        'Revision|REGISTRY|https://learn.microsoft.com/en-us/intune/app-management/deployment/deploy-win32-update-package',
        'Services|CIM|https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service',
        'GPOAU|REGISTRY|https://learn.microsoft.com/de-de/security-updates/windowsupdateservices/21669493',
        'GPOUpdate|REGISTRY|https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update',
        'Reboot|DERIVED|https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-isysteminformation',
        'InstalledCBSUpdates|CIM|https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering')){
        $p=$row.Split('|');[pscustomobject]@{Id=$p[0];Provider=$p[1];ReferenceUrl=$p[2];List=($p[0] -cin @('Services','InstalledCBSUpdates'))}
    }
}

function Get-WinSecWindowsUpdateTechnicalFields {
    [CmdletBinding()]param()
    $groups=@(@('Platform','Version','Version'),@('Platform','Build','BuildNumber'),@('Platform','UInt32','OperatingSystemSKU,ProductType'),
        @('Revision','Build','CurrentBuildNumber'),@('Revision','UInt32','UBR'),@('Services','ServiceName','Name'),
        @('Services','ServiceState','State'),@('Services','StartMode','StartMode'),@('Services','Boolean','Started'),@('Services','UInt32','ExitCode,ServiceSpecificExitCode'),
        @('GPOAU','UInt32','NoAutoUpdate,AUOptions,ScheduledInstallDay,ScheduledInstallTime,NoAutoRebootWithLoggedOnUsers,UseWUServer,DetectionFrequencyEnabled,DetectionFrequency'),
        @('GPOUpdate','UInt32','ExcludeWUDriversInQualityUpdate,DeferFeatureUpdates,DeferFeatureUpdatesPeriodInDays,DeferQualityUpdates,DeferQualityUpdatesPeriodInDays,SetDisableUXWUAccess,DoNotConnectToWindowsUpdateInternetLocations,TargetReleaseVersion,ConfigureDeadlineForQualityUpdates,ConfigureDeadlineForFeatureUpdates,ConfigureDeadlineGracePeriod,SetDisablePauseUXAccess'),
        @('Reboot','Boolean','RebootRequired'),@('InstalledCBSUpdates','HotFix','HotFixID'),@('InstalledCBSUpdates','DateText','InstalledOn'),
        @('InstalledCBSUpdates','Utc','InstallDate'),@('InstalledCBSUpdates','QfeStatus','Status'))
    foreach($area in Get-WinSecWindowsUpdateTechnicalAreas){$groups+=,@('Capture','CaptureTime',($area.Id+'AtUTC'));$groups+=,@('Capture','SourceState',($area.Id+'State'))}
    $groups+=,@('Capture','Scope','InstalledInventoryScope')
    foreach($group in $groups){foreach($name in $group[2].Split(',')){
        $type=switch($group[1]){Boolean {'Boolean'};{$_ -cin @('UInt32','Build')} {'UInt32'};default {'String'}}
        $required=($group[0] -cin @('Platform','Revision','GPOAU','GPOUpdate','Reboot','Capture') -or
            ($group[0] -ceq 'Services' -and $name -cin @('Name','State','StartMode','Started')) -or $name -ceq 'HotFixID')
        [pscustomobject]@{Id=($group[0]+'.'+$name);Inventory=$group[0];Property=$name;Kind=$group[1];Type=$type;Unit='none';Required=$required}
    }}
}

function Get-WinSecWindowsUpdateTechnicalCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecWindowsUpdateTechnicalAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider=$_.Provider;ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=(-not $_.List);Applicability=$rule}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=$rule}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.WindowsUpdate.Candidate';CatalogVersion='1.0.0';CheckId='WSA-SYS-003';
        Sources=$sources;Inventories=$inventories;Fields=@(Get-WinSecWindowsUpdateTechnicalFields|ForEach-Object {
            [pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit=$_.Unit;Required=$_.Required;Exposure='CONFIGURATION';Applicability=$rule}})}
}
