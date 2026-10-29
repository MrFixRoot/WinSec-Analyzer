# Isolated reviewed Win32_Service projections. No service enumeration or mutation.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecWindowsServicesCandidateAreas {
    [CmdletBinding()]param()
    [pscustomobject]@{Id='Platform';Location='CIMV2';Provider='CIM';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem';Singleton=$true}
    [pscustomobject]@{Id='Services';Location='CIMV2_WIN32_SERVICE';Provider='CIM';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service';Singleton=$false}
}

function Get-WinSecWindowsServicesCandidateConstants {
    [ordered]@{Scope='LOCAL_WIN32_SERVICE_CONFIGURATION_ONLY';ProviderClass='Win32_Service';Actions='NOT_PERFORMED';SecurityEvaluation='NOT_PERFORMED';DriverInventory='NOT_COLLECTED';PolicyAuthority='NOT_OBSERVED'}
}

function Get-WinSecWindowsServicesCandidateFields {
    [CmdletBinding()]param()
    foreach($row in @('Platform|Version:Version,BuildNumber:Build,OperatingSystemSKU:UInt32,ProductType:UInt32',
        'Services|Name:ServiceName,State:ServiceState,StartMode:StartMode,Started:Boolean,DelayedAutoStart:Boolean,ServiceType:ServiceType,ErrorControl:ErrorControl,AcceptPause:Boolean,AcceptStop:Boolean,DesktopInteract:Boolean,ExitCode:UInt32,ServiceSpecificExitCode:UInt32,ProcessId:UInt32,CheckPoint:UInt32,WaitHint:UInt32,TagId:UInt32,Status:ServiceStatus')){
        $p=$row.Split('|');foreach($entry in $p[1].Split(',')){$f=$entry.Split(':')
            $fieldName=if($f[0] -ceq 'WaitHint'){'WaitHintMilliseconds'}else{$f[0]}
            [pscustomobject]@{Id=($p[0]+'.'+$fieldName);Inventory=$p[0];Property=$f[0];Kind=$f[1];Type=$(if($f[1] -ceq 'Boolean'){'Boolean'}elseif($f[1] -cin @('Build','UInt32')){'UInt32'}else{'String'});Unit='none';Required=($p[0] -ceq 'Platform' -or $f[0] -cin @('Name','State','StartMode','Started'));Derived=$false;Exposure=$(if($f[0] -cin @('Name','ProcessId')){'IDENTIFIABLE'}else{'CONFIGURATION'})}
        }
    }
    foreach($a in Get-WinSecWindowsServicesCandidateAreas){foreach($kind in @('Time','SourceState','Location')){[pscustomobject]@{Id=('Capture.'+$a.Id+$kind);Inventory='Capture';Property=($a.Id+$kind);Kind=$kind;Type='String';Unit='none';Required=$true;Derived=$true;Exposure='CONFIGURATION'}}}
    foreach($key in (Get-WinSecWindowsServicesCandidateConstants).Keys){[pscustomobject]@{Id=('Capture.'+$key);Inventory='Capture';Property=$key;Kind='Constant';Type='String';Unit='none';Required=$true;Derived=$true;Exposure='CONFIGURATION'}}
    foreach($key in @('BinaryCommandLine','ServiceAccounts','SecurityDescriptors','DependenciesAndTriggers','RecoveryConfiguration')){[pscustomobject]@{Id=('Capture.'+$key);Inventory='Capture';Property=$key;Kind='ExcludedDetail';Type='String';Unit='none';Required=$false;Derived=$true;Exposure='CONFIGURATION'}}
}

function Get-WinSecWindowsServicesCandidateCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecWindowsServicesCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider=$_.Provider;ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=$_.Singleton;Applicability=$rule}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=$rule}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.WindowsServices.Candidate';CatalogVersion='1.0.0';CheckId='WSA-HRD-001';Sources=$sources;Inventories=$inventories;
        Fields=@(Get-WinSecWindowsServicesCandidateFields|ForEach-Object {[pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit=$_.Unit;Required=$_.Required;Exposure=$_.Exposure;Applicability=$rule}})}
}
