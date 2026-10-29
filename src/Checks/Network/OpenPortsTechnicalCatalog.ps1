# Isolated passive endpoint catalog. No sockets, queries or production imports.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecOpenPortsCandidateAreas {
    [CmdletBinding()]param()
    [pscustomobject]@{Id='Platform';Location='CIMV2';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem'}
    [pscustomobject]@{Id='TCP';Location='STANDARDCIMV2';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/nettcpipprov/msft-nettcpconnection'}
    [pscustomobject]@{Id='UDP';Location='STANDARDCIMV2';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/nettcpipprov/msft-netudpendpoint'}
}

function Get-WinSecOpenPortsCandidateFields {
    [CmdletBinding()]param()
    foreach($a in Get-WinSecOpenPortsCandidateAreas){
        $groups=if($a.Id -ceq 'Platform'){@('Version|Version','Build|BuildNumber','UInt32|OperatingSystemSKU,ProductType')}
        else{
            @('Address|LocalAddress','UInt16|LocalPort','UInt32|OwningProcess','NativeTime|CreationTime,TimeOfLastStateChange',
                'UInt16|Directionality,HealthState,EnabledState','TimeBasis|CreationTime,TimeOfLastStateChange',
                'CanonicalAddress|LocalAddress','Family|LocalAddress','BindingScope|LocalAddress','Protocol|Protocol')
            if($a.Id -ceq 'TCP'){'UInt8|State,AppliedSetting,OffloadState'}
        }
        foreach($spec in $groups){$p=$spec.Split('|');foreach($name in $p[1].Split(',')){
            $suffix=switch($p[0]){TimeBasis {'Basis'};CanonicalAddress {'Canonical'};Family {'Family'};BindingScope {'Scope'};default {''}}
            $type=if($p[0] -cin @('UInt8','UInt16','UInt32','Build')){'UInt32'}else{'String'}
            $derived=($p[0] -cin @('TimeBasis','CanonicalAddress','Family','BindingScope','Protocol'))
            $required=($a.Id -ceq 'Platform' -or $p[0] -cin @('Address','CanonicalAddress','Family','BindingScope','Protocol') -or $name -ceq 'LocalPort' -or ($a.Id -ceq 'TCP' -and $name -ceq 'State'))
            [pscustomobject]@{Id=($a.Id+'.'+$name+$suffix);Inventory=$a.Id;Property=$name;Kind=$p[0];Type=$type;Required=$required;Derived=$derived;
                Exposure=$(if($p[0] -cin @('Address','CanonicalAddress') -or $name -ceq 'OwningProcess'){'IDENTIFIABLE'}else{'CONFIGURATION'})}
        }}
    }
    foreach($a in Get-WinSecOpenPortsCandidateAreas){foreach($kind in @('Time','SourceState','Location')){
        [pscustomobject]@{Id=('Capture.'+$a.Id+$kind);Inventory='Capture';Property=($a.Id+$kind);Kind=$kind;Type='String';Required=$true;Derived=$true;Exposure='CONFIGURATION'}
    }}
    [pscustomobject]@{Id='Capture.Scope';Inventory='Capture';Property='Scope';Kind='Scope';Type='String';Required=$true;Derived=$true;Exposure='CONFIGURATION'}
}

function Get-WinSecOpenPortsCandidateCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecOpenPortsCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider='CIM';ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netudpendpoint'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=($_.Id -ceq 'Platform');Applicability=$rule}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=$rule}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.OpenPorts.Candidate';CatalogVersion='1.0.0';CheckId='WSA-NET-004';Sources=$sources;Inventories=$inventories;
        Fields=@(Get-WinSecOpenPortsCandidateFields|ForEach-Object {[pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit='none';Required=$_.Required;Exposure=$_.Exposure;Applicability=$rule}})}
}
