# Isolated candidate contract. No native queries, activation or production imports.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecFirewallCandidateAreas {
    [CmdletBinding()]param()
    [pscustomobject]@{Id='Platform';Role='Platform';Store='NONE';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem'}
    $base='https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/'
    foreach($store in @('Active','Persistent')){foreach($spec in @('Profiles|msft-netfirewallprofile','Rules|msft-netfirewallrule','Ports|msft-netprotocolportfilter','Links|msft-netfirewallrulefilterbyprotocolport')){
        $p=$spec.Split('|');[pscustomobject]@{Id=($store+$p[0]);Role=$p[0];Store=($store+'Store');ReferenceUrl=($base+$p[1])}
    }}
}

function Get-WinSecFirewallCandidateFields {
    [CmdletBinding()]param()
    foreach($area in Get-WinSecFirewallCandidateAreas){
        $groups=switch($area.Role){
            Platform {'Version|Version';'Build|BuildNumber';'UInt32|OperatingSystemSKU,ProductType'}
            Profiles {'Profile|Name';'UInt32|Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules,AllowUserApps,AllowUserPorts,AllowUnicastResponseToMulticast,NotifyOnListen,LogAllowed,LogBlocked,LogIgnored,EnableStealthModeForIPsec';'UInt64Text|LogMaxSizeKilobytes'}
            Rules {'Identifier|InstanceID';'UInt32|Enabled,Profiles,Direction,Action,EdgeTraversalPolicy,PolicyStoreSourceType,StatusCode'}
            Ports {'Identifier|InstanceID';'Protocol|Protocol';'LocalPorts|LocalPort';'RemotePorts|RemotePort';'Icmp|IcmpType';'UInt32|DynamicTransport';'ListCount|LocalPort,RemotePort,IcmpType'}
            Links {'Identifier|RuleInstanceID,FilterInstanceID'}
        }
        foreach($spec in $groups){$group=$spec.Split('|');foreach($name in $group[1].Split(',')){
            $suffix=if($group[0] -ceq 'ListCount'){'ReportedCount'}else{''}
            $type=switch($group[0]){{$_ -cin @('Build','UInt32','ListCount')} {'UInt32'};Int64 {'Int64'};{$_ -cin @('LocalPorts','RemotePorts','Icmp')} {'StringArray'};default {'String'}}
            $required=($area.Role -cin @('Platform','Links') -or $group[0] -cin @('Profile','Identifier') -or
                ($area.Role -ceq 'Profiles' -and $name -cin @('Enabled','DefaultInboundAction','DefaultOutboundAction')) -or
                ($area.Role -ceq 'Rules' -and $name -cin @('Enabled','Profiles','Direction','Action')) -or ($area.Role -ceq 'Ports' -and $name -cin @('Protocol','LocalPort','RemotePort')))
            [pscustomobject]@{Id=($area.Id+'.'+$name+$suffix);Inventory=$area.Id;Property=$name;Kind=$group[0];Type=$type;Required=$required;
                Exposure=$(if($group[0] -ceq 'Identifier'){'IDENTIFIABLE'}else{'CONFIGURATION'})}
        }}
    }
    foreach($area in Get-WinSecFirewallCandidateAreas){foreach($meta in @('Time','State','Store')){
        [pscustomobject]@{Id=('Capture.'+$area.Id+$meta);Inventory='Capture';Property=($area.Id+$meta);Kind=$meta;Type='String';Required=$true;Exposure='CONFIGURATION'}
    }}
    [pscustomobject]@{Id='Capture.Scope';Inventory='Capture';Property='Scope';Kind='Scope';Type='String';Required=$true;Exposure='CONFIGURATION'}
}

function Get-WinSecFirewallCandidateCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecFirewallCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider='CIM';ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=($_.Role -ceq 'Platform');Applicability=$rule}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=$rule}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.Firewall.Candidate';CatalogVersion='1.0.0';CheckId='WSA-NET-001';
        Sources=$sources;Inventories=$inventories;Fields=@(Get-WinSecFirewallCandidateFields|ForEach-Object {
            [pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit=$(if($_.Kind -ceq 'ListCount'){'count'}else{'none'});Required=$_.Required;Exposure=$_.Exposure;Applicability=$rule}})}
}
