# Reviewed captured configuration only. Importing this catalog never queries Windows.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecNetworkCandidateAreas {
    [CmdletBinding()]param()
    $base='https://learn.microsoft.com/en-us/windows/win32/'
    $rows=@(
        'Platform|CIMV2|cimwin32prov/win32-operatingsystem'
        'Adapter|STANDARDCIMV2|fwp/wmi/netadaptercimprov/msft-netadapter'
        'IPInterface|STANDARDCIMV2|fwp/wmi/nettcpipprov/msft-netipinterface'
        'IPAddress|STANDARDCIMV2|fwp/wmi/nettcpipprov/msft-netipaddress'
        'Route|STANDARDCIMV2|fwp/wmi/nettcpipprov/msft-netroute'
        'DNSServer|STANDARDCIMV2|fwp/wmi/dnsclientcimprov/msft-dnsclientserveraddress'
        'DNSClient|STANDARDCIMV2|fwp/wmi/dnsclientcimprov/msft-dnsclient'
        'Profile|STANDARDCIMV2|fwp/wmi/netconnectioncimprov/msft-netconnectionprofile'
        'Legacy|CIMV2|cimwin32prov/win32-networkadapterconfiguration'
        'DNSGlobal|STANDARDCIMV2|fwp/wmi/dnsclientcimprov/msft-dnsclientglobalsetting'
    )
    foreach($row in $rows){$p=$row.Split('|');$reference=if($p[0] -ceq 'Profile'){'https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile'}else{$base+$p[2]};[pscustomobject]@{Id=$p[0];Location=$p[1];ReferenceUrl=$reference}}
    [pscustomobject]@{Id='Registry';Location='HKLM_REGISTRY64';ReferenceUrl='https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient'}
}

function Get-WinSecNetworkCandidateFields {
    [CmdletBinding()]param()
    $spec=@(
        'Platform|Version:Version,BuildNumber:Build,OperatingSystemSKU:UInt32,ProductType:UInt32|Version,BuildNumber,OperatingSystemSKU,ProductType'
        'Adapter|InterfaceIndex:UInt32,InterfaceType:UInt32,State:UInt32,InterfaceOperationalStatus:UInt32,InterfaceAdminStatus:UInt32,MediaConnectState:UInt32,MediaDuplexState:UInt32,MtuSize:UInt32,VlanID:UInt16,TransmitLinkSpeed:UInt64Text,ReceiveLinkSpeed:UInt64Text,Virtual:Boolean,Hidden:Boolean,HardwareInterface:Boolean,ConnectorPresent:Boolean,FullDuplex:Boolean,PromiscuousMode:Boolean,AutoSense:Boolean,InterfaceGuid:Guid|InterfaceIndex'
        'IPInterface|InterfaceIndex:UInt32,AddressFamily:Family,Forwarding:UInt8,Advertising:UInt8,NlMtu:UInt32,InterfaceMetric:UInt32,NeighborUnreachabilityDetection:UInt8,BaseReachableTime:UInt32,RetransmitTime:UInt32,DadTransmits:UInt32,RouterDiscovery:UInt8,ManagedAddressConfiguration:UInt8,OtherStatefulConfiguration:UInt8,WeakHostSend:UInt8,WeakHostReceive:UInt8,IgnoreDefaultRoutes:UInt8,CurrentHopLimit:UInt32,Dhcp:UInt8,AutomaticMetric:UInt8,ConnectionState:UInt8|InterfaceIndex,AddressFamily'
        'IPAddress|InterfaceIndex:UInt32,AddressFamily:Family,IPAddress:Address,PrefixLength:UInt8,PrefixOrigin:UInt16,SuffixOrigin:UInt16,AddressState:UInt16,SkipAsSource:Boolean,Type:UInt8,Store:UInt8|InterfaceIndex,AddressFamily,IPAddress,PrefixLength'
        'Route|InterfaceIndex:UInt32,AddressFamily:Family,DestinationPrefix:Prefix,NextHop:Address,RouteMetric:UInt16,Protocol:UInt16,Publish:UInt8,Store:UInt8,IsStatic:Boolean,AdminDistance:UInt16|InterfaceIndex,AddressFamily,DestinationPrefix,NextHop'
        'DNSServer|InterfaceIndex:UInt32,AddressFamily:Family,ServerAddresses:Addresses|InterfaceIndex,AddressFamily'
        'DNSClient|InterfaceIndex:UInt32,RegisterThisConnectionsAddress:Boolean,UseSuffixWhenRegistering:Boolean|InterfaceIndex'
        'Profile|InterfaceIndex:UInt32,NetworkCategory:UInt32,IPv4Connectivity:UInt32,IPv6Connectivity:UInt32|InterfaceIndex,NetworkCategory'
        'Legacy|Index:UInt32,InterfaceIndex:UInt32,IPEnabled:Boolean,DHCPEnabled:Boolean,TcpipNetbiosOptions:UInt32,IPFilterSecurityEnabled:Boolean,IPPortSecurityEnabled:Boolean,WINSEnableLMHostsLookup:Boolean,DNSEnabledForWINSResolution:Boolean,FullDNSRegistrationEnabled:Boolean,DomainDNSRegistrationEnabled:Boolean,DHCPServer:Address,DefaultIPGateway:Addresses,DNSServerSearchOrder:Addresses|Index,IPEnabled'
        'DNSGlobal|UseDevolution:Boolean,DevolutionLevel:UInt32|'
        'Registry|EnableMulticast:RegistryDWord,DisableSmartNameResolution:RegistryDWord,DoHPolicy:RegistryDWord|EnableMulticast,DisableSmartNameResolution,DoHPolicy'
    )
    foreach($row in $spec){$p=$row.Split('|');foreach($pair in $p[1].Split(',')){
        $f=$pair.Split(':');$type=switch($f[1]){Boolean {'Boolean'};Addresses {'StringArray'};{$_ -cin @('Address','Prefix','Guid','Version','UInt64Text')} {'String'};default {'UInt32'}}
        $required=($f[0] -cin $p[2].Split(','));$exposure=if($f[1] -cin @('Address','Prefix','Guid','Addresses')){'IDENTIFIABLE'}else{'CONFIGURATION'}
        [pscustomobject]@{Id=($p[0]+'.'+$f[0]);Inventory=$p[0];Property=$f[0];Kind=$f[1];Type=$type;Required=$required;Derived=$false;Exposure=$exposure}
        if($f[1] -ceq 'Addresses'){foreach($suffix in @('ReportedCount','RetainedCount')){
            [pscustomobject]@{Id=($p[0]+'.'+$f[0]+$suffix);Inventory=$p[0];Property=$f[0];Kind=$suffix;Type='UInt32';Required=$false;Derived=$true;Exposure='CONFIGURATION'}
        }}
    }}
    foreach($a in Get-WinSecNetworkCandidateAreas){foreach($kind in @('Time','SourceState','Location')){
        [pscustomobject]@{Id=('Capture.'+$a.Id+$kind);Inventory='Capture';Property=($a.Id+$kind);Kind=$kind;Type='String';Required=$true;Derived=$true;Exposure='CONFIGURATION'}
    }}
    [pscustomobject]@{Id='Capture.Scope';Inventory='Capture';Property='Scope';Kind='Scope';Type='String';Required=$true;Derived=$true;Exposure='CONFIGURATION'}
}

function Get-WinSecNetworkCandidateCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecNetworkCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider=$(if($_.Id -ceq 'Registry'){'REGISTRY'}else{'CIM'});ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/nettcpipprov/msft-netipinterface'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=($_.Id -cin @('Platform','DNSGlobal','Registry'));Applicability=$rule}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=$rule}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.NetworkConfiguration.Candidate';CatalogVersion='1.0.0';CheckId='WSA-NET-005';Sources=$sources;Inventories=$inventories;
        Fields=@(Get-WinSecNetworkCandidateFields|ForEach-Object {[pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit=$(if($_.Kind -cin @('ReportedCount','RetainedCount')){'count'}else{'none'});Required=$_.Required;Exposure=$_.Exposure;Applicability=$rule}})}
}
