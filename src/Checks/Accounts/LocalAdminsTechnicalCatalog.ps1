# Isolated reviewed local group catalog. No native calls, compilation or production imports.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecLocalAdminsCandidateAreas {
    [CmdletBinding()]param()
    [pscustomobject]@{Id='Platform';Location='CIMV2';Provider='CIM';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem'}
    [pscustomobject]@{Id='Group';Location='CIMV2';Provider='CIM';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-group'}
    [pscustomobject]@{Id='Members';Location='LOCAL_NETAPI_LEVEL0';Provider='NETAPI';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupgetmembers'}
}

function Get-WinSecLocalAdminsCandidateFields {
    [CmdletBinding()]param()
    $spec=@(
        'Platform|Version:Version,BuildNumber:Build,OperatingSystemSKU:UInt32,ProductType:UInt32|Version,BuildNumber,OperatingSystemSKU,ProductType'
        'Group|SID:GroupSID,Name:GroupName,LocalAccount:Boolean,SIDType:UInt8|SID,Name,LocalAccount'
        'Pages|Sequence:PageSequence,Status:UInt32,EntriesRead:UInt32,TotalEntries:UInt32,ResumePending:Boolean,ProvidedMemberCount:ProvidedCount|Sequence,Status,EntriesRead,ResumePending,ProvidedMemberCount'
        'Members|SID:SID,PageSequence:PageSequence|SID,PageSequence'
    )
    foreach($row in $spec){$p=$row.Split('|');foreach($entry in $p[1].Split(',')){
        $f=$entry.Split(':');$type=switch($f[1]){Boolean {'Boolean'};{$_ -cin @('SID','GroupSID','GroupName','Version')} {'String'};default {'UInt32'}}
        $derived=($f[1] -cin @('PageSequence','ProvidedCount') -or ($p[0] -ceq 'Pages' -and $f[0] -ceq 'ResumePending'))
        [pscustomobject]@{Id=($p[0]+'.'+$f[0]);Inventory=$p[0];Property=$f[0];Kind=$f[1];Type=$type;Required=($f[0] -cin $p[2].Split(','));Derived=$derived;
            Exposure=$(if($f[1] -cin @('SID','GroupName')){'IDENTIFIABLE'}else{'CONFIGURATION'})}
    }}
    foreach($a in Get-WinSecLocalAdminsCandidateAreas){foreach($kind in @('Time','SourceState','Location')){
        [pscustomobject]@{Id=('Capture.'+$a.Id+$kind);Inventory='Capture';Property=($a.Id+$kind);Kind=$kind;Type='String';Required=$true;Derived=$true;Exposure='CONFIGURATION'}
    }}
    foreach($entry in @('Scope:Scope','RequestedGroupSID:GroupSID','RequestedAPILevel:Level','DomainExpansion:NotPerformed','CloudResolution:NotPerformed','PolicyAuthority:NotObserved','TotalEntriesMeaning:TotalMeaning')){
        $p=$entry.Split(':');[pscustomobject]@{Id=('Capture.'+$p[0]);Inventory='Capture';Property=$p[0];Kind=$p[1];Type=$(if($p[1] -ceq 'Level'){'UInt32'}else{'String'});Required=$true;Derived=$true;Exposure='CONFIGURATION'}
    }
}

function Get-WinSecLocalAdminsCandidateCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecLocalAdminsCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider=$_.Provider;ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-localgroup_members_info_0'}
    $inventories=@(foreach($id in @('Platform','Group','Pages','Members','Capture')){
        [pscustomobject]@{Id=$id;SourceId=$(if($id -ceq 'Pages'){'Members'}else{$id});Required=$true;Singleton=($id -cin @('Platform','Group','Capture'));Applicability=$rule}
    })
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.LocalAdmins.Candidate';CatalogVersion='1.0.0';CheckId='WSA-IAM-001';Sources=$sources;Inventories=$inventories;
        Fields=@(Get-WinSecLocalAdminsCandidateFields|ForEach-Object {[pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit=$(if($_.Property -cin @('EntriesRead','TotalEntries','ProvidedMemberCount')){'count'}else{'none'});Required=$_.Required;Exposure=$_.Exposure;Applicability=$rule}})}
}
