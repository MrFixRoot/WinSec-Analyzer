# Prepared system audit configuration contract. No audit API, LSA, Registry or event access.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecAuditPolicyCandidateAreas {
    [CmdletBinding()]param()
    foreach($row in @(
        'Platform|CIMV2|CIM|https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem'
        'Categories|LOCAL_AUDIT_CATEGORIES|DERIVED|https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditenumeratecategories'
        'Subcategories|LOCAL_AUDIT_SUBCATEGORIES_ALL|DERIVED|https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditenumeratesubcategories'
        'Requests|LOCAL_AUDIT_QUERY_REQUEST|DERIVED|https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy'
        'SystemPolicy|LOCAL_AUDIT_SYSTEM_POLICY|DERIVED|https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information'
        'Options|HKLM_REGISTRY64_AUDIT_OPTION|REGISTRY|https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/506f97dd-00f9-49dc-b3ba-bb041328cafb'
    )){$p=$row.Split('|');[pscustomobject]@{Id=$p[0];Location=$p[1];Provider=$p[2];ReferenceUrl=$p[3];Singleton=($p[0] -cin @('Platform','Options'))}}
}

function Get-WinSecAuditPolicyCandidateConstants {
    [ordered]@{Scope='LOCAL_SYSTEM_AUDIT_CONFIGURATION_ONLY';SubcategoryEnumeration='ALL_AVAILABLE';PolicyQuery='ENUMERATED_SUBCATEGORIES_ONLY';EffectivePerUser='NOT_COMPUTED';PolicyAuthority='NOT_OBSERVED';ContentAccess='NOT_PERFORMED'}
}

function Get-WinSecAuditPolicyCandidateFields {
    [CmdletBinding()]param()
    foreach($row in @('Platform|Version:Version,BuildNumber:Build,OperatingSystemSKU:UInt32,ProductType:UInt32',
        'Categories|AuditCategoryGuid:Guid','Subcategories|AuditSubCategoryGuid:Guid','Requests|AuditSubCategoryGuid:Guid',
        'SystemPolicy|AuditSubCategoryGuid:Guid,AuditingInformation:UInt32,AuditCategoryGuid:Guid,Success:Success,Failure:Failure,Mode:Mode',
        'Options|SCENoApplyLegacyAuditPolicy:RegistryFlag')){
        $p=$row.Split('|');foreach($entry in $p[1].Split(',')){$f=$entry.Split(':');$derived=($p[0] -ceq 'Requests' -or $f[1] -cin @('Success','Failure','Mode'))
            [pscustomobject]@{Id=($p[0]+'.'+$f[0]);Inventory=$p[0];Property=$f[0];Kind=$f[1];Type=$(if($f[1] -cin @('Success','Failure')){'Boolean'}elseif($f[1] -cin @('UInt32','Build','RegistryFlag')){'UInt32'}else{'String'});Required=($f[1] -cnotin @('Success','Failure','Mode'));Derived=$derived;Exposure='CONFIGURATION'}
        }
    }
    foreach($a in Get-WinSecAuditPolicyCandidateAreas){foreach($kind in @('Time','SourceState','Location')){
        [pscustomobject]@{Id=('Capture.'+$a.Id+$kind);Inventory='Capture';Property=($a.Id+$kind);Kind=$kind;Type='String';Required=$true;Derived=$true;Exposure='CONFIGURATION'}
    }}
    foreach($key in (Get-WinSecAuditPolicyCandidateConstants).Keys){[pscustomobject]@{Id=('Capture.'+$key);Inventory='Capture';Property=$key;Kind='Constant';Type='String';Required=$true;Derived=$true;Exposure='CONFIGURATION'}}
    foreach($key in @('LegacyCategoryPolicy','PerUserPolicy','GlobalObjectSacl','AuditOptions')){[pscustomobject]@{Id=('Capture.'+$key);Inventory='Capture';Property=$key;Kind='ExcludedDetail';Type='String';Required=$false;Derived=$true;Exposure='CONFIGURATION'}}
}

function Get-WinSecAuditPolicyCandidateCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecAuditPolicyCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider=$_.Provider;ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=$_.Singleton;Applicability=$rule}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=$rule}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.AuditPolicy.Candidate';CatalogVersion='1.0.0';CheckId='WSA-LOG-002';Sources=$sources;Inventories=$inventories;
        Fields=@(Get-WinSecAuditPolicyCandidateFields|ForEach-Object {[pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit='none';Required=$_.Required;Exposure=$_.Exposure;Applicability=$rule}})}
}
