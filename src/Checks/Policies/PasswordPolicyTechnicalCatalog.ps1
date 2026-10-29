# Prepared policy configuration only. No native calls or production registration.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecPasswordPolicyCandidateAreas {
    [CmdletBinding()]param()
    [pscustomobject]@{Id='Platform';Location='CIMV2';Provider='CIM';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem'}
    [pscustomobject]@{Id='Policy';Location='LOCAL_NETAPI_LEVEL0';Provider='NETAPI';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_0'}
    [pscustomobject]@{Id='Lockout';Location='LOCAL_NETAPI_LEVEL3';Provider='NETAPI';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_3'}
    [pscustomobject]@{Id='Template';Location='LOCAL_SECURITY_DATABASE_EXPORT';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b40db09-d95d-40a6-8467-32aedec8140c'}
}

function Get-WinSecPasswordPolicyCandidateConstants {
    [ordered]@{Scope='LOCAL_ACCOUNT_POLICY_CONFIGURATION_ONLY';ServerTarget='NULL_LOCAL_COMPUTER';DomainPolicy='NOT_COLLECTED';MDMPolicy='NOT_COLLECTED';CloudPolicy='NOT_COLLECTED';PolicyAuthority='NOT_OBSERVED';EffectivePolicy='NOT_RESOLVED';TemplateMode='LOCAL_DATABASE_WITHOUT_MERGEDPOLICY'}
}

function Get-WinSecPasswordPolicyCandidateFields {
    [CmdletBinding()]param()
    $spec=@(
        'Platform|Version:Version:none,BuildNumber:Build:none,OperatingSystemSKU:UInt32:none,ProductType:UInt32:none'
        'Policy|ReturnValue:UInt32:none,MinimumLength:UInt32:characters,MaximumAgeSeconds:UInt32:seconds,MinimumAgeSeconds:UInt32:seconds,ForceLogoffSeconds:UInt32:seconds,HistoryLength:UInt32:count'
        'Lockout|ReturnValue:UInt32:none,DurationSeconds:UInt32:seconds,ObservationWindowSeconds:UInt32:seconds,Threshold:UInt32:count'
        'Template|ReturnValue:UInt32:none,PasswordComplexity:PolicyFlag:none,ClearTextPassword:PolicyFlag:none'
    )
    foreach($row in $spec){$p=$row.Split('|');foreach($entry in $p[1].Split(',')){
        $f=$entry.Split(':');[pscustomobject]@{Id=($p[0]+'.'+$f[0]);Inventory=$p[0];Property=$f[0];Kind=$f[1];Type=$(if($f[1] -ceq 'Version'){'String'}else{'UInt32'});Unit=$f[2];Required=($p[0] -cne 'Template' -or $f[0] -ceq 'ReturnValue');Derived=$false;Exposure='CONFIGURATION'}
    }}
    foreach($a in Get-WinSecPasswordPolicyCandidateAreas){foreach($kind in @('Time','SourceState','Location')){
        [pscustomobject]@{Id=('Capture.'+$a.Id+$kind);Inventory='Capture';Property=($a.Id+$kind);Kind=$kind;Type='String';Unit='none';Required=$true;Derived=$true;Exposure='CONFIGURATION'}
    }}
    foreach($key in (Get-WinSecPasswordPolicyCandidateConstants).Keys){
        [pscustomobject]@{Id=('Capture.'+$key);Inventory='Capture';Property=$key;Kind='Constant';Type='String';Unit='none';Required=$true;Derived=$true;Exposure='CONFIGURATION'}
    }
}

function Get-WinSecPasswordPolicyCandidateCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecPasswordPolicyCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider=$_.Provider;ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsget'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=$true;Applicability=$rule}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=$rule}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.PasswordPolicy.Candidate';CatalogVersion='1.0.0';CheckId='WSA-IAM-003';Sources=$sources;Inventories=$inventories;
        Fields=@(Get-WinSecPasswordPolicyCandidateFields|ForEach-Object {[pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit=$_.Unit;Required=$_.Required;Exposure=$_.Exposure;Applicability=$rule}})}
}
