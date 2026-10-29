# Reviewed captured built-in Guest data only. No account queries or production imports.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecGuestCandidateAreas {
    [CmdletBinding()]param()
    [pscustomobject]@{Id='Platform';Location='CIMV2';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem'}
    [pscustomobject]@{Id='Guest';Location='CIMV2';ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-useraccount'}
}

function Get-WinSecGuestCandidateFields {
    [CmdletBinding()]param()
    $spec=@(
        'Platform|Version:Version,BuildNumber:Build,OperatingSystemSKU:UInt32,ProductType:UInt32|Version,BuildNumber,OperatingSystemSKU,ProductType'
        'Guest|SID:GuestSID,Name:AccountName,Domain:AccountDomain,Disabled:Boolean,LocalAccount:Boolean,Lockout:Boolean,PasswordRequired:Boolean,PasswordChangeable:Boolean,PasswordExpires:Boolean,AccountType:UInt32,SIDType:UInt8,Status:AccountStatus,Present:Present,AccountDomainSID:DerivedDomainSID|SID,Disabled,LocalAccount,Present,AccountDomainSID'
    )
    foreach($row in $spec){$p=$row.Split('|');foreach($entry in $p[1].Split(',')){
        $f=$entry.Split(':');$type=switch($f[1]){{$_ -cin @('Boolean','Present')} {'Boolean'};{$_ -cin @('UInt32','UInt8','Build')} {'UInt32'};default {'String'}}
        [pscustomobject]@{Id=($p[0]+'.'+$f[0]);Inventory=$p[0];Property=$f[0];Kind=$f[1];Type=$type;Required=($f[0] -cin $p[2].Split(','));Derived=($f[1] -cin @('Present','DerivedDomainSID'));
            Exposure=$(if($f[1] -cin @('GuestSID','AccountName','AccountDomain','DerivedDomainSID')){'IDENTIFIABLE'}else{'CONFIGURATION'})}
    }}
    foreach($a in Get-WinSecGuestCandidateAreas){foreach($kind in @('Time','SourceState','Location')){
        [pscustomobject]@{Id=('Capture.'+$a.Id+$kind);Inventory='Capture';Property=($a.Id+$kind);Kind=$kind;Type='String';Required=$true;Derived=$true;Exposure='CONFIGURATION'}
    }}
    foreach($entry in @('Scope:Scope','RequestedRID:RID','DomainResolution:NotPerformed','CloudResolution:NotPerformed','PolicyAuthority:NotObserved','AccountDomainSIDBasis:DomainSIDBasis')){
        $p=$entry.Split(':');[pscustomobject]@{Id=('Capture.'+$p[0]);Inventory='Capture';Property=$p[0];Kind=$p[1];Type=$(if($p[1] -ceq 'RID'){'UInt32'}else{'String'});Required=$true;Derived=$true;Exposure='CONFIGURATION'}
    }
}

function Get-WinSecGuestCandidateCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecGuestCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider='CIM';ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=($_.Id -ceq 'Platform');Applicability=$rule}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=$rule}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.Guest.Candidate';CatalogVersion='1.0.0';CheckId='WSA-IAM-002';Sources=$sources;Inventories=$inventories;
        Fields=@(Get-WinSecGuestCandidateFields|ForEach-Object {[pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit='none';Required=$_.Required;Exposure=$_.Exposure;Applicability=$rule}})}
}
