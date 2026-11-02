# Isolated candidate field contract. No native queries or execution registration.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecBitLockerTechnicalAreas {
    [CmdletBinding()]param()
    $base='https://learn.microsoft.com/en-us/windows/win32/'
    foreach($row in @('Platform|cimwin32prov/win32-operatingsystem','Volume|secprov/win32-encryptablevolume',
        'Protection|secprov/getprotectionstatus-win32-encryptablevolume','Conversion|secprov/getconversionstatus-win32-encryptablevolume',
        'Algorithm|secprov/getencryptionmethod-win32-encryptablevolume','Lock|secprov/getlockstatus-win32-encryptablevolume',
        'Metadata|secprov/getversion-win32-encryptablevolume','HardwareTest|secprov/gethardwareteststatus-win32-encryptablevolume')){
        $parts=$row.Split('|');[pscustomobject]@{Id=$parts[0];Method=($parts[0] -cnotin @('Platform','Volume'));ReferenceUrl=($base+$parts[1])}
    }
}

function Get-WinSecBitLockerTechnicalFields {
    [CmdletBinding()]param()
    $groups=@(@('Platform','Version','Version'),@('Platform','Build','BuildNumber'),@('Platform','UInt32','OperatingSystemSKU,ProductType'),
        @('Platform','Drive','SystemDrive'),@('Volume','VolumeId','DeviceID'),@('Volume','Drive','DriveLetter'),@('Volume','UInt32','VolumeType'),
        @('Volume','Boolean','IsVolumeInitializedForProtection'),@('Protection','UInt32','ReturnValue,ProtectionStatus'),
        @('Conversion','UInt32','ReturnValue,ConversionStatus,EncryptionFlags,WipingStatus'),@('Conversion','Percent','EncryptionPercentage,WipingPercentage'),
        @('Algorithm','UInt32','ReturnValue,EncryptionMethod'),@('Lock','UInt32','ReturnValue,LockStatus'),
        @('Metadata','UInt32','ReturnValue,Version'),@('HardwareTest','UInt32','ReturnValue,TestStatus,TestError'))
    foreach($area in Get-WinSecBitLockerTechnicalAreas){
        $groups+=,@($area.Id,'CaptureTime','CollectedAtUTC')
        if($area.Method){$groups+=,@($area.Id,'Target','TargetVolumeId')}
    }
    foreach($group in $groups){foreach($name in $group[2].Split(',')){
        $type=switch($group[1]){Boolean {'Boolean'};{$_ -cin @('UInt32','Build','Percent')} {'UInt32'};default {'String'}}
        $required=($group[0] -ceq 'Platform' -or $name -cin @('ReturnValue','CollectedAtUTC','TargetVolumeId') -or
            ($group[0] -ceq 'Volume' -and $name -cne 'IsVolumeInitializedForProtection') -or
            ($group[0] -ceq 'Protection') -or ($group[0] -ceq 'Conversion' -and $name -cin @('ConversionStatus','EncryptionPercentage')) -or
            $group[0] -cin @('Algorithm','Lock'))
        [pscustomobject]@{Id=($group[0]+'.'+$name);Inventory=$group[0];Property=$name;Kind=$group[1];Type=$type;
            Unit=$(if($group[1] -ceq 'Percent'){'percent'}else{'none'});Required=$required;
            Exposure=$(if($group[1] -cin @('VolumeId','Target')){'IDENTIFIABLE'}else{'CONFIGURATION'})}
    }}
}

function Get-WinSecBitLockerTechnicalCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecBitLockerTechnicalAreas)
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.BitLocker.Candidate';CatalogVersion='1.0.0';CheckId='WSA-SYS-002';
        Sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider='CIM';ReferenceUrl=$_.ReferenceUrl}});
        Inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=$true;Applicability=$rule}});
        Fields=@(Get-WinSecBitLockerTechnicalFields|ForEach-Object {[pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit=$_.Unit;Required=$_.Required;Exposure=$_.Exposure;Applicability=$rule}})}
}
