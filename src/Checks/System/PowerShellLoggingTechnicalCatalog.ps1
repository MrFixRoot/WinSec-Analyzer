# Reviewed machine policy flags only. No Registry, event or transcript reads at import.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecPowerShellLoggingCandidateAreas {
    [CmdletBinding()]param()
    [pscustomobject]@{Id='Platform';Location='CIMV2';Provider='CIM';Root=$null;ReferenceUrl='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem'}
    [pscustomobject]@{Id='WinPS';Location='HKLM_REGISTRY64_WINPS';Provider='REGISTRY';Root='SOFTWARE\Policies\Microsoft\Windows\PowerShell';ReferenceUrl='https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1'}
    [pscustomobject]@{Id='Core';Location='HKLM_REGISTRY64_CORE';Provider='REGISTRY';Root='SOFTWARE\Policies\Microsoft\PowerShellCore';ReferenceUrl='https://raw.githubusercontent.com/PowerShell/PowerShell/v7.6.0/src/System.Management.Automation/engine/Utils.cs'}
    [pscustomobject]@{Id='Protected';Location='HKLM_REGISTRY64_EVENTLOG';Provider='REGISTRY';Root='SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging';ReferenceUrl='https://raw.githubusercontent.com/PowerShell/PowerShell/v7.6.0/src/System.Management.Automation/engine/PSConfiguration.cs'}
}

function Get-WinSecPowerShellLoggingCandidateConstants {
    [ordered]@{Scope='HKLM_REGISTRY64_POLICY_FLAGS_ONLY';UserPolicies='NOT_COLLECTED';Registry32='NOT_COLLECTED';JsonConfiguration='NOT_COLLECTED';RuntimeOverrides='NOT_OBSERVED';EffectivePolicy='NOT_RESOLVED';RuntimeInstallations='NOT_SURVEYED';ContentAccess='NOT_PERFORMED';PolicyAuthority='NOT_OBSERVED'}
}

function Get-WinSecPowerShellLoggingCandidateFields {
    [CmdletBinding()]param()
    foreach($entry in @('Version:Version','BuildNumber:Build','OperatingSystemSKU:UInt32','ProductType:UInt32')){
        $p=$entry.Split(':');[pscustomobject]@{Id=('Platform.'+$p[0]);Inventory='Platform';Property=$p[0];Kind=$p[1];Type=$(if($p[1] -ceq 'Version'){'String'}else{'UInt32'});Required=$true;Derived=$false;Key=$null;ValueName=$null}
    }
    foreach($family in @('WinPS','Core')){
        $spec=@('EnableScriptBlockLogging|ScriptBlockLogging|EnableScriptBlockLogging','EnableScriptBlockInvocationLogging|ScriptBlockLogging|EnableScriptBlockInvocationLogging',
            'EnableModuleLogging|ModuleLogging|EnableModuleLogging','EnableTranscripting|Transcription|EnableTranscripting','EnableInvocationHeader|Transcription|EnableInvocationHeader')
        if($family -ceq 'Core'){$spec+=@('ScriptBlockPolicyFallback|ScriptBlockLogging|UseWindowsPowerShellPolicySetting','ModulePolicyFallback|ModuleLogging|UseWindowsPowerShellPolicySetting','TranscriptionPolicyFallback|Transcription|UseWindowsPowerShellPolicySetting')}
        $area=@(Get-WinSecPowerShellLoggingCandidateAreas|Where-Object Id -CEQ $family)[0]
        foreach($row in $spec){$p=$row.Split('|');[pscustomobject]@{Id=($family+'.'+$p[0]);Inventory=$family;Property=$p[0];Kind='RegistryFlag';Type='UInt32';Required=$true;Derived=$false;Key=($area.Root+'\'+$p[1]);ValueName=$p[2]}}
    }
    [pscustomobject]@{Id='Protected.EnableProtectedEventLogging';Inventory='Protected';Property='EnableProtectedEventLogging';Kind='RegistryFlag';Type='UInt32';Required=$true;Derived=$false;Key='SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging';ValueName='EnableProtectedEventLogging'}
    foreach($a in Get-WinSecPowerShellLoggingCandidateAreas){foreach($kind in @('Time','SourceState','Location')){
        [pscustomobject]@{Id=('Capture.'+$a.Id+$kind);Inventory='Capture';Property=($a.Id+$kind);Kind=$kind;Type='String';Required=$true;Derived=$true;Key=$null;ValueName=$null}
    }}
    foreach($key in (Get-WinSecPowerShellLoggingCandidateConstants).Keys){
        [pscustomobject]@{Id=('Capture.'+$key);Inventory='Capture';Property=$key;Kind='Constant';Type='String';Required=$true;Derived=$true;Key=$null;ValueName=$null}
    }
    foreach($key in @('ModuleTargets','TranscriptDestination','EncryptionCertificate')){
        [pscustomobject]@{Id=('Capture.'+$key);Inventory='Capture';Property=$key;Kind='ExcludedDetail';Type='String';Required=$false;Derived=$true;Key=$null;ValueName=$null}
    }
}

function Get-WinSecPowerShellLoggingCandidateCatalog {
    [CmdletBinding()]param()
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()};$areas=@(Get-WinSecPowerShellLoggingCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider=$_.Provider;ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-7.6'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=$true;Applicability=$rule}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=$rule}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.PowerShellLogging.Candidate';CatalogVersion='1.0.0';CheckId='WSA-LOG-001';Sources=$sources;Inventories=$inventories;
        Fields=@(Get-WinSecPowerShellLoggingCandidateFields|ForEach-Object {[pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit='none';Required=$_.Required;Exposure='CONFIGURATION';Applicability=$rule}})}
}
