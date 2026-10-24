# WinSec Analyzer
# Archivo: src\Checks\System\Test-WindowsUpdate.ps1
# Inventario local de configuracion; no busca, descarga ni instala actualizaciones.
# Las politicas observadas no acreditan politica efectiva ni parches al dia.

function Get-WinSecWindowsUpdateProperty {
    [CmdletBinding()]
    param([AllowNull()][object]$InputObject,[Parameter(Mandatory)][string]$Name)
    if($null -eq $InputObject){return $null}
    if($InputObject -is [System.Collections.IDictionary]) {
        if($InputObject.Contains($Name)){return ,$InputObject[$Name]}
        return $null
    }
    $property=$InputObject.PSObject.Properties[$Name]
    if($null -ne $property -and $property.MemberType -in @('Property','NoteProperty')){return ,$property.Value}
    return $null
}

function ConvertTo-WinSecWindowsUpdateUInt32 {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if(($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int] -or $Value -is [uint32] -or $Value -is [long] -or $Value -is [uint64]) -and
        [decimal]$Value -ge 0 -and [decimal]$Value -le [uint32]::MaxValue){return [long]$Value}
    return $null
}

function Open-WinSecWindowsUpdatePolicyKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
            'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU')]
        [string]$SubKey
    )
    # Windows 11 uses the 64-bit policy view, also from a 32-bit host.
    # false requests read-only access; an absent key returns null, never creates it.
    $baseKey=[Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try {return $baseKey.OpenSubKey($SubKey,$false)}
    finally {$baseKey.Dispose()}
}

function Test-WinSecWindowsUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DeviceId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ScanId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CheckId
    )
    if($CheckId -cne 'WSA-SYS-003' -or $DeviceId -cnotmatch '\Alocal:hw1-[a-f0-9]{64}\z' -or
        $ScanId -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z'){throw 'Invalid Windows Update collection identity.'}
    try {$localIds=@(Get-WinSecLocalHardwareDeviceId -ErrorAction Stop)}
    catch {throw 'Unable to validate local hardware identity for Windows Update.'}
    if($localIds.Count -ne 1 -or $localIds[0] -isnot [string] -or $localIds[0] -cne $DeviceId) {
        throw 'Windows Update collection requires the current local hardware identity.'
    }

    $now=[datetime]::UtcNow.ToString('o')
    $issues=New-Object 'System.Collections.Generic.List[string]'
    $successfulSources=0
    $platform=[pscustomobject]@{Version=$null;BuildNumber=$null;OperatingSystemSKU=$null;ProductType=$null;State='UNKNOWN'}
    $service=[pscustomobject]@{Name='wuauserv';State='UNKNOWN';StartMode='UNKNOWN';Source='CIM:Win32_Service'}
    $policies=[pscustomobject]@{}
    $evidence=[pscustomobject]@{
        SchemaVersion='1.0.0';CheckId=$CheckId;DeviceId=$DeviceId;ScanId=$ScanId;CollectedAtUTC=$now
        Scope='LOCAL_CONFIGURATION_ONLY';Platform=$platform;UpdateService=$service;PolicyRegistry=$policies
        CollectionSuccessful=$false;CollectionComplete=$false;CollectionIssues=@()
        EffectivePolicyVerified=$false;UpdateSearchPerformed=$false;PatchCurrency='NOT_EVALUATED'
        ScoringEligible=$false;ComplianceAssessment='NOT_EVALUATED';CriteriaSource=$null
    }
    $result=[pscustomobject]@{
        CheckId=$CheckId;DeviceId=$DeviceId;ScanId=$ScanId;SectionKey='SystemSecurity';Status='UNKNOWN'
        Evidence=$evidence;NotApplicableReason=$null;ErrorMessage='';TimestampUTC=$now
    }

    $failure='OS_QUERY_FAILED'
    try {
        $systems=@(Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_OperatingSystem' `
            -Property @('Version','BuildNumber','OperatingSystemSKU','ProductType') -OperationTimeoutSec 10 -ErrorAction Stop)
        $failure='OS_TELEMETRY_INVALID'
        if($systems.Count -ne 1){throw 'Ambiguous platform.'}
        $version=Get-WinSecWindowsUpdateProperty $systems[0] 'Version'
        $build=Get-WinSecWindowsUpdateProperty $systems[0] 'BuildNumber'
        $sku=ConvertTo-WinSecWindowsUpdateUInt32 (Get-WinSecWindowsUpdateProperty $systems[0] 'OperatingSystemSKU')
        $type=ConvertTo-WinSecWindowsUpdateUInt32 (Get-WinSecWindowsUpdateProperty $systems[0] 'ProductType')
        if($version -isnot [string] -or $version -cnotmatch '\A10\.0\.[1-9][0-9]{3,5}\z' -or
            $build -isnot [string] -or $build -cnotmatch '\A[1-9][0-9]{3,5}\z' -or
            $version -cne ('10.0.'+$build) -or $null -eq $sku -or $null -eq $type -or $type -notin @(1,2,3)) {
            throw 'Invalid platform telemetry.'
        }
        $platform.Version=$version;$platform.BuildNumber=$build;$platform.OperatingSystemSKU=$sku
        $platform.ProductType=$type;$platform.State='OBSERVED';$successfulSources++
    } catch {$issues.Add($failure)}

    $failure='UPDATE_SERVICE_QUERY_FAILED'
    try {
        $services=@(Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_Service' `
            -Filter "Name = 'wuauserv'" -Property @('Name','State','StartMode') -OperationTimeoutSec 10 -ErrorAction Stop)
        $failure='UPDATE_SERVICE_UNAVAILABLE'
        if($services.Count -eq 0){throw 'Missing update service.'}
        $failure='UPDATE_SERVICE_IDENTITY_INVALID'
        if($services.Count -ne 1){throw 'Ambiguous update service.'}
        $name=Get-WinSecWindowsUpdateProperty $services[0] 'Name'
        if($name -isnot [string] -or $name -ine 'wuauserv'){throw 'Foreign service.'}
        $state=Get-WinSecWindowsUpdateProperty $services[0] 'State'
        $mode=Get-WinSecWindowsUpdateProperty $services[0] 'StartMode'
        if($state -is [string] -and $state -cin @('Stopped','Start Pending','Stop Pending','Running','Continue Pending','Pause Pending','Paused')) {
            $service.State=$state.ToUpperInvariant().Replace(' ','_')
        } else {$issues.Add('UPDATE_SERVICE_STATE_UNKNOWN')}
        if($mode -is [string] -and $mode -cin @('Boot','System','Auto','Manual','Disabled')) {
            $service.StartMode=$mode.ToUpperInvariant()
        } else {$issues.Add('UPDATE_SERVICE_START_MODE_UNKNOWN')}
        if($service.State -cne 'UNKNOWN' -and $service.StartMode -cne 'UNKNOWN'){$successfulSources++}
    } catch {$issues.Add($failure)}

    # Only named DWORD policies; do not read WSUS URLs, accounts, history or logs.
    $areas=@(
        @{Name='AutomaticUpdates';Suffix='\AU';Fields=@('NoAutoUpdate','AUOptions','UseWUServer')},
        @{Name='WindowsUpdate';Suffix='';Fields=@('DeferQualityUpdates','DeferQualityUpdatesPeriodInDays',
            'SetDisableUXWUAccess','DoNotConnectToWindowsUpdateInternetLocations','SetPolicyDrivenUpdateSourceForQualityUpdates')}
    )
    foreach($area in $areas) {
        $path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'+$area.Suffix
        $snapshot=[pscustomobject]@{Source=('REGISTRY64:HKLM\'+$path);ReadState='UNKNOWN'}
        foreach($field in $area.Fields) {
            $snapshot|Add-Member -NotePropertyName $field -NotePropertyValue ([pscustomobject]@{State='UNKNOWN';Value=$null})
        }
        $policies|Add-Member -NotePropertyName $area.Name -NotePropertyValue $snapshot
        $key=$null
        try {
            $key=Open-WinSecWindowsUpdatePolicyKey -SubKey $path -ErrorAction Stop
            if($null -eq $key) {
                $snapshot.ReadState='NOT_CONFIGURED'
                foreach($field in $area.Fields){$snapshot.$field.State='NOT_CONFIGURED'}
            } else {
                $snapshot.ReadState='READ'
                foreach($field in $area.Fields) {
                    try {
                        $value=$key.GetValue($field,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        if($null -eq $value){$snapshot.$field.State='NOT_CONFIGURED';continue}
                        if($key.GetValueKind($field) -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
                            $issues.Add($area.Name+'_'+$field+'_INVALID_TYPE');continue
                        }
                        # Preserve the unsigned DWORD bit pattern without accepting text/QWORD.
                        if($value -isnot [int] -and $value -isnot [uint32]) {
                            $issues.Add($area.Name+'_'+$field+'_INVALID_VALUE');continue
                        }
                        $snapshot.$field.Value=([long]$value -band 4294967295L)
                        $snapshot.$field.State='CONFIGURED'
                    } catch {$issues.Add($area.Name+'_'+$field+'_READ_FAILED')}
                }
            }
            $successfulSources++
        } catch {$issues.Add($area.Name+'_KEY_READ_FAILED')}
        finally {
            if($null -ne $key) {
                try {$key.Dispose()} catch {$issues.Add($area.Name+'_KEY_CLOSE_FAILED')}
            }
        }
    }
    $evidence.CollectionSuccessful=($successfulSources -gt 0)
    $evidence.CollectionComplete=($issues.Count -eq 0)
    $evidence.CollectionIssues=@($issues.ToArray())
    $result.Status=if($evidence.CollectionSuccessful){'INFORMATIONAL'}else{'ERROR'}
    if($issues.Count -gt 0){$result.ErrorMessage='Some Windows Update configuration sources could not be read or validated. No patch or security verdict was inferred.'}
    return $result
}
