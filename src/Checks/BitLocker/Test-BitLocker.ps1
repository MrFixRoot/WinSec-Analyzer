# WinSec Analyzer
# Archivo: src\Checks\BitLocker\Test-BitLocker.ps1
# Recolector local de solo lectura: exclusivamente el volumen de Windows.
# No consulta protectores, contraseñas, claves, paquetes de recuperación ni TPM.
# Evaluación y habilitación requieren validación independiente.

function Get-WinSecBitLockerProperty {
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

function ConvertTo-WinSecBitLockerUInt32 {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    # No convertir null, booleanos, texto o fracciones en un estado válido.
    if(($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int] -or $Value -is [uint32] -or $Value -is [long] -or $Value -is [uint64]) -and
        [decimal]$Value -ge 0 -and [decimal]$Value -le [uint32]::MaxValue){return [long]$Value}
    return $null
}

function Test-WinSecBitLocker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DeviceId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ScanId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CheckId
    )
    if($CheckId -cne 'WSA-SYS-002' -or $DeviceId -cnotmatch '\Alocal:hw1-[a-f0-9]{64}\z' -or
        $ScanId -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z'){throw 'Invalid BitLocker collection identity.'}
    try {$localIds=@(Get-WinSecLocalHardwareDeviceId -ErrorAction Stop)}
    catch {throw 'Unable to validate local hardware identity for BitLocker.'}
    if($localIds.Count -ne 1 -or $localIds[0] -isnot [string] -or $localIds[0] -cne $DeviceId) {
        throw 'BitLocker collection requires the current local hardware identity.'
    }

    $now=[datetime]::UtcNow.ToString('o')
    $issues=New-Object 'System.Collections.Generic.List[string]'
    $systemVolume=[pscustomobject]@{
        DriveLetter=$null;ProtectionStatus='UNKNOWN';ConversionStatus='UNKNOWN';EncryptionPercentage=$null
        EncryptionMethod='UNKNOWN';LockStatus='UNKNOWN'
    }
    $evidence=[pscustomobject]@{
        SchemaVersion='1.0.0';CheckId=$CheckId;DeviceId=$DeviceId;ScanId=$ScanId;CollectedAtUTC=$now
        CollectionSuccessful=$false;CollectionComplete=$false;StatusSource='CIM:Win32_EncryptableVolume'
        Scope='OS_VOLUME_ONLY';SystemVolume=$systemVolume;CollectionIssues=@()
        ScoringEligible=$false;ComplianceAssessment='NOT_EVALUATED';CriteriaSource=$null
    }
    $result=[pscustomobject]@{
        CheckId=$CheckId;DeviceId=$DeviceId;ScanId=$ScanId;SectionKey='SystemSecurity';Status='UNKNOWN'
        Evidence=$evidence;NotApplicableReason=$null;ErrorMessage='';TimestampUTC=$now
    }

    # No suponer C:. Consultar SystemDrive sólo después de validar el equipo.
    $failure='OS_VOLUME_QUERY_FAILED'
    try {
        $systems=@(Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_OperatingSystem' `
            -Property @('SystemDrive') -OperationTimeoutSec 10 -ErrorAction Stop)
        $failure='OS_VOLUME_IDENTITY_INVALID'
        if($systems.Count -ne 1){throw 'Ambiguous system volume.'}
        $drive=Get-WinSecBitLockerProperty $systems[0] 'SystemDrive'
        if($drive -isnot [string] -or $drive -cnotmatch '\A[A-Za-z]:\z'){throw 'Invalid system drive.'}
        $drive=$drive.ToUpperInvariant()

        $failure='BITLOCKER_PROVIDER_UNAVAILABLE'
        $volumes=@(Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftVolumeEncryption' `
            -ClassName 'Win32_EncryptableVolume' -Property @('DeviceID','DriveLetter','VolumeType') `
            -Filter ("DriveLetter = '"+$drive+"'") -OperationTimeoutSec 10 -ErrorAction Stop)
        $failure='OS_VOLUME_NOT_FOUND'
        if($volumes.Count -eq 0){throw 'No system volume telemetry.'}
        $failure='BITLOCKER_VOLUME_IDENTITY_INVALID'
        if($volumes.Count -ne 1){throw 'Ambiguous BitLocker volume.'}
        $volume=$volumes[0]
        $letter=Get-WinSecBitLockerProperty $volume 'DriveLetter'
        $volumeId=Get-WinSecBitLockerProperty $volume 'DeviceID'
        $type=ConvertTo-WinSecBitLockerUInt32 (Get-WinSecBitLockerProperty $volume 'VolumeType')
        if($letter -isnot [string] -or $letter.ToUpperInvariant() -cne $drive -or $null -eq $type -or $type -ne 0 -or
            $volumeId -isnot [string] -or $volumeId -notmatch '\A\\\\\?\\Volume\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}\\\z') {
            throw 'Volume does not identify the Windows drive.'
        }
        $systemVolume.DriveLetter=$drive
    }
    catch {
        $issues.Add($failure)
        if($failure -cne 'OS_VOLUME_NOT_FOUND'){$result.Status='ERROR'}
        $result.ErrorMessage='Unable to collect Windows system volume encryption telemetry.'
        $evidence.CollectionIssues=@($issues.ToArray())
        return $result
    }

    # Lista cerrada de métodos de lectura; nunca serializar objetos CIM.
    $readings=@(
        @{Method='GetProtectionStatus';Field='ProtectionStatus';Values=@('OFF','ON','UNKNOWN')},
        @{Method='GetConversionStatus';Field='ConversionStatus';Values=@('FULLY_DECRYPTED','FULLY_ENCRYPTED',
            'ENCRYPTION_IN_PROGRESS','DECRYPTION_IN_PROGRESS','ENCRYPTION_PAUSED','DECRYPTION_PAUSED')},
        @{Method='GetEncryptionMethod';Field='EncryptionMethod';Values=@('NONE','AES_128_WITH_DIFFUSER',
            'AES_256_WITH_DIFFUSER','AES_128','AES_256','HARDWARE_ENCRYPTION','XTS_AES_128','XTS_AES_256')},
        @{Method='GetLockStatus';Field='LockStatus';Values=@('UNLOCKED','LOCKED')}
    )
    foreach($reading in $readings) {
        try {
            $responses=@(Invoke-CimMethod -InputObject $volume -MethodName $reading.Method -OperationTimeoutSec 10 -ErrorAction Stop)
            if($responses.Count -ne 1){throw 'Ambiguous method result.'}
            $response=$responses[0]
            $code=ConvertTo-WinSecBitLockerUInt32 (Get-WinSecBitLockerProperty $response 'ReturnValue')
            if($null -eq $code -or $code -ne 0){throw 'Method unavailable.'}
        }
        catch {$issues.Add($reading.Method+'_UNAVAILABLE');continue}
        $value=ConvertTo-WinSecBitLockerUInt32 (Get-WinSecBitLockerProperty $response $reading.Field)
        if($null -ne $value -and $value -lt $reading.Values.Count){$systemVolume.($reading.Field)=$reading.Values[[int]$value]}
        if($systemVolume.($reading.Field) -ceq 'UNKNOWN'){$issues.Add($reading.Field+'_UNKNOWN')}
        if($reading.Method -ceq 'GetConversionStatus') {
            $percentage=ConvertTo-WinSecBitLockerUInt32 (Get-WinSecBitLockerProperty $response 'EncryptionPercentage')
            if($null -ne $percentage -and $percentage -le 100){$systemVolume.EncryptionPercentage=$percentage}
            else {$issues.Add('ENCRYPTION_PERCENTAGE_UNKNOWN')}
        }
    }
    # El porcentaje no demuestra FULLY_ENCRYPTED. UNLOCKED/OFF no son PASS/FAIL.
    $known=@('ProtectionStatus','ConversionStatus','EncryptionMethod','LockStatus'|Where-Object {$systemVolume.$_ -cne 'UNKNOWN'}).Count
    $evidence.CollectionSuccessful=($known -gt 0 -or $null -ne $systemVolume.EncryptionPercentage)
    $evidence.CollectionComplete=($known -eq 4 -and $null -ne $systemVolume.EncryptionPercentage)
    $evidence.CollectionIssues=@($issues.ToArray())
    if($evidence.CollectionSuccessful){$result.Status='INFORMATIONAL'}
    else {$result.ErrorMessage='No usable Windows system volume encryption telemetry.'}
    return $result
}
