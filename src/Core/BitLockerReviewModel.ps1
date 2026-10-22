# Observaciones públicas permitidas del volumen de Windows. No consulta Windows.
# REVIEW_ONLY no añade criterios, hallazgos ni puntos de configuración.
function Get-WinSecBitLockerReviewId {
    param([string]$DeviceId,[string]$ScanId,[string]$SettingId)
    $hash=[Security.Cryptography.SHA256]::Create()
    try {
        $text=ConvertTo-Json @($DeviceId,$ScanId,$SettingId) -Compress
        return 'blk-review-'+[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).Replace('-','').ToLowerInvariant()
    } finally {$hash.Dispose()}
}

function ConvertTo-WinSecBitLockerReviewItem {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Item,[Parameter(Mandatory)][object]$Owner)
    $copy=Copy-WinSecResultData $Item
    Assert-WinSecConfigurationFields $copy @('ReviewId','CheckId','DeviceId','ScanId','Type','Status','BitLockerSetting')
    $setting=$copy.BitLockerSetting
    Assert-WinSecConfigurationFields $setting @('SchemaVersion','Scope','SettingId','Value')
    if($copy.CheckId -isnot [string] -or $copy.CheckId -cne 'WSA-SYS-002' -or
        $copy.DeviceId -isnot [string] -or $copy.ScanId -isnot [string] -or
        $copy.DeviceId -cne $Owner.DeviceId -or $copy.ScanId -cne $Owner.ScanId -or
        $copy.DeviceId -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z' -or $copy.ScanId -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z' -or
        $copy.Type -isnot [string] -or $copy.Type -cne 'REVIEW_ONLY' -or
        $copy.Status -isnot [string] -or $copy.Status -cnotin @('OBSERVED','UNKNOWN')){throw 'Invalid BitLocker review identity.'}
    foreach($property in $setting.PSObject.Properties) {
        if($property.Value -isnot [string] -or $property.Value.Length -gt 64 -or $property.Value -match '[\p{C}]'){throw 'Invalid BitLocker review value.'}
    }
    $valid=$false
    switch -CaseSensitive ($setting.SettingId) {
        EncryptionMethod {$valid=$setting.Value -cin @('NONE','AES_128_WITH_DIFFUSER','AES_256_WITH_DIFFUSER','AES_128','AES_256','HARDWARE_ENCRYPTION','XTS_AES_128','XTS_AES_256','UNKNOWN')}
        EncryptionProgress {$valid=$setting.Value -ceq 'UNKNOWN' -or $setting.Value -cmatch '\A(?:0|[1-9][0-9]?|100)\z'}
        LockStatus {$valid=$setting.Value -cin @('LOCKED','UNLOCKED','UNKNOWN')}
    }
    $status=if($setting.Value -ceq 'UNKNOWN'){'UNKNOWN'}else{'OBSERVED'}
    if(-not $valid -or $setting.SchemaVersion -cne '1.0.0' -or $setting.Scope -cne 'OS_VOLUME_ONLY' -or
        $copy.Status -cne $status -or $copy.ReviewId -isnot [string] -or
        $copy.ReviewId -cne (Get-WinSecBitLockerReviewId $copy.DeviceId $copy.ScanId $setting.SettingId)){throw 'Invalid BitLocker review state.'}
    return $copy
}

function New-WinSecBitLockerReviewItems {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$ControlResult)
    $control=Copy-WinSecResultData $ControlResult
    if($control.CheckId -cne 'WSA-SYS-002'){return}
    $observed=Get-WinSecResultField $control 'ObservedStatus'
    if($null -eq $observed){$observed=$control.Status}
    if($observed -cne 'INFORMATIONAL'){return}
    $e=Get-WinSecResultField $control 'Evidence'
    if($null -eq $e -or $e.CollectionSuccessful -isnot [bool] -or -not $e.CollectionSuccessful){return}
    foreach($field in @('CheckId','DeviceId','ScanId')) {
        if(-not (Test-WinSecResultText $control.$field) -or (Get-WinSecResultField $e $field) -cne $control.$field){throw 'Foreign BitLocker review evidence.'}
    }
    if($e.SchemaVersion -cne '1.0.0' -or $e.Scope -cne 'OS_VOLUME_ONLY' -or $e.SystemVolume.DriveLetter -isnot [string] -or
        $e.SystemVolume.DriveLetter -cnotmatch '\A[A-Z]:\z'){throw 'Invalid BitLocker review collection scope.'}
    $items=New-Object 'System.Collections.Generic.List[object]'
    foreach($id in @('EncryptionMethod','EncryptionProgress','LockStatus')) {
        $value=if($id -ceq 'EncryptionProgress') {
            $n=Get-WinSecResultField $e.SystemVolume 'EncryptionPercentage'
            if(($n -is [byte] -or $n -is [sbyte] -or $n -is [int16] -or $n -is [uint16] -or $n -is [int] -or
                $n -is [uint32] -or $n -is [long] -or $n -is [uint64]) -and $n -ge 0 -and $n -le 100){[string]$n}else{'UNKNOWN'}
        } else {Get-WinSecResultField $e.SystemVolume $id}
        if($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)){$value='UNKNOWN'}
        # El recolector ya normaliza enumeraciones; una categoría inválida se rechaza.
        $item=[pscustomobject]@{ReviewId=(Get-WinSecBitLockerReviewId $control.DeviceId $control.ScanId $id);
            CheckId='WSA-SYS-002';DeviceId=$control.DeviceId;ScanId=$control.ScanId;Type='REVIEW_ONLY';
            Status=if($value -ceq 'UNKNOWN'){'UNKNOWN'}else{'OBSERVED'};
            BitLockerSetting=[pscustomobject]@{SchemaVersion='1.0.0';Scope='OS_VOLUME_ONLY';SettingId=$id;Value=$value}}
        $items.Add((ConvertTo-WinSecBitLockerReviewItem $item $control))
    }
    return $items.ToArray()
}

function ConvertTo-WinSecBitLockerReviewRows {
    [CmdletBinding()]
    param([object[]]$ReviewItems=@())
    foreach($review in $ReviewItems) {
        $safe=ConvertTo-WinSecBitLockerReviewItem $review $review
        $s=$safe.BitLockerSetting
        $name=switch -CaseSensitive ($s.SettingId){EncryptionMethod {'Encryption algorithm'};EncryptionProgress {'Native encryption progress'};LockStatus {'Volume lock state'}}
        $value=$s.Value
        if($s.SettingId -ceq 'EncryptionProgress' -and $value -cne 'UNKNOWN'){$value+='%'}
        [pscustomobject]@{Id=$safe.ReviewId;FindingId=$safe.ReviewId;Finding=($name+': '+$value);
            Description='Windows volume observation; excluded from configuration scoring. Native progress is not a security score or proof of completed encryption.';
            ConfigurationState='REVIEW_ONLY';Kind='REVIEW_ONLY';EvaluationStatus='NOT_EVALUATED';ConfigurationPercent='N/A';
            Severity='UNASSIGNED';Priority='UNASSIGNED';Evidence='';
            Recommendation='Review algorithm against device performance, regulatory requirements and approved policy. An unlocked running Windows volume is expected; do not lock it. No remediation is executed.';
            Reference='https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure';FrameworkReferences=@();
            CheckId=$safe.CheckId;ControlKey='BitLocker';SectionKey='SystemSecurity';DeviceId=$safe.DeviceId;ScanId=$safe.ScanId}
    }
}
