# Public, categorical observations only. No criteria approval or Windows queries.
function Get-WinSecDefenderReviewId {
    param([string]$DeviceId,[string]$ScanId,[string]$Topic,[string]$SettingId)
    $text=ConvertTo-Json @($DeviceId,$ScanId,$Topic,$SettingId) -Compress
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return 'def-review-'+[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).Replace('-','').ToLowerInvariant()}
    finally{$hash.Dispose()}
}

function ConvertTo-WinSecDefenderReviewItem {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Item,[Parameter(Mandatory)][object]$Owner)
    $copy=Copy-WinSecResultData $Item
    Assert-WinSecConfigurationFields $copy @('ReviewId','CheckId','DeviceId','ScanId','Type','Status','DefenderSetting')
    $setting=$copy.DefenderSetting
    Assert-WinSecConfigurationFields $setting @('SchemaVersion','Topic','SettingId','Mode','InventoryState')
    if ($copy.CheckId -isnot [string] -or $copy.CheckId -cne 'WSA-SYS-001' -or $copy.DeviceId -isnot [string] -or $copy.ScanId -isnot [string] -or
        $copy.DeviceId -cne $Owner.DeviceId -or $copy.ScanId -cne $Owner.ScanId -or
        $copy.ReviewId -isnot [string] -or $copy.ReviewId -cnotmatch '\Adef-review-[a-f0-9]{64}\z' -or
        $copy.Type -isnot [string] -or $copy.Type -cne 'REVIEW_ONLY' -or $copy.Status -isnot [string] -or
        $copy.Status -cnotin @('OBSERVED','UNKNOWN') -or $setting.SchemaVersion -cne '1.0.0') {
        throw 'Invalid Defender review identity.'
    }
    foreach($property in $setting.PSObject.Properties) {
        if($property.Value -isnot [string] -or $property.Value.Length -gt 64 -or $property.Value -match '[\p{C}]') {
            throw 'Invalid Defender review value.'
        }
    }
    $valid=$false
    switch -CaseSensitive ($setting.Topic) {
        'PUA' {$valid=$setting.SettingId -ceq 'PUAProtection' -and $setting.Mode -cin @('BLOCK','AUDIT','DISABLED','UNKNOWN') -and $setting.InventoryState -ceq 'NOT_APPLICABLE'}
        'CLOUD' {$valid=$setting.SettingId -ceq 'MAPSReporting' -and $setting.Mode -cin @('ENABLED','DISABLED','UNKNOWN') -and $setting.InventoryState -ceq 'NOT_APPLICABLE'}
        'TAMPER' {$valid=$setting.SettingId -ceq 'IsTamperProtected' -and $setting.Mode -cin @('ENABLED','DISABLED','UNKNOWN') -and $setting.InventoryState -ceq 'NOT_APPLICABLE'}
        'ASR' {
            $valid=$setting.InventoryState -cin @('COMPLETE','INCOMPLETE','UNAVAILABLE') -and (
                ($setting.SettingId -ceq 'INVENTORY' -and $setting.Mode -ceq 'INVENTORY') -or
                ($setting.SettingId -cmatch '\A[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z' -and
                 $setting.Mode -cin @('BLOCK','AUDIT','WARN','DISABLED','NOT_CONFIGURED','UNKNOWN') -and
                 ($setting.InventoryState -ceq 'COMPLETE' -or $setting.Mode -ceq 'UNKNOWN')))
        }
    }
    $expectedStatus=if($setting.Mode -ceq 'UNKNOWN' -or ($setting.Topic -ceq 'ASR' -and $setting.InventoryState -cne 'COMPLETE')){'UNKNOWN'}else{'OBSERVED'}
    if(-not $valid -or $copy.Status -cne $expectedStatus -or
        $copy.ReviewId -cne (Get-WinSecDefenderReviewId $copy.DeviceId $copy.ScanId $setting.Topic $setting.SettingId)){throw 'Invalid Defender review state.'}
    return $copy
}

function New-WinSecDefenderReviewItems {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$ControlResult)
    $control=Copy-WinSecResultData $ControlResult
    if($control.CheckId -cne 'WSA-SYS-001' -or $control.Status -cne 'INFORMATIONAL'){return}
    $evidence=Get-WinSecResultField $control 'Evidence'
    if($null -eq $evidence -or $evidence.CollectionSuccessful -isnot [bool] -or -not $evidence.CollectionSuccessful){return}
    foreach($field in @('CheckId','DeviceId','ScanId')) {
        if(-not (Test-WinSecResultText $control.$field) -or
            (Get-WinSecResultField $evidence $field) -cne $control.$field){throw 'Foreign Defender review evidence.'}
    }
    $add={param($Topic,$Id,$Mode,$InventoryState='NOT_APPLICABLE')
        $reviewId=Get-WinSecDefenderReviewId $control.DeviceId $control.ScanId $Topic $Id
        $item=[pscustomobject]@{ReviewId=$reviewId;CheckId='WSA-SYS-001';DeviceId=$control.DeviceId;ScanId=$control.ScanId;
            Type='REVIEW_ONLY';Status=if($Mode -ceq 'UNKNOWN' -or ($Topic -ceq 'ASR' -and $InventoryState -cne 'COMPLETE')){'UNKNOWN'}else{'OBSERVED'};
            DefenderSetting=[pscustomobject]@{SchemaVersion='1.0.0';Topic=$Topic;SettingId=$Id;Mode=$Mode;InventoryState=$InventoryState}}
        ConvertTo-WinSecDefenderReviewItem $item $control
    }
    $items=New-Object 'System.Collections.Generic.List[object]'
    $pua=Get-WinSecResultField (Get-WinSecResultField $evidence 'PUAProtectionAssessment') 'Mode'
    if($pua -isnot [string] -or $pua -cnotin @('BLOCK','AUDIT','DISABLED')){$pua='UNKNOWN'}
    $items.Add((& $add PUA PUAProtection $pua))
    $cloud=Get-WinSecResultField (Get-WinSecResultField $evidence 'DefenderPreferences') 'MAPSReporting'
    $cloudMode='UNKNOWN'
    if($null -ne $cloud -and ($cloud -is [string] -or $cloud.GetType().IsEnum -or
        $cloud.GetType() -in @([byte],[sbyte],[int16],[uint16],[int32],[uint32],[int64],[uint64]))) {
        if([string]$cloud -cin @('1','2','Basic','Advanced')){$cloudMode='ENABLED'}
        elseif([string]$cloud -cin @('0','Disabled')){$cloudMode='DISABLED'}
    }
    $items.Add((& $add CLOUD MAPSReporting $cloudMode))
    $tamper=Get-WinSecResultField (Get-WinSecResultField $evidence 'DefenderStatus') 'IsTamperProtected'
    $tamperMode=if($tamper -isnot [bool]){'UNKNOWN'}elseif($tamper){'ENABLED'}else{'DISABLED'}
    $items.Add((& $add TAMPER IsTamperProtected $tamperMode))
    $asr=Get-WinSecResultField $evidence 'AttackSurfaceReduction'
    $available=Get-WinSecResultField $asr 'Available';$complete=Get-WinSecResultField $asr 'Complete'
    $inventoryState=if($available -isnot [bool] -or -not $available){'UNAVAILABLE'}
        elseif($complete -is [bool] -and $complete){'COMPLETE'}else{'INCOMPLETE'}
    $items.Add((& $add ASR INVENTORY INVENTORY $inventoryState))
    $rules=Get-WinSecResultField $asr 'Rules'
    if($null -eq $rules){return $items.ToArray()}
    if($rules -isnot [array] -or $rules.Count -gt 128){throw 'Invalid bounded ASR inventory.'}
    $seen=@{}
    foreach($rule in $rules) {
        $id=Get-WinSecResultField $rule 'RuleId';$mode=Get-WinSecResultField $rule 'Mode'
        if($id -isnot [string] -or $id -cnotmatch '\A[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z' -or $seen.ContainsKey($id)){throw 'Invalid ASR review rule identity.'}
        $seen[$id]=$true
        if($inventoryState -cne 'COMPLETE' -or $mode -isnot [string] -or $mode -cnotin @('BLOCK','AUDIT','WARN','DISABLED','NOT_CONFIGURED')){$mode='UNKNOWN'}
        $items.Add((& $add ASR $id $mode $inventoryState))
    }
    return $items.ToArray()
}

function ConvertTo-WinSecDefenderReviewRows {
    [CmdletBinding()]
    param([object[]]$ReviewItems=@())
    foreach($review in $ReviewItems) {
        $s=$review.DefenderSetting
        $name=switch -CaseSensitive ($s.Topic){PUA {'PUA protection'};CLOUD {'Cloud protection (MAPS)'};TAMPER {'Tamper protection'};ASR {'ASR '+$s.SettingId}}
        $mode=if($s.SettingId -ceq 'INVENTORY'){$s.InventoryState}else{$s.Mode}
        $url=switch -CaseSensitive ($s.Topic){
            PUA {'https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus'}
            CLOUD {'https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-configure'}
            TAMPER {'https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection'}
            ASR {'https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview'}
        }
        [pscustomobject]@{Id=$review.ReviewId;FindingId=$review.ReviewId;Finding=($name+': '+$mode);
            Description='Observed configuration only; not a confirmed misconfiguration or effective enforcement test.';
            ConfigurationState='REVIEW_ONLY';Kind='REVIEW_ONLY';EvaluationStatus='NOT_EVALUATED';
            Severity='UNASSIGNED';Priority='UNASSIGNED';Evidence='';Recommendation='Review applicability and the approved local policy before changing configuration. Unlisted ASR rules are not assessed.';
            Reference=$url;FrameworkReferences=@();
            CheckId=$review.CheckId;ControlKey='Defender';SectionKey='SystemSecurity';DeviceId=$review.DeviceId;ScanId=$review.ScanId}
    }
}
