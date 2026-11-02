# Data-only candidate: consumes prepared receipts, never queries or changes Windows.
. (Join-Path $PSScriptRoot 'BitLockerTechnicalCatalog.ps1')

function Get-WinSecBitLockerCapturedProperty {
    param([AllowNull()][object]$Data,[string]$Name)
    $missing=[pscustomobject]@{Exists=$false;Safe=$true;Value=$null}
    if($null -eq $Data){return $missing}
    if($Data.GetType() -in @([hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){
        $keys=@($Data.Keys|Where-Object {$_ -is [string] -and [string]::Equals($_,$Name,[StringComparison]::OrdinalIgnoreCase)})
        if(-not $keys.Count){return $missing}
        if($keys.Count -ne 1){return [pscustomobject]@{Exists=$true;Safe=$false;Value=$null}}
        return [pscustomobject]@{Exists=$true;Safe=$true;Value=$Data[$keys[0]]}
    }
    if($Data.GetType() -ne [Management.Automation.PSCustomObject]){return [pscustomobject]@{Exists=$true;Safe=$false;Value=$null}}
    $properties=@($Data.PSObject.Properties|Where-Object {[string]::Equals($_.Name,$Name,[StringComparison]::OrdinalIgnoreCase)})
    if(-not $properties.Count){return $missing}
    if($properties.Count -ne 1 -or $properties[0].MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){return [pscustomobject]@{Exists=$true;Safe=$false;Value=$null}}
    [pscustomobject]@{Exists=$true;Safe=$true;Value=$properties[0].Value}
}

function ConvertTo-WinSecBitLockerTechnicalValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    $invalid=[pscustomobject]@{Valid=$false;Value=$null}
    if($null -eq $Value){return $invalid}
    switch -CaseSensitive ($Kind){
        Boolean {if($Value -is [bool]){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        {$_ -cin @('UInt32','Build','Percent')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){
                $parsed=[uint32]0;if(-not [uint32]::TryParse($Value,[ref]$parsed)){return $invalid};$Value=$parsed
            }
            if($Value.GetType().IsEnum){try{$Value=[long]$Value}catch{return $invalid}}
            if((Test-WinSecSnapshotUInt $Value) -and ($Kind -cne 'Percent' -or $Value -le 100)){return [pscustomobject]@{Valid=$true;Value=[uint32]$Value}}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        Drive {if($Value -is [string] -and $Value -cmatch '\A[A-Za-z]:\z'){return [pscustomobject]@{Valid=$true;Value=$Value.ToUpperInvariant()}}}
        {$_ -cin @('VolumeId','Target')} {
            if($Value -is [string] -and $Value -cmatch '\A\\\\\?\\Volume\{([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})\}\\\z'){
                return [pscustomobject]@{Valid=$true;Value=('\\?\Volume{'+$Matches[1].ToLowerInvariant()+'}\')}
            }
        }
        CaptureTime {
            try{$date=ConvertTo-WinSecSnapshotUtc $Value;return [pscustomobject]@{Valid=$true;Value=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}}catch{return $invalid}
        }
    }
    return $invalid
}

function New-WinSecBitLockerTechnicalSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('o')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity
    if($Identity.CheckId -cne 'WSA-SYS-002'){throw 'BitLocker candidate cannot process another control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid BitLocker capture operation.'}
    $areas=@(Get-WinSecBitLockerTechnicalAreas);$inputs=@{};$collected=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'BitLocker requires exactly the reviewed source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','VolumeDeviceId','State','Data')
        if($source.SourceId -isnot [string] -or $source.SourceId -cnotin $areas.Id -or $inputs.ContainsKey($source.SourceId) -or
            $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign or invalid BitLocker source.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC
        if($time -lt $start -or $time -gt $end){throw 'BitLocker source lies outside its operation.'}
        if($time -gt $collected){$collected=$time}
        if($source.State -ceq 'OBSERVED'){
            if($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'BitLocker capture must be plain data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable BitLocker source contains raw data.'}
        $inputs[$source.SourceId]=$source
    }
    if($null -ne $inputs.Platform.VolumeDeviceId){throw 'Platform source cannot claim a BitLocker volume.'}
    $volumeId=$null
    if($inputs.Volume.State -ceq 'OBSERVED'){
        $binding=@{}
        foreach($entry in @(@('Drive','Platform','SystemDrive'),@('Drive','Volume','DriveLetter'),@('VolumeId','Volume','DeviceID'),@('UInt32','Volume','VolumeType'))){
            $source=$inputs[$entry[1]];$property=Get-WinSecBitLockerCapturedProperty $source.Data $entry[2]
            $value=ConvertTo-WinSecBitLockerTechnicalValue $property.Value $entry[0]
            if($source.State -cne 'OBSERVED' -or -not $property.Safe -or -not $property.Exists -or -not $value.Valid){throw 'Unable to verify the Windows volume binding.'}
            $binding[$entry[2]]=$value.Value
        }
        if($binding.SystemDrive -cne $binding.DriveLetter -or $binding.VolumeType -ne 0){throw 'BitLocker capture is not the Windows volume.'}
        $volumeId=$binding.DeviceID
    }
    foreach($area in $areas|Where-Object Id -CNE Platform){
        $source=$inputs[$area.Id]
        if($null -eq $volumeId){
            if($null -ne $source.VolumeDeviceId -or $source.State -ceq 'OBSERVED'){throw 'Unbound BitLocker volume source.'}
        }else{
            $target=ConvertTo-WinSecBitLockerTechnicalValue $source.VolumeDeviceId Target
            if(-not $target.Valid -or $target.Value -cne $volumeId){throw 'BitLocker source belongs to another volume.'}
        }
    }
    $catalog=Get-WinSecBitLockerTechnicalCatalog;$digest=Get-WinSecSnapshotCatalogHash $catalog;$specs=@(Get-WinSecBitLockerTechnicalFields)
    $platform=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    $inventories=@();$batches=@();$counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0}
    $stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected'};$complete=$true
    foreach($area in $areas){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $source=$inputs[$area.Id];$readings=@();$ok=($source.State -ceq 'OBSERVED');$reason='NONE';$return=$null;$returnSafe=$false
        if(-not $ok){$reason=if($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}}
        if($area.Method -and $ok){
            $property=Get-WinSecBitLockerCapturedProperty $source.Data ReturnValue
            $return=ConvertTo-WinSecBitLockerTechnicalValue $property.Value UInt32;$returnSafe=($property.Safe -and $property.Exists -and $return.Valid)
            if(-not $returnSafe){$ok=$false;$reason='INVALID_VALUE'}elseif($return.Value -ne 0){$ok=$false;$reason='PROVIDER_UNAVAILABLE'}
        }
        foreach($definition in $specs|Where-Object Inventory -CEQ $area.Id){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $state='UNKNOWN';$why='PROVIDER_UNAVAILABLE';$value=$null
            if($definition.Kind -ceq 'CaptureTime'){$raw=$source.CollectedAtUTC;$safe=$true}
            elseif($definition.Kind -ceq 'Target'){$raw=$source.VolumeDeviceId;$safe=$true}
            else{$property=Get-WinSecBitLockerCapturedProperty $source.Data $definition.Property;$raw=$property.Value;$safe=$property.Safe}
            if($definition.Kind -cin @('CaptureTime','Target')){
                $converted=ConvertTo-WinSecBitLockerTechnicalValue $raw $definition.Kind
                if($converted.Valid){$state='OBSERVED';$why='NONE';$value=$converted.Value}
            }elseif($source.State -cne 'OBSERVED'){
                $state=$source.State;$why=if($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}
            }elseif($area.Method -and $definition.Property -cne 'ReturnValue' -and -not $ok){
                $state=if($returnSafe){'ERROR'}else{'UNKNOWN'};$why=$reason
            }elseif(-not $safe){$why='INVALID_VALUE'}elseif($null -ne $raw){
                $converted=ConvertTo-WinSecBitLockerTechnicalValue $raw $definition.Kind
                if($converted.Valid){$state='OBSERVED';$why='NONE';$value=$converted.Value}else{$why='INVALID_VALUE'}
            }
            $readings+=,[pscustomobject]@{FieldId=$definition.Id;State=$state;Reason=$why;Value=$value};$counts[$stateCount[$state]]++
            if($definition.Required -and $state -cne 'OBSERVED'){$complete=$false}
            if($area.Id -ceq 'Platform' -and $state -ceq 'OBSERVED' -and $definition.Property -cin @('Version','BuildNumber','OperatingSystemSKU','ProductType')){$platform.($definition.Property)=$value}
        }
        if(-not $ok){$complete=$false}
        $inventories+=,[pscustomobject]@{Id=$area.Id;State='OBSERVED';Complete=$ok;ReportedRecords=$(if($source.State -ceq 'OBSERVED'){1}else{$null});RetainedRecords=1;Reason=$reason}
        $batches+=,[pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$area.Id;Sequence=1;
            Records=@([pscustomobject]@{Id=($area.Id+'0');Readings=$readings})};$counts.RetainedRecords++
        if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{InventoryId=$area.Id;CompletedInventories=$inventories.Count;TotalInventories=$areas.Count})}
    }
    if(($null -ne $platform.BuildNumber -and $platform.BuildNumber -lt 22000) -or ($null -ne $platform.ProductType -and $platform.ProductType -ne 1)){throw 'BitLocker candidate supports observed Windows 11 clients only.'}
    $complete=($complete -and $null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1)
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]}
    $snapshot=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$owner;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$digest;CollectorVersion='1.0.0';
        StartedAtUTC=$StartedAtUTC;CollectedAtUTC=$collected.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);CompletedAtUTC=$CompletedAtUTC;GeneratedAtUTC=$GeneratedAtUTC;
        Platform=$platform;SelectedProfile=$SelectedProfile;Collection=[pscustomobject]$collection;Inventories=$inventories;Batches=$batches}
    Assert-WinSecBitLockerTechnicalSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$digest;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecBitLockerTechnicalSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    if($ExpectedIdentity.CheckId -cne 'WSA-SYS-002'){throw 'Foreign BitLocker candidate identity.'}
    $catalog=Get-WinSecBitLockerTechnicalCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed BitLocker candidate collector version.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$definitions=@{};foreach($definition in Get-WinSecBitLockerTechnicalFields){$definitions[$definition.Id]=$definition}
    $readings=@{};$inventories=@{};foreach($inventory in $Snapshot.Inventories){$inventories[$inventory.Id]=$inventory}
    foreach($batch in $Snapshot.Batches){foreach($record in $batch.Records){foreach($reading in $record.Readings){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$readings[$reading.FieldId]=$reading
        if($reading.State -cne 'OBSERVED'){continue}
        $converted=ConvertTo-WinSecBitLockerTechnicalValue $reading.Value $definitions[$reading.FieldId].Kind
        if(-not $converted.Valid -or $converted.Value -cne $reading.Value){throw 'Unreviewed BitLocker technical value.'}
    }}}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){
        $reading=$readings['Platform.'+$name];$observed=if($reading.State -ceq 'OBSERVED'){$reading.Value}else{$null}
        if($Snapshot.Platform.$name -cne $observed){throw 'BitLocker platform differs from captured readings.'}
    }
    if($null -ne $Snapshot.Platform.OSRelease -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.UBR){throw 'Unobserved BitLocker platform metadata.'}
    $volume=$readings['Volume.DeviceID'];$drive=$readings['Platform.SystemDrive'];$letter=$readings['Volume.DriveLetter'];$type=$readings['Volume.VolumeType']
    if($volume.State -ceq 'OBSERVED'){
        if($drive.State -cne 'OBSERVED' -or $letter.State -cne 'OBSERVED' -or $drive.Value -cne $letter.Value -or $type.State -cne 'OBSERVED' -or $type.Value -ne 0){throw 'Unverified Windows volume in BitLocker snapshot.'}
    }elseif($letter.State -ceq 'OBSERVED' -or $type.State -ceq 'OBSERVED'){throw 'Incomplete BitLocker volume identity.'}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($area in Get-WinSecBitLockerTechnicalAreas){
        $time=$readings[$area.Id+'.CollectedAtUTC']
        if($time.State -cne 'OBSERVED'){throw 'Missing BitLocker capture timestamp.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value
        if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'Foreign BitLocker capture timestamp.'}
        if($stamp -gt $latest){$latest=$stamp}
        if(-not $area.Method){continue}
        $target=$readings[$area.Id+'.TargetVolumeId'];$return=$readings[$area.Id+'.ReturnValue']
        if(($volume.State -ceq 'OBSERVED' -and ($target.State -cne 'OBSERVED' -or $target.Value -cne $volume.Value)) -or
            ($volume.State -cne 'OBSERVED' -and ($target.State -ceq 'OBSERVED' -or $return.State -ceq 'OBSERVED'))){throw 'Foreign BitLocker method volume.'}
        $ok=($return.State -ceq 'OBSERVED' -and $return.Value -eq 0)
        if($inventories[$area.Id].Complete -cne $ok){throw 'BitLocker method completion contradicts its return code.'}
        if(-not $ok){foreach($definition in $definitions.Values|Where-Object {$_.Inventory -ceq $area.Id -and $_.Kind -cnotin @('CaptureTime','Target') -and $_.Property -cne 'ReturnValue'}){
            $output=$readings[$definition.Id]
            if($output.State -ceq 'OBSERVED' -or ($return.State -ceq 'OBSERVED' -and ($output.State -cne 'ERROR' -or $output.Reason -cne 'PROVIDER_UNAVAILABLE'))){throw 'Unsuccessful BitLocker method supplies usable output.'}
        }}
    }
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC)){throw 'BitLocker collection timestamp contradicts its sources.'}
}
