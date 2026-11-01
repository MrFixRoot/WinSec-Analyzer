# Data-only candidate adapter 1.2. No native queries, execution registration or production imports.
. (Join-Path $PSScriptRoot 'DefenderStatusReadings.ps1')

function Assert-WinSecDefenderCapturedCimSource {
    param([object]$Data,[string]$SourceId)
    # Invoke CLR accessors explicitly: ETS ScriptProperties must never replace them.
    try {
        if($Data -isnot [Microsoft.Management.Infrastructure.CimInstance]){throw 'Invalid carrier.'}
        $system=[Microsoft.Management.Infrastructure.CimInstance].GetProperty('CimSystemProperties').GetValue($Data,$null)
        $class=[Microsoft.Management.Infrastructure.CimSystemProperties].GetProperty('ClassName').GetValue($system,$null)
        $namespace=[Microsoft.Management.Infrastructure.CimSystemProperties].GetProperty('Namespace').GetValue($system,$null)
        $expectedClass=switch -CaseSensitive ($SourceId){
            Platform {'Win32_OperatingSystem'}
            Status {'MSFT_MpComputerStatus'}
            Preferences {'MSFT_MpPreference'}
            default {throw 'Unknown source.'}
        }
        $expectedNamespace=if($SourceId -ceq 'Platform'){'root/cimv2'}else{'root/Microsoft/Windows/Defender'}
        if($class -isnot [string] -or $namespace -isnot [string] -or
            -not [string]::Equals($class,$expectedClass,[StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($namespace.Replace('\','/'),$expectedNamespace,[StringComparison]::OrdinalIgnoreCase)){
            throw 'Foreign CIM source.'
        }
    }catch{throw 'Invalid Defender captured CIM source.'}
    # This checks a supplied carrier, not its native origin, locality or authorization.
}

function Get-WinSecDefenderCapturedProperty {
    param([AllowNull()][object]$Data,[string]$Name)
    $missing=[pscustomobject]@{Exists=$false;Safe=$true;Value=$null}
    if($null -eq $Data){return $missing}
    if($Data -is [Microsoft.Management.Infrastructure.CimInstance]){
        try {
            $properties=[Microsoft.Management.Infrastructure.CimInstance].GetProperty('CimInstanceProperties').GetValue($Data,$null)
            $property=$properties[$Name]
            if($null -eq $property){return $missing}
            $value=[Microsoft.Management.Infrastructure.CimProperty].GetProperty('Value').GetValue($property,$null)
            return [pscustomobject]@{Exists=$true;Safe=$true;Value=$value}
        }catch{return [pscustomobject]@{Exists=$true;Safe=$false;Value=$null}}
    }
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

function ConvertTo-WinSecDefenderTechnicalValue {
    param([AllowNull()][object]$Value,[string]$Kind,[scriptblock]$CancellationAction,
        [Diagnostics.Stopwatch]$Clock=([Diagnostics.Stopwatch]::StartNew()))
    $invalid=[pscustomobject]@{Valid=$false;Value=$null}
    if($null -eq $Value){return $invalid}
    switch -CaseSensitive ($Kind){
        Boolean {if($Value -is [bool]){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        {$_ -cin @('UInt32','Build','Percent','Count')} {
            if($Kind -ceq 'Count'){
                if($Value -isnot [array] -or $Value.Rank -ne 1){return $invalid}
                # Validate carrier types without stringifying or retaining private contents.
                for($i=0;$i -lt $Value.Length;$i++){
                    if(($i % 128) -eq 0){Assert-WinSecSnapshotValidationBudget $Clock $CancellationAction}
                    if($Value[$i] -isnot [string] -or [string]::IsNullOrWhiteSpace($Value[$i])){return $invalid}
                }
                return [pscustomobject]@{Valid=$true;Value=[uint32]$Value.Length}
            }
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){
                $parsed=[uint32]0;if(-not [uint32]::TryParse($Value,[ref]$parsed)){return $invalid};$Value=$parsed
            }
            if($Value.GetType().IsEnum){try{$Value=[long]$Value}catch{return $invalid}}
            if(Test-WinSecSnapshotUInt $Value){
                if($Kind -ceq 'Percent' -and $Value -gt 100){return $invalid}
                return [pscustomobject]@{Valid=$true;Value=[uint32]$Value}
            }
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A[0-9]{1,5}(?:\.[0-9]{1,5}){1,4}\z'){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        PlatformVersion {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        RunningMode {if($Value -is [string] -and $Value -cin @('Normal','Passive','Passive Mode','EDR Block Mode')){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        Guid {
            $guid=[guid]::Empty
            if($Value -is [string] -and [guid]::TryParseExact($Value,'D',[ref]$guid)){return [pscustomobject]@{Valid=$true;Value=$guid.ToString('D')}}
        }
        Utc {
            $date=[datetimeoffset]::MinValue
            if($Value -is [datetimeoffset]){$date=$Value}
            elseif($Value -is [datetime] -and $Value.Kind -ne [DateTimeKind]::Unspecified){$date=[datetimeoffset]$Value}
            elseif($Value -is [string] -and $Value -cmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|[+-][0-9]{2}:[0-9]{2})\z'){
                if(-not [datetimeoffset]::TryParse($Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date)){return $invalid}
            }else{return $invalid}
            return [pscustomobject]@{Valid=$true;Value=$date.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}
        }
    }
    return $invalid
}

function Get-WinSecDefenderTechnicalPayloadBudget {
    # Reserve space for the fixed envelope/scalar inventories; never raise shared limits.
    return ((Get-WinSecSnapshotSpecification).MaxDocumentBytes-131072)
}

function New-WinSecDefenderTechnicalSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('o')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity
    if($Identity.CheckId -cne 'WSA-SYS-001'){throw 'Defender candidate cannot process another control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid capture timeline or context.'}
    $inputs=@{};$collected=$start
    if($Sources.Count -ne 3){throw 'Defender capture requires exactly three source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','State','Data')
        if($source.SourceId -isnot [string] -or $source.SourceId -cnotin @('Platform','Status','Preferences') -or $inputs.ContainsKey($source.SourceId) -or
            $source.DeviceId -isnot [string] -or $source.ScanId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or $source.ScanId -cne $owner.ScanId -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Invalid or foreign captured source.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC
        if($time -lt $start -or $time -gt $end){throw 'Captured source lies outside its operation.'}
        if($time -gt $collected){$collected=$time}
        if($source.State -ceq 'OBSERVED'){
            if($source.Data -is [Microsoft.Management.Infrastructure.CimInstance]){
                Assert-WinSecDefenderCapturedCimSource $source.Data $source.SourceId
            }elseif($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Captured source must contain reviewed data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable capture must not contain raw data.'}
        $inputs[$source.SourceId]=$source
    }
    $statusReadings=$null
    if($inputs.Status.State -ceq 'OBSERVED' -and $inputs.Status.Data -isnot [Microsoft.Management.Infrastructure.CimInstance]){
        $marker=Get-WinSecDefenderCapturedProperty $inputs.Status.Data ArtifactType
        if($marker.Safe -and $marker.Value -is [string] -and $marker.Value -ceq 'WinSec.Defender.StatusReadings'){
            Assert-WinSecDefenderStatusReadings $inputs.Status.Data -CancellationAction $CancellationAction
            $statusReadings=@{};foreach($reading in $inputs.Status.Data.Readings){$statusReadings[$reading.FieldId]=$reading.PSObject.Copy()}
        }
    }
    $catalog=Get-WinSecDefenderTechnicalCatalog;$digest=Get-WinSecSnapshotCatalogHash $catalog;$specs=@(Get-WinSecDefenderTechnicalFields)
    $definitionsById=@{};foreach($definition in $specs){$definitionsById[$definition.Id]=$definition}
    $platform=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    $inventories=New-Object 'Collections.Generic.List[object]';$batches=New-Object 'Collections.Generic.List[object]'
    $counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0}
    $stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$payload=0;$limit=Get-WinSecDefenderTechnicalPayloadBudget
    foreach($area in @('Platform','Status','Preferences','ExclusionCounts','ASR')){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $source=$inputs[$(if($area -cin @('ASR','ExclusionCounts')){'Preferences'}else{$area})]
        $definitions=@($specs|Where-Object Inventory -CEQ $area);$records=@();$sequence=1;$retained=0;$reported=$null;$complete=$true;$reason='NONE';$inventoryState='OBSERVED'
        $ids=$null;$actions=$null;$rowCount=1
        if($area -ceq 'ASR'){
            if($source.State -cne 'OBSERVED'){$rowCount=0;$complete=$false;$inventoryState=$source.State;$reason=if($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}}
            else{
                $ids=Get-WinSecDefenderCapturedProperty $source.Data AttackSurfaceReductionRules_Ids
                $actions=Get-WinSecDefenderCapturedProperty $source.Data AttackSurfaceReductionRules_Actions
                if(-not $ids.Exists -or -not $actions.Exists -or -not $ids.Safe -or -not $actions.Safe -or
                    ($null -ne $ids.Value -and ($ids.Value -isnot [array] -or $ids.Value.Rank -ne 1)) -or
                    ($null -ne $actions.Value -and ($actions.Value -isnot [array] -or $actions.Value.Rank -ne 1))){
                    $rowCount=0;$complete=$false;$inventoryState='UNKNOWN';$reason='INVALID_VALUE'
                }elseif($null -eq $ids.Value -and $null -eq $actions.Value){
                    $rowCount=0;$complete=$false;$inventoryState='UNKNOWN';$reason='PROVIDER_UNAVAILABLE'
                }else{
                    $idCount=if($null -eq $ids.Value){0}else{$ids.Value.Length};$actionCount=if($null -eq $actions.Value){0}else{$actions.Value.Length}
                    $rowCount=[Math]::Max($idCount,$actionCount);$reported=$rowCount
                    if($idCount -ne $actionCount){$complete=$false;$reason='INVALID_VALUE'}
                    if($null -eq $ids.Value -or $null -eq $actions.Value){
                        $complete=$false;$reason='PROVIDER_UNAVAILABLE'
                        if($rowCount -eq 0){$reported=$null;$inventoryState='UNKNOWN'}
                    }
                }
            }
        }elseif($source.State -ceq 'OBSERVED'){$reported=1}else{$complete=$false;$reason=if($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}}
        $seenRules=@{}
        for($index=0;$index -lt $rowCount;$index++){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $readings=@()
            foreach($definition in $definitions){
                $state='UNKNOWN';$why='PROVIDER_UNAVAILABLE';$value=$null
                if($source.State -ceq 'ERROR'){$state='ERROR'}elseif($source.State -ceq 'NOT_COLLECTED'){$state='NOT_COLLECTED';$why='NOT_REQUESTED'}
                elseif($area -ceq 'Status' -and $null -ne $statusReadings){
                    $captured=$statusReadings[$definition.Id];$state=$captured.State;$why=$captured.Reason;$value=$captured.Value
                }else{
                    $property=if($area -ceq 'ASR'){
                        $array=if($definition.Property -ceq 'RuleId'){,$ids.Value}else{,$actions.Value}
                        if($null -ne $array -and $index -lt $array.Length){[pscustomobject]@{Exists=$true;Safe=$true;Value=$array[$index]}}else{[pscustomobject]@{Exists=$false;Safe=$true;Value=$null}}
                    }else{Get-WinSecDefenderCapturedProperty $source.Data $definition.Property}
                    if(-not $property.Safe){$why='INVALID_VALUE'}elseif($property.Exists -and $null -ne $property.Value){
                        $normalized=ConvertTo-WinSecDefenderTechnicalValue $property.Value $definition.Kind -CancellationAction $CancellationAction -Clock $clock
                        if($normalized.Valid){$state='OBSERVED';$why='NONE';$value=$normalized.Value}else{$why='INVALID_VALUE'}
                    }
                }
                $readings+=[pscustomobject]@{FieldId=$definition.Id;State=$state;Reason=$why;Value=$value}
                if($area -ceq 'Platform' -and $state -ceq 'OBSERVED'){$platform.($definition.Property)=$value}
            }
            if($area -ceq 'ASR'){
                if(@($readings|Where-Object State -CNE OBSERVED).Count){$complete=$false;$reason='INVALID_VALUE'}
                if($readings[0].State -ceq 'OBSERVED'){
                    $ruleId=$readings[0].Value
                    if($seenRules.ContainsKey($ruleId)){$complete=$false;$reason='INVALID_VALUE'}else{$seenRules[$ruleId]=$true}
                }
            }
            $record=[pscustomobject]@{Id=($area+$index);Readings=$readings}
            $size=512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $record -Depth 8 -Compress))
            if($area -ceq 'ASR' -and ($payload+$size) -gt $limit){$complete=$false;$reason='RESOURCE_LIMIT';break}
            $payload+=$size;$records+=,$record;$retained++;$counts.RetainedRecords++
            foreach($reading in $readings){$counts[$stateCount[$reading.State]]++}
            if($records.Count -eq 128 -or $index -eq ($rowCount-1)){
                $batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$area;Sequence=$sequence;Records=$records});$sequence++;$records=@()
            }
            if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{InventoryId=$area;RetainedRecords=$retained;ReportedRecords=$reported})}
        }
        if($records.Count){$batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$area;Sequence=$sequence;Records=$records})}
        $inventories.Add([pscustomobject]@{Id=$area;State=$inventoryState;Complete=$complete;ReportedRecords=$reported;RetainedRecords=$retained;Reason=$reason})
    }
    if(($null -ne $platform.BuildNumber -and $platform.BuildNumber -lt 22000) -or ($null -ne $platform.ProductType -and $platform.ProductType -ne 1)) {throw 'Defender candidate supports observed Windows 11 clients only.'}
    if($null -ne $platform.Version -and ($null -eq $platform.BuildNumber -or $platform.Version -cne ('10.0.'+$platform.BuildNumber))){throw 'Contradictory observed Windows platform.'}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($inventories|Where-Object {-not $_.Complete}).Count -eq 0)
    foreach($batch in $batches){foreach($record in $batch.Records){foreach($reading in $record.Readings){
        $definition=$definitionsById[$reading.FieldId]
        if($definition.Required -and $reading.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){$complete=$false}
    }}}
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]}
    $snapshot=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$owner;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$digest;CollectorVersion='1.2.0';
        StartedAtUTC=$StartedAtUTC;CollectedAtUTC=$collected.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);CompletedAtUTC=$CompletedAtUTC;GeneratedAtUTC=$GeneratedAtUTC;
        Platform=$platform;SelectedProfile=$SelectedProfile;Collection=[pscustomobject]$collection;Inventories=$inventories.ToArray();Batches=$batches.ToArray()}
    Assert-WinSecDefenderTechnicalSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$digest;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecDefenderTechnicalSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    $catalog=Get-WinSecDefenderTechnicalCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    if($ExpectedIdentity.CheckId -cne 'WSA-SYS-001'){throw 'Foreign Defender candidate identity.'}
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -isnot [string] -or $Snapshot.CollectorVersion -cnotin @('1.0.0','1.1.0','1.2.0')){throw 'Unreviewed Defender candidate collector version.'}
    $definitionsById=@{};foreach($definition in Get-WinSecDefenderTechnicalFields){$definitionsById[$definition.Id]=$definition};$observed=@{}
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $asrProblem=$false;$ruleIds=@{}
    foreach($batch in $Snapshot.Batches){foreach($record in $batch.Records){foreach($reading in $record.Readings){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($batch.InventoryId -ceq 'ASR'){
            if($reading.State -cne 'OBSERVED'){$asrProblem=$true}
            elseif($reading.FieldId -ceq 'ASR.RuleId'){
                if($ruleIds.ContainsKey($reading.Value)){$asrProblem=$true}else{$ruleIds[$reading.Value]=$true}
            }
        }
        if($reading.State -cne 'OBSERVED'){continue};$definition=$definitionsById[$reading.FieldId]
        if($definition.Kind -ceq 'Count'){$observed[$reading.FieldId]=$reading.Value;continue}
        $value=ConvertTo-WinSecDefenderTechnicalValue $reading.Value $definition.Kind -CancellationAction $CancellationAction -Clock $clock
        if(-not $value.Valid -or $value.Value -cne $reading.Value){throw 'Unreviewed Defender technical value.'}
        $observed[$reading.FieldId]=$reading.Value
    }}}
    $asr=@($Snapshot.Inventories|Where-Object Id -CEQ ASR)[0]
    if($asr.Complete -and ($asrProblem -or $null -eq $asr.ReportedRecords)){throw 'Unverified ASR inventory completion.'}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){
        $key='Platform.'+$name;$value=if($observed.ContainsKey($key)){$observed[$key]}else{$null}
        if($Snapshot.Platform.$name -cne $value){throw 'Defender platform differs from observed readings.'}
    }
    if($null -ne $Snapshot.Platform.OSRelease -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.UBR){throw 'Uncollected platform metadata cannot be inferred.'}
}
