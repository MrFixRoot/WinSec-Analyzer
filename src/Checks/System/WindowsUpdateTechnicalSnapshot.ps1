# Prepared-data candidate only. No WUA session, registry access or Windows queries.
. (Join-Path $PSScriptRoot 'WindowsUpdateTechnicalCatalog.ps1')

function Get-WinSecWindowsUpdateCapturedProperty {
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
    $p=@($Data.PSObject.Properties|Where-Object {[string]::Equals($_.Name,$Name,[StringComparison]::OrdinalIgnoreCase)})
    if(-not $p.Count){return $missing}
    if($p.Count -ne 1 -or $p[0].MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){return [pscustomobject]@{Exists=$true;Safe=$false;Value=$null}}
    [pscustomobject]@{Exists=$true;Safe=$true;Value=$p[0].Value}
}

function ConvertTo-WinSecWindowsUpdateTechnicalValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    $invalid=[pscustomobject]@{Valid=$false;Value=$null};if($null -eq $Value){return $invalid}
    switch -CaseSensitive ($Kind){
        Boolean {if($Value -is [bool]){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        {$_ -cin @('UInt32','Build')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if(-not [uint32]::TryParse($Value,[ref]$n)){return $invalid};$Value=$n}
            if($Value.GetType().IsEnum){try{$Value=[long]$Value}catch{return $invalid}}
            if(Test-WinSecSnapshotUInt $Value){return [pscustomobject]@{Valid=$true;Value=[uint32]$Value}}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        ServiceName {if($Value -is [string]){foreach($name in Get-WinSecWindowsUpdateTechnicalServices){if([string]::Equals($Value,$name,[StringComparison]::OrdinalIgnoreCase)){return [pscustomobject]@{Valid=$true;Value=$name}}}}}
        ServiceState {if($Value -is [string] -and $Value -cin @('Stopped','Start Pending','Stop Pending','Running','Continue Pending','Pause Pending','Paused','Unknown')){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        StartMode {if($Value -is [string] -and $Value -cin @('Boot','System','Auto','Manual','Disabled')){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        HotFix {if($Value -is [string] -and $Value -imatch '\AKB[0-9]{4,10}\z'){return [pscustomobject]@{Valid=$true;Value=$Value.ToUpperInvariant()}}}
        DateText {if($Value -is [string] -and $Value -cmatch '\A(?:[0-9A-Fa-f]{16}|[0-9]{1,4}(?:[./-][0-9]{1,4}){2}(?: [0-9]{1,2}:[0-9]{2}(?::[0-9]{2})?)?)\z'){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        QfeStatus {if($Value -is [string] -and $Value -cin @('OK','Error','Degraded','Unknown','Pred Fail','Starting','Stopping','Service','Stressed','NonRecover','No Contact','Lost Comm')){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        Utc {
            if($Value -is [datetimeoffset]){return [pscustomobject]@{Valid=$true;Value=$Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}}
            if($Value -is [datetime] -and $Value.Kind -ne [DateTimeKind]::Unspecified){return [pscustomobject]@{Valid=$true;Value=$Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}}
            try{$date=ConvertTo-WinSecSnapshotUtc $Value;return [pscustomobject]@{Valid=$true;Value=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}}catch{}
        }
        CaptureTime {try{$date=ConvertTo-WinSecSnapshotUtc $Value;return [pscustomobject]@{Valid=$true;Value=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}}catch{}}
        SourceState {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED')){return [pscustomobject]@{Valid=$true;Value=$Value}}}
        Scope {if($Value -is [string] -and $Value -ceq 'CBS_QFE_ONLY'){return [pscustomobject]@{Valid=$true;Value=$Value}}}
    }
    return $invalid
}

function ConvertFrom-WinSecWindowsUpdateCapturedRegistry {
    param([object]$Property,[object]$Definition,[switch]$Policy)
    $reading=[pscustomobject]@{FieldId=$Definition.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
    if(-not $Property.Safe){$reading.Reason='INVALID_VALUE';return $reading}
    if(-not $Property.Exists -or $null -eq $Property.Value){return $reading}
    $entry=$Property.Value;Assert-WinSecSnapshotFields $entry @('State','Kind','Value')
    if($entry.State -isnot [string] -or $entry.State -cnotin @('OBSERVED','NOT_CONFIGURED','UNKNOWN','ERROR','NOT_COLLECTED')){throw 'Invalid captured registry state.'}
    if($entry.State -ceq 'OBSERVED'){
        $kind=if($Definition.Kind -ceq 'Build'){'String'}else{'DWord'}
        if($entry.Kind -isnot [string] -or $entry.Kind -cne $kind){$reading.Reason='INVALID_VALUE';return $reading}
        $raw=$entry.Value
        # Only tagged policy REG_DWORD values may arrive as signed Int32 bit patterns.
        if($Policy -and $raw -is [int] -and $raw -lt 0){$raw=[uint32]([long]$raw -band 4294967295L)}
        $value=ConvertTo-WinSecWindowsUpdateTechnicalValue $raw $Definition.Kind
        if($value.Valid){$reading.State='OBSERVED';$reading.Reason='NONE';$reading.Value=$value.Value}else{$reading.Reason='INVALID_VALUE'}
    }else{
        if($null -ne $entry.Value -or $null -ne $entry.Kind -or ($entry.State -ceq 'NOT_CONFIGURED' -and -not $Policy)){throw 'Unverified captured registry absence.'}
        $reading.State=$entry.State;$reading.Reason=switch($entry.State){NOT_CONFIGURED {'ABSENT'};NOT_COLLECTED {'NOT_REQUESTED'};default {'PROVIDER_UNAVAILABLE'}}
    }
    return $reading
}

function Get-WinSecWindowsUpdateTechnicalPayloadBudget {
    return ((Get-WinSecSnapshotSpecification).MaxDocumentBytes-131072)
}

function New-WinSecWindowsUpdateTechnicalSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('o')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity
    if($Identity.CheckId -cne 'WSA-SYS-003'){throw 'Windows Update candidate cannot process another control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid Windows Update capture operation.'}
    $areas=@(Get-WinSecWindowsUpdateTechnicalAreas);$inputs=@{};$collected=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'Windows Update requires the exact reviewed source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','State','Data')
        if($source.SourceId -isnot [string] -or $source.SourceId -cnotin $areas.Id -or $inputs.ContainsKey($source.SourceId) -or
            $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign or invalid Windows Update capture.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC
        if($time -lt $start -or $time -gt $end){throw 'Windows Update capture lies outside its operation.'}
        if($time -gt $collected){$collected=$time}
        $area=@($areas|Where-Object Id -CEQ $source.SourceId)[0]
        if($source.State -ceq 'OBSERVED'){
            if($area.List){if($source.Data -isnot [array] -or $source.Data.Rank -ne 1){throw 'Captured inventory requires an explicit array.'}}
            elseif($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Captured singleton requires plain data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable Windows Update source contains raw data.'}
        $inputs[$source.SourceId]=$source
    }
    $capture=[ordered]@{InstalledInventoryScope='CBS_QFE_ONLY'}
    foreach($area in $areas){$capture[$area.Id+'AtUTC']=$inputs[$area.Id].CollectedAtUTC;$capture[$area.Id+'State']=$inputs[$area.Id].State}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture}
    $catalog=Get-WinSecWindowsUpdateTechnicalCatalog;$digest=Get-WinSecSnapshotCatalogHash $catalog;$specs=@(Get-WinSecWindowsUpdateTechnicalFields)
    $definitions=@{};foreach($definition in $specs){$definitions[$definition.Id]=$definition}
    $platform=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    $inventories=@();$batches=New-Object 'Collections.Generic.List[object]';$payload=0;$limit=Get-WinSecWindowsUpdateTechnicalPayloadBudget
    $counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0}
    $stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected';NOT_CONFIGURED='NotConfigured'};$complete=$true
    foreach($inventory in $catalog.Inventories){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $source=$inputs[$inventory.Id];$rowCount=1;$reported=$null;$ok=($source.State -ceq 'OBSERVED');$reason='NONE';$state='OBSERVED'
        if(-not $ok){$reason=if($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}}
        if(-not $inventory.Singleton){
            if($ok){$rowCount=$source.Data.Length;$reported=$rowCount}else{$rowCount=0;$state=$source.State}
        }elseif($ok){$reported=1}
        $rows=@();$sequence=1;$retained=0;$services=@{}
        for($index=0;$index -lt $rowCount;$index++){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $data=if($inventory.Singleton){$source.Data}else{$source.Data[$index]}
            if(-not $inventory.Singleton){
                if($null -eq $data -or $data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Unreviewed captured inventory row.'}
                if($inventory.Id -ceq 'Services'){
                    $property=Get-WinSecWindowsUpdateCapturedProperty $data Name;$name=ConvertTo-WinSecWindowsUpdateTechnicalValue $property.Value ServiceName
                    if(-not $property.Safe -or -not $name.Valid -or $services.ContainsKey($name.Value)){throw 'Foreign or duplicate Windows Update service.'};$services[$name.Value]=$true
                }
            }
            $readings=@()
            foreach($definition in $specs|Where-Object Inventory -CEQ $inventory.Id){
                $reading=[pscustomobject]@{FieldId=$definition.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
                if($source.State -cne 'OBSERVED'){$reading.State=$source.State;$reading.Reason=$reason}
                else{
                    $property=Get-WinSecWindowsUpdateCapturedProperty $data $definition.Property
                    if($inventory.Id -cin @('Revision','GPOAU','GPOUpdate')){$reading=ConvertFrom-WinSecWindowsUpdateCapturedRegistry $property $definition -Policy:($inventory.Id -cne 'Revision')}
                    elseif(-not $property.Safe){$reading.Reason='INVALID_VALUE'}elseif($property.Exists -and $null -ne $property.Value){
                        $value=ConvertTo-WinSecWindowsUpdateTechnicalValue $property.Value $definition.Kind
                        if($value.Valid){$reading.State='OBSERVED';$reading.Reason='NONE';$reading.Value=$value.Value}else{$reading.Reason='INVALID_VALUE'}
                    }
                }
                $readings+=,$reading
            }
            $record=[pscustomobject]@{Id=($inventory.Id+$index);Readings=$readings}
            $size=512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $record -Depth 8 -Compress))
            if($inventory.Id -ceq 'InstalledCBSUpdates' -and ($payload+$size) -gt $limit){$ok=$false;$reason='RESOURCE_LIMIT';break}
            $payload+=$size;$rows+=,$record;$retained++;$counts.RetainedRecords++
            foreach($reading in $readings){$counts[$stateCount[$reading.State]]++;if($definitions[$reading.FieldId].Required -and $reading.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){$complete=$false}}
            if($rows.Count -eq 128 -or $index -eq ($rowCount-1)){
                $batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$inventory.Id;Sequence=$sequence;Records=$rows});$sequence++;$rows=@()
            }
            if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{InventoryId=$inventory.Id;RetainedRecords=$retained;ReportedRecords=$reported})}
        }
        if($rows.Count){$batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$inventory.Id;Sequence=$sequence;Records=$rows})}
        if($inventory.Id -ceq 'Services' -and $ok -and $services.Count -ne @(Get-WinSecWindowsUpdateTechnicalServices).Count){$ok=$false;$reason='PROVIDER_UNAVAILABLE'}
        if(-not $ok){$complete=$false}
        $inventories+=,[pscustomobject]@{Id=$inventory.Id;State=$state;Complete=$ok;ReportedRecords=$reported;RetainedRecords=$retained;Reason=$reason}
    }
    foreach($batch in $batches|Where-Object InventoryId -CEQ Platform){foreach($reading in $batch.Records[0].Readings){if($reading.State -ceq 'OBSERVED'){$platform.($reading.FieldId.Substring(9))=$reading.Value}}}
    $revision=@($batches|Where-Object InventoryId -CEQ Revision)[0].Records[0].Readings
    $revBuild=@($revision|Where-Object FieldId -CEQ Revision.CurrentBuildNumber)[0];$ubr=@($revision|Where-Object FieldId -CEQ Revision.UBR)[0]
    if($revBuild.State -ceq 'OBSERVED' -and $null -ne $platform.BuildNumber -and $revBuild.Value -ne $platform.BuildNumber){throw 'Captured Windows builds disagree.'}
    if($ubr.State -ceq 'OBSERVED' -and $revBuild.State -ceq 'OBSERVED' -and $null -ne $platform.BuildNumber){$platform.UBR=$ubr.Value}
    $complete=($complete -and $null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1)
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]}
    $snapshot=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$owner;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$digest;CollectorVersion='1.0.0';
        StartedAtUTC=$StartedAtUTC;CollectedAtUTC=$collected.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);CompletedAtUTC=$CompletedAtUTC;GeneratedAtUTC=$GeneratedAtUTC;
        Platform=$platform;SelectedProfile=$SelectedProfile;Collection=[pscustomobject]$collection;Inventories=$inventories;Batches=$batches.ToArray()}
    Assert-WinSecWindowsUpdateTechnicalSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$digest;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecWindowsUpdateTechnicalSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    if($ExpectedIdentity.CheckId -cne 'WSA-SYS-003'){throw 'Foreign Windows Update identity.'}
    $catalog=Get-WinSecWindowsUpdateTechnicalCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed Windows Update candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$defs=@{};foreach($d in Get-WinSecWindowsUpdateTechnicalFields){$defs[$d.Id]=$d}
    $fixed=@{};$services=@{};$summaries=@{};foreach($i in $Snapshot.Inventories){$summaries[$i.Id]=$i}
    foreach($batch in $Snapshot.Batches){foreach($record in $batch.Records){foreach($reading in $record.Readings){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($batch.InventoryId -cnotin @('Services','InstalledCBSUpdates')){$fixed[$reading.FieldId]=$reading}
        if($reading.State -ceq 'NOT_CONFIGURED' -and $batch.InventoryId -cnotin @('GPOAU','GPOUpdate')){throw 'Unverified Windows Update policy absence.'}
        if($reading.State -ceq 'OBSERVED'){
            $value=ConvertTo-WinSecWindowsUpdateTechnicalValue $reading.Value $defs[$reading.FieldId].Kind
            if(-not $value.Valid -or $value.Value -cne $reading.Value){throw 'Unreviewed Windows Update technical value.'}
            if($reading.FieldId -ceq 'Services.Name'){if($services.ContainsKey($reading.Value)){throw 'Duplicate saved Windows Update service.'};$services[$reading.Value]=$true}
        }
    }}}
    foreach($batch in $Snapshot.Batches|Where-Object InventoryId -CEQ Services){foreach($record in $batch.Records){
        if(@($record.Readings|Where-Object { $_.FieldId -ceq 'Services.Name' -and $_.State -ceq 'OBSERVED'}).Count -ne 1){throw 'Unidentified saved Windows Update service.'}
    }}
    if($summaries.Services.Complete -and $services.Count -ne @(Get-WinSecWindowsUpdateTechnicalServices).Count){throw 'False Windows Update service inventory completion.'}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){
        $r=$fixed['Platform.'+$name];$observed=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null}
        if($Snapshot.Platform.$name -cne $observed){throw 'Windows Update platform contradicts its readings.'}
    }
    $build=$fixed['Revision.CurrentBuildNumber'];$ubr=$fixed['Revision.UBR'];$expectedUbr=$null
    if($build.State -ceq 'OBSERVED' -and $null -ne $Snapshot.Platform.BuildNumber){
        if($build.Value -ne $Snapshot.Platform.BuildNumber){throw 'Saved Windows Update builds disagree.'}
        if($ubr.State -ceq 'OBSERVED'){$expectedUbr=$ubr.Value}
    }
    if($Snapshot.Platform.UBR -cne $expectedUbr -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.OSRelease){throw 'Unobserved Windows Update platform metadata.'}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($area in Get-WinSecWindowsUpdateTechnicalAreas){
        $time=$fixed['Capture.'+$area.Id+'AtUTC'];$state=$fixed['Capture.'+$area.Id+'State']
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED'){throw 'Missing Windows Update capture metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value
        if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'Foreign Windows Update capture timestamp.'}
        if($stamp -gt $latest){$latest=$stamp}
        $summary=$summaries[$area.Id]
        if($state.Value -ceq 'OBSERVED'){
            if($summary.State -cne 'OBSERVED' -or $null -eq $summary.ReportedRecords -or (-not $area.List -and -not $summary.Complete)){throw 'Captured Windows Update source contradicts its summary.'}
        }elseif($area.List -and ($summary.State -cne $state.Value -or $null -ne $summary.ReportedRecords -or $summary.RetainedRecords -ne 0)){
            throw 'Unavailable Windows Update inventory claims observations.'
        }
        if($state.Value -cne 'OBSERVED'){
            if($summaries[$area.Id].Complete){throw 'Unavailable Windows Update source claims completion.'}
            foreach($batch in $Snapshot.Batches|Where-Object InventoryId -CEQ $area.Id){foreach($record in $batch.Records){foreach($r in $record.Readings){if($r.State -cne $state.Value){throw 'Unavailable Windows Update source supplies inconsistent readings.'}}}}
        }
    }
    if($fixed['Capture.InstalledInventoryScope'].State -cne 'OBSERVED' -or $fixed['Capture.InstalledInventoryScope'].Value -cne 'CBS_QFE_ONLY' -or
        $latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC)){throw 'Invalid Windows Update collection scope or date.'}
}
