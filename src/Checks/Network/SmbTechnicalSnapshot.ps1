# Prepared local captures only. This module never calls SMB, CIM or Registry providers.
. (Join-Path $PSScriptRoot 'SmbTechnicalCatalog.ps1')

function Get-WinSecSmbCapturedProperty {
    param([AllowNull()][object]$Data,[string]$Name)
    $missing=[pscustomobject]@{Safe=$true;Exists=$false;Value=$null}
    if($null -eq $Data){return $missing}
    if($Data.GetType() -eq [Management.Automation.PSCustomObject]){
        $p=@($Data.PSObject.Properties|Where-Object {[string]::Equals($_.Name,$Name,[StringComparison]::OrdinalIgnoreCase)})
        if(-not $p.Count){return $missing}
        if($p.Count -ne 1 -or $p[0].MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){return [pscustomobject]@{Safe=$false;Exists=$true;Value=$null}}
        return [pscustomobject]@{Safe=$true;Exists=$true;Value=$p[0].Value}
    }
    if($Data.GetType() -in @([hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){
        $keys=@(foreach($key in $Data.Keys){if($key -is [string] -and [string]::Equals($key,$Name,[StringComparison]::OrdinalIgnoreCase)){$key}})
        if(-not $keys.Count){return $missing};if($keys.Count -ne 1){return [pscustomobject]@{Safe=$false;Exists=$true;Value=$null}}
        return [pscustomobject]@{Safe=$true;Exists=$true;Value=$Data[$keys[0]]}
    }
    [pscustomobject]@{Safe=$false;Exists=$true;Value=$null}
}

function ConvertTo-WinSecSmbCandidateValue {
    param([AllowNull()][object]$Value,[string]$Kind,[scriptblock]$CancellationAction,
        [Diagnostics.Stopwatch]$Clock=([Diagnostics.Stopwatch]::StartNew()))
    $bad=[pscustomobject]@{Valid=$false;Resource=$false;Value=$null};if($null -eq $Value){return $bad}
    $valid=$false;$converted=$null
    switch -CaseSensitive ($Kind){
        Boolean {if($Value -is [bool]){$valid=$true;$converted=$Value}}
        {$_ -cin @('UInt32','Build','RegistryDWord')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if(-not [uint32]::TryParse($Value,[ref]$n)){return $bad};$Value=$n}
            if($Kind -ceq 'RegistryDWord' -and $Value -is [int] -and $Value -lt 0){$Value=[uint32]([long]$Value -band 4294967295L)}
            if(Test-WinSecSnapshotUInt $Value){$valid=$true;$converted=[uint32]$Value}
        }
        UInt64Text {
            if($Value -is [string] -and $Value -cmatch '\A(?:0|[1-9][0-9]{0,19})\z'){$n=[uint64]0;if([uint64]::TryParse($Value,[ref]$n)){$valid=$true;$converted=$n.ToString([Globalization.CultureInfo]::InvariantCulture)}}
            elseif($Value.GetType() -in @([byte],[int16],[uint16],[int],[uint32],[long],[uint64]) -and $Value -ge 0){$valid=$true;$converted=([uint64]$Value).ToString([Globalization.CultureInfo]::InvariantCulture)}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){$valid=$true;$converted=$Value}}
        Ciphers {
            if($Value -is [string] -and $Value.Length -le (Get-WinSecSnapshotSpecification).MaxTextChars -and
                $Value -cmatch '\A(?:AES_128_GCM|AES_128_CCM|AES_256_GCM|AES_256_CCM)(?: *, *(?:AES_128_GCM|AES_128_CCM|AES_256_GCM|AES_256_CCM))*\z'){$valid=$true;$converted=$Value}
        }
        Dialect {
            if($Value.GetType().IsEnum){try{$Value=[uint32]$Value}catch{return $bad}}
            if(Test-WinSecSnapshotUInt $Value){$valid=$true;$converted=([uint32]$Value).ToString([Globalization.CultureInfo]::InvariantCulture)}
            elseif($Value -is [string] -and $Value -cin @('None','SMB202','SMB210','SMB300','SMB302','SMB311')){$valid=$true;$converted=$Value}
            elseif($Value -is [string] -and $Value -cmatch '\A(?:0|[1-9][0-9]{0,9})\z'){$n=[uint32]0;if([uint32]::TryParse($Value,[ref]$n)){$valid=$true;$converted=$Value}}
        }
        FeatureName {if($Value -is [string] -and $Value -cin @('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server','SMB1Protocol-Deprecation')){$valid=$true;$converted=$Value}}
        ServiceName {if($Value -is [string]){foreach($name in @('LanmanServer','LanmanWorkstation')){if([string]::Equals($Value,$name,[StringComparison]::OrdinalIgnoreCase)){$valid=$true;$converted=$name;break}}}}
        Installation {if($Value -is [string] -and $Value -cin @('ENABLED','DISABLED','ABSENT','UNKNOWN')){$valid=$true;$converted=$Value}}
        ServiceState {if($Value -is [string] -and $Value -cin @('Stopped','Start Pending','Stop Pending','Running','Continue Pending','Pause Pending','Paused','Unknown')){$valid=$true;$converted=$Value}}
        StartMode {if($Value -is [string] -and $Value -cin @('Boot','System','Auto','Manual','Disabled')){$valid=$true;$converted=$Value}}
        ErrorControl {if($Value -is [string] -and $Value -cin @('Ignore','Normal','Severe','Critical','Unknown')){$valid=$true;$converted=$Value}}
        Status {if($Value -is [string] -and $Value -cin @('OK','Error','Degraded','Unknown','Pred Fail','Starting','Stopping','Service','Stressed','NonRecover','No Contact','Lost Comm')){$valid=$true;$converted=$Value}}
        Utc {
            if($Value -is [datetimeoffset]){$valid=$true;$converted=$Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}
            elseif($Value -is [datetime] -and $Value.Kind -eq [DateTimeKind]::Utc){$valid=$true;$converted=$Value.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}
            elseif($Value -is [string]){try{$date=ConvertTo-WinSecSnapshotUtc $Value;$valid=$true;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}catch{}}
        }
        DependencyCount {if($Value -is [array] -and $Value.Rank -eq 1){$valid=$true;$converted=[uint32]$Value.Length}}
        Dependencies {
            if($Value -isnot [array] -or $Value.Rank -ne 1){return $bad}
            $bytes=0;$limit=(Get-WinSecSnapshotSpecification).MaxBatchBytes/4;$items=New-Object 'Collections.Generic.List[string]'
            for($i=0;$i -lt $Value.Length;$i++){
                if(($i % 128) -eq 0){Assert-WinSecSnapshotValidationBudget $Clock $CancellationAction}
                $v=$Value[$i];if($v -isnot [string] -or $v -cnotmatch '\A[A-Za-z0-9_][A-Za-z0-9_. -]{0,255}\z'){return $bad}
                $bytes+=([Text.Encoding]::UTF8.GetByteCount($v)+4);if($bytes -gt $limit){return [pscustomobject]@{Valid=$false;Resource=$true;Value=$null}}
                $items.Add($v)
            };$valid=$true;$converted=$items.ToArray()
        }
        Time {try{$date=ConvertTo-WinSecSnapshotUtc $Value;$valid=$true;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}catch{}}
        SourceState {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED')){$valid=$true;$converted=$Value}}
        Location {if($Value -is [string] -and $Value -cin @('LOCAL','HKLM_REGISTRY64')){$valid=$true;$converted=$Value}}
        Scope {if($Value -is [string] -and $Value -ceq 'LOCAL_CONFIGURATION_NO_NEGOTIATED_SESSIONS'){$valid=$true;$converted=$Value}}
    }
    [pscustomobject]@{Valid=$valid;Resource=$false;Value=$converted}
}

function Get-WinSecSmbInstallationState {
    param([object]$Reading)
    if($Reading.State -ceq 'OBSERVED'){switch($Reading.Value){1 {return 'ENABLED'};2 {return 'DISABLED'};3 {return 'ABSENT'}}}
    return 'UNKNOWN'
}

function Get-WinSecSmbCandidateIntegrity {
    param([object]$Snapshot,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$capture=@{};$summaries=@{};$rows=@{};$result=@{}
    foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($b.InventoryId -ceq 'Capture'){foreach($r in $record.Readings){$capture[$r.FieldId]=$r};continue}
        if($b.InventoryId -cin @('Features','Services')){if(-not $rows.ContainsKey($b.InventoryId)){$rows[$b.InventoryId]=New-Object 'Collections.Generic.List[object]'};$rows[$b.InventoryId].Add($record)}
    }}
    foreach($a in Get-WinSecSmbCandidateAreas){
        $s=$summaries[$a.Id];$state=$capture['Capture.'+$a.Id+'SourceState'].Value
        $ok=($state -ceq 'OBSERVED' -and $null -ne $s.ReportedRecords -and $s.ReportedRecords -eq $s.RetainedRecords)
        $reason=if($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}elseif($state -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}elseif(-not $ok){'RESOURCE_LIMIT'}else{'NONE'}
        if($ok -and $a.Id -cin @('Features','Services')){
            $seen=@{};$invalid=$false;$unknown=$false
            if($rows.ContainsKey($a.Id)){foreach($record in $rows[$a.Id]){
                $local=@{};foreach($r in $record.Readings){$local[$r.FieldId]=$r}
                $name=$local[$a.Id+'.Name'];if($name.State -cne 'OBSERVED'){$invalid=$true;continue}
                if($seen.ContainsKey($name.Value)){$invalid=$true}else{$seen[$name.Value]=$true}
                if($a.Id -ceq 'Features' -and (Get-WinSecSmbInstallationState $local['Features.InstallState']) -ceq 'UNKNOWN'){$unknown=$true}
            }}
            $expected=if($a.Id -ceq 'Features'){4}else{2}
            if($invalid){$ok=$false;$reason='INVALID_VALUE'}elseif($seen.Count -ne $expected -or $unknown){$ok=$false;$reason='PROVIDER_UNAVAILABLE'}
        }
        $result[$a.Id]=[pscustomobject]@{Complete=$ok;Reason=$reason}
    };return $result
}

function Get-WinSecSmbCandidatePayloadBudget {return ((Get-WinSecSnapshotSpecification).MaxDocumentBytes-131072)}

function New-WinSecSmbCandidateSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('o')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity;if($Identity.CheckId -cne 'WSA-NET-002'){throw 'Foreign SMB candidate control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid SMB capture operation.'}
    $areas=@(Get-WinSecSmbCandidateAreas);$inputs=@{};$latest=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'SMB candidate requires the exact source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','Location','State','Data')
        if($source.SourceId -isnot [string]){throw 'Invalid SMB source identifier.'};$a=@($areas|Where-Object Id -CEQ $source.SourceId)
        if($a.Count -ne 1 -or $inputs.ContainsKey($source.SourceId) -or $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or
            $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or $source.Location -isnot [string] -or $source.Location -cne $a[0].Location -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign SMB source, identity or location.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;if($time -lt $start -or $time -gt $end){throw 'SMB source outside its operation.'};if($time -gt $latest){$latest=$time}
        if($source.State -ceq 'OBSERVED'){
            if($source.SourceId -cin @('Features','Services')){if($source.Data -isnot [array] -or $source.Data.Rank -ne 1){throw 'SMB inventory requires an explicit array.'}}
            elseif($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'SMB singleton requires ordinary captured data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable SMB source contains data.'};$inputs[$source.SourceId]=$source
    }
    $capture=[ordered]@{Scope='LOCAL_CONFIGURATION_NO_NEGOTIATED_SESSIONS'}
    foreach($a in $areas){$s=$inputs[$a.Id];$capture[$a.Id+'Time']=$s.CollectedAtUTC;$capture[$a.Id+'SourceState']=$s.State;$capture[$a.Id+'Location']=$s.Location}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture}
    $catalog=Get-WinSecSmbCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog;$definitions=@(Get-WinSecSmbCandidateFields);$byInventory=@{}
    foreach($i in $catalog.Inventories){$byInventory[$i.Id]=@($definitions|Where-Object Inventory -CEQ $i.Id)}
    $batches=New-Object 'Collections.Generic.List[object]';$summaries=@();$payload=0;$limit=Get-WinSecSmbCandidatePayloadBudget
    $counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0};$stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected';NOT_CONFIGURED='NotConfigured'}
    foreach($inventory in $catalog.Inventories){
        $source=$inputs[$inventory.Id];$total=if($inventory.Singleton){1}elseif($source.State -ceq 'OBSERVED'){$source.Data.Length}else{0}
        $reported=if($source.State -ceq 'OBSERVED'){$total}else{$null};$state=if($inventory.Singleton){'OBSERVED'}else{$source.State}
        $rows=New-Object 'Collections.Generic.List[object]';$bytes=16384;$sequence=1;$retained=0;$ok=($source.State -ceq 'OBSERVED');$reason=if($ok){'NONE'}elseif($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}
        for($index=0;$index -lt $total;$index++){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $data=if($inventory.Singleton){$source.Data}else{$source.Data[$index]}
            if($source.State -ceq 'OBSERVED' -and ($null -eq $data -or $data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]]))){throw 'Unreviewed SMB captured record.'}
            $local=@{};$readings=@(foreach($d in $byInventory[$inventory.Id]){
                $r=[pscustomobject]@{FieldId=$d.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
                if($source.State -cne 'OBSERVED'){$r.State=$source.State;$r.Reason=$reason}
                elseif($d.Kind -ceq 'Installation'){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=Get-WinSecSmbInstallationState $local['Features.InstallState']}
                else{
                    $p=Get-WinSecSmbCapturedProperty $data $d.Property
                    if(-not $p.Safe){$r.Reason='INVALID_VALUE'}elseif($p.Exists -and $null -ne $p.Value){
                        $raw=$p.Value;$available=$true
                        if($inventory.Id -ceq 'Registry'){
                            Assert-WinSecSnapshotFields $raw @('State','Kind','Value')
                            if($raw.State -isnot [string] -or $raw.State -cnotin @('OBSERVED','NOT_CONFIGURED','UNKNOWN','ERROR','NOT_COLLECTED')){throw 'Invalid SMB registry state.'}
                            if($raw.State -ceq 'OBSERVED'){
                                $expected=if($d.Kind -ceq 'RegistryDWord'){'DWord'}else{'MultiString'}
                                if($raw.Kind -isnot [string] -or $raw.Kind -cne $expected){$available=$false;$r.Reason='INVALID_VALUE'}else{$raw=$raw.Value}
                            }else{
                                if($null -ne $raw.Value -or $null -ne $raw.Kind){throw 'Unverified SMB registry absence.'}
                                $r.State=$raw.State;$r.Reason=switch($raw.State){NOT_CONFIGURED {'ABSENT'};NOT_COLLECTED {'NOT_REQUESTED'};default {'PROVIDER_UNAVAILABLE'}};$available=$false
                            }
                        }
                        if($available){$v=ConvertTo-WinSecSmbCandidateValue $raw $d.Kind -CancellationAction $CancellationAction -Clock $clock
                            if($v.Valid){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=$v.Value}elseif($v.Resource){$r.State='NOT_COLLECTED';$r.Reason='RESOURCE_LIMIT'}else{$r.Reason='INVALID_VALUE'}}
                    }
                }
                if($d.Kind -cin @('FeatureName','ServiceName') -and $source.State -ceq 'OBSERVED' -and $r.State -cne 'OBSERVED'){throw 'Foreign or unidentifiable SMB inventory record.'}
                $local[$d.Id]=$r;$r
            })
            $record=[pscustomobject]@{Id=($inventory.Id+$index);Readings=$readings};$size=512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $record -Depth 8 -Compress))
            if(-not $inventory.Singleton -and ($payload+$size) -gt $limit){$ok=$false;$reason='RESOURCE_LIMIT';break}
            if($rows.Count -and ($rows.Count -ge 128 -or ($bytes+$size) -gt (Get-WinSecSnapshotSpecification).MaxBatchBytes)){
                $batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$inventory.Id;Sequence=$sequence;Records=$rows.ToArray()});$rows.Clear();$sequence++;$bytes=16384
            }
            $payload+=$size;$bytes+=$size;$rows.Add($record);$retained++;$counts.RetainedRecords++;foreach($r in $readings){$counts[$stateCount[$r.State]]++}
            if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{InventoryId=$inventory.Id;RetainedRecords=$retained;ReportedRecords=$reported})}
        }
        if($rows.Count){$batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$inventory.Id;Sequence=$sequence;Records=$rows.ToArray()})}
        $summaries+=,[pscustomobject]@{Id=$inventory.Id;State=$state;Complete=$ok;ReportedRecords=$reported;RetainedRecords=$retained;Reason=$reason}
    }
    $platform=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    foreach($r in $batches[0].Records[0].Readings){if($r.State -ceq 'OBSERVED'){$platform.($r.FieldId.Substring(9))=$r.Value}}
    $snapshot=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$owner;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$hash;CollectorVersion='1.0.0';
        StartedAtUTC=$StartedAtUTC;CollectedAtUTC=$latest.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);CompletedAtUTC=$CompletedAtUTC;GeneratedAtUTC=$GeneratedAtUTC;
        Platform=$platform;SelectedProfile=$SelectedProfile;Collection=$null;Inventories=$summaries;Batches=$batches.ToArray()}
    $integrity=Get-WinSecSmbCandidateIntegrity $snapshot -CancellationAction $CancellationAction
    foreach($s in $summaries){if($s.Id -cne 'Capture'){$s.Complete=$integrity[$s.Id].Complete;$s.Reason=$integrity[$s.Id].Reason}}
    $required=@{};foreach($d in $definitions){$required[$d.Id]=$d.Required}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($summaries|Where-Object {-not $_.Complete}).Count -eq 0)
    foreach($batch in $batches){foreach($record in $batch.Records){foreach($r in $record.Readings){if($required[$r.FieldId] -and $r.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){$complete=$false}}}}
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]};$snapshot.Collection=[pscustomobject]$collection
    Assert-WinSecSmbCandidateSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecSmbCandidateSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-NET-002'){throw 'Foreign SMB candidate identity.'}
    $catalog=Get-WinSecSmbCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed SMB candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$definitions=@{};$fixed=@{};$summaries=@{}
    foreach($d in Get-WinSecSmbCandidateFields){$definitions[$d.Id]=$d};foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        $local=@{};foreach($r in $record.Readings){$local[$r.FieldId]=$r;if($b.InventoryId -cin @('Platform','Capture')){$fixed[$r.FieldId]=$r}
            if($r.State -ceq 'NOT_CONFIGURED' -and $b.InventoryId -cne 'Registry'){throw 'Unverified SMB configuration absence outside Registry64.'}
            if($r.State -cne 'OBSERVED' -or $definitions[$r.FieldId].Kind -ceq 'DependencyCount'){continue}
            $v=ConvertTo-WinSecSmbCandidateValue $r.Value $definitions[$r.FieldId].Kind -CancellationAction $CancellationAction -Clock $clock
            if(-not $v.Valid -or (ConvertTo-Json -InputObject $v.Value -Compress) -cne (ConvertTo-Json -InputObject $r.Value -Compress)){throw 'Unreviewed SMB candidate value.'}
        }
        if($b.InventoryId -ceq 'Features'){
            $code=$local['Features.InstallState'];$derived=$local['Features.InstallationState'];$expected=Get-WinSecSmbInstallationState $code
            $sourceObserved=@($record.Readings|Where-Object State -CEQ OBSERVED).Count -gt 0
            if($sourceObserved -and ($derived.State -cne 'OBSERVED' -or $derived.Value -cne $expected)){throw 'SMB feature interpretation differs from its native state.'}
        }
        if($b.InventoryId -ceq 'Registry'){
            $r=$local['Registry.ClientDependencies'];$n=$local['Registry.ClientDependenciesReportedCount']
            if($r.State -ceq 'OBSERVED' -and ($n.State -cne 'OBSERVED' -or $n.Value -ne $r.Value.Length)){throw 'SMB dependency count differs from its list.'}
            if($r.State -ceq 'NOT_COLLECTED' -and $r.Reason -ceq 'RESOURCE_LIMIT' -and $n.State -cne 'OBSERVED'){throw 'Oversized SMB dependencies lack a reported count.'}
            if($r.State -ceq 'NOT_CONFIGURED' -and ($n.State -cne 'NOT_CONFIGURED' -or $n.Reason -cne 'ABSENT')){throw 'SMB dependency absence is contradictory.'}
            if(($r.State -ceq 'ERROR' -or ($r.State -ceq 'NOT_COLLECTED' -and $r.Reason -ceq 'NOT_REQUESTED')) -and
                ($n.State -cne $r.State -or $n.Reason -cne $r.Reason)){throw 'Unavailable SMB dependencies supply an apparent count.'}
            if($r.State -ceq 'UNKNOWN' -and $n.State -cne 'OBSERVED' -and ($n.State -cne 'UNKNOWN' -or $n.Reason -cne $r.Reason)){throw 'Unknown SMB dependency provenance is contradictory.'}
        }
    }}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){$r=$fixed['Platform.'+$name];$v=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null};if($Snapshot.Platform.$name -cne $v){throw 'SMB platform differs from its readings.'}}
    if($null -ne $Snapshot.Platform.UBR -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.OSRelease){throw 'Unobserved SMB platform metadata.'}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($a in Get-WinSecSmbCandidateAreas){
        $time=$fixed['Capture.'+$a.Id+'Time'];$state=$fixed['Capture.'+$a.Id+'SourceState'];$location=$fixed['Capture.'+$a.Id+'Location'];$summary=$summaries[$a.Id]
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED' -or $location.State -cne 'OBSERVED' -or $location.Value -cne $a.Location){throw 'Missing or foreign SMB source metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value;if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'SMB source timestamp outside its operation.'};if($stamp -gt $latest){$latest=$stamp}
        if($state.Value -ceq 'OBSERVED'){if($summary.State -cne 'OBSERVED' -or $null -eq $summary.ReportedRecords){throw 'SMB observed source has no counts.'}}
        else{
            if($null -ne $summary.ReportedRecords -or ($a.Id -cin @('Features','Services') -and ($summary.State -cne $state.Value -or $summary.RetainedRecords -ne 0))){throw 'Unavailable SMB source claims records.'}
            foreach($b in $Snapshot.Batches|Where-Object InventoryId -CEQ $a.Id){foreach($record in $b.Records){foreach($r in $record.Readings){if($r.State -cne $state.Value){throw 'Unavailable SMB source supplies readings.'}}}}
        }
    }
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC) -or $fixed['Capture.Scope'].State -cne 'OBSERVED' -or
        $fixed['Capture.Scope'].Value -cne 'LOCAL_CONFIGURATION_NO_NEGOTIATED_SESSIONS'){throw 'Invalid SMB capture scope or timestamp.'}
    $expected=Get-WinSecSmbCandidateIntegrity $Snapshot -CancellationAction $CancellationAction
    foreach($a in Get-WinSecSmbCandidateAreas){if($summaries[$a.Id].Complete -cne $expected[$a.Id].Complete -or $summaries[$a.Id].Reason -cne $expected[$a.Id].Reason){throw 'SMB completion contradicts its captured sources.'}}
}
