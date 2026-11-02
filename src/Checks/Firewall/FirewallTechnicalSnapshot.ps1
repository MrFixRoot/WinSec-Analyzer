# Prepared data only. No native Firewall queries, remote calls or execution registration.
. (Join-Path $PSScriptRoot 'FirewallTechnicalCatalog.ps1')

function Get-WinSecFirewallCapturedProperty {
    param([AllowNull()][object]$Data,[string]$Name)
    $missing=[pscustomobject]@{Safe=$true;Value=$null}
    if($null -eq $Data){return $missing}
    if($Data.GetType() -eq [Management.Automation.PSCustomObject]){
        $p=$Data.PSObject.Properties[$Name];if($null -eq $p){return $missing}
        if($p.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){return [pscustomobject]@{Safe=$false;Value=$null}}
        return [pscustomobject]@{Safe=$true;Value=$p.Value}
    }
    if($Data.GetType() -in @([hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){
        $keys=@(foreach($key in $Data.Keys){if($key -is [string] -and [string]::Equals($key,$Name,[StringComparison]::OrdinalIgnoreCase)){$key}})
        if(-not $keys.Count){return $missing};if($keys.Count -ne 1){return [pscustomobject]@{Safe=$false;Value=$null}}
        return [pscustomobject]@{Safe=$true;Value=$Data[$keys[0]]}
    }
    [pscustomobject]@{Safe=$false;Value=$null}
}

function ConvertTo-WinSecFirewallCandidateValue {
    param([AllowNull()][object]$Value,[string]$Kind,[scriptblock]$CancellationAction,
        [Diagnostics.Stopwatch]$Clock=([Diagnostics.Stopwatch]::StartNew()))
    $invalid=[pscustomobject]@{Valid=$false;Resource=$false;Value=$null}
    if($null -eq $Value){return $invalid}
    $converted=$null;$valid=$false
    switch -CaseSensitive ($Kind){
        {$_ -cin @('Build','UInt32')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if(-not [uint32]::TryParse($Value,[ref]$n)){return $invalid};$Value=$n}
            if($Value.GetType().IsEnum){try{$Value=[long]$Value}catch{return $invalid}}
            if(Test-WinSecSnapshotUInt $Value){$converted=[uint32]$Value;$valid=$true}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){$converted=$Value;$valid=$true}}
        UInt64Text {
            if($Value -is [string] -and $Value -cmatch '\A(?:0|[1-9][0-9]{0,19})\z'){$n=[uint64]0;if([uint64]::TryParse($Value,[ref]$n)){$converted=$n.ToString([Globalization.CultureInfo]::InvariantCulture);$valid=$true}}
            elseif($Value.GetType() -in @([byte],[int16],[uint16],[int],[uint32],[long],[uint64]) -and $Value -ge 0){$converted=([uint64]$Value).ToString([Globalization.CultureInfo]::InvariantCulture);$valid=$true}
        }
        Identifier {if($Value -is [string] -and $Value -cmatch '\A[A-Za-z0-9{][A-Za-z0-9_.{} -]{0,511}\z' -and -not [string]::IsNullOrWhiteSpace($Value)){$converted=$Value;$valid=$true}}
        Profile {if($Value -is [string] -and $Value -cin @('Domain','Private','Public')){$converted=$Value;$valid=$true}}
        Protocol {
            if($Value -is [string]){
                if($Value -cmatch '\A[0-9]{1,3}\z' -and [int]$Value -le 255){$converted=$Value;$valid=$true}
                else{foreach($token in @('Any','TCP','UDP','ICMPv4','ICMPv6','HOPOPT')){if([string]::Equals($token,$Value,[StringComparison]::OrdinalIgnoreCase)){$converted=$token;$valid=$true;break}}}
            }
        }
        ListCount {if($Value -is [array] -and $Value.Rank -eq 1){$converted=[uint32]$Value.Length;$valid=$true}}
        {$_ -cin @('LocalPorts','RemotePorts','Icmp')} {
            if($Value -isnot [array] -or $Value.Rank -ne 1){return $invalid}
            $items=New-Object 'Collections.Generic.List[string]';$bytes=0;$maxBytes=(Get-WinSecSnapshotSpecification).MaxBatchBytes/4
            $allowed=if($Kind -ceq 'LocalPorts'){@('Any','RPC','RPC-EPMap','IPHTTPSIn','PlayToDiscovery')}elseif($Kind -ceq 'RemotePorts'){@('Any','IPHTTPSOut')}else{@('Any')}
            for($i=0;$i -lt $Value.Length;$i++){
                if(($i % 128) -eq 0){Assert-WinSecSnapshotValidationBudget $Clock $CancellationAction}
                $item=$Value[$i];if($item -isnot [string]){return $invalid}
                $good=($item -cin $allowed)
                if(-not $good -and $Kind -ceq 'Icmp' -and $item -cmatch '\A([0-9]{1,3})(?:[.:]([0-9]{1,3}))?\z'){
                    $good=([int]$Matches[1] -le 255 -and (-not $Matches[2] -or [int]$Matches[2] -le 255))
                }elseif(-not $good -and $Kind -cne 'Icmp' -and $item -cmatch '\A([0-9]{1,5})(?:-([0-9]{1,5}))?\z'){
                    $good=([int]$Matches[1] -le 65535 -and (-not $Matches[2] -or ([int]$Matches[2] -le 65535 -and [int]$Matches[1] -le [int]$Matches[2])))
                }
                if(-not $good){return $invalid};$bytes+=([Text.Encoding]::UTF8.GetByteCount($item)+4)
                if($bytes -gt $maxBytes){return [pscustomobject]@{Valid=$false;Resource=$true;Value=$null}}
                $items.Add($item)
            }
            $converted=$items.ToArray();$valid=$true
        }
        Time {try{$date=ConvertTo-WinSecSnapshotUtc $Value;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);$valid=$true}catch{}}
        State {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED')){$converted=$Value;$valid=$true}}
        Store {if($Value -is [string] -and $Value -cin @('NONE','ActiveStore','PersistentStore')){$converted=$Value;$valid=$true}}
        Scope {if($Value -is [string] -and $Value -ceq 'HOST_PROFILES_RULES_PORTS_ASSOCIATIONS'){$converted=$Value;$valid=$true}}
    }
    [pscustomobject]@{Valid=$valid;Resource=$false;Value=$converted}
}

function Get-WinSecFirewallCandidatePayloadBudget {
    return ((Get-WinSecSnapshotSpecification).MaxDocumentBytes-131072)
}

function Get-WinSecFirewallCandidateIntegrity {
    param([object]$Snapshot,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$meta=@{};$summaries=@{};$indexes=@{};$links=@{};$result=@{}
    foreach($summary in $Snapshot.Inventories){$summaries[$summary.Id]=$summary}
    foreach($batch in $Snapshot.Batches){foreach($record in $batch.Records){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($batch.InventoryId -ceq 'Capture'){foreach($r in $record.Readings){$meta[$r.FieldId]=$r};continue}
        $row=@{};foreach($r in $record.Readings){$row[$r.FieldId.Substring($batch.InventoryId.Length+1)]=$r}
        if($batch.InventoryId.EndsWith('Links',[StringComparison]::Ordinal)){
            if(-not $links.ContainsKey($batch.InventoryId)){$links[$batch.InventoryId]=New-Object 'Collections.Generic.List[object]'};$links[$batch.InventoryId].Add($row)
        }elseif($batch.InventoryId -cne 'Platform'){
            if(-not $indexes.ContainsKey($batch.InventoryId)){$indexes[$batch.InventoryId]=[pscustomobject]@{Ids=(New-Object 'Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal));Invalid=$false}}
            $id=if($batch.InventoryId.EndsWith('Profiles',[StringComparison]::Ordinal)){$row.Name}else{$row.InstanceID}
            if($id.State -cne 'OBSERVED'){$indexes[$batch.InventoryId].Invalid=$true;continue}
            if($indexes[$batch.InventoryId].Ids.ContainsKey($id.Value)){$indexes[$batch.InventoryId].Ids[$id.Value]++}else{$indexes[$batch.InventoryId].Ids[$id.Value]=1}
        }
    }}
    foreach($area in Get-WinSecFirewallCandidateAreas){
        $summary=$summaries[$area.Id];$state=$meta['Capture.'+$area.Id+'State'].Value
        $ok=($state -ceq 'OBSERVED' -and $null -ne $summary.ReportedRecords -and $summary.ReportedRecords -eq $summary.RetainedRecords)
        $reason=if($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}elseif($state -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}elseif(-not $ok){'RESOURCE_LIMIT'}else{'NONE'}
        if($ok -and $area.Role -cin @('Profiles','Rules','Ports')){
            $index=$indexes[$area.Id]
            if($null -ne $index -and ($index.Invalid -or @($index.Ids.Values|Where-Object {$_ -ne 1}).Count)){$ok=$false;$reason='INVALID_VALUE'}
            elseif($area.Role -ceq 'Profiles' -and ($null -eq $index -or $index.Ids.Count -ne 3)){$ok=$false;$reason='PROVIDER_UNAVAILABLE'}
        }
        $result[$area.Id]=[pscustomobject]@{Complete=$ok;Reason=$reason}
    }
    foreach($store in @('Active','Persistent')){
        $id=$store+'Links';$ruleIds=if($indexes.ContainsKey($store+'Rules')){$indexes[$store+'Rules'].Ids}else{New-Object 'Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)}
        $portIds=if($indexes.ContainsKey($store+'Ports')){$indexes[$store+'Ports'].Ids}else{New-Object 'Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)}
        $seenRules=New-Object 'Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal);$seenPorts=New-Object 'Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)
        $invalid=$false;$unresolved=(-not $result[$store+'Rules'].Complete -or -not $result[$store+'Ports'].Complete)
        if($links.ContainsKey($id)){foreach($row in $links[$id]){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $rule=$row.RuleInstanceID;$port=$row.FilterInstanceID
            if($rule.State -cne 'OBSERVED' -or $port.State -cne 'OBSERVED'){$invalid=$true;continue}
            if($seenRules.ContainsKey($rule.Value)){$seenRules[$rule.Value]++;$invalid=$true}else{$seenRules[$rule.Value]=1}
            if($seenPorts.ContainsKey($port.Value)){$seenPorts[$port.Value]++;$invalid=$true}else{$seenPorts[$port.Value]=1}
            if(-not $ruleIds.ContainsKey($rule.Value) -or $ruleIds[$rule.Value] -ne 1 -or -not $portIds.ContainsKey($port.Value) -or $portIds[$port.Value] -ne 1){$unresolved=$true}
        }}
        if($seenRules.Count -ne $ruleIds.Count -or $seenPorts.Count -ne $portIds.Count){$unresolved=$true}
        if($result[$id].Complete -and ($invalid -or $unresolved)){$result[$id]=[pscustomobject]@{Complete=$false;Reason=$(if($invalid){'INVALID_VALUE'}else{'PROVIDER_UNAVAILABLE'})}}
    }
    return $result
}

function New-WinSecFirewallCandidateSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('o')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity
    if($Identity.CheckId -cne 'WSA-NET-001'){throw 'Firewall candidate cannot process another control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid Firewall capture operation.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$areas=@(Get-WinSecFirewallCandidateAreas);$inputs=@{};$collected=$start
    if($Sources.Count -ne $areas.Count){throw 'Firewall candidate requires the exact reviewed source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','PolicyStore','State','Data')
        if($source.SourceId -isnot [string]){throw 'Invalid Firewall source identifier type.'}
        $area=@($areas|Where-Object Id -CEQ $source.SourceId)
        if($source.SourceId -isnot [string] -or $area.Count -ne 1 -or $inputs.ContainsKey($source.SourceId) -or
            $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or
            $source.PolicyStore -isnot [string] -or $source.PolicyStore -cne $area[0].Store -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign Firewall source, identity or store.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC
        if($time -lt $start -or $time -gt $end){throw 'Firewall source lies outside its operation.'};if($time -gt $collected){$collected=$time}
        if($source.State -ceq 'OBSERVED'){
            if($area[0].Role -cne 'Platform'){if($source.Data -isnot [array] -or $source.Data.Rank -ne 1){throw 'Firewall list requires an explicit captured array.'}}
            elseif($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Firewall singleton requires ordinary captured data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable Firewall source contains raw data.'}
        $inputs[$source.SourceId]=$source
    }
    $capture=[ordered]@{Scope='HOST_PROFILES_RULES_PORTS_ASSOCIATIONS'}
    foreach($area in $areas){$s=$inputs[$area.Id];$capture[$area.Id+'Time']=$s.CollectedAtUTC;$capture[$area.Id+'State']=$s.State;$capture[$area.Id+'Store']=$s.PolicyStore}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture}
    $catalog=Get-WinSecFirewallCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog;$fields=@(Get-WinSecFirewallCandidateFields);$byInventory=@{}
    foreach($inventory in $catalog.Inventories){$byInventory[$inventory.Id]=@($fields|Where-Object Inventory -CEQ $inventory.Id)}
    $batches=New-Object 'Collections.Generic.List[object]';$summaries=@();$counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0}
    $stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected'};$payload=0;$limit=Get-WinSecFirewallCandidatePayloadBudget
    foreach($inventory in $catalog.Inventories){
        $source=$inputs[$inventory.Id];$total=if($inventory.Singleton){1}elseif($source.State -ceq 'OBSERVED'){$source.Data.Length}else{0}
        $reported=if($source.State -ceq 'OBSERVED'){$total}else{$null};$state=if($inventory.Singleton){'OBSERVED'}else{$source.State}
        $rows=New-Object 'Collections.Generic.List[object]';$batchBytes=16384;$sequence=1;$retained=0;$ok=($source.State -ceq 'OBSERVED');$reason='NONE'
        if(-not $ok){$reason=if($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}}
        for($i=0;$i -lt $total;$i++){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $data=if($inventory.Singleton){$source.Data}else{$source.Data[$i]}
            if($source.State -ceq 'OBSERVED' -and ($null -eq $data -or $data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]]))){throw 'Unreviewed captured Firewall row.'}
            $readings=@(foreach($definition in $byInventory[$inventory.Id]){
                $reading=[pscustomobject]@{FieldId=$definition.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
                if($source.State -cne 'OBSERVED'){$reading.State=$source.State;$reading.Reason=$reason}
                else{
                    $property=Get-WinSecFirewallCapturedProperty $data $definition.Property
                    if(-not $property.Safe){$reading.Reason='INVALID_VALUE'}elseif($null -ne $property.Value){
                        $value=ConvertTo-WinSecFirewallCandidateValue $property.Value $definition.Kind -CancellationAction $CancellationAction -Clock $clock
                        if($value.Valid){$reading.State='OBSERVED';$reading.Reason='NONE';$reading.Value=$value.Value}
                        elseif($value.Resource){$reading.State='NOT_COLLECTED';$reading.Reason='RESOURCE_LIMIT'}else{$reading.Reason='INVALID_VALUE'}
                    }
                };$reading
            })
            $record=[pscustomobject]@{Id=($inventory.Id+$i);Readings=$readings};$size=512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $record -Depth 8 -Compress))
            if(-not $inventory.Singleton -and ($payload+$size) -gt $limit){$ok=$false;$reason='RESOURCE_LIMIT';break}
            if($rows.Count -and ($rows.Count -ge 128 -or ($batchBytes+$size) -gt (Get-WinSecSnapshotSpecification).MaxBatchBytes)){
                $batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$inventory.Id;Sequence=$sequence;Records=$rows.ToArray()});$rows.Clear();$sequence++;$batchBytes=16384
            }
            $payload+=$size;$batchBytes+=$size;$rows.Add($record);$retained++;$counts.RetainedRecords++
            foreach($reading in $readings){$counts[$stateCount[$reading.State]]++}
            if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{InventoryId=$inventory.Id;RetainedRecords=$retained;ReportedRecords=$reported})}
        }
        if($rows.Count){$batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$inventory.Id;Sequence=$sequence;Records=$rows.ToArray()})}
        $summaries+=,[pscustomobject]@{Id=$inventory.Id;State=$state;Complete=$ok;ReportedRecords=$reported;RetainedRecords=$retained;Reason=$reason}
    }
    $platform=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    foreach($reading in $batches[0].Records[0].Readings){if($reading.State -ceq 'OBSERVED'){$platform.($reading.FieldId.Substring(9))=$reading.Value}}
    $snapshot=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$owner;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$hash;CollectorVersion='1.0.0';
        StartedAtUTC=$StartedAtUTC;CollectedAtUTC=$collected.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);CompletedAtUTC=$CompletedAtUTC;GeneratedAtUTC=$GeneratedAtUTC;
        Platform=$platform;SelectedProfile=$SelectedProfile;Collection=$null;Inventories=$summaries;Batches=$batches.ToArray()}
    $integrity=Get-WinSecFirewallCandidateIntegrity $snapshot -CancellationAction $CancellationAction
    foreach($summary in $summaries){if($summary.Id -cne 'Capture'){$summary.Complete=$integrity[$summary.Id].Complete;$summary.Reason=$integrity[$summary.Id].Reason}}
    $required=@{};foreach($f in $fields){$required[$f.Id]=$f.Required}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($summaries|Where-Object {-not $_.Complete}).Count -eq 0)
    foreach($batch in $batches){foreach($record in $batch.Records){foreach($r in $record.Readings){if($required[$r.FieldId] -and $r.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){$complete=$false}}}}
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]}
    $snapshot.Collection=[pscustomobject]$collection;Assert-WinSecFirewallCandidateSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecFirewallCandidateSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity
    if($ExpectedIdentity.CheckId -cne 'WSA-NET-001'){throw 'Foreign Firewall candidate identity.'}
    $catalog=Get-WinSecFirewallCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed Firewall candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$definitions=@{};$fixed=@{};$summaries=@{}
    foreach($d in Get-WinSecFirewallCandidateFields){$definitions[$d.Id]=$d};foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($batch in $Snapshot.Batches){foreach($record in $batch.Records){
        $local=@{};foreach($r in $record.Readings){$local[$r.FieldId]=$r;if($batch.InventoryId -cin @('Platform','Capture')){$fixed[$r.FieldId]=$r}
            if($r.State -ne 'OBSERVED'){continue}
            $value=ConvertTo-WinSecFirewallCandidateValue $r.Value $definitions[$r.FieldId].Kind -CancellationAction $CancellationAction -Clock $clock
            # List counts are derived from input arrays; their saved representation is UInt32.
            if($definitions[$r.FieldId].Kind -ceq 'ListCount'){continue}
            if(-not $value.Valid -or (ConvertTo-Json -InputObject $value.Value -Compress) -cne (ConvertTo-Json -InputObject $r.Value -Compress)){throw 'Unreviewed Firewall candidate value.'}
        }
        if($batch.InventoryId.EndsWith('Ports',[StringComparison]::Ordinal)){
            foreach($name in @('LocalPort','RemotePort','IcmpType')){
                $r=$local[$batch.InventoryId+'.'+$name];$n=$local[$batch.InventoryId+'.'+$name+'ReportedCount']
                if($r.State -ceq 'OBSERVED' -and ($n.State -cne 'OBSERVED' -or $n.Value -ne $r.Value.Length)){throw 'Firewall list count contradicts its readings.'}
                if($r.State -ceq 'NOT_COLLECTED' -and $r.Reason -ceq 'RESOURCE_LIMIT' -and $n.State -cne 'OBSERVED'){throw 'Missing oversized Firewall list count.'}
            }
        }
    }}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){
        $r=$fixed['Platform.'+$name];$value=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null}
        if($Snapshot.Platform.$name -cne $value){throw 'Firewall platform differs from its observations.'}
    }
    if($null -ne $Snapshot.Platform.UBR -or $null -ne $Snapshot.Platform.OSRelease -or $null -ne $Snapshot.Platform.Edition){throw 'Unobserved Firewall platform metadata.'}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($area in Get-WinSecFirewallCandidateAreas){
        $time=$fixed['Capture.'+$area.Id+'Time'];$state=$fixed['Capture.'+$area.Id+'State'];$store=$fixed['Capture.'+$area.Id+'Store'];$summary=$summaries[$area.Id]
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED' -or $store.State -cne 'OBSERVED' -or $store.Value -cne $area.Store){throw 'Missing or foreign Firewall capture metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value
        if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'Foreign Firewall capture timestamp.'};if($stamp -gt $latest){$latest=$stamp}
        if($state.Value -ceq 'OBSERVED'){
            if($summary.State -cne 'OBSERVED' -or $null -eq $summary.ReportedRecords){throw 'Firewall observed source has no counts.'}
        }else{
            if($null -ne $summary.ReportedRecords -or ($area.Role -cne 'Platform' -and ($summary.State -cne $state.Value -or $summary.RetainedRecords -ne 0))){throw 'Unavailable Firewall source claims rows.'}
            foreach($batch in $Snapshot.Batches|Where-Object InventoryId -CEQ $area.Id){foreach($record in $batch.Records){foreach($r in $record.Readings){if($r.State -cne $state.Value){throw 'Unavailable Firewall source supplies readings.'}}}}
        }
    }
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC) -or $fixed['Capture.Scope'].State -cne 'OBSERVED' -or
        $fixed['Capture.Scope'].Value -cne 'HOST_PROFILES_RULES_PORTS_ASSOCIATIONS'){throw 'Invalid Firewall candidate scope or date.'}
    $expected=Get-WinSecFirewallCandidateIntegrity $Snapshot -CancellationAction $CancellationAction
    foreach($area in Get-WinSecFirewallCandidateAreas){if($summaries[$area.Id].Complete -cne $expected[$area.Id].Complete -or $summaries[$area.Id].Reason -cne $expected[$area.Id].Reason){throw 'Firewall association or completion summary contradicts its sources.'}}
}
