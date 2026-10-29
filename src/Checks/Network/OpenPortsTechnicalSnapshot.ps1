# Prepared endpoint data only. Never opens sockets, resolves DNS, queries processes or connects remotely.
. (Join-Path $PSScriptRoot 'OpenPortsTechnicalCatalog.ps1')

function Get-WinSecOpenPortsCapturedProperty {
    param([AllowNull()][object]$Data,[string]$Name)
    $missing=[pscustomobject]@{Safe=$true;Exists=$false;Value=$null}
    if($null -eq $Data){return $missing}
    if($Data.GetType() -eq [Management.Automation.PSCustomObject]){
        $p=@($Data.PSObject.Properties|Where-Object {[string]::Equals($_.Name,$Name,[StringComparison]::OrdinalIgnoreCase)})
        if(-not $p.Count){return $missing};if($p.Count -ne 1 -or $p[0].MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){return [pscustomobject]@{Safe=$false;Exists=$true;Value=$null}}
        return [pscustomobject]@{Safe=$true;Exists=$true;Value=$p[0].Value}
    }
    if($Data.GetType() -in @([hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){
        $keys=@(foreach($key in $Data.Keys){if($key -is [string] -and [string]::Equals($key,$Name,[StringComparison]::OrdinalIgnoreCase)){$key}})
        if(-not $keys.Count){return $missing};if($keys.Count -ne 1){return [pscustomobject]@{Safe=$false;Exists=$true;Value=$null}}
        return [pscustomobject]@{Safe=$true;Exists=$true;Value=$Data[$keys[0]]}
    };[pscustomobject]@{Safe=$false;Exists=$true;Value=$null}
}

function ConvertTo-WinSecOpenPortsCandidateAddress {
    param([AllowNull()][object]$Value)
    if($Value -isnot [string] -or $Value.Length -gt 80){return $null}
    if($Value.Contains(':')){
        if($Value -cnotmatch '\A[0-9A-Fa-f:.]+(?:%[0-9]{1,10})?\z'){return $null}
        if($Value.Contains('%')){$scope=[uint32]0;if(-not [uint32]::TryParse($Value.Split('%')[1],[ref]$scope)){return $null}}
    }elseif($Value -cnotmatch '\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z'){return $null}
    $address=$null;if(-not [Net.IPAddress]::TryParse($Value,[ref]$address)){return $null}
    $family=if($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){'IPv4'}elseif($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){'IPv6'}else{return $null}
    $scope=if([Net.IPAddress]::IsLoopback($address)){'LOOPBACK'}elseif($address.Equals([Net.IPAddress]::Any) -or $address.Equals([Net.IPAddress]::IPv6Any)){'ANY'}else{'SPECIFIC'}
    [pscustomobject]@{Original=$Value;Canonical=$address.ToString().ToLowerInvariant();Family=$family;Scope=$scope}
}

function ConvertTo-WinSecOpenPortsCapturedTime {
    param([AllowNull()][object]$Value)
    $culture=[Globalization.CultureInfo]::InvariantCulture;$wall='yyyy-MM-ddTHH:mm:ss.fffffff'
    if($Value -is [datetimeoffset]){return [pscustomobject]@{Text=$Value.ToString(($wall+'zzz'),$culture);Basis='OFFSET'}}
    if($Value -is [datetime]){
        $basis=if($Value.Kind -eq [DateTimeKind]::Utc){'UTC'}elseif($Value.Kind -eq [DateTimeKind]::Local){'LOCAL'}else{'UNSPECIFIED'}
        return [pscustomobject]@{Text=$Value.ToString(($wall+$(if($basis -ceq 'UTC'){'Z'}else{''})),$culture);Basis=$basis}
    }
    if($Value -is [timespan] -and $Value.Ticks -ge 0){return [pscustomobject]@{Text=$Value.ToString('c',$culture);Basis='INTERVAL'}}
    if($Value -isnot [string] -or $Value.Length -gt 40){return $null}
    if($Value -cmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z\z'){
        try{$date=ConvertTo-WinSecSnapshotUtc $Value;return [pscustomobject]@{Text=$Value;Basis='UTC'}}catch{return $null}
    }
    if($Value -cmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}[+-][0-9]{2}:[0-9]{2}\z'){
        $date=[datetimeoffset]::MinValue;if([datetimeoffset]::TryParseExact($Value,($wall+'zzz'),$culture,[Globalization.DateTimeStyles]::None,[ref]$date)){return [pscustomobject]@{Text=$Value;Basis='OFFSET'}}
    }
    if($Value -cmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}\z'){
        $date=[datetime]::MinValue;if([datetime]::TryParseExact($Value,$wall,$culture,[Globalization.DateTimeStyles]::None,[ref]$date)){return [pscustomobject]@{Text=$Value;Basis='UNSPECIFIED'}}
    }
    if($Value -cmatch '\A(?:[0-9]{1,8}\.)?[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{7})?\z'){
        $span=[timespan]::Zero;if([timespan]::TryParseExact($Value,'c',$culture,[ref]$span) -and $span.Ticks -ge 0 -and $span.ToString('c',$culture) -ceq $Value){return [pscustomobject]@{Text=$Value;Basis='INTERVAL'}}
    };return $null
}

function ConvertTo-WinSecOpenPortsCandidateValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    $valid=$false;$converted=$null
    if($null -ne $Value){switch -CaseSensitive ($Kind){
        {$_ -cin @('UInt8','UInt16','UInt32','Build')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if([uint32]::TryParse($Value,[ref]$n)){$Value=$n}}
            if($Value.GetType().IsEnum){try{$Value=[long]$Value}catch{return [pscustomobject]@{Valid=$false;Value=$null}}}
            $max=switch($Kind){UInt8 {255};UInt16 {65535};default {4294967295}}
            if(Test-WinSecSnapshotUInt $Value $max){$valid=$true;$converted=[uint32]$Value}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){$valid=$true;$converted=$Value}}
        {$_ -cin @('Address','CanonicalAddress','Family','BindingScope')} {
            $info=ConvertTo-WinSecOpenPortsCandidateAddress $Value
            if($null -ne $info){$valid=$true;$converted=switch($Kind){Address {$info.Original};CanonicalAddress {$info.Canonical};Family {$info.Family};BindingScope {$info.Scope}}}
        }
        NativeTime {$time=ConvertTo-WinSecOpenPortsCapturedTime $Value;if($null -ne $time){$valid=$true;$converted=$time.Text}}
        TimeBasis {$time=ConvertTo-WinSecOpenPortsCapturedTime $Value;if($null -ne $time){$valid=$true;$converted=$time.Basis}}
        Protocol {if($Value -is [string] -and $Value -cin @('TCP','UDP')){$valid=$true;$converted=$Value}}
        Time {try{$date=ConvertTo-WinSecSnapshotUtc $Value;$valid=$true;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}catch{}}
        SourceState {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED')){$valid=$true;$converted=$Value}}
        Location {if($Value -is [string] -and $Value -cin @('CIMV2','STANDARDCIMV2')){$valid=$true;$converted=$Value}}
        Scope {if($Value -is [string] -and $Value -ceq 'PASSIVE_TCP_LISTEN_UDP_BINDINGS_NO_PEERS'){$valid=$true;$converted=$Value}}
    }};[pscustomobject]@{Valid=$valid;Value=$converted}
}

function Get-WinSecOpenPortsCandidateIntegrity {
    param([object]$Snapshot,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$meta=@{};$summaries=@{};$ports=@{};$result=@{}
    foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($b.InventoryId -ceq 'Capture'){foreach($r in $record.Readings){$meta[$r.FieldId]=$r}}
        elseif($b.InventoryId -cin @('TCP','UDP')){if(-not $ports.ContainsKey($b.InventoryId)){$ports[$b.InventoryId]=New-Object 'Collections.Generic.List[object]'}
            $ports[$b.InventoryId].Add(@($record.Readings|Where-Object FieldId -CEQ ($b.InventoryId+'.LocalPort'))[0])}
    }}
    foreach($a in Get-WinSecOpenPortsCandidateAreas){
        $s=$summaries[$a.Id];$state=$meta['Capture.'+$a.Id+'SourceState'].Value
        $ok=($state -ceq 'OBSERVED' -and $null -ne $s.ReportedRecords -and $s.ReportedRecords -eq $s.RetainedRecords)
        $reason=if($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}elseif($state -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}elseif(-not $ok){'RESOURCE_LIMIT'}else{'NONE'}
        if($ok -and $ports.ContainsKey($a.Id)){foreach($r in $ports[$a.Id]){if($r.State -ceq 'OBSERVED' -and $r.Value -eq 0){$ok=$false;$reason='INVALID_VALUE'}}}
        $result[$a.Id]=[pscustomobject]@{Complete=$ok;Reason=$reason}
    };return $result
}

function Get-WinSecOpenPortsCandidatePayloadBudget {return ((Get-WinSecSnapshotSpecification).MaxDocumentBytes-131072)}

function New-WinSecOpenPortsCandidateSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('o')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity;if($Identity.CheckId -cne 'WSA-NET-004'){throw 'Foreign Open Ports candidate control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid endpoint capture operation.'}
    $areas=@(Get-WinSecOpenPortsCandidateAreas);$inputs=@{};$latest=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'Open Ports requires the exact source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','Location','State','Data')
        if($source.SourceId -isnot [string]){throw 'Invalid endpoint source identifier.'};$a=@($areas|Where-Object Id -CEQ $source.SourceId)
        if($a.Count -ne 1 -or $inputs.ContainsKey($source.SourceId) -or $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or
            $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or $source.Location -isnot [string] -or $source.Location -cne $a[0].Location -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign endpoint source, identity or location.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;if($time -lt $start -or $time -gt $end){throw 'Endpoint source outside its operation.'};if($time -gt $latest){$latest=$time}
        if($source.State -ceq 'OBSERVED'){
            if($source.SourceId -cne 'Platform'){if($source.Data -isnot [array] -or $source.Data.Rank -ne 1){throw 'Endpoint inventory requires an explicit array.'}}
            elseif($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Endpoint platform requires ordinary captured data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable endpoint source contains data.'};$inputs[$source.SourceId]=$source
    }
    $capture=[ordered]@{Scope='PASSIVE_TCP_LISTEN_UDP_BINDINGS_NO_PEERS'}
    foreach($a in $areas){$s=$inputs[$a.Id];$capture[$a.Id+'Time']=$s.CollectedAtUTC;$capture[$a.Id+'SourceState']=$s.State;$capture[$a.Id+'Location']=$s.Location}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture}
    $catalog=Get-WinSecOpenPortsCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog;$defs=@(Get-WinSecOpenPortsCandidateFields);$byInventory=@{}
    foreach($i in $catalog.Inventories){$byInventory[$i.Id]=@($defs|Where-Object Inventory -CEQ $i.Id)}
    $batches=New-Object 'Collections.Generic.List[object]';$summaries=@();$payload=0;$limit=Get-WinSecOpenPortsCandidatePayloadBudget
    $counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0};$stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected'}
    foreach($i in $catalog.Inventories){
        $source=$inputs[$i.Id];$total=if($i.Singleton){1}elseif($source.State -ceq 'OBSERVED'){$source.Data.Length}else{0}
        $reported=if($source.State -ceq 'OBSERVED'){$total}else{$null};$state=if($i.Singleton){'OBSERVED'}else{$source.State}
        $ok=($source.State -ceq 'OBSERVED');$reason=if($ok){'NONE'}elseif($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}
        $rows=New-Object 'Collections.Generic.List[object]';$bytes=16384;$sequence=1;$retained=0
        for($index=0;$index -lt $total;$index++){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $data=if($i.Singleton){$source.Data}else{$source.Data[$index]}
            if($source.State -ceq 'OBSERVED' -and ($null -eq $data -or $data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]]))){throw 'Unreviewed endpoint captured record.'}
            $readings=@(foreach($d in $byInventory[$i.Id]){
                $r=[pscustomobject]@{FieldId=$d.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
                if($source.State -cne 'OBSERVED'){$r.State=$source.State;$r.Reason=$reason}
                else{
                    $p=if($d.Kind -ceq 'Protocol'){[pscustomobject]@{Safe=$true;Exists=$true;Value=$i.Id}}else{Get-WinSecOpenPortsCapturedProperty $data $d.Property}
                    if(-not $p.Safe){$r.Reason='INVALID_VALUE'}elseif($p.Exists -and $null -ne $p.Value){
                        $v=ConvertTo-WinSecOpenPortsCandidateValue $p.Value $d.Kind
                        if($v.Valid -and -not ($d.Property -ceq 'CreationTime' -and (ConvertTo-WinSecOpenPortsCapturedTime $p.Value).Basis -ceq 'INTERVAL')){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=$v.Value}else{$r.Reason='INVALID_VALUE'}
                    }
                };$r
            })
            if($i.Id -ceq 'TCP'){$tcpState=@($readings|Where-Object FieldId -CEQ TCP.State)[0];if($tcpState.State -cne 'OBSERVED' -or $tcpState.Value -ne 2){throw 'Unverified TCP LISTEN scope.'}}
            $record=[pscustomobject]@{Id=($i.Id+$index);Readings=$readings};$size=512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $record -Depth 8 -Compress))
            if(-not $i.Singleton -and ($payload+$size) -gt $limit){$ok=$false;$reason='RESOURCE_LIMIT';break}
            if($rows.Count -and ($rows.Count -ge 128 -or ($bytes+$size) -gt (Get-WinSecSnapshotSpecification).MaxBatchBytes)){
                $batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$i.Id;Sequence=$sequence;Records=$rows.ToArray()});$rows.Clear();$sequence++;$bytes=16384
            }
            $payload+=$size;$bytes+=$size;$rows.Add($record);$retained++;$counts.RetainedRecords++;foreach($r in $readings){$counts[$stateCount[$r.State]]++}
            if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{InventoryId=$i.Id;RetainedRecords=$retained;ReportedRecords=$reported})}
        }
        if($rows.Count){$batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$i.Id;Sequence=$sequence;Records=$rows.ToArray()})}
        $summaries+=,[pscustomobject]@{Id=$i.Id;State=$state;Complete=$ok;ReportedRecords=$reported;RetainedRecords=$retained;Reason=$reason}
    }
    $platform=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    foreach($r in $batches[0].Records[0].Readings){if($r.State -ceq 'OBSERVED'){$platform.($r.FieldId.Substring(9))=$r.Value}}
    $snapshot=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$owner;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$hash;CollectorVersion='1.0.0';
        StartedAtUTC=$StartedAtUTC;CollectedAtUTC=$latest.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);CompletedAtUTC=$CompletedAtUTC;GeneratedAtUTC=$GeneratedAtUTC;
        Platform=$platform;SelectedProfile=$SelectedProfile;Collection=$null;Inventories=$summaries;Batches=$batches.ToArray()}
    $integrity=Get-WinSecOpenPortsCandidateIntegrity $snapshot -CancellationAction $CancellationAction
    foreach($s in $summaries){if($s.Id -cne 'Capture'){$s.Complete=$integrity[$s.Id].Complete;$s.Reason=$integrity[$s.Id].Reason}}
    $required=@{};foreach($d in $defs){$required[$d.Id]=$d.Required}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($summaries|Where-Object {-not $_.Complete}).Count -eq 0)
    foreach($b in $batches){foreach($record in $b.Records){foreach($r in $record.Readings){if($required[$r.FieldId] -and $r.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){$complete=$false}}}}
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]};$snapshot.Collection=[pscustomobject]$collection
    Assert-WinSecOpenPortsCandidateSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecOpenPortsCandidateSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-NET-004'){throw 'Foreign Open Ports candidate identity.'}
    $catalog=Get-WinSecOpenPortsCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed endpoint candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$defs=@{};$fixed=@{};$summaries=@{}
    foreach($d in Get-WinSecOpenPortsCandidateFields){$defs[$d.Id]=$d};foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        $local=@{};foreach($r in $record.Readings){$local[$r.FieldId]=$r;if($b.InventoryId -cin @('Platform','Capture')){$fixed[$r.FieldId]=$r}
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            if($r.State -cin @('NOT_CONFIGURED','NOT_APPLICABLE')){throw 'Unverified endpoint absence or exclusion.'}
            if($r.State -cne 'OBSERVED'){continue};$d=$defs[$r.FieldId]
            if($d.Kind -cin @('Family','BindingScope','TimeBasis')){continue}
            $v=ConvertTo-WinSecOpenPortsCandidateValue $r.Value $d.Kind
            if(-not $v.Valid -or (ConvertTo-Json -InputObject $v.Value -Compress) -cne (ConvertTo-Json -InputObject $r.Value -Compress)){throw 'Unreviewed endpoint candidate value.'}
        }
        if($b.InventoryId -cin @('TCP','UDP')){
            $prefix=$b.InventoryId+'.';$protocol=$local[$prefix+'Protocol']
            if($protocol.State -cne 'OBSERVED' -or $protocol.Value -cne $b.InventoryId){throw 'Foreign endpoint protocol.'}
            if($b.InventoryId -ceq 'TCP' -and ($local['TCP.State'].State -cne 'OBSERVED' -or $local['TCP.State'].Value -ne 2)){throw 'Unverified stored TCP LISTEN scope.'}
            $raw=$local[$prefix+'LocalAddress'];$info=if($raw.State -ceq 'OBSERVED'){ConvertTo-WinSecOpenPortsCandidateAddress $raw.Value}else{$null}
            foreach($spec in @('Canonical|Canonical','Family|Family','Scope|Scope')){
                $p=$spec.Split('|');$r=$local[$prefix+'LocalAddress'+$p[0]]
                if($null -ne $info){if($r.State -cne 'OBSERVED' -or $r.Value -cne $info.($p[1])){throw 'Endpoint address derivation is contradictory.'}}
                elseif($r.State -cne $raw.State -or $r.Reason -cne $raw.Reason){throw 'Unobserved endpoint address supplies derived metadata.'}
            }
            foreach($name in @('CreationTime','TimeOfLastStateChange')){
                $r=$local[$prefix+$name];$basis=$local[$prefix+$name+'Basis']
                if($r.State -ceq 'OBSERVED'){
                    $time=ConvertTo-WinSecOpenPortsCapturedTime $r.Value
                    $allowed=if($time.Basis -ceq 'UNSPECIFIED'){@('LOCAL','UNSPECIFIED')}else{@($time.Basis)}
                    if($basis.State -cne 'OBSERVED' -or $basis.Value -cnotin $allowed -or ($name -ceq 'CreationTime' -and $time.Basis -ceq 'INTERVAL')){throw 'Endpoint time basis is contradictory.'}
                }elseif($basis.State -cne $r.State -or $basis.Reason -cne $r.Reason){throw 'Unobserved endpoint timestamp supplies a basis.'}
            }
        }
    }}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){$r=$fixed['Platform.'+$name];$v=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null};if($Snapshot.Platform.$name -cne $v){throw 'Endpoint platform differs from its readings.'}}
    if($null -ne $Snapshot.Platform.UBR -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.OSRelease){throw 'Unobserved endpoint platform metadata.'}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($a in Get-WinSecOpenPortsCandidateAreas){
        $time=$fixed['Capture.'+$a.Id+'Time'];$state=$fixed['Capture.'+$a.Id+'SourceState'];$location=$fixed['Capture.'+$a.Id+'Location'];$s=$summaries[$a.Id]
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED' -or $location.State -cne 'OBSERVED' -or $location.Value -cne $a.Location){throw 'Missing or foreign endpoint capture metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value;if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'Endpoint source timestamp outside its operation.'};if($stamp -gt $latest){$latest=$stamp}
        if($state.Value -ceq 'OBSERVED'){if($s.State -cne 'OBSERVED' -or $null -eq $s.ReportedRecords){throw 'Observed endpoint source lacks counts.'}}
        else{
            if($null -ne $s.ReportedRecords -or ($a.Id -cne 'Platform' -and ($s.State -cne $state.Value -or $s.RetainedRecords -ne 0))){throw 'Unavailable endpoint source claims records.'}
            foreach($b in $Snapshot.Batches|Where-Object InventoryId -CEQ $a.Id){foreach($record in $b.Records){foreach($r in $record.Readings){if($r.State -cne $state.Value){throw 'Unavailable endpoint source supplies readings.'}}}}
        }
    }
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC) -or $fixed['Capture.Scope'].State -cne 'OBSERVED' -or $fixed['Capture.Scope'].Value -cne 'PASSIVE_TCP_LISTEN_UDP_BINDINGS_NO_PEERS'){throw 'Invalid endpoint scope or timestamp.'}
    $expected=Get-WinSecOpenPortsCandidateIntegrity $Snapshot -CancellationAction $CancellationAction
    foreach($a in Get-WinSecOpenPortsCandidateAreas){if($summaries[$a.Id].Complete -cne $expected[$a.Id].Complete -or $summaries[$a.Id].Reason -cne $expected[$a.Id].Reason){throw 'Endpoint completion contradicts its captured sources.'}}
}
