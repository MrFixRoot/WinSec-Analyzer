# Prepared network data only. No Windows, DNS, traffic or remote queries.
. (Join-Path $PSScriptRoot 'NetworkConfigurationTechnicalCatalog.ps1')

function Get-WinSecNetworkCapturedProperty {
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

function ConvertTo-WinSecNetworkCandidateAddress {
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

function ConvertTo-WinSecNetworkCandidateValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    $valid=$false;$converted=$null
    if($null -ne $Value){switch -CaseSensitive ($Kind){
        Boolean {if($Value -is [bool]){$valid=$true;$converted=$Value}}
        {$_ -cin @('UInt8','UInt16','UInt32','Family','Build','RegistryDWord','ReportedCount','RetainedCount')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if([uint32]::TryParse($Value,[ref]$n)){$Value=$n}}
            if($Kind -ceq 'RegistryDWord' -and $Value -is [int] -and $Value -lt 0){$Value=[uint32]([long]$Value -band 4294967295L)}
            if($Value.GetType().IsEnum){try{$Value=[long]$Value}catch{return [pscustomobject]@{Valid=$false;Value=$null}}}
            $max=switch($Kind){UInt8 {255};UInt16 {65535};default {4294967295}}
            if(Test-WinSecSnapshotUInt $Value $max){$valid=$true;$converted=[uint32]$Value}
        }
        UInt64Text {
            if($Value.GetType() -in @([byte],[int16],[uint16],[int],[uint32],[long],[uint64]) -and [decimal]$Value -ge 0){$Value=$Value.ToString([Globalization.CultureInfo]::InvariantCulture)}
            $n=[uint64]0;if($Value -is [string] -and $Value -cmatch '\A(?:0|[1-9][0-9]{0,19})\z' -and [uint64]::TryParse($Value,[ref]$n)){$valid=$true;$converted=$Value}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){$valid=$true;$converted=$Value}}
        Guid {if($Value -is [string] -and $Value -cmatch '\A[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\z'){$valid=$true;$converted=$Value}}
        Address {$a=ConvertTo-WinSecNetworkCandidateAddress $Value;if($null -ne $a){$valid=$true;$converted=$a.Original}}
        Prefix {
            if($Value -is [string] -and $Value -cmatch '\A([^/]{1,80})/(0|[1-9][0-9]{0,2})\z'){
                $text=$Matches[1];$length=[int]$Matches[2];$a=ConvertTo-WinSecNetworkCandidateAddress $text
                if($null -ne $a -and $length -le $(if($a.Family -ceq 'IPv4'){32}else{128})){$valid=$true;$converted=$Value}
            }
        }
        Time {try{$date=ConvertTo-WinSecSnapshotUtc $Value;$valid=$true;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}catch{}}
        SourceState {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED')){$valid=$true;$converted=$Value}}
        Location {if($Value -is [string] -and $Value -cin @('CIMV2','STANDARDCIMV2','HKLM_REGISTRY64')){$valid=$true;$converted=$Value}}
        Scope {if($Value -is [string] -and $Value -ceq 'LOCAL_CONFIGURATION_NO_TRAFFIC_OR_RESOLUTION'){$valid=$true;$converted=$Value}}
    }};[pscustomobject]@{Valid=$valid;Value=$converted}
}

function Get-WinSecNetworkCandidateListBudget {return [int]((Get-WinSecSnapshotSpecification).MaxBatchBytes/4)}
function ConvertTo-WinSecNetworkCandidateList {
    param([object]$Property,[Diagnostics.Stopwatch]$Clock,[scriptblock]$CancellationAction)
    $r=[pscustomobject]@{State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null;Reported=$null;Retained=$null}
    if(-not $Property.Safe){$r.Reason='INVALID_VALUE';return $r}
    if(-not $Property.Exists -or $null -eq $Property.Value){return $r}
    $list=$Property.Value
    if($list -isnot [array] -or $list.Rank -ne 1){$r.Reason='INVALID_VALUE';return $r}
    $r.Reported=[uint32]$list.Length;$r.Retained=[uint32]0;$items=New-Object 'Collections.Generic.List[string]';$bytes=2
    foreach($value in $list){
        Assert-WinSecSnapshotValidationBudget $Clock $CancellationAction
        $a=ConvertTo-WinSecNetworkCandidateAddress $value
        if($null -eq $a){$r.Reason='INVALID_VALUE';return $r}
        $bytes+=3+[Text.Encoding]::UTF8.GetByteCount($value)
        if($bytes -gt (Get-WinSecNetworkCandidateListBudget)){$r.State='NOT_COLLECTED';$r.Reason='RESOURCE_LIMIT';return $r}
        $items.Add($value)
    }
    $r.State='OBSERVED';$r.Reason='NONE';$r.Value=$items.ToArray();$r.Retained=$r.Reported;return $r
}

function Get-WinSecNetworkCandidateIntegrity {
    param([object]$Snapshot,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$meta=@{};$summaries=@{};$records=@{};$result=@{}
    foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($b.InventoryId -ceq 'Capture'){foreach($r in $record.Readings){$meta[$r.FieldId]=$r}}
        else{if(-not $records.ContainsKey($b.InventoryId)){$records[$b.InventoryId]=New-Object 'Collections.Generic.List[object]'};$records[$b.InventoryId].Add($record)}
    }}
    foreach($a in Get-WinSecNetworkCandidateAreas){
        $s=$summaries[$a.Id];$state=$meta['Capture.'+$a.Id+'SourceState'].Value
        $ok=($state -ceq 'OBSERVED' -and $null -ne $s.ReportedRecords -and $s.ReportedRecords -eq $s.RetainedRecords)
        $reason=if($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}elseif($state -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}elseif(-not $ok){'RESOURCE_LIMIT'}else{'NONE'}
        $seen=@{}
        if($state -ceq 'OBSERVED'){foreach($record in $records[$a.Id]){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $v=@{};foreach($r in $record.Readings){$v[$r.FieldId.Substring($a.Id.Length+1)]=$r;if($r.Reason -ceq 'RESOURCE_LIMIT'){$ok=$false;$reason='RESOURCE_LIMIT'}}
            $invalid=$false;$family=$v.AddressFamily
            if($null -ne $family -and $family.State -ceq 'OBSERVED' -and $family.Value -notin @(2,23)){$invalid=$true}
            if($a.Id -ceq 'IPAddress' -and $family.State -ceq 'OBSERVED' -and $v.PrefixLength.State -ceq 'OBSERVED' -and $v.PrefixLength.Value -gt $(if($family.Value -eq 2){32}else{128})){$invalid=$true}
            foreach($name in @('IPAddress','NextHop','DestinationPrefix','ServerAddresses')){
                if(-not $v.ContainsKey($name) -or $v[$name].State -cne 'OBSERVED' -or $null -eq $family -or $family.State -cne 'OBSERVED'){continue}
                foreach($text in @($v[$name].Value)){
                    $address=ConvertTo-WinSecNetworkCandidateAddress $text.Split('/')[0]
                    if($null -ne $address -and $(if($address.Family -ceq 'IPv4'){2}else{23}) -ne $family.Value){$invalid=$true}
                }
            }
            if($a.Id -ceq 'Legacy'){
                if($v.Index.State -ceq 'OBSERVED'){$key=[string]$v.Index.Value;if($seen.ContainsKey($key)){$invalid=$true};$seen[$key]=$true}
                if($v.IPEnabled.State -ceq 'OBSERVED' -and $v.IPEnabled.Value -ceq $true -and $v.InterfaceIndex.State -cne 'OBSERVED'){$invalid=$true}
                if($v.InterfaceIndex.State -cne 'OBSERVED' -and $v.InterfaceIndex.Reason -ceq 'INVALID_VALUE'){$invalid=$true}
                if($v.TcpipNetbiosOptions.State -ceq 'OBSERVED' -and $v.TcpipNetbiosOptions.Value -gt 2){$invalid=$true}
            }
            if($a.Id -ceq 'Profile' -and $v.NetworkCategory.State -ceq 'OBSERVED' -and $v.NetworkCategory.Value -gt 2){$invalid=$true}
            if($a.Id -ceq 'Registry'){foreach($name in @('EnableMulticast','DisableSmartNameResolution','DoHPolicy')){
                if($v[$name].State -ceq 'OBSERVED' -and $v[$name].Value -gt $(if($name -ceq 'DoHPolicy'){3}else{1})){$invalid=$true}
            }}
            if($invalid){$ok=$false;if($reason -cne 'RESOURCE_LIMIT'){$reason='INVALID_VALUE'}}
        }}
        $result[$a.Id]=[pscustomobject]@{Complete=$ok;Reason=$reason}
    };return $result
}

function Get-WinSecNetworkCandidatePayloadBudget {return ((Get-WinSecSnapshotSpecification).MaxDocumentBytes-131072)}

function New-WinSecNetworkCandidateSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('o')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity;if($Identity.CheckId -cne 'WSA-NET-005'){throw 'Foreign network candidate control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid network capture operation.'}
    $areas=@(Get-WinSecNetworkCandidateAreas);$inputs=@{};$latest=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'Network configuration requires exact source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','Location','State','Data')
        if($source.SourceId -isnot [string]){throw 'Invalid network source identifier.'};$a=@($areas|Where-Object Id -CEQ $source.SourceId)
        if($a.Count -ne 1 -or $inputs.ContainsKey($source.SourceId) -or $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or
            $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or $source.Location -isnot [string] -or $source.Location -cne $a[0].Location -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign network source, identity or location.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;if($time -lt $start -or $time -gt $end){throw 'Network source outside its operation.'};if($time -gt $latest){$latest=$time}
        if($source.State -ceq 'OBSERVED'){
            if($source.SourceId -cnotin @('Platform','DNSGlobal','Registry')){if($source.Data -isnot [array] -or $source.Data.Rank -ne 1){throw 'Network inventory requires an explicit array.'}}
            elseif($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Network singleton requires ordinary captured data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable network source contains data.'};$inputs[$source.SourceId]=$source
    }
    $capture=[ordered]@{Scope='LOCAL_CONFIGURATION_NO_TRAFFIC_OR_RESOLUTION'}
    foreach($a in $areas){$s=$inputs[$a.Id];$capture[$a.Id+'Time']=$s.CollectedAtUTC;$capture[$a.Id+'SourceState']=$s.State;$capture[$a.Id+'Location']=$s.Location}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture}
    $catalog=Get-WinSecNetworkCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog;$defs=@(Get-WinSecNetworkCandidateFields);$byInventory=@{}
    foreach($i in $catalog.Inventories){$byInventory[$i.Id]=@($defs|Where-Object Inventory -CEQ $i.Id)}
    $batches=New-Object 'Collections.Generic.List[object]';$summaries=@();$payload=0;$limit=Get-WinSecNetworkCandidatePayloadBudget
    $counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0};$stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected';NOT_CONFIGURED='NotConfigured'}
    foreach($i in $catalog.Inventories){
        $source=$inputs[$i.Id];$total=if($i.Singleton){1}elseif($source.State -ceq 'OBSERVED'){$source.Data.Length}else{0}
        $reported=if($source.State -ceq 'OBSERVED'){$total}else{$null};$state=if($i.Singleton){'OBSERVED'}else{$source.State}
        $ok=($source.State -ceq 'OBSERVED');$reason=if($ok){'NONE'}elseif($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}
        $rows=New-Object 'Collections.Generic.List[object]';$bytes=16384;$sequence=1;$retained=0
        for($index=0;$index -lt $total;$index++){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $data=if($i.Singleton){$source.Data}else{$source.Data[$index]}
            if($source.State -ceq 'OBSERVED' -and ($null -eq $data -or $data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]]))){throw 'Unreviewed network captured record.'}
            $lists=@{}
            $readings=@(foreach($d in $byInventory[$i.Id]){
                $r=[pscustomobject]@{FieldId=$d.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
                if($source.State -cne 'OBSERVED'){$r.State=$source.State;$r.Reason=$reason}
                else{
                    $p=Get-WinSecNetworkCapturedProperty $data $d.Property
                    if($d.Kind -cin @('Addresses','ReportedCount','RetainedCount')){
                        if(-not $lists.ContainsKey($d.Property)){$lists[$d.Property]=ConvertTo-WinSecNetworkCandidateList $p $clock $CancellationAction};$list=$lists[$d.Property]
                        if($d.Kind -ceq 'Addresses'){$r.State=$list.State;$r.Reason=$list.Reason;$r.Value=$list.Value}
                        else{$n=if($d.Kind -ceq 'ReportedCount'){$list.Reported}else{$list.Retained};if($null -ne $n){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=$n}else{$r.Reason=$list.Reason}}
                    }elseif(-not $p.Safe){$r.Reason='INVALID_VALUE'}elseif($p.Exists -and $null -ne $p.Value){
                        $raw=$p.Value;$available=$true
                        if($i.Id -ceq 'Registry'){
                            Assert-WinSecSnapshotFields $raw @('State','Kind','Value')
                            if($raw.State -isnot [string] -or $raw.State -cnotin @('OBSERVED','NOT_CONFIGURED','UNKNOWN','ERROR','NOT_COLLECTED')){throw 'Invalid network registry state.'}
                            if($raw.State -ceq 'OBSERVED'){if($raw.Kind -isnot [string] -or $raw.Kind -cne 'DWord'){$available=$false;$r.Reason='INVALID_VALUE'}else{$raw=$raw.Value}}
                            else{if($null -ne $raw.Value -or $null -ne $raw.Kind){throw 'Unverified network registry absence.'};$r.State=$raw.State;$r.Reason=switch($raw.State){NOT_CONFIGURED {'ABSENT'};NOT_COLLECTED {'NOT_REQUESTED'};default {'PROVIDER_UNAVAILABLE'}};$available=$false}
                        }
                        if($available){$v=ConvertTo-WinSecNetworkCandidateValue $raw $d.Kind;if($v.Valid){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=$v.Value}else{$r.Reason='INVALID_VALUE'}}
                    }
                };$r
            })
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
    $integrity=Get-WinSecNetworkCandidateIntegrity $snapshot -CancellationAction $CancellationAction
    foreach($s in $summaries){if($s.Id -cne 'Capture'){$s.Complete=$integrity[$s.Id].Complete;$s.Reason=$integrity[$s.Id].Reason}}
    $required=@{};foreach($d in $defs){$required[$d.Id]=$d.Required}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($summaries|Where-Object {-not $_.Complete}).Count -eq 0)
    foreach($b in $batches){foreach($record in $b.Records){foreach($r in $record.Readings){if($required[$r.FieldId] -and $r.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){$complete=$false}}}}
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]};$snapshot.Collection=[pscustomobject]$collection
    Assert-WinSecNetworkCandidateSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecNetworkCandidateSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-NET-005'){throw 'Foreign network candidate identity.'}
    $catalog=Get-WinSecNetworkCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed network candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$defs=@{};$fixed=@{};$summaries=@{};$listDefs=@(Get-WinSecNetworkCandidateFields|Where-Object Kind -CEQ Addresses)
    foreach($d in Get-WinSecNetworkCandidateFields){$defs[$d.Id]=$d};foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        $local=@{};foreach($r in $record.Readings){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $local[$r.FieldId]=$r;if($b.InventoryId -cin @('Platform','Capture')){$fixed[$r.FieldId]=$r}
            if($r.State -ceq 'NOT_APPLICABLE' -or ($r.State -ceq 'NOT_CONFIGURED' -and $b.InventoryId -cne 'Registry')){throw 'Unverified network exclusion or absence.'}
            if($r.State -cne 'OBSERVED'){continue};$d=$defs[$r.FieldId]
            if($d.Kind -ceq 'Addresses'){
                $p=[pscustomobject]@{Safe=$true;Exists=$true;Value=$r.Value};$list=ConvertTo-WinSecNetworkCandidateList $p $clock $CancellationAction
                if($list.State -cne 'OBSERVED'){throw 'Unreviewed stored address list.'}
            }else{
                $v=ConvertTo-WinSecNetworkCandidateValue $r.Value $d.Kind
                if(-not $v.Valid -or (ConvertTo-Json -InputObject $v.Value -Compress) -cne (ConvertTo-Json -InputObject $r.Value -Compress)){throw 'Unreviewed network candidate value.'}
            }
        }
        foreach($d in $listDefs|Where-Object Inventory -CEQ $b.InventoryId){
            $r=$local[$d.Id];$reported=$local[$d.Id+'ReportedCount'];$retained=$local[$d.Id+'RetainedCount']
            if($r.State -ceq 'OBSERVED'){
                if($reported.State -cne 'OBSERVED' -or $retained.State -cne 'OBSERVED' -or $reported.Value -ne $r.Value.Length -or $retained.Value -ne $r.Value.Length){throw 'Stored address list counts contradict its values.'}
            }elseif($reported.State -ceq 'OBSERVED'){
                if($retained.State -cne 'OBSERVED' -or $retained.Value -ne 0 -or $r.State -cnotin @('UNKNOWN','NOT_COLLECTED') -or
                    $r.Reason -cnotin @('INVALID_VALUE','RESOURCE_LIMIT') -or ($r.Reason -ceq 'RESOURCE_LIMIT' -and ($r.State -cne 'NOT_COLLECTED' -or $reported.Value -eq 0))){throw 'Unverified unretained address list.'}
            }elseif($reported.State -cne $r.State -or $retained.State -cne $r.State -or $reported.Reason -cne $r.Reason -or $retained.Reason -cne $r.Reason){throw 'Unknown address list supplies apparent counts.'}
        }
    }}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){$r=$fixed['Platform.'+$name];$v=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null};if($Snapshot.Platform.$name -cne $v){throw 'Network platform differs from its readings.'}}
    if($null -ne $Snapshot.Platform.UBR -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.OSRelease){throw 'Unobserved network platform metadata.'}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($a in Get-WinSecNetworkCandidateAreas){
        $time=$fixed['Capture.'+$a.Id+'Time'];$state=$fixed['Capture.'+$a.Id+'SourceState'];$location=$fixed['Capture.'+$a.Id+'Location'];$s=$summaries[$a.Id]
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED' -or $location.State -cne 'OBSERVED' -or $location.Value -cne $a.Location){throw 'Missing or foreign network capture metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value;if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'Network source timestamp outside its operation.'};if($stamp -gt $latest){$latest=$stamp}
        if($state.Value -ceq 'OBSERVED'){if($s.State -cne 'OBSERVED' -or $null -eq $s.ReportedRecords){throw 'Observed network source lacks counts.'}}
        else{
            if($null -ne $s.ReportedRecords -or ($a.Id -cnotin @('Platform','DNSGlobal','Registry') -and ($s.State -cne $state.Value -or $s.RetainedRecords -ne 0))){throw 'Unavailable network source claims records.'}
            foreach($b in $Snapshot.Batches|Where-Object InventoryId -CEQ $a.Id){foreach($record in $b.Records){foreach($r in $record.Readings){if($r.State -cne $state.Value){throw 'Unavailable network source supplies readings.'}}}}
        }
    }
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC) -or $fixed['Capture.Scope'].State -cne 'OBSERVED' -or $fixed['Capture.Scope'].Value -cne 'LOCAL_CONFIGURATION_NO_TRAFFIC_OR_RESOLUTION'){throw 'Invalid network capture scope or timestamp.'}
    $expected=Get-WinSecNetworkCandidateIntegrity $Snapshot -CancellationAction $CancellationAction
    foreach($a in Get-WinSecNetworkCandidateAreas){if($summaries[$a.Id].Complete -cne $expected[$a.Id].Complete -or $summaries[$a.Id].Reason -cne $expected[$a.Id].Reason){throw 'Network completion contradicts its captured sources.'}}
}

