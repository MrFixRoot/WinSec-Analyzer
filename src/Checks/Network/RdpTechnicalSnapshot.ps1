# Prepared-data candidate only. No Windows, user-session, network or certificate queries.
. (Join-Path $PSScriptRoot 'RdpTechnicalCatalog.ps1')

function Get-WinSecRdpCapturedProperty {
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

function ConvertTo-WinSecRdpCandidateValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    $valid=$false;$converted=$null
    if($null -ne $Value){switch -CaseSensitive ($Kind){
        Boolean {if($Value -is [bool]){$valid=$true;$converted=$Value}}
        {$_ -cin @('UInt32','Build','RegistryDWord')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if([uint32]::TryParse($Value,[ref]$n)){$Value=$n}}
            if($Kind -ceq 'RegistryDWord' -and $Value -is [int] -and $Value -lt 0){$Value=[uint32]([long]$Value -band 4294967295L)}
            if(Test-WinSecSnapshotUInt $Value){$valid=$true;$converted=[uint32]$Value}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){$valid=$true;$converted=$Value}}
        Listener {if($Value -is [string] -and $Value -cmatch '\A[\p{L}\p{Nd}][\p{L}\p{M}\p{Nd}_. -]{0,255}\z'){$valid=$true;$converted=$Value}}
        Protocol {if($Value -is [string] -and $Value -cmatch '\AMicrosoft RDP [0-9]{1,2}\.[0-9]{1,2}\z'){$valid=$true;$converted=$Value}}
        Transport {if($Value -is [string] -and $Value -cin @('TCP','NetBIOS','IPX/SPX')){$valid=$true;$converted=$Value}}
        ServiceName {if($Value -is [string]){foreach($name in @('TermService','UmRdpService','SessionEnv')){if([string]::Equals($Value,$name,[StringComparison]::OrdinalIgnoreCase)){$valid=$true;$converted=$name;break}}}}
        ServiceState {if($Value -is [string] -and $Value -cin @('Stopped','Start Pending','Stop Pending','Running','Continue Pending','Pause Pending','Paused','Unknown')){$valid=$true;$converted=$Value}}
        StartMode {if($Value -is [string] -and $Value -cin @('Boot','System','Auto','Manual','Disabled')){$valid=$true;$converted=$Value}}
        ErrorControl {if($Value -is [string] -and $Value -cin @('Ignore','Normal','Severe','Critical','Unknown')){$valid=$true;$converted=$Value}}
        Time {try{$date=ConvertTo-WinSecSnapshotUtc $Value;$valid=$true;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}catch{}}
        SourceState {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED','NOT_APPLICABLE')){$valid=$true;$converted=$Value}}
        Location {if($Value -is [string] -and $Value -cin @('CIMV2','TERMINALSERVICES','HKLM_REGISTRY64')){$valid=$true;$converted=$Value}}
        Scope {if($Value -is [string] -and $Value -ceq 'LOCAL_RDP_CONFIGURATION_NO_USER_SESSIONS'){$valid=$true;$converted=$Value}}
    }}
    [pscustomobject]@{Valid=$valid;Value=$converted}
}

function Get-WinSecRdpCandidatePlatform {
    param([object]$Source)
    $p=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    if($Source.State -ceq 'OBSERVED'){foreach($d in Get-WinSecRdpCandidateFields|Where-Object Inventory -CEQ Platform){
        $property=Get-WinSecRdpCapturedProperty $Source.Data $d.Property;if($property.Safe){$v=ConvertTo-WinSecRdpCandidateValue $property.Value $d.Kind;if($v.Valid){$p.($d.Property)=$v.Value}}
    }};return $p
}

function Get-WinSecRdpCandidatePlatformProof {
    param([object]$Platform)
    $client=($null -ne $Platform.Version -and $null -ne $Platform.BuildNumber -and $Platform.BuildNumber -ge 22000 -and
        $Platform.Version -ceq ('10.0.'+$Platform.BuildNumber) -and $Platform.ProductType -eq 1 -and $null -ne $Platform.OperatingSystemSKU)
    [pscustomobject]@{Client=$client;Home=($client -and $Platform.OperatingSystemSKU -cin @(98,99,100,101));
        KnownHost=($client -and $Platform.OperatingSystemSKU -cin @(4,27,48,49,121,122,125,126,161,162,164,165,188,191))}
}

function Get-WinSecRdpCandidateIntegrity {
    param([object]$Snapshot,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$meta=@{};$summaries=@{};$records=@{};$result=@{};$proof=Get-WinSecRdpCandidatePlatformProof $Snapshot.Platform
    foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($b.InventoryId -ceq 'Capture'){foreach($r in $record.Readings){$meta[$r.FieldId]=$r};continue}
        if(-not $records.ContainsKey($b.InventoryId)){$records[$b.InventoryId]=New-Object 'Collections.Generic.List[object]'};$records[$b.InventoryId].Add($record)
    }}
    foreach($a in Get-WinSecRdpCandidateAreas){
        $s=$summaries[$a.Id];$state=$meta['Capture.'+$a.Id+'SourceState'].Value
        if($state -ceq 'NOT_APPLICABLE'){
            if(-not $a.Host -or -not $proof.Home){throw 'Unverified RDP host exclusion.'}
            $result[$a.Id]=[pscustomobject]@{Complete=$true;Reason='PLATFORM_EXCLUDED'};continue
        }
        $ok=($state -ceq 'OBSERVED' -and $null -ne $s.ReportedRecords -and $s.ReportedRecords -eq $s.RetainedRecords)
        $reason=if($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}elseif($state -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}elseif(-not $ok){'RESOURCE_LIMIT'}else{'NONE'}
        if($ok -and ($a.Id -ceq 'Services' -or ($a.Host -and $a.Id -cne 'Global'))){
            $seen=New-Object 'Collections.Generic.Dictionary[string,int]' ([StringComparer]::OrdinalIgnoreCase);$invalid=$false
            if($records.ContainsKey($a.Id)){foreach($record in $records[$a.Id]){
                $field=if($a.Id -ceq 'Services'){'Services.Name'}else{$a.Id+'.TerminalName'};$id=@($record.Readings|Where-Object FieldId -CEQ $field)[0]
                if($id.State -cne 'OBSERVED'){$invalid=$true;continue}
                if($seen.ContainsKey($id.Value)){$seen[$id.Value]++;$invalid=$true}else{$seen[$id.Value]=1}
            }}
            if($invalid){$ok=$false;$reason='INVALID_VALUE'}elseif($seen.Count -eq 0 -or ($a.Id -ceq 'Services' -and $seen.Count -ne 3)){$ok=$false;$reason='PROVIDER_UNAVAILABLE'}
        }
        if($ok -and $a.Host -and -not $proof.Home -and -not $proof.KnownHost){$ok=$false;$reason='PROVIDER_UNAVAILABLE'}
        if($ok -and $a.Id -cin @('Global','General')){foreach($record in $records[$a.Id]){foreach($r in $record.Readings){
            $allowed=switch -CaseSensitive ($r.FieldId){Global.AllowTSConnections {@(0,1)};General.UserAuthenticationRequired {@(0,1)};General.MinEncryptionLevel {@(1,2,3,4)};General.SecurityLayer {@(0,1,2,3,4)};default {@()}}
            if($allowed.Count -and ($r.State -cne 'OBSERVED' -or $r.Value -cnotin $allowed)){$ok=$false;$reason=if($r.State -ceq 'OBSERVED'){'INVALID_VALUE'}else{'PROVIDER_UNAVAILABLE'}}
        }}}
        if($ok -and $a.Id -ceq 'Registry'){foreach($record in $records.Registry){foreach($r in $record.Readings){
            if($r.State -cne 'OBSERVED'){continue}
            $max=switch -CaseSensitive ($r.FieldId){Registry.ListenerPort {65535};Registry.ListenerSecurityLayer {2};Registry.ListenerEncryption {4};default {1}}
            if($r.Value -gt $max -or ($r.FieldId -ceq 'Registry.ListenerPort' -and $r.Value -lt 1)){$ok=$false;$reason='INVALID_VALUE'}
        }}}
        $result[$a.Id]=[pscustomobject]@{Complete=$ok;Reason=$reason}
    };return $result
}

function Get-WinSecRdpCandidatePayloadBudget {return ((Get-WinSecSnapshotSpecification).MaxDocumentBytes-131072)}

function New-WinSecRdpCandidateSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('o')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity;if($Identity.CheckId -cne 'WSA-NET-003'){throw 'Foreign RDP candidate control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid RDP capture operation.'}
    $areas=@(Get-WinSecRdpCandidateAreas);$inputs=@{};$latest=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'RDP requires the exact reviewed capture receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','Location','State','Data')
        if($source.SourceId -isnot [string]){throw 'Invalid RDP source identifier.'};$a=@($areas|Where-Object Id -CEQ $source.SourceId)
        if($a.Count -ne 1 -or $inputs.ContainsKey($source.SourceId) -or $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or
            $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or $source.Location -isnot [string] -or $source.Location -cne $a[0].Location -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED','NOT_APPLICABLE')){throw 'Foreign RDP source, identity or location.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;if($time -lt $start -or $time -gt $end){throw 'RDP source outside its operation.'};if($time -gt $latest){$latest=$time}
        if($source.State -ceq 'OBSERVED'){
            if($source.SourceId -cnotin @('Platform','Global','Registry')){if($source.Data -isnot [array] -or $source.Data.Rank -ne 1){throw 'RDP inventory requires an explicit array.'}}
            elseif($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'RDP singleton requires ordinary captured data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable RDP source contains data.'};$inputs[$source.SourceId]=$source
    }
    $platform=Get-WinSecRdpCandidatePlatform $inputs.Platform;$proof=Get-WinSecRdpCandidatePlatformProof $platform
    foreach($a in $areas){if($inputs[$a.Id].State -ceq 'NOT_APPLICABLE' -and (-not $a.Host -or -not $proof.Home)){throw 'Unverified captured RDP exclusion.'}}
    $capture=[ordered]@{Scope='LOCAL_RDP_CONFIGURATION_NO_USER_SESSIONS'}
    foreach($a in $areas){$s=$inputs[$a.Id];$capture[$a.Id+'Time']=$s.CollectedAtUTC;$capture[$a.Id+'SourceState']=$s.State;$capture[$a.Id+'Location']=$s.Location}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture}
    $catalog=Get-WinSecRdpCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog;$defs=@(Get-WinSecRdpCandidateFields);$byInventory=@{}
    foreach($i in $catalog.Inventories){$byInventory[$i.Id]=@($defs|Where-Object Inventory -CEQ $i.Id)}
    $batches=New-Object 'Collections.Generic.List[object]';$summaries=@();$payload=0;$limit=Get-WinSecRdpCandidatePayloadBudget
    $counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0};$stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected';NOT_CONFIGURED='NotConfigured';NOT_APPLICABLE='NotApplicable'}
    foreach($i in $catalog.Inventories){
        $source=$inputs[$i.Id];$excluded=($source.State -ceq 'NOT_APPLICABLE')
        $total=if($excluded){0}elseif($i.Singleton){1}elseif($source.State -ceq 'OBSERVED'){$source.Data.Length}else{0}
        $reported=if($source.State -ceq 'OBSERVED'){$total}else{$null};$state=if($i.Singleton -and -not $excluded){'OBSERVED'}else{$source.State}
        $ok=($source.State -ceq 'OBSERVED' -or $excluded);$reason=if($excluded){'PLATFORM_EXCLUDED'}elseif($ok){'NONE'}elseif($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}
        $rows=New-Object 'Collections.Generic.List[object]';$bytes=16384;$sequence=1;$retained=0
        for($index=0;$index -lt $total;$index++){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $data=if($i.Singleton){$source.Data}else{$source.Data[$index]}
            if($source.State -ceq 'OBSERVED' -and ($null -eq $data -or $data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]]))){throw 'Unreviewed RDP captured record.'}
            $readings=@(foreach($d in $byInventory[$i.Id]){
                $r=[pscustomobject]@{FieldId=$d.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
                if($source.State -cne 'OBSERVED'){$r.State=$source.State;$r.Reason=$reason}
                else{
                    $p=Get-WinSecRdpCapturedProperty $data $d.Property
                    if(-not $p.Safe){$r.Reason='INVALID_VALUE'}elseif($p.Exists -and $null -ne $p.Value){
                        $raw=$p.Value;$available=$true
                        if($i.Id -ceq 'Registry'){
                            Assert-WinSecSnapshotFields $raw @('State','Kind','Value')
                            if($raw.State -isnot [string] -or $raw.State -cnotin @('OBSERVED','NOT_CONFIGURED','UNKNOWN','ERROR','NOT_COLLECTED')){throw 'Invalid RDP registry state.'}
                            if($raw.State -ceq 'OBSERVED'){if($raw.Kind -isnot [string] -or $raw.Kind -cne 'DWord'){$available=$false;$r.Reason='INVALID_VALUE'}else{$raw=$raw.Value}}
                            else{
                                if($null -ne $raw.Value -or $null -ne $raw.Kind){throw 'Unverified RDP registry absence.'}
                                $r.State=$raw.State;$r.Reason=switch($raw.State){NOT_CONFIGURED {'ABSENT'};NOT_COLLECTED {'NOT_REQUESTED'};default {'PROVIDER_UNAVAILABLE'}};$available=$false
                            }
                        }
                        if($available){$v=ConvertTo-WinSecRdpCandidateValue $raw $d.Kind;if($v.Valid){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=$v.Value}else{$r.Reason='INVALID_VALUE'}}
                    }
                }
                if($d.Kind -cin @('Listener','ServiceName') -and $source.State -ceq 'OBSERVED' -and $r.State -cne 'OBSERVED'){throw 'Unidentifiable RDP inventory record.'};$r
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
    $snapshot=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$owner;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$hash;CollectorVersion='1.0.0';
        StartedAtUTC=$StartedAtUTC;CollectedAtUTC=$latest.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);CompletedAtUTC=$CompletedAtUTC;GeneratedAtUTC=$GeneratedAtUTC;
        Platform=$platform;SelectedProfile=$SelectedProfile;Collection=$null;Inventories=$summaries;Batches=$batches.ToArray()}
    $integrity=Get-WinSecRdpCandidateIntegrity $snapshot -CancellationAction $CancellationAction
    foreach($s in $summaries){if($s.Id -cne 'Capture'){$s.Complete=$integrity[$s.Id].Complete;$s.Reason=$integrity[$s.Id].Reason}}
    $required=@{};foreach($d in $defs){$required[$d.Id]=$d.Required}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($summaries|Where-Object {-not $_.Complete}).Count -eq 0)
    foreach($b in $batches){foreach($record in $b.Records){foreach($r in $record.Readings){if($required[$r.FieldId] -and $r.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){$complete=$false}}}}
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]};$snapshot.Collection=[pscustomobject]$collection
    Assert-WinSecRdpCandidateSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecRdpCandidateSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-NET-003'){throw 'Foreign RDP candidate identity.'}
    $catalog=Get-WinSecRdpCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed RDP candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$defs=@{};$fixed=@{};$summaries=@{};$proof=Get-WinSecRdpCandidatePlatformProof $Snapshot.Platform
    foreach($d in Get-WinSecRdpCandidateFields){$defs[$d.Id]=$d};foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){foreach($r in $record.Readings){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($b.InventoryId -cin @('Platform','Capture')){$fixed[$r.FieldId]=$r}
        if($r.State -ceq 'NOT_CONFIGURED' -and $b.InventoryId -cne 'Registry'){throw 'Unverified RDP absence outside Registry64.'}
        # Contract v2.0 has no reviewed per-property retirement predicate. Do not manufacture one using SKU/build ranges.
        if($r.State -ceq 'NOT_APPLICABLE'){throw 'Unverified RDP field exclusion.'}
        if($r.State -cne 'OBSERVED'){continue};$v=ConvertTo-WinSecRdpCandidateValue $r.Value $defs[$r.FieldId].Kind
        if(-not $v.Valid -or (ConvertTo-Json -InputObject $v.Value -Compress) -cne (ConvertTo-Json -InputObject $r.Value -Compress)){throw 'Unreviewed RDP candidate value.'}
    }}}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){$r=$fixed['Platform.'+$name];$v=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null};if($Snapshot.Platform.$name -cne $v){throw 'RDP platform differs from its readings.'}}
    if($null -ne $Snapshot.Platform.UBR -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.OSRelease){throw 'Unobserved RDP platform metadata.'}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($a in Get-WinSecRdpCandidateAreas){
        $time=$fixed['Capture.'+$a.Id+'Time'];$state=$fixed['Capture.'+$a.Id+'SourceState'];$location=$fixed['Capture.'+$a.Id+'Location'];$s=$summaries[$a.Id]
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED' -or $location.State -cne 'OBSERVED' -or $location.Value -cne $a.Location){throw 'Missing or foreign RDP capture metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value;if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'RDP source timestamp outside operation.'};if($stamp -gt $latest){$latest=$stamp}
        if($state.Value -ceq 'OBSERVED'){if($s.State -cne 'OBSERVED' -or $null -eq $s.ReportedRecords){throw 'RDP observed source has no counts.'}}
        elseif($state.Value -ceq 'NOT_APPLICABLE'){
            if(-not $a.Host -or -not $proof.Home -or $s.State -cne 'NOT_APPLICABLE' -or $s.RetainedRecords -ne 0 -or $null -ne $s.ReportedRecords){throw 'Unverified RDP host exclusion.'}
        }else{
            if($null -ne $s.ReportedRecords -or ($a.Id -cnotin @('Platform','Global','Registry') -and ($s.State -cne $state.Value -or $s.RetainedRecords -ne 0))){throw 'Unavailable RDP source claims records.'}
            foreach($b in $Snapshot.Batches|Where-Object InventoryId -CEQ $a.Id){foreach($record in $b.Records){foreach($r in $record.Readings){if($r.State -cne $state.Value){throw 'Unavailable RDP source supplies readings.'}}}}
        }
    }
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC) -or $fixed['Capture.Scope'].State -cne 'OBSERVED' -or $fixed['Capture.Scope'].Value -cne 'LOCAL_RDP_CONFIGURATION_NO_USER_SESSIONS'){throw 'Invalid RDP scope or timestamp.'}
    $expected=Get-WinSecRdpCandidateIntegrity $Snapshot -CancellationAction $CancellationAction
    foreach($a in Get-WinSecRdpCandidateAreas){if($summaries[$a.Id].Complete -cne $expected[$a.Id].Complete -or $summaries[$a.Id].Reason -cne $expected[$a.Id].Reason){throw 'RDP completion contradicts its captured sources.'}}
}
