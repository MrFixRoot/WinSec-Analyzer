# Prepared local group receipts only. No SAM queries, SID translation, domain or cloud lookup.
. (Join-Path $PSScriptRoot 'LocalAdminsTechnicalCatalog.ps1')

function Get-WinSecLocalAdminsCapturedProperty {
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

function ConvertTo-WinSecLocalAdminsCandidateValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    $valid=$false;$converted=$null
    if($null -ne $Value){switch -CaseSensitive ($Kind){
        Boolean {if($Value -is [bool]){$valid=$true;$converted=$Value}}
        {$_ -cin @('UInt32','UInt8','Build','PageSequence','ProvidedCount','Level')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if([uint32]::TryParse($Value,[ref]$n)){$Value=$n}}
            $max=if($Kind -ceq 'UInt8'){255}else{4294967295}
            if(Test-WinSecSnapshotUInt $Value $max){$valid=$true;$converted=[uint32]$Value}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){$valid=$true;$converted=$Value}}
        GroupSID {if($Value -is [string] -and $Value -ceq 'S-1-5-32-544'){$valid=$true;$converted=$Value}}
        SID {
            if($Value -is [string] -and $Value.Length -le 184 -and $Value -cmatch '\AS-1-[0-9]+(?:-[0-9]+){1,15}\z'){
                try{$sid=[Security.Principal.SecurityIdentifier]::new($Value);if($sid.Value -ceq $Value){$valid=$true;$converted=$Value}}catch{}
            }
        }
        GroupName {
            if($Value -is [string] -and $Value.Length -le 256 -and -not [string]::IsNullOrWhiteSpace($Value) -and
                $Value -notmatch '[\p{C}\p{Zl}\p{Zp}"/\\\[\]:|<>+=;,?*]' -and -not $Value.EndsWith('.')){$valid=$true;$converted=$Value}
        }
        Time {try{$date=ConvertTo-WinSecSnapshotUtc $Value;$valid=$true;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}catch{}}
        SourceState {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED')){$valid=$true;$converted=$Value}}
        Location {if($Value -is [string] -and $Value -cin @('CIMV2','LOCAL_NETAPI_LEVEL0')){$valid=$true;$converted=$Value}}
        Scope {if($Value -is [string] -and $Value -ceq 'DIRECT_LOCAL_ADMINISTRATORS_MEMBERSHIP_ONLY'){$valid=$true;$converted=$Value}}
        NotPerformed {if($Value -is [string] -and $Value -ceq 'NOT_PERFORMED'){$valid=$true;$converted=$Value}}
        NotObserved {if($Value -is [string] -and $Value -ceq 'NOT_OBSERVED'){$valid=$true;$converted=$Value}}
        TotalMeaning {if($Value -is [string] -and $Value -ceq 'PROVIDER_REMAINING_AT_EACH_CALL'){$valid=$true;$converted=$Value}}
    }};[pscustomobject]@{Valid=$valid;Value=$converted}
}

function Get-WinSecLocalAdminsCandidateIntegrity {
    param([object]$Snapshot,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$meta=@{};$summaries=@{};$records=@{};$result=@{}
    foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($b.InventoryId -ceq 'Capture'){foreach($r in $record.Readings){$meta[$r.FieldId]=$r}}
        else{if(-not $records.ContainsKey($b.InventoryId)){$records[$b.InventoryId]=New-Object 'Collections.Generic.List[object]'}
            $v=@{};foreach($r in $record.Readings){$v[$r.FieldId.Substring($b.InventoryId.Length+1)]=$r};$records[$b.InventoryId].Add($v)}
    }}
    foreach($i in (Get-WinSecLocalAdminsCandidateCatalog).Inventories|Where-Object Id -CNE Capture){
        $s=$summaries[$i.Id];$state=$meta['Capture.'+$i.SourceId+'SourceState'].Value
        $ok=($state -ceq 'OBSERVED' -and $null -ne $s.ReportedRecords -and $s.ReportedRecords -eq $s.RetainedRecords)
        $reason=if($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}elseif($state -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}elseif(-not $ok){'RESOURCE_LIMIT'}else{'NONE'}
        $result[$i.Id]=[pscustomobject]@{Complete=$ok;Reason=$reason}
    }
    if($records.ContainsKey('Group')){foreach($g in $records.Group){if($g.SIDType.State -ceq 'OBSERVED' -and $g.SIDType.Value -ne 4){$result.Group.Complete=$false;$result.Group.Reason='INVALID_VALUE'}}}
    if($meta['Capture.MembersSourceState'].Value -ceq 'OBSERVED'){
        $pages=@{};$provided=[long]0;$allCounts=$true;$invalid=$false;$unfinished=$false;$pageIndex=0
        foreach($p in $records.Pages){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$pageIndex++
            if($p.Sequence.State -cne 'OBSERVED' -or $p.Sequence.Value -ne $pageIndex -or $p.ProvidedMemberCount.State -cne 'OBSERVED'){throw 'Unverified local member page identity or count.'}
            $pages[[string]$p.Sequence.Value]=$p;$provided+=$p.ProvidedMemberCount.Value
            if($p.EntriesRead.State -cne 'OBSERVED'){$allCounts=$false}elseif($p.EntriesRead.Value -ne $p.ProvidedMemberCount.Value){$invalid=$true}
            if($p.Status.State -cne 'OBSERVED' -or $p.ResumePending.State -cne 'OBSERVED'){$unfinished=$true;continue}
            if($p.Sequence.Value -lt $summaries.Pages.ReportedRecords){
                if($p.Status.Value -ne 234 -or $p.ResumePending.Value -cne $true -or ($p.EntriesRead.State -ceq 'OBSERVED' -and $p.EntriesRead.Value -eq 0)){$invalid=$true}
            }else{
                if($p.Status.Value -ne 0){$unfinished=$true}elseif($p.ResumePending.Value -cne $false){$invalid=$true}
            }
        }
        if($result.Pages.Complete -and ($pageIndex -eq 0 -or -not $allCounts)){$unfinished=$true}
        if($result.Pages.Complete -and $provided -ne $summaries.Members.ReportedRecords){$invalid=$true}
        $seen=@{};$retainedByPage=@{}
        foreach($member in $records.Members){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            if($member.PageSequence.State -cne 'OBSERVED' -or -not $pages.ContainsKey([string]$member.PageSequence.Value)){throw 'Member has no retained parent page.'}
            $key=[string]$member.PageSequence.Value;if(-not $retainedByPage.ContainsKey($key)){$retainedByPage[$key]=0};$retainedByPage[$key]++
            if($retainedByPage[$key] -gt $pages[$key].ProvidedMemberCount.Value){throw 'Member page exceeds its provided count.'}
            if($member.SID.State -ceq 'OBSERVED'){$sid=$member.SID.Value;if($seen.ContainsKey($sid)){$invalid=$true};$seen[$sid]=$true}
        }
        if($result.Members.Complete -and $result.Pages.Complete){foreach($key in $pages.Keys){if([long]$retainedByPage[$key] -ne $pages[$key].ProvidedMemberCount.Value){throw 'Member counts differ from their parent pages.'}}}
        foreach($id in @('Pages','Members')){
            if($invalid -or $unfinished){$result[$id].Complete=$false;if($result[$id].Reason -cne 'RESOURCE_LIMIT'){$result[$id].Reason=$(if($invalid){'INVALID_VALUE'}else{'PROVIDER_UNAVAILABLE'})}}
        }
        if(-not $result.Pages.Complete){$result.Members.Complete=$false;if($result.Members.Reason -ceq 'NONE'){$result.Members.Reason=$result.Pages.Reason}}
    };return $result
}

function Get-WinSecLocalAdminsCandidatePayloadBudget {return ((Get-WinSecSnapshotSpecification).MaxDocumentBytes-131072)}

function New-WinSecLocalAdminsCandidateSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('o')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity;if($Identity.CheckId -cne 'WSA-IAM-001'){throw 'Foreign Local Administrators candidate control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid local group capture operation.'}
    $areas=@(Get-WinSecLocalAdminsCandidateAreas);$inputs=@{};$latest=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'Local Administrators requires exact source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','Location','State','Data')
        if($source.SourceId -isnot [string]){throw 'Invalid local group source identifier.'};$a=@($areas|Where-Object Id -CEQ $source.SourceId)
        if($a.Count -ne 1 -or $inputs.ContainsKey($source.SourceId) -or $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or
            $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or $source.Location -isnot [string] -or $source.Location -cne $a[0].Location -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign local group source, identity or location.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;if($time -lt $start -or $time -gt $end){throw 'Local group source outside its operation.'};if($time -gt $latest){$latest=$time}
        if($source.State -ceq 'OBSERVED'){
            if($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Local group source requires ordinary captured data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable local group source contains data.'};$inputs[$source.SourceId]=$source
    }
    if($inputs.Group.State -ceq 'OBSERVED'){
        $sid=Get-WinSecLocalAdminsCapturedProperty $inputs.Group.Data SID;$local=Get-WinSecLocalAdminsCapturedProperty $inputs.Group.Data LocalAccount
        if(-not $sid.Safe -or $sid.Value -isnot [string] -or $sid.Value -cne 'S-1-5-32-544' -or -not $local.Safe -or $local.Value -isnot [bool] -or $local.Value -cne $true){throw 'Unverified local Administrators group identity.'}
    }
    $capture=[ordered]@{Scope='DIRECT_LOCAL_ADMINISTRATORS_MEMBERSHIP_ONLY';RequestedGroupSID='S-1-5-32-544';RequestedAPILevel=[uint32]0;
        DomainExpansion='NOT_PERFORMED';CloudResolution='NOT_PERFORMED';PolicyAuthority='NOT_OBSERVED';TotalEntriesMeaning='PROVIDER_REMAINING_AT_EACH_CALL'}
    foreach($a in $areas){$s=$inputs[$a.Id];$capture[$a.Id+'Time']=$s.CollectedAtUTC;$capture[$a.Id+'SourceState']=$s.State;$capture[$a.Id+'Location']=$s.Location}
    $state=$inputs.Members.State;$members=$null;$pages=$null
    if($state -ceq 'OBSERVED'){
        if($inputs.Group.State -cne 'OBSERVED' -or (ConvertTo-WinSecSnapshotUtc $inputs.Group.CollectedAtUTC) -gt (ConvertTo-WinSecSnapshotUtc $inputs.Members.CollectedAtUTC)){throw 'Unbound or premature local membership capture.'}
        $raw=$inputs.Members.Data;Assert-WinSecSnapshotFields $raw @('GroupSID','Level','Pages')
        if($raw.GroupSID -isnot [string] -or $raw.GroupSID -cne 'S-1-5-32-544' -or -not (Test-WinSecSnapshotUInt $raw.Level) -or $raw.Level -ne 0 -or
            $raw.Pages -isnot [array] -or $raw.Pages.Rank -ne 1){throw 'Unreviewed membership scope or API level.'}
        $members=New-Object 'Collections.Generic.List[object]';$pages=New-Object 'Collections.Generic.List[object]';$sequence=0
        foreach($page in $raw.Pages){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;Assert-WinSecSnapshotFields $page @('Status','EntriesRead','TotalEntries','ResumePending','Records')
            if($page.Records -isnot [array] -or $page.Records.Rank -ne 1){throw 'Local membership page requires an explicit record array.'};$sequence++
            $pages.Add([pscustomobject]@{Sequence=[uint32]$sequence;Status=$page.Status;EntriesRead=$page.EntriesRead;TotalEntries=$page.TotalEntries;ResumePending=$page.ResumePending;ProvidedMemberCount=[uint32]$page.Records.Length})
            foreach($record in $page.Records){Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
                if($null -eq $record -or $record.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Unreviewed local member record.'}
                $members.Add([pscustomobject]@{Record=$record;PageSequence=[uint32]$sequence})
            }
        };$members=$members.ToArray();$pages=$pages.ToArray()
    }
    $inputs.Members=[pscustomobject]@{State=$state;Data=$members};$inputs.Pages=[pscustomobject]@{State=$state;Data=$pages}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture}
    $catalog=Get-WinSecLocalAdminsCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog;$defs=@(Get-WinSecLocalAdminsCandidateFields);$byInventory=@{}
    foreach($i in $catalog.Inventories){$byInventory[$i.Id]=@($defs|Where-Object Inventory -CEQ $i.Id)}
    $batches=New-Object 'Collections.Generic.List[object]';$summaries=@();$payload=0;$limit=Get-WinSecLocalAdminsCandidatePayloadBudget;$retainedPages=@{}
    $counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0};$stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected'}
    foreach($i in $catalog.Inventories){
        $source=$inputs[$i.Id];$total=if($i.Singleton){1}elseif($source.State -ceq 'OBSERVED'){$source.Data.Length}else{0}
        $reported=if($source.State -ceq 'OBSERVED'){$total}else{$null};$inventoryState=if($i.Singleton){'OBSERVED'}else{$source.State}
        $ok=($source.State -ceq 'OBSERVED');$reason=if($ok){'NONE'}elseif($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}
        $rows=New-Object 'Collections.Generic.List[object]';$bytes=16384;$batchSequence=1;$retained=0
        for($index=0;$index -lt $total;$index++){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $data=if($i.Singleton){$source.Data}else{$source.Data[$index]}
            if($i.Id -ceq 'Members' -and -not $retainedPages.ContainsKey([string]$data.PageSequence)){$ok=$false;$reason='RESOURCE_LIMIT';break}
            $readings=@(foreach($d in $byInventory[$i.Id]){
                $r=[pscustomobject]@{FieldId=$d.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
                if($source.State -cne 'OBSERVED'){$r.State=$source.State;$r.Reason=$reason}
                else{
                    $rawData=if($i.Id -ceq 'Members' -and $d.Property -ceq 'SID'){$data.Record}else{$data}
                    $p=Get-WinSecLocalAdminsCapturedProperty $rawData $d.Property
                    if(-not $p.Safe){$r.Reason='INVALID_VALUE'}elseif($p.Exists -and $null -ne $p.Value){
                        $v=ConvertTo-WinSecLocalAdminsCandidateValue $p.Value $d.Kind
                        if($v.Valid){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=$v.Value}else{$r.Reason='INVALID_VALUE'}
                    }
                };$r
            })
            $record=[pscustomobject]@{Id=($i.Id+$index);Readings=$readings};$size=512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $record -Depth 8 -Compress))
            if(-not $i.Singleton -and ($payload+$size) -gt $limit){$ok=$false;$reason='RESOURCE_LIMIT';break}
            if($rows.Count -and ($rows.Count -ge 128 -or ($bytes+$size) -gt (Get-WinSecSnapshotSpecification).MaxBatchBytes)){
                $batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$i.Id;Sequence=$batchSequence;Records=$rows.ToArray()});$rows.Clear();$batchSequence++;$bytes=16384
            }
            $payload+=$size;$bytes+=$size;$rows.Add($record);$retained++;$counts.RetainedRecords++;foreach($r in $readings){$counts[$stateCount[$r.State]]++}
            if($i.Id -ceq 'Pages'){$retainedPages[[string]$data.Sequence]=$true}
            if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{InventoryId=$i.Id;RetainedRecords=$retained;ReportedRecords=$reported})}
        }
        if($rows.Count){$batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$i.Id;Sequence=$batchSequence;Records=$rows.ToArray()})}
        $summaries+=,[pscustomobject]@{Id=$i.Id;State=$inventoryState;Complete=$ok;ReportedRecords=$reported;RetainedRecords=$retained;Reason=$reason}
    }
    $platform=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    foreach($r in $batches[0].Records[0].Readings){if($r.State -ceq 'OBSERVED'){$platform.($r.FieldId.Substring(9))=$r.Value}}
    $snapshot=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$owner;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$hash;CollectorVersion='1.0.0';
        StartedAtUTC=$StartedAtUTC;CollectedAtUTC=$latest.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);CompletedAtUTC=$CompletedAtUTC;GeneratedAtUTC=$GeneratedAtUTC;
        Platform=$platform;SelectedProfile=$SelectedProfile;Collection=$null;Inventories=$summaries;Batches=$batches.ToArray()}
    $integrity=Get-WinSecLocalAdminsCandidateIntegrity $snapshot -CancellationAction $CancellationAction
    foreach($s in $summaries){if($s.Id -cne 'Capture'){$s.Complete=$integrity[$s.Id].Complete;$s.Reason=$integrity[$s.Id].Reason}}
    $required=@{};foreach($d in $defs){$required[$d.Id]=$d.Required}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($summaries|Where-Object {-not $_.Complete}).Count -eq 0)
    foreach($b in $batches){foreach($record in $b.Records){foreach($r in $record.Readings){if($required[$r.FieldId] -and $r.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){$complete=$false}}}}
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]};$snapshot.Collection=[pscustomobject]$collection
    Assert-WinSecLocalAdminsCandidateSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecLocalAdminsCandidateSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-IAM-001'){throw 'Foreign Local Administrators candidate identity.'}
    $catalog=Get-WinSecLocalAdminsCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed Local Administrators candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$defs=@{};$fixed=@{};$summaries=@{}
    foreach($d in Get-WinSecLocalAdminsCandidateFields){$defs[$d.Id]=$d};foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){foreach($r in $record.Readings){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($b.InventoryId -cin @('Platform','Group','Capture')){$fixed[$r.FieldId]=$r}
        if($r.State -cin @('NOT_CONFIGURED','NOT_APPLICABLE')){throw 'Unverified local group absence or exclusion.'}
        if($r.State -cne 'OBSERVED'){continue};$v=ConvertTo-WinSecLocalAdminsCandidateValue $r.Value $defs[$r.FieldId].Kind
        if(-not $v.Valid -or (ConvertTo-Json -InputObject $v.Value -Compress) -cne (ConvertTo-Json -InputObject $r.Value -Compress)){throw 'Unreviewed local group candidate value.'}
    }}}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){$r=$fixed['Platform.'+$name];$v=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null};if($Snapshot.Platform.$name -cne $v){throw 'Local group platform differs from its readings.'}}
    if($null -ne $Snapshot.Platform.UBR -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.OSRelease){throw 'Unobserved local group platform metadata.'}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($a in Get-WinSecLocalAdminsCandidateAreas){
        $time=$fixed['Capture.'+$a.Id+'Time'];$state=$fixed['Capture.'+$a.Id+'SourceState'];$location=$fixed['Capture.'+$a.Id+'Location']
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED' -or $location.State -cne 'OBSERVED' -or $location.Value -cne $a.Location){throw 'Missing or foreign local group source metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value;if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'Local group timestamp outside its operation.'};if($stamp -gt $latest){$latest=$stamp}
        foreach($i in $catalog.Inventories|Where-Object SourceId -CEQ $a.Id){$s=$summaries[$i.Id]
            if($state.Value -ceq 'OBSERVED'){if($s.State -cne 'OBSERVED' -or $null -eq $s.ReportedRecords){throw 'Observed local group source lacks counts.'}}
            else{
                if($null -ne $s.ReportedRecords -or (-not $i.Singleton -and ($s.State -cne $state.Value -or $s.RetainedRecords -ne 0))){throw 'Unavailable local group source claims records.'}
                foreach($b in $Snapshot.Batches|Where-Object InventoryId -CEQ $i.Id){foreach($record in $b.Records){foreach($r in $record.Readings){if($r.State -cne $state.Value){throw 'Unavailable local group source supplies readings.'}}}}
            }
        }
    }
    if($fixed['Capture.GroupSourceState'].Value -ceq 'OBSERVED'){
        if($fixed['Group.SID'].State -cne 'OBSERVED' -or $fixed['Group.SID'].Value -cne 'S-1-5-32-544' -or $fixed['Group.LocalAccount'].State -cne 'OBSERVED' -or $fixed['Group.LocalAccount'].Value -cne $true){throw 'Unverified stored local Administrators identity.'}
    }
    if($fixed['Capture.MembersSourceState'].Value -ceq 'OBSERVED' -and ($fixed['Capture.GroupSourceState'].Value -cne 'OBSERVED' -or
        (ConvertTo-WinSecSnapshotUtc $fixed['Capture.GroupTime'].Value) -gt (ConvertTo-WinSecSnapshotUtc $fixed['Capture.MembersTime'].Value))){throw 'Unbound stored membership source.'}
    foreach($name in @('Scope','RequestedGroupSID','RequestedAPILevel','DomainExpansion','CloudResolution','PolicyAuthority','TotalEntriesMeaning')){
        if($fixed['Capture.'+$name].State -cne 'OBSERVED'){throw 'Unverified local group scope metadata.'}
    }
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC) -or $fixed['Capture.RequestedAPILevel'].Value -ne 0){throw 'Invalid local group scope or timestamp.'}
    $expected=Get-WinSecLocalAdminsCandidateIntegrity $Snapshot -CancellationAction $CancellationAction
    foreach($i in $catalog.Inventories|Where-Object Id -CNE Capture){if($summaries[$i.Id].Complete -cne $expected[$i.Id].Complete -or $summaries[$i.Id].Reason -cne $expected[$i.Id].Reason){throw 'Local group completion contradicts its captured sources.'}}
}

