# Prepared local audit configuration only. No events, activity, users or native API calls.
. (Join-Path $PSScriptRoot 'AuditPolicyTechnicalCatalog.ps1')

function Get-WinSecAuditPolicyCapturedProperty {
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

function ConvertTo-WinSecAuditPolicyCandidateValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    $valid=$false;$converted=$null
    if($null -ne $Value){switch -CaseSensitive ($Kind){
        {$_ -cin @('UInt32','Build','RegistryFlag')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if([uint32]::TryParse($Value,[ref]$n)){$Value=$n}}
            if(Test-WinSecSnapshotUInt $Value){$valid=$true;$converted=[uint32]$Value}
        }
        Guid {$g=[guid]::Empty;if($Value -is [string] -and [guid]::TryParseExact($Value,'D',[ref]$g) -and $g -ne [guid]::Empty -and $g.ToString('D') -ceq $Value){$valid=$true;$converted=$Value}}
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){$valid=$true;$converted=$Value}}
        {$_ -cin @('Success','Failure')} {if($Value -is [bool]){$valid=$true;$converted=$Value}}
        Mode {if($Value -is [string] -and $Value -cin @('UNCHANGED','SUCCESS','FAILURE','SUCCESS_AND_FAILURE','NONE','UNRECOGNIZED')){$valid=$true;$converted=$Value}}
        Time {try{$date=ConvertTo-WinSecSnapshotUtc $Value;$valid=$true;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}catch{}}
        SourceState {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED')){$valid=$true;$converted=$Value}}
        Location {if($Value -is [string] -and $Value -cin @((Get-WinSecAuditPolicyCandidateAreas).Location)){$valid=$true;$converted=$Value}}
        Constant {if($Value -is [string] -and $Value -cin @((Get-WinSecAuditPolicyCandidateConstants).Values)){$valid=$true;$converted=$Value}}
    }};[pscustomobject]@{Valid=$valid;Value=$converted}
}

function Get-WinSecAuditPolicyMaskReading {
    param($Mask,[string]$Kind,[string]$FieldId)
    $r=[pscustomobject]@{FieldId=$FieldId;State=$Mask.State;Reason=$Mask.Reason;Value=$null}
    if($Mask.State -cne 'OBSERVED'){return $r}
    $code=$Mask.Value
    if($Kind -ceq 'Mode'){$r.Value=switch($code){0 {'UNCHANGED'};1 {'SUCCESS'};2 {'FAILURE'};3 {'SUCCESS_AND_FAILURE'};4 {'NONE'};default {'UNRECOGNIZED'}}}
    elseif($code -in @(1,2,3,4)){$r.Value=if($Kind -ceq 'Success'){[bool]($code -band 1)}else{[bool]($code -band 2)}}
    else{$r.State='UNKNOWN';$r.Reason=if($code -eq 0){'PROVIDER_UNAVAILABLE'}else{'INVALID_VALUE'}}
    return $r
}

function ConvertTo-WinSecAuditPolicyRegistryReading {
    param([AllowNull()][object]$Entry)
    $r=[pscustomobject]@{FieldId='Options.SCENoApplyLegacyAuditPolicy';State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
    if($null -eq $Entry){return $r};Assert-WinSecSnapshotFields $Entry @('State','Kind','Value')
    if($Entry.State -isnot [string] -or $Entry.State -cnotin @('OBSERVED','UNKNOWN','ERROR','NOT_COLLECTED','NOT_CONFIGURED')){throw 'Unreviewed audit registry state.'}
    if($Entry.State -ceq 'OBSERVED'){
        if($Entry.Kind -is [string] -and $Entry.Kind -ceq 'DWord' -and (Test-WinSecSnapshotUInt $Entry.Value)){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=[uint32]$Entry.Value}else{$r.Reason='INVALID_VALUE'}
    }else{
        if($null -ne $Entry.Kind -or $null -ne $Entry.Value){throw 'Unavailable audit option contains data.'}
        $r.State=$Entry.State;$r.Reason=switch($Entry.State){NOT_CONFIGURED {'ABSENT'};NOT_COLLECTED {'NOT_REQUESTED'};default {'PROVIDER_UNAVAILABLE'}}
    };return $r
}

function Get-WinSecAuditPolicyCandidateIntegrity {
    param([object]$Snapshot,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$values=@{};$summaries=@{};$sets=@{};$result=@{}
    foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s;$sets[$s.Id]=@{}}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$local=@{}
        foreach($r in $record.Readings){$local[$r.FieldId]=$r;if($b.InventoryId -cin @('Capture','Options','Platform')){$values[$r.FieldId]=$r}}
        if($b.InventoryId -cin @('Categories','Subcategories','Requests','SystemPolicy')){
            $field=if($b.InventoryId -ceq 'Categories'){'AuditCategoryGuid'}else{'AuditSubCategoryGuid'};$key=$local[$b.InventoryId+'.'+$field].Value
            if($sets[$b.InventoryId].ContainsKey($key)){$sets[$b.InventoryId][$key]++}else{$sets[$b.InventoryId][$key]=1}
        }
    }}
    foreach($a in Get-WinSecAuditPolicyCandidateAreas){
        $s=$summaries[$a.Id];$state=$values['Capture.'+$a.Id+'SourceState'].Value
        $ok=($state -ceq 'OBSERVED' -and $null -ne $s.ReportedRecords -and $s.ReportedRecords -eq $s.RetainedRecords)
        $reason=if($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}elseif($state -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}elseif(-not $ok){'RESOURCE_LIMIT'}else{'NONE'}
        if(-not $a.Singleton -and $state -ceq 'OBSERVED'){
            if($s.ReportedRecords -eq 0){$ok=$false;$reason='PROVIDER_UNAVAILABLE'}
            if(@($sets[$a.Id].Values|Where-Object {$_ -gt 1}).Count){$ok=$false;$reason='INVALID_VALUE'}
        }
        if($a.Id -ceq 'Options'){$r=$values['Options.SCENoApplyLegacyAuditPolicy'];if($state -ceq 'OBSERVED' -and ($r.State -cnotin @('OBSERVED','NOT_CONFIGURED') -or ($r.State -ceq 'OBSERVED' -and $r.Value -gt 1))){$ok=$false;$reason=if($r.State -ceq 'OBSERVED' -or $r.Reason -ceq 'INVALID_VALUE'){'INVALID_VALUE'}else{'PROVIDER_UNAVAILABLE'}}}
        $result[$a.Id]=[pscustomobject]@{Complete=$ok;Reason=$reason}
    }
    $states=@{};foreach($id in @('Categories','Subcategories','Requests','SystemPolicy')){$states[$id]=$values['Capture.'+$id+'SourceState'].Value}
    if($states.Requests -ceq 'OBSERVED' -and $states.Subcategories -cne 'OBSERVED'){throw 'Audit request lacks observed enumeration.'}
    if($states.SystemPolicy -ceq 'OBSERVED' -and $states.Requests -cne 'OBSERVED'){throw 'Audit response lacks captured requests.'}
    foreach($pair in @('Subcategories|Requests','Requests|SystemPolicy')){
        $p=$pair.Split('|');$parent=$p[0];$child=$p[1]
        if($summaries[$parent].RetainedRecords -eq $summaries[$parent].ReportedRecords){
            foreach($key in $sets[$child].Keys){if(-not $sets[$parent].ContainsKey($key)){throw 'Foreign audit subcategory outside captured request scope.'}}
            if($states[$child] -ceq 'OBSERVED' -and $summaries[$child].RetainedRecords -eq $summaries[$child].ReportedRecords -and $sets[$child].Count -ne $sets[$parent].Count){$result[$child].Complete=$false;$result[$child].Reason='PROVIDER_UNAVAILABLE'}
        }elseif($summaries[$child].RetainedRecords -gt 0 -and $states[$parent] -ceq 'OBSERVED'){throw 'Audit records reference an omitted parent inventory.'}
    }
    foreach($b in $Snapshot.Batches|Where-Object InventoryId -CEQ SystemPolicy){foreach($record in $b.Records){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$v=@{};foreach($r in $record.Readings){$v[$r.FieldId]=$r}
        $category=$v['SystemPolicy.AuditCategoryGuid'].Value
        if($states.Categories -ceq 'OBSERVED'){
            if($summaries.Categories.RetainedRecords -ne $summaries.Categories.ReportedRecords -or -not $sets.Categories.ContainsKey($category)){throw 'Audit policy references an unverified category.'}
        }
        $r=$v['SystemPolicy.AuditingInformation'];if($r.State -cne 'OBSERVED' -or $r.Value -notin @(0,1,2,3,4)){$result.SystemPolicy.Complete=$false;$result.SystemPolicy.Reason=if($r.State -ceq 'OBSERVED' -or $r.Reason -ceq 'INVALID_VALUE'){'INVALID_VALUE'}else{'PROVIDER_UNAVAILABLE'}}
    }};return $result
}

function Get-WinSecAuditPolicyCandidatePayloadBudget {return ((Get-WinSecSnapshotSpecification).MaxDocumentBytes-131072)}

function New-WinSecAuditPolicyCandidateSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity;if($Identity.CheckId -cne 'WSA-LOG-002'){throw 'Foreign audit policy candidate control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid audit capture operation.'}
    $areas=@(Get-WinSecAuditPolicyCandidateAreas);$inputs=@{};$latest=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'Audit policy requires exact source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','Location','State','Data')
        if($source.SourceId -isnot [string]){throw 'Invalid audit source identifier.'};$a=@($areas|Where-Object Id -CEQ $source.SourceId)
        if($a.Count -ne 1 -or $inputs.ContainsKey($source.SourceId) -or $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or
            $source.Location -isnot [string] -or $source.Location -cne $a[0].Location -or $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign audit source, identity or location.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;if($time -lt $start -or $time -gt $end){throw 'Audit source outside its operation.'};if($time -gt $latest){$latest=$time}
        if($source.State -ceq 'OBSERVED'){
            if(-not $a[0].Singleton){if($source.Data -isnot [array] -or $source.Data.Rank -ne 1){throw 'Audit inventory requires an explicit array.'}}
            elseif($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Audit singleton requires ordinary captured data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable audit source contains data.'};$inputs[$source.SourceId]=$source
    }
    if($inputs.Requests.State -ceq 'OBSERVED' -and (ConvertTo-WinSecSnapshotUtc $inputs.Requests.CollectedAtUTC) -lt (ConvertTo-WinSecSnapshotUtc $inputs.Subcategories.CollectedAtUTC)){throw 'Audit requests precede enumeration.'}
    if($inputs.SystemPolicy.State -ceq 'OBSERVED' -and (ConvertTo-WinSecSnapshotUtc $inputs.SystemPolicy.CollectedAtUTC) -lt (ConvertTo-WinSecSnapshotUtc $inputs.Requests.CollectedAtUTC)){throw 'Audit response precedes request.'}
    $capture=Get-WinSecAuditPolicyCandidateConstants
    foreach($a in $areas){$s=$inputs[$a.Id];$capture[$a.Id+'Time']=$s.CollectedAtUTC;$capture[$a.Id+'SourceState']=$s.State;$capture[$a.Id+'Location']=$s.Location}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture}
    $catalog=Get-WinSecAuditPolicyCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog;$defs=@(Get-WinSecAuditPolicyCandidateFields);$byInventory=@{}
    foreach($i in $catalog.Inventories){$byInventory[$i.Id]=@($defs|Where-Object Inventory -CEQ $i.Id)}
    $batches=New-Object 'Collections.Generic.List[object]';$summaries=@();$bySummary=@{};$payload=0;$limit=Get-WinSecAuditPolicyCandidatePayloadBudget
    $counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0};$stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected';NOT_CONFIGURED='NotConfigured'}
    foreach($i in $catalog.Inventories){
        $source=$inputs[$i.Id];$total=if($i.Singleton){1}elseif($source.State -ceq 'OBSERVED'){$source.Data.Length}else{0}
        $reported=if($source.State -ceq 'OBSERVED'){$total}else{$null};$state=if($i.Singleton){'OBSERVED'}else{$source.State}
        $ok=($source.State -ceq 'OBSERVED');$reason=if($ok){'NONE'}elseif($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}
        $rows=New-Object 'Collections.Generic.List[object]';$bytes=16384;$sequence=1;$retained=0;$skip=$false
        $parents=switch($i.Id){Requests {@('Subcategories')};SystemPolicy {@('Categories','Requests')};default {@()}}
        foreach($parent in $parents){if($inputs[$parent].State -ceq 'OBSERVED' -and $bySummary[$parent].RetainedRecords -ne $bySummary[$parent].ReportedRecords){$skip=$true}}
        if($skip){$ok=$false;$reason='RESOURCE_LIMIT'}
        for($index=0;$index -lt $total -and -not $skip;$index++){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$data=if($i.Singleton){$source.Data}else{$source.Data[$index]}
            if($source.State -ceq 'OBSERVED' -and ($null -eq $data -or $data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]]))){throw 'Unreviewed audit captured record.'}
            $readings=@();$mask=$null
            foreach($d in $byInventory[$i.Id]){
                $r=[pscustomobject]@{FieldId=$d.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
                if($d.Kind -ceq 'ExcludedDetail'){$r.State='NOT_COLLECTED';$r.Reason='NOT_REQUESTED'}
                elseif($source.State -cne 'OBSERVED'){$r.State=$source.State;$r.Reason=$reason}
                elseif($d.Kind -cin @('Success','Failure','Mode')){$r=Get-WinSecAuditPolicyMaskReading $mask $d.Kind $d.Id}
                else{
                    $p=Get-WinSecAuditPolicyCapturedProperty $data $d.Property
                    if(-not $p.Safe){$r.Reason='INVALID_VALUE'}elseif($d.Kind -ceq 'RegistryFlag'){$r=ConvertTo-WinSecAuditPolicyRegistryReading $p.Value}
                    elseif($p.Exists -and $null -ne $p.Value){$v=ConvertTo-WinSecAuditPolicyCandidateValue $p.Value $d.Kind;if($v.Valid){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=$v.Value}else{$r.Reason='INVALID_VALUE'}}
                }
                if($d.Kind -ceq 'Guid' -and $source.State -ceq 'OBSERVED' -and $r.State -cne 'OBSERVED'){throw 'Unverified audit configuration GUID.'}
                if($d.Property -ceq 'AuditingInformation'){$mask=$r};$readings+=,$r
            }
            $record=[pscustomobject]@{Id=($i.Id+$index);Readings=$readings};$size=512+[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $record -Depth 8 -Compress))
            if(-not $i.Singleton -and ($payload+$size) -gt $limit){$ok=$false;$reason='RESOURCE_LIMIT';break}
            if($size+16384 -gt (Get-WinSecSnapshotSpecification).MaxBatchBytes){throw 'Audit record exceeds batch budget.'}
            if($rows.Count -and ($rows.Count -ge 128 -or ($bytes+$size) -gt (Get-WinSecSnapshotSpecification).MaxBatchBytes)){
                $batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$i.Id;Sequence=$sequence;Records=$rows.ToArray()});$rows.Clear();$sequence++;$bytes=16384
            }
            $payload+=$size;$bytes+=$size;$rows.Add($record);$retained++;$counts.RetainedRecords++;foreach($r in $readings){$counts[$stateCount[$r.State]]++}
            if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{InventoryId=$i.Id;RetainedRecords=$retained;ReportedRecords=$reported})}
        }
        if($rows.Count){$batches.Add([pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$i.Id;Sequence=$sequence;Records=$rows.ToArray()})}
        $summary=[pscustomobject]@{Id=$i.Id;State=$state;Complete=$ok;ReportedRecords=$reported;RetainedRecords=$retained;Reason=$reason};$summaries+=,$summary;$bySummary[$i.Id]=$summary
    }
    $platform=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    foreach($r in $batches[0].Records[0].Readings){if($r.State -ceq 'OBSERVED'){$platform.($r.FieldId.Substring(9))=$r.Value}}
    $snapshot=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$owner;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$hash;CollectorVersion='1.0.0';
        StartedAtUTC=$StartedAtUTC;CollectedAtUTC=$latest.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);CompletedAtUTC=$CompletedAtUTC;GeneratedAtUTC=$GeneratedAtUTC;
        Platform=$platform;SelectedProfile=$SelectedProfile;Collection=$null;Inventories=$summaries;Batches=$batches.ToArray()}
    $integrity=Get-WinSecAuditPolicyCandidateIntegrity $snapshot -CancellationAction $CancellationAction
    foreach($s in $summaries){if($s.Id -cne 'Capture'){$s.Complete=$integrity[$s.Id].Complete;$s.Reason=$integrity[$s.Id].Reason}}
    $required=@{};foreach($d in $defs){$required[$d.Id]=$d.Required}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($summaries|Where-Object {-not $_.Complete}).Count -eq 0)
    foreach($b in $batches){foreach($record in $b.Records){foreach($r in $record.Readings){if($required[$r.FieldId] -and $r.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){$complete=$false}}}}
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]};$snapshot.Collection=[pscustomobject]$collection
    Assert-WinSecAuditPolicyCandidateSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecAuditPolicyCandidateSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-LOG-002'){throw 'Foreign audit policy candidate identity.'}
    $catalog=Get-WinSecAuditPolicyCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed audit candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$defs=@{};$fixed=@{};$summaries=@{}
    foreach($d in Get-WinSecAuditPolicyCandidateFields){$defs[$d.Id]=$d};foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        $local=@{};foreach($r in $record.Readings){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$local[$r.FieldId]=$r;if($b.InventoryId -cin @('Platform','Capture')){$fixed[$r.FieldId]=$r}
            $d=$defs[$r.FieldId]
            if($r.State -ceq 'NOT_APPLICABLE' -or ($r.State -ceq 'NOT_CONFIGURED' -and $d.Kind -cne 'RegistryFlag')){throw 'Unverified audit absence or exclusion.'}
            if($d.Kind -ceq 'Guid' -and $r.State -cne 'OBSERVED'){throw 'Missing stored audit GUID.'}
            if($d.Kind -ceq 'ExcludedDetail' -and ($r.State -cne 'NOT_COLLECTED' -or $r.Reason -cne 'NOT_REQUESTED' -or $null -ne $r.Value)){throw 'Unreviewed audit detail.'}
            if($r.State -cne 'OBSERVED'){continue};$v=ConvertTo-WinSecAuditPolicyCandidateValue $r.Value $d.Kind
            if(-not $v.Valid -or (ConvertTo-Json -InputObject $v.Value -Compress) -cne (ConvertTo-Json -InputObject $r.Value -Compress)){throw 'Unreviewed audit candidate value.'}
        }
        if($b.InventoryId -ceq 'SystemPolicy'){foreach($kind in @('Success','Failure','Mode')){
            $expected=Get-WinSecAuditPolicyMaskReading $local['SystemPolicy.AuditingInformation'] $kind ('SystemPolicy.'+$kind)
            if((ConvertTo-Json $expected -Compress) -cne (ConvertTo-Json $local['SystemPolicy.'+$kind] -Compress)){throw 'Audit flag derivation contradicts the system mask.'}
        }}
    }}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){$r=$fixed['Platform.'+$name];$v=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null};if($Snapshot.Platform.$name -cne $v){throw 'Audit platform differs from its readings.'}}
    if($null -ne $Snapshot.Platform.UBR -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.OSRelease){throw 'Unobserved audit platform metadata.'}
    foreach($key in (Get-WinSecAuditPolicyCandidateConstants).Keys){$r=$fixed['Capture.'+$key];if($r.State -cne 'OBSERVED' -or $r.Value -cne (Get-WinSecAuditPolicyCandidateConstants)[$key]){throw 'Foreign audit scope metadata.'}}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($a in Get-WinSecAuditPolicyCandidateAreas){
        $time=$fixed['Capture.'+$a.Id+'Time'];$state=$fixed['Capture.'+$a.Id+'SourceState'];$location=$fixed['Capture.'+$a.Id+'Location'];$s=$summaries[$a.Id]
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED' -or $location.State -cne 'OBSERVED' -or $location.Value -cne $a.Location){throw 'Missing or foreign audit source metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value;if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'Audit source outside operation.'};if($stamp -gt $latest){$latest=$stamp}
        if($state.Value -ceq 'OBSERVED'){if($s.State -cne 'OBSERVED' -or $null -eq $s.ReportedRecords){throw 'Observed audit source lacks counts.'}}
        else{
            if($null -ne $s.ReportedRecords -or (-not $a.Singleton -and ($s.State -cne $state.Value -or $s.RetainedRecords -ne 0))){throw 'Unavailable audit source claims records.'}
            foreach($b in $Snapshot.Batches|Where-Object InventoryId -CEQ $a.Id){foreach($record in $b.Records){foreach($r in $record.Readings){if($r.State -cne $state.Value){throw 'Unavailable audit source supplies readings.'}}}}
        }
    }
    foreach($pair in @('Subcategories|Requests','Requests|SystemPolicy')){$p=$pair.Split('|');if($fixed['Capture.'+$p[1]+'SourceState'].Value -ceq 'OBSERVED' -and
        (ConvertTo-WinSecSnapshotUtc $fixed['Capture.'+$p[1]+'Time'].Value) -lt (ConvertTo-WinSecSnapshotUtc $fixed['Capture.'+$p[0]+'Time'].Value)){throw 'Audit query ordering is unverified.'}}
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC)){throw 'Audit collection time differs from sources.'}
    $expected=Get-WinSecAuditPolicyCandidateIntegrity $Snapshot -CancellationAction $CancellationAction
    foreach($a in Get-WinSecAuditPolicyCandidateAreas){if($summaries[$a.Id].Complete -cne $expected[$a.Id].Complete -or $summaries[$a.Id].Reason -cne $expected[$a.Id].Reason){throw 'Audit completion contradicts captured sources.'}}
}

