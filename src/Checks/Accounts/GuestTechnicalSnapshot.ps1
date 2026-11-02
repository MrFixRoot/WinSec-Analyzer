# Prepared Guest receipts only. Never queries accounts, translates SIDs or attempts authentication.
. (Join-Path $PSScriptRoot 'GuestTechnicalCatalog.ps1')

function Get-WinSecGuestCapturedProperty {
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

function ConvertTo-WinSecGuestCandidateValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    $valid=$false;$converted=$null
    if($null -ne $Value){switch -CaseSensitive ($Kind){
        Boolean {if($Value -is [bool]){$valid=$true;$converted=$Value}}
        Present {if($Value -is [bool] -and $Value -ceq $true){$valid=$true;$converted=$Value}}
        {$_ -cin @('UInt32','UInt8','Build','RID')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if([uint32]::TryParse($Value,[ref]$n)){$Value=$n}}
            $max=if($Kind -ceq 'UInt8'){255}else{4294967295}
            if(Test-WinSecSnapshotUInt $Value $max){$valid=$true;$converted=[uint32]$Value}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){$valid=$true;$converted=$Value}}
        {$_ -cin @('GuestSID','DerivedDomainSID')} {
            $pattern=if($Kind -ceq 'GuestSID'){'\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-501\z'}else{'\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+\z'}
            if($Value -is [string] -and $Value.Length -le 184 -and $Value -cmatch $pattern){
                try{$sid=[Security.Principal.SecurityIdentifier]::new($Value);if($sid.Value -ceq $Value){$valid=$true;$converted=$Value}}catch{}
            }
        }
        AccountName {
            if($Value -is [string] -and $Value.Length -le 256 -and -not [string]::IsNullOrWhiteSpace($Value) -and
                $Value -notmatch '[\p{C}\p{Zl}\p{Zp}"/\\\[\]:|<>+=;,?*]' -and -not $Value.EndsWith('.')){$valid=$true;$converted=$Value}
        }
        AccountDomain {if($Value -is [string] -and $Value.Length -le 255 -and $Value -cmatch '\A[\p{L}\p{Nd}][\p{L}\p{M}\p{Nd}_.-]*\z'){$valid=$true;$converted=$Value}}
        AccountStatus {if($Value -is [string] -and $Value -cin @('OK','Error','Degraded','Unknown','Pred Fail','Starting','Stopping','Service','Stressed','NonRecover','No Contact','Lost Comm')){$valid=$true;$converted=$Value}}
        Time {try{$date=ConvertTo-WinSecSnapshotUtc $Value;$valid=$true;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}catch{}}
        SourceState {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED')){$valid=$true;$converted=$Value}}
        Location {if($Value -is [string] -and $Value -ceq 'CIMV2'){$valid=$true;$converted=$Value}}
        Scope {if($Value -is [string] -and $Value -ceq 'LOCAL_BUILTIN_GUEST_RID501_ONLY'){$valid=$true;$converted=$Value}}
        NotPerformed {if($Value -is [string] -and $Value -ceq 'NOT_PERFORMED'){$valid=$true;$converted=$Value}}
        NotObserved {if($Value -is [string] -and $Value -ceq 'NOT_OBSERVED'){$valid=$true;$converted=$Value}}
        DomainSIDBasis {if($Value -is [string] -and $Value -ceq 'DERIVED_FROM_GUEST_SID_NOT_MACHINE_ATTESTATION'){$valid=$true;$converted=$Value}}
    }};[pscustomobject]@{Valid=$valid;Value=$converted}
}

function Get-WinSecGuestCandidateIntegrity {
    param([object]$Snapshot,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$meta=@{};$summaries=@{};$guest=@();$result=@{}
    foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($b.InventoryId -ceq 'Capture'){foreach($r in $record.Readings){$meta[$r.FieldId]=$r}}
        elseif($b.InventoryId -ceq 'Guest'){$v=@{};foreach($r in $record.Readings){$v[$r.FieldId]=$r};$guest+=,$v}
    }}
    foreach($a in Get-WinSecGuestCandidateAreas){
        $s=$summaries[$a.Id];$state=$meta['Capture.'+$a.Id+'SourceState'].Value
        $ok=($state -ceq 'OBSERVED' -and $null -ne $s.ReportedRecords -and $s.ReportedRecords -eq $s.RetainedRecords)
        $reason=if($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}elseif($state -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}elseif(-not $ok){'RESOURCE_LIMIT'}else{'NONE'}
        if($a.Id -ceq 'Guest' -and $state -ceq 'OBSERVED'){
            if($s.ReportedRecords -gt 1){throw 'Ambiguous built-in Guest inventory.'}
            if($s.ReportedRecords -eq 0){$ok=$false;$reason='PROVIDER_UNAVAILABLE'}
            foreach($record in $guest){
                if($record['Guest.Disabled'].State -cne 'OBSERVED'){$ok=$false;$reason=$(if($record['Guest.Disabled'].Reason -ceq 'INVALID_VALUE'){'INVALID_VALUE'}else{'PROVIDER_UNAVAILABLE'})}
                if($record['Guest.SIDType'].State -ceq 'OBSERVED' -and $record['Guest.SIDType'].Value -ne 1){$ok=$false;$reason='INVALID_VALUE'}
            }
        }
        $result[$a.Id]=[pscustomobject]@{Complete=$ok;Reason=$reason}
    };return $result
}

function Get-WinSecGuestCandidatePayloadBudget {return ((Get-WinSecSnapshotSpecification).MaxDocumentBytes-131072)}

function New-WinSecGuestCandidateSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('o')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity;if($Identity.CheckId -cne 'WSA-IAM-002'){throw 'Foreign Open Ports candidate control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid Guest capture operation.'}
    $areas=@(Get-WinSecGuestCandidateAreas);$inputs=@{};$latest=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'Open Ports requires the exact source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','Location','State','Data')
        if($source.SourceId -isnot [string]){throw 'Invalid Guest source identifier.'};$a=@($areas|Where-Object Id -CEQ $source.SourceId)
        if($a.Count -ne 1 -or $inputs.ContainsKey($source.SourceId) -or $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or
            $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or $source.Location -isnot [string] -or $source.Location -cne $a[0].Location -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign Guest source, identity or location.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;if($time -lt $start -or $time -gt $end){throw 'Guest source outside its operation.'};if($time -gt $latest){$latest=$time}
        if($source.State -ceq 'OBSERVED'){
            if($source.SourceId -cne 'Platform'){if($source.Data -isnot [array] -or $source.Data.Rank -ne 1){throw 'Guest inventory requires an explicit array.'}}
            elseif($null -eq $source.Data -or $source.Data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Guest platform requires ordinary captured data.'}
        }elseif($null -ne $source.Data){throw 'Unavailable Guest source contains data.'};$inputs[$source.SourceId]=$source
    }
    if($inputs.Guest.State -ceq 'OBSERVED'){
        if($inputs.Guest.Data.Length -gt 1){throw 'Ambiguous built-in Guest inventory.'}
        foreach($record in $inputs.Guest.Data){
            if($null -eq $record -or $record.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Unreviewed Guest captured record.'}
            $sid=Get-WinSecGuestCapturedProperty $record SID;$local=Get-WinSecGuestCapturedProperty $record LocalAccount
            if(-not $sid.Safe -or -not (ConvertTo-WinSecGuestCandidateValue $sid.Value GuestSID).Valid -or -not $local.Safe -or $local.Value -isnot [bool] -or $local.Value -cne $true){throw 'Unverified built-in local Guest identity.'}
        }
    }
    $capture=[ordered]@{Scope='LOCAL_BUILTIN_GUEST_RID501_ONLY';RequestedRID=[uint32]501;DomainResolution='NOT_PERFORMED';CloudResolution='NOT_PERFORMED';PolicyAuthority='NOT_OBSERVED';AccountDomainSIDBasis='DERIVED_FROM_GUEST_SID_NOT_MACHINE_ATTESTATION'}
    foreach($a in $areas){$s=$inputs[$a.Id];$capture[$a.Id+'Time']=$s.CollectedAtUTC;$capture[$a.Id+'SourceState']=$s.State;$capture[$a.Id+'Location']=$s.Location}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture}
    $catalog=Get-WinSecGuestCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog;$defs=@(Get-WinSecGuestCandidateFields);$byInventory=@{}
    foreach($i in $catalog.Inventories){$byInventory[$i.Id]=@($defs|Where-Object Inventory -CEQ $i.Id)}
    $batches=New-Object 'Collections.Generic.List[object]';$summaries=@();$payload=0;$limit=Get-WinSecGuestCandidatePayloadBudget
    $counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0};$stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected'}
    foreach($i in $catalog.Inventories){
        $source=$inputs[$i.Id];$total=if($i.Singleton){1}elseif($source.State -ceq 'OBSERVED'){$source.Data.Length}else{0}
        $reported=if($source.State -ceq 'OBSERVED'){$total}else{$null};$state=if($i.Singleton){'OBSERVED'}else{$source.State}
        $ok=($source.State -ceq 'OBSERVED');$reason=if($ok){'NONE'}elseif($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}
        $rows=New-Object 'Collections.Generic.List[object]';$bytes=16384;$sequence=1;$retained=0
        for($index=0;$index -lt $total;$index++){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $data=if($i.Singleton){$source.Data}else{$source.Data[$index]}
            if($source.State -ceq 'OBSERVED' -and ($null -eq $data -or $data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]]))){throw 'Unreviewed Guest captured record.'}
            $readings=@(foreach($d in $byInventory[$i.Id]){
                $r=[pscustomobject]@{FieldId=$d.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
                if($source.State -cne 'OBSERVED'){$r.State=$source.State;$r.Reason=$reason}
                else{
                    $p=if($d.Kind -ceq 'Present'){[pscustomobject]@{Safe=$true;Exists=$true;Value=$true}}
                    elseif($d.Kind -ceq 'DerivedDomainSID'){$sidValue=(Get-WinSecGuestCapturedProperty $data SID).Value;[pscustomobject]@{Safe=$true;Exists=$true;Value=$sidValue.Substring(0,$sidValue.LastIndexOf('-'))}}
                    else{Get-WinSecGuestCapturedProperty $data $d.Property}
                    if(-not $p.Safe){$r.Reason='INVALID_VALUE'}elseif($p.Exists -and $null -ne $p.Value){
                        $v=ConvertTo-WinSecGuestCandidateValue $p.Value $d.Kind
                        if($v.Valid){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=$v.Value}else{$r.Reason='INVALID_VALUE'}
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
    $integrity=Get-WinSecGuestCandidateIntegrity $snapshot -CancellationAction $CancellationAction
    foreach($s in $summaries){if($s.Id -cne 'Capture'){$s.Complete=$integrity[$s.Id].Complete;$s.Reason=$integrity[$s.Id].Reason}}
    $required=@{};foreach($d in $defs){$required[$d.Id]=$d.Required}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($summaries|Where-Object {-not $_.Complete}).Count -eq 0)
    foreach($b in $batches){foreach($record in $b.Records){foreach($r in $record.Readings){if($required[$r.FieldId] -and $r.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){$complete=$false}}}}
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]};$snapshot.Collection=[pscustomobject]$collection
    Assert-WinSecGuestCandidateSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecGuestCandidateSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-IAM-002'){throw 'Foreign Guest candidate identity.'}
    $catalog=Get-WinSecGuestCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed Guest candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$defs=@{};$fixed=@{};$summaries=@{};$guestCount=0
    foreach($d in Get-WinSecGuestCandidateFields){$defs[$d.Id]=$d};foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){
        $local=@{};foreach($r in $record.Readings){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $local[$r.FieldId]=$r;if($b.InventoryId -cin @('Platform','Capture')){$fixed[$r.FieldId]=$r}
            if($r.State -cin @('NOT_CONFIGURED','NOT_APPLICABLE')){throw 'Unverified Guest absence or exclusion.'}
            if($r.State -cne 'OBSERVED'){continue};$v=ConvertTo-WinSecGuestCandidateValue $r.Value $defs[$r.FieldId].Kind
            if(-not $v.Valid -or (ConvertTo-Json -InputObject $v.Value -Compress) -cne (ConvertTo-Json -InputObject $r.Value -Compress)){throw 'Unreviewed Guest candidate value.'}
        }
        if($b.InventoryId -ceq 'Guest'){
            $guestCount++;if($guestCount -gt 1){throw 'Ambiguous stored Guest identity.'}
            $sid=$local['Guest.SID'];$localAccount=$local['Guest.LocalAccount'];$present=$local['Guest.Present'];$domain=$local['Guest.AccountDomainSID']
            if($sid.State -cne 'OBSERVED' -or $localAccount.State -cne 'OBSERVED' -or $localAccount.Value -cne $true -or
                $present.State -cne 'OBSERVED' -or $present.Value -cne $true -or $domain.State -cne 'OBSERVED' -or
                $domain.Value -cne $sid.Value.Substring(0,$sid.Value.LastIndexOf('-'))){throw 'Stored Guest identity or derivation is unverified.'}
        }
    }}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){$r=$fixed['Platform.'+$name];$v=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null};if($Snapshot.Platform.$name -cne $v){throw 'Guest platform differs from its readings.'}}
    if($null -ne $Snapshot.Platform.UBR -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.OSRelease){throw 'Unobserved Guest platform metadata.'}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($a in Get-WinSecGuestCandidateAreas){
        $time=$fixed['Capture.'+$a.Id+'Time'];$state=$fixed['Capture.'+$a.Id+'SourceState'];$location=$fixed['Capture.'+$a.Id+'Location'];$s=$summaries[$a.Id]
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED' -or $location.State -cne 'OBSERVED' -or $location.Value -cne $a.Location){throw 'Missing or foreign Guest source metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value;if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'Guest source timestamp outside its operation.'};if($stamp -gt $latest){$latest=$stamp}
        if($state.Value -ceq 'OBSERVED'){if($s.State -cne 'OBSERVED' -or $null -eq $s.ReportedRecords){throw 'Observed Guest source lacks counts.'}}
        else{
            if($null -ne $s.ReportedRecords -or ($a.Id -ceq 'Guest' -and ($s.State -cne $state.Value -or $s.RetainedRecords -ne 0))){throw 'Unavailable Guest source claims records.'}
            foreach($b in $Snapshot.Batches|Where-Object InventoryId -CEQ $a.Id){foreach($record in $b.Records){foreach($r in $record.Readings){if($r.State -cne $state.Value){throw 'Unavailable Guest source supplies readings.'}}}}
        }
    }
    foreach($name in @('Scope','RequestedRID','DomainResolution','CloudResolution','PolicyAuthority','AccountDomainSIDBasis')){if($fixed['Capture.'+$name].State -cne 'OBSERVED'){throw 'Unverified Guest scope metadata.'}}
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC) -or $fixed['Capture.RequestedRID'].Value -ne 501){throw 'Invalid Guest scope or timestamp.'}
    $expected=Get-WinSecGuestCandidateIntegrity $Snapshot -CancellationAction $CancellationAction
    foreach($a in Get-WinSecGuestCandidateAreas){if($summaries[$a.Id].Complete -cne $expected[$a.Id].Complete -or $summaries[$a.Id].Reason -cne $expected[$a.Id].Reason){throw 'Guest completion contradicts its captured sources.'}}
}

