# Isolated normalizer of prepared local configuration receipts. No native adapter.
. (Join-Path $PSScriptRoot 'PasswordPolicyTechnicalCatalog.ps1')

function Get-WinSecPasswordPolicyCapturedProperty {
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

function ConvertTo-WinSecPasswordPolicyCandidateValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    $valid=$false;$converted=$null
    if($null -ne $Value){switch -CaseSensitive ($Kind){
        {$_ -cin @('UInt32','PolicyFlag','Build')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if([uint32]::TryParse($Value,[ref]$n)){$Value=$n}}
            $max=if($Kind -ceq 'PolicyFlag'){65536}else{4294967295}
            if(Test-WinSecSnapshotUInt $Value $max){$valid=$true;$converted=[uint32]$Value}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){$valid=$true;$converted=$Value}}
        Time {try{$date=ConvertTo-WinSecSnapshotUtc $Value;$valid=$true;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}catch{}}
        SourceState {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED')){$valid=$true;$converted=$Value}}
        Location {if($Value -is [string] -and $Value -cin @((Get-WinSecPasswordPolicyCandidateAreas).Location)){$valid=$true;$converted=$Value}}
        Constant {if($Value -is [string] -and $Value -cin @((Get-WinSecPasswordPolicyCandidateConstants).Values)){$valid=$true;$converted=$Value}}
    }};[pscustomobject]@{Valid=$valid;Value=$converted}
}

function Get-WinSecPasswordPolicyCandidateIntegrity {
    param([object]$Snapshot,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$values=@{};$summaries=@{};$result=@{}
    foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){foreach($r in $record.Readings){Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$values[$r.FieldId]=$r}}}
    foreach($a in Get-WinSecPasswordPolicyCandidateAreas){
        $s=$summaries[$a.Id];$state=$values['Capture.'+$a.Id+'SourceState'].Value
        $ok=($state -ceq 'OBSERVED');$reason=if($ok){'NONE'}elseif($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}
        if($ok -and $a.Id -cne 'Platform'){
            $ret=$values[$a.Id+'.ReturnValue']
            if($ret.State -cne 'OBSERVED' -or $ret.Value -ne 0){$ok=$false;$reason='PROVIDER_UNAVAILABLE'}
        }
        foreach($d in Get-WinSecPasswordPolicyCandidateFields|Where-Object Inventory -CEQ $a.Id){
            $r=$values[$d.Id];if($state -ceq 'OBSERVED' -and $d.Required -and $r.State -cne 'OBSERVED'){$ok=$false;$reason=if($r.Reason -ceq 'INVALID_VALUE'){'INVALID_VALUE'}else{'PROVIDER_UNAVAILABLE'}}
        }
        if($a.Id -ceq 'Policy' -and $values['Policy.MaximumAgeSeconds'].State -ceq 'OBSERVED' -and $values['Policy.MinimumAgeSeconds'].State -ceq 'OBSERVED' -and
            $values['Policy.MaximumAgeSeconds'].Value -ne 4294967295 -and $values['Policy.MinimumAgeSeconds'].Value -gt $values['Policy.MaximumAgeSeconds'].Value){$ok=$false;$reason='INVALID_VALUE'}
        $result[$a.Id]=[pscustomobject]@{Complete=$ok;Reason=$reason}
    };return $result
}

function New-WinSecPasswordPolicyCandidateSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity;if($Identity.CheckId -cne 'WSA-IAM-003'){throw 'Foreign Password Policies candidate control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid Password Policies capture operation.'}
    $areas=@(Get-WinSecPasswordPolicyCandidateAreas);$inputs=@{};$latest=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'Password Policies requires exact source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','Location','State','Data')
        if($source.SourceId -isnot [string]){throw 'Invalid policy source identifier.'};$a=@($areas|Where-Object Id -CEQ $source.SourceId)
        if($a.Count -ne 1 -or $inputs.ContainsKey($source.SourceId) -or $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or
            $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or $source.Location -isnot [string] -or $source.Location -cne $a[0].Location -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign policy source, identity or location.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;if($time -lt $start -or $time -gt $end){throw 'Policy source outside its operation.'};if($time -gt $latest){$latest=$time}
        $data=$null
        if($source.State -ceq 'OBSERVED'){
            if($source.SourceId -ceq 'Platform'){$data=$source.Data}
            else{
                if($source.SourceId -ceq 'Template'){
                    Assert-WinSecSnapshotFields $source.Data @('ReturnValue','Settings','Section','MergedPolicy')
                    if($source.Data.Section -isnot [string] -or $source.Data.Section -cne 'System Access' -or $source.Data.MergedPolicy -isnot [bool] -or $source.Data.MergedPolicy){throw 'Unreviewed or merged security policy template.'}
                }else{
                    Assert-WinSecSnapshotFields $source.Data @('ReturnValue','Settings','Level','ServerName')
                    $level=if($source.SourceId -ceq 'Policy'){0}else{3}
                    if(-not (Test-WinSecSnapshotUInt $source.Data.Level) -or $source.Data.Level -ne $level -or $null -ne $source.Data.ServerName){throw 'Remote or unreviewed policy request.'}
                }
                if(-not (Test-WinSecSnapshotUInt $source.Data.ReturnValue)){throw 'Unreviewed policy provider return code.'}
                $data=$source.Data.Settings
                if($source.Data.ReturnValue -ne 0){if($null -ne $data){throw 'Failed policy provider supplied output values.'}}
            }
            if(($source.SourceId -ceq 'Platform' -or $source.Data.ReturnValue -eq 0) -and
                ($null -eq $data -or $data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]]))){throw 'Policy requires an ordinary singleton configuration.'}
        }elseif($null -ne $source.Data){throw 'Unavailable policy source contains data.'}
        $inputs[$source.SourceId]=[pscustomobject]@{State=$source.State;Data=$data;Receipt=$source}
    }
    $capture=Get-WinSecPasswordPolicyCandidateConstants
    foreach($a in $areas){$s=$inputs[$a.Id].Receipt;$capture[$a.Id+'Time']=$s.CollectedAtUTC;$capture[$a.Id+'SourceState']=$s.State;$capture[$a.Id+'Location']=$s.Location}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture;Receipt=$null}
    $catalog=Get-WinSecPasswordPolicyCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog;$defs=@(Get-WinSecPasswordPolicyCandidateFields)
    $batches=@();$summaries=@();$counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0}
    $stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected'}
    foreach($i in $catalog.Inventories){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$source=$inputs[$i.Id]
        $reason=if($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}elseif($source.State -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}else{'NONE'}
        $readings=@(foreach($d in $defs|Where-Object Inventory -CEQ $i.Id){
            $r=[pscustomobject]@{FieldId=$d.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
            if($source.State -cne 'OBSERVED'){$r.State=$source.State;$r.Reason=$reason}
            elseif($i.Id -cnotin @('Platform','Capture') -and $d.Property -cne 'ReturnValue' -and $source.Receipt.Data.ReturnValue -ne 0){$r.State='ERROR'}
            else{
                $p=if($d.Property -ceq 'ReturnValue'){[pscustomobject]@{Safe=$true;Exists=$true;Value=$source.Receipt.Data.ReturnValue}}else{Get-WinSecPasswordPolicyCapturedProperty $source.Data $d.Property}
                if(-not $p.Safe){$r.Reason='INVALID_VALUE'}elseif($p.Exists -and $null -ne $p.Value){
                    $v=ConvertTo-WinSecPasswordPolicyCandidateValue $p.Value $d.Kind
                    if($v.Valid){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=$v.Value}else{$r.Reason='INVALID_VALUE'}
                }
            };$counts[$stateCount[$r.State]]++;$r
        })
        # These providers return single structures, not paged account inventories.
        $record=[pscustomobject]@{Id=($i.Id+'0');Readings=$readings}
        if([Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $record -Depth 8 -Compress)) -gt (Get-WinSecSnapshotSpecification).MaxBatchBytes){throw 'Policy singleton exceeds the shared batch budget.'}
        $batches+=,[pscustomobject]@{DeviceId=$owner.DeviceId;ScanId=$owner.ScanId;SnapshotId=$owner.SnapshotId;CheckId=$owner.CheckId;InventoryId=$i.Id;Sequence=1;Records=@($record)}
        $summaries+=,[pscustomobject]@{Id=$i.Id;State='OBSERVED';Complete=($source.State -ceq 'OBSERVED');ReportedRecords=$(if($source.State -ceq 'OBSERVED'){1}else{$null});RetainedRecords=1;Reason=$reason}
        $counts.RetainedRecords++;if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{InventoryId=$i.Id;RetainedRecords=1;ReportedRecords=$summaries[-1].ReportedRecords})}
    }
    $platform=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    foreach($r in $batches[0].Records[0].Readings){if($r.State -ceq 'OBSERVED'){$platform.($r.FieldId.Substring(9))=$r.Value}}
    $snapshot=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.0.0';Identity=$owner;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$hash;CollectorVersion='1.0.0';
        StartedAtUTC=$StartedAtUTC;CollectedAtUTC=$latest.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);CompletedAtUTC=$CompletedAtUTC;GeneratedAtUTC=$GeneratedAtUTC;
        Platform=$platform;SelectedProfile=$SelectedProfile;Collection=$null;Inventories=$summaries;Batches=$batches}
    $integrity=Get-WinSecPasswordPolicyCandidateIntegrity $snapshot -CancellationAction $CancellationAction
    foreach($s in $summaries){if($s.Id -cne 'Capture'){$s.Complete=$integrity[$s.Id].Complete;$s.Reason=$integrity[$s.Id].Reason}}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($summaries|Where-Object {-not $_.Complete}).Count -eq 0)
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]};$snapshot.Collection=[pscustomobject]$collection
    Assert-WinSecPasswordPolicyCandidateSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecPasswordPolicyCandidateSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-IAM-003'){throw 'Foreign Password Policies candidate identity.'}
    $catalog=Get-WinSecPasswordPolicyCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed policy candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$defs=@{};$values=@{};$summaries=@{}
    foreach($d in Get-WinSecPasswordPolicyCandidateFields){$defs[$d.Id]=$d};foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){foreach($r in $record.Readings){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$values[$r.FieldId]=$r
        if($r.State -cin @('NOT_CONFIGURED','NOT_APPLICABLE')){throw 'Unverified policy absence or exclusion.'}
        if($r.State -cne 'OBSERVED'){continue};$v=ConvertTo-WinSecPasswordPolicyCandidateValue $r.Value $defs[$r.FieldId].Kind
        if(-not $v.Valid -or (ConvertTo-Json -InputObject $v.Value -Compress) -cne (ConvertTo-Json -InputObject $r.Value -Compress)){throw 'Unreviewed policy candidate value.'}
    }}}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){$r=$values['Platform.'+$name];$v=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null};if($Snapshot.Platform.$name -cne $v){throw 'Policy platform differs from its readings.'}}
    if($null -ne $Snapshot.Platform.UBR -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.OSRelease){throw 'Unobserved policy platform metadata.'}
    foreach($key in (Get-WinSecPasswordPolicyCandidateConstants).Keys){$r=$values['Capture.'+$key];if($r.State -cne 'OBSERVED' -or $r.Value -cne (Get-WinSecPasswordPolicyCandidateConstants)[$key]){throw 'Foreign policy scope or authority metadata.'}}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($a in Get-WinSecPasswordPolicyCandidateAreas){
        $time=$values['Capture.'+$a.Id+'Time'];$state=$values['Capture.'+$a.Id+'SourceState'];$location=$values['Capture.'+$a.Id+'Location'];$s=$summaries[$a.Id]
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED' -or $location.State -cne 'OBSERVED' -or $location.Value -cne $a.Location){throw 'Missing or foreign policy source metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value;if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'Policy source timestamp outside operation.'};if($stamp -gt $latest){$latest=$stamp}
        if($state.Value -ceq 'OBSERVED'){
            if($s.ReportedRecords -ne 1 -or $null -eq $s.ReportedRecords){throw 'Observed policy singleton lacks its count.'}
            if($a.Id -cne 'Platform'){
                $ret=$values[$a.Id+'.ReturnValue'];if($ret.State -cne 'OBSERVED'){throw 'Observed policy source lacks return status.'}
                if($ret.Value -ne 0){foreach($d in $defs.Values|Where-Object {$_.Inventory -ceq $a.Id -and $_.Property -cne 'ReturnValue'}){
                    $r=$values[$d.Id];if($r.State -cne 'ERROR' -or $r.Reason -cne 'PROVIDER_UNAVAILABLE'){throw 'Failed policy source supplies usable output.'}
                }}
            }
        }else{
            if($null -ne $s.ReportedRecords){throw 'Unavailable policy source claims a known count.'}
            foreach($d in $defs.Values|Where-Object Inventory -CEQ $a.Id){if($values[$d.Id].State -cne $state.Value){throw 'Unavailable policy source supplies readings.'}}
        }
    }
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC)){throw 'Policy collection timestamp differs from sources.'}
    $expected=Get-WinSecPasswordPolicyCandidateIntegrity $Snapshot -CancellationAction $CancellationAction
    foreach($a in Get-WinSecPasswordPolicyCandidateAreas){if($summaries[$a.Id].Complete -cne $expected[$a.Id].Complete -or $summaries[$a.Id].Reason -cne $expected[$a.Id].Reason){throw 'Policy completion contradicts its sources.'}}
}
