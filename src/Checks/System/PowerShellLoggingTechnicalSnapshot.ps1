# Isolated machine policy normalizer. No Registry, events or personal data read.
. (Join-Path $PSScriptRoot 'PowerShellLoggingTechnicalCatalog.ps1')

function Get-WinSecPowerShellLoggingCapturedProperty {
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

function ConvertTo-WinSecPowerShellLoggingCandidateValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    $valid=$false;$converted=$null
    if($null -ne $Value){switch -CaseSensitive ($Kind){
        {$_ -cin @('UInt32','RegistryFlag','Build')} {
            if($Kind -ceq 'Build' -and $Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}\z'){$n=[uint32]0;if([uint32]::TryParse($Value,[ref]$n)){$Value=$n}}
            if(Test-WinSecSnapshotUInt $Value){$valid=$true;$converted=[uint32]$Value}
        }
        Version {if($Value -is [string] -and $Value -cmatch '\A10\.0\.[0-9]{5,10}\z'){$valid=$true;$converted=$Value}}
        Time {try{$date=ConvertTo-WinSecSnapshotUtc $Value;$valid=$true;$converted=$date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)}catch{}}
        SourceState {if($Value -is [string] -and $Value -cin @('OBSERVED','ERROR','NOT_COLLECTED')){$valid=$true;$converted=$Value}}
        Location {if($Value -is [string] -and $Value -cin @((Get-WinSecPowerShellLoggingCandidateAreas).Location)){$valid=$true;$converted=$Value}}
        Constant {if($Value -is [string] -and $Value -cin @((Get-WinSecPowerShellLoggingCandidateConstants).Values)){$valid=$true;$converted=$Value}}
    }};[pscustomobject]@{Valid=$valid;Value=$converted}
}

function ConvertTo-WinSecPowerShellLoggingRegistryReading {
    param([object]$Definition,[AllowNull()][object]$Entry)
    $r=[pscustomobject]@{FieldId=$Definition.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
    if($null -eq $Entry){return $r}
    Assert-WinSecSnapshotFields $Entry @('State','Kind','Value')
    if($Entry.State -isnot [string] -or $Entry.State -cnotin @('OBSERVED','UNKNOWN','ERROR','NOT_COLLECTED','NOT_CONFIGURED')){throw 'Unreviewed logging registry state.'}
    if($Entry.State -ceq 'OBSERVED'){
        if($Entry.Kind -is [string] -and $Entry.Kind -ceq 'DWord' -and (Test-WinSecSnapshotUInt $Entry.Value)){
            $r.State='OBSERVED';$r.Reason='NONE';$r.Value=[uint32]$Entry.Value
        }else{$r.Reason='INVALID_VALUE'}
    }else{
        if($null -ne $Entry.Kind -or $null -ne $Entry.Value){throw 'Unavailable logging registry value contains data.'}
        $r.State=$Entry.State;$r.Reason=switch -CaseSensitive ($Entry.State){NOT_CONFIGURED {'ABSENT'};NOT_COLLECTED {'NOT_REQUESTED'};default {'PROVIDER_UNAVAILABLE'}}
    };return $r
}

function Get-WinSecPowerShellLoggingCandidateIntegrity {
    param([object]$Snapshot,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew();$values=@{};$summaries=@{};$result=@{}
    foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){foreach($r in $record.Readings){Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$values[$r.FieldId]=$r}}}
    foreach($a in Get-WinSecPowerShellLoggingCandidateAreas){
        $state=$values['Capture.'+$a.Id+'SourceState'].Value
        $ok=($state -ceq 'OBSERVED');$reason=if($ok){'NONE'}elseif($state -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}else{'NOT_REQUESTED'}
        foreach($d in Get-WinSecPowerShellLoggingCandidateFields|Where-Object Inventory -CEQ $a.Id){
            $r=$values[$d.Id]
            if($state -ceq 'OBSERVED' -and $r.State -cnotin @('OBSERVED','NOT_CONFIGURED')){$ok=$false;$reason=if($r.Reason -ceq 'INVALID_VALUE'){'INVALID_VALUE'}elseif($r.State -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}else{'PROVIDER_UNAVAILABLE'}}
            if($d.Kind -ceq 'RegistryFlag' -and $r.State -ceq 'OBSERVED' -and $r.Value -gt 1){$ok=$false;$reason='INVALID_VALUE'}
        }
        $result[$a.Id]=[pscustomobject]@{Complete=$ok;Reason=$reason}
    };return $result
}

function New-WinSecPowerShellLoggingCandidateSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[Parameter(Mandatory)][object[]]$Sources,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC,
        [string]$SelectedProfile='NONE',[string]$GeneratedAtUTC=([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')),
        [scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Assert-WinSecSnapshotIdentity $Identity;if($Identity.CheckId -cne 'WSA-LOG-001'){throw 'Foreign PowerShell Logging candidate control.'}
    $owner=$Identity.PSObject.Copy();$start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    if($start -gt $end -or -not (Test-WinSecSnapshotToken $SelectedProfile)){throw 'Invalid PowerShell Logging capture operation.'}
    $areas=@(Get-WinSecPowerShellLoggingCandidateAreas);$inputs=@{};$latest=$start;$clock=[Diagnostics.Stopwatch]::StartNew()
    if($Sources.Count -ne $areas.Count){throw 'PowerShell Logging requires exact source receipts.'}
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;Assert-WinSecSnapshotFields $source @('SourceId','DeviceId','ScanId','CollectedAtUTC','Location','State','Data')
        if($source.SourceId -isnot [string]){throw 'Invalid policy source identifier.'};$a=@($areas|Where-Object Id -CEQ $source.SourceId)
        if($a.Count -ne 1 -or $inputs.ContainsKey($source.SourceId) -or $source.DeviceId -isnot [string] -or $source.DeviceId -cne $owner.DeviceId -or
            $source.ScanId -isnot [string] -or $source.ScanId -cne $owner.ScanId -or $source.Location -isnot [string] -or $source.Location -cne $a[0].Location -or
            $source.State -isnot [string] -or $source.State -cnotin @('OBSERVED','ERROR','NOT_COLLECTED')){throw 'Foreign policy source, identity or location.'}
        $time=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;if($time -lt $start -or $time -gt $end){throw 'Policy source outside its operation.'};if($time -gt $latest){$latest=$time}
        $data=$null
        if($source.State -ceq 'OBSERVED'){
            $data=$source.Data
            if($null -eq $data -or $data.GetType() -notin @([Management.Automation.PSCustomObject],[hashtable],[Collections.Specialized.OrderedDictionary],[Collections.Generic.Dictionary[string,object]])){throw 'Logging requires ordinary singleton captured configuration.'}
        }elseif($null -ne $source.Data){throw 'Unavailable policy source contains data.'}
        $inputs[$source.SourceId]=[pscustomobject]@{State=$source.State;Data=$data;Receipt=$source}
    }
    $capture=Get-WinSecPowerShellLoggingCandidateConstants
    foreach($a in $areas){$s=$inputs[$a.Id].Receipt;$capture[$a.Id+'Time']=$s.CollectedAtUTC;$capture[$a.Id+'SourceState']=$s.State;$capture[$a.Id+'Location']=$s.Location}
    $inputs.Capture=[pscustomobject]@{State='OBSERVED';Data=[pscustomobject]$capture;Receipt=$null}
    $catalog=Get-WinSecPowerShellLoggingCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog;$defs=@(Get-WinSecPowerShellLoggingCandidateFields)
    $batches=@();$summaries=@();$counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0}
    $stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected';NOT_CONFIGURED='NotConfigured'}
    foreach($i in $catalog.Inventories){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$source=$inputs[$i.Id]
        $reason=if($source.State -ceq 'ERROR'){'PROVIDER_UNAVAILABLE'}elseif($source.State -ceq 'NOT_COLLECTED'){'NOT_REQUESTED'}else{'NONE'}
        $readings=@(foreach($d in $defs|Where-Object Inventory -CEQ $i.Id){
            $r=[pscustomobject]@{FieldId=$d.Id;State='UNKNOWN';Reason='PROVIDER_UNAVAILABLE';Value=$null}
            if($d.Kind -ceq 'ExcludedDetail'){$r.State='NOT_COLLECTED';$r.Reason='NOT_REQUESTED'}
            elseif($source.State -cne 'OBSERVED'){$r.State=$source.State;$r.Reason=$reason}
            else{
                $p=Get-WinSecPowerShellLoggingCapturedProperty $source.Data $d.Property
                if(-not $p.Safe){$r.Reason='INVALID_VALUE'}elseif($d.Kind -ceq 'RegistryFlag'){$r=ConvertTo-WinSecPowerShellLoggingRegistryReading $d $p.Value}
                elseif($p.Exists -and $null -ne $p.Value){
                    $v=ConvertTo-WinSecPowerShellLoggingCandidateValue $p.Value $d.Kind
                    if($v.Valid){$r.State='OBSERVED';$r.Reason='NONE';$r.Value=$v.Value}else{$r.Reason='INVALID_VALUE'}
                }
            };$counts[$stateCount[$r.State]]++;$r
        })
        # Fixed policy projections are singleton records, not inventories of events or users.
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
    $integrity=Get-WinSecPowerShellLoggingCandidateIntegrity $snapshot -CancellationAction $CancellationAction
    foreach($s in $summaries){if($s.Id -cne 'Capture'){$s.Complete=$integrity[$s.Id].Complete;$s.Reason=$integrity[$s.Id].Reason}}
    $complete=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($summaries|Where-Object {-not $_.Complete}).Count -eq 0)
    $collection=[ordered]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and -not ($counts.Unknown+$counts.Errors+$counts.NotCollected)){'COMPLETE'}else{'LIMITED'})}
    foreach($key in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){$collection[$key]=$counts[$key]};$snapshot.Collection=[pscustomobject]$collection
    Assert-WinSecPowerShellLoggingCandidateSnapshot $snapshot $owner -CancellationAction $CancellationAction
    [pscustomobject]@{Snapshot=$snapshot;Catalog=$catalog;CatalogSha256=$hash;Identity=$owner.PSObject.Copy()}
}

function Assert-WinSecPowerShellLoggingCandidateSnapshot {
    [CmdletBinding()]param([object]$Snapshot,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotIdentity $ExpectedIdentity;if($ExpectedIdentity.CheckId -cne 'WSA-LOG-001'){throw 'Foreign PowerShell Logging candidate identity.'}
    $catalog=Get-WinSecPowerShellLoggingCandidateCatalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
    Assert-WinSecTechnicalSnapshot $Snapshot $catalog $hash $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.CollectorVersion -cne '1.0.0'){throw 'Unreviewed policy candidate collector.'}
    $clock=[Diagnostics.Stopwatch]::StartNew();$defs=@{};$values=@{};$summaries=@{}
    foreach($d in Get-WinSecPowerShellLoggingCandidateFields){$defs[$d.Id]=$d};foreach($s in $Snapshot.Inventories){$summaries[$s.Id]=$s}
    foreach($b in $Snapshot.Batches){foreach($record in $b.Records){foreach($r in $record.Readings){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$values[$r.FieldId]=$r
            if($r.State -ceq 'NOT_APPLICABLE' -or ($r.State -ceq 'NOT_CONFIGURED' -and $defs[$r.FieldId].Kind -cne 'RegistryFlag')){throw 'Unverified logging absence or exclusion.'}
        if($r.State -cne 'OBSERVED'){continue};$v=ConvertTo-WinSecPowerShellLoggingCandidateValue $r.Value $defs[$r.FieldId].Kind
        if(-not $v.Valid -or (ConvertTo-Json -InputObject $v.Value -Compress) -cne (ConvertTo-Json -InputObject $r.Value -Compress)){throw 'Unreviewed policy candidate value.'}
    }}}
    foreach($name in @('Version','BuildNumber','OperatingSystemSKU','ProductType')){$r=$values['Platform.'+$name];$v=if($r.State -ceq 'OBSERVED'){$r.Value}else{$null};if($Snapshot.Platform.$name -cne $v){throw 'Policy platform differs from its readings.'}}
    if($null -ne $Snapshot.Platform.UBR -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.OSRelease){throw 'Unobserved policy platform metadata.'}
    foreach($key in (Get-WinSecPowerShellLoggingCandidateConstants).Keys){$r=$values['Capture.'+$key];if($r.State -cne 'OBSERVED' -or $r.Value -cne (Get-WinSecPowerShellLoggingCandidateConstants)[$key]){throw 'Foreign policy scope or authority metadata.'}}
    foreach($d in $defs.Values|Where-Object Kind -CEQ ExcludedDetail){$r=$values[$d.Id];if($r.State -cne 'NOT_COLLECTED' -or $r.Reason -cne 'NOT_REQUESTED' -or $null -ne $r.Value){throw 'Unreviewed logging detail collection.'}}
    $latest=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC
    foreach($a in Get-WinSecPowerShellLoggingCandidateAreas){
        $time=$values['Capture.'+$a.Id+'Time'];$state=$values['Capture.'+$a.Id+'SourceState'];$location=$values['Capture.'+$a.Id+'Location'];$s=$summaries[$a.Id]
        if($time.State -cne 'OBSERVED' -or $state.State -cne 'OBSERVED' -or $location.State -cne 'OBSERVED' -or $location.Value -cne $a.Location){throw 'Missing or foreign policy source metadata.'}
        $stamp=ConvertTo-WinSecSnapshotUtc $time.Value;if($stamp -lt (ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC) -or $stamp -gt $end){throw 'Policy source timestamp outside operation.'};if($stamp -gt $latest){$latest=$stamp}
        if($state.Value -ceq 'OBSERVED'){
            if($s.ReportedRecords -ne 1 -or $null -eq $s.ReportedRecords){throw 'Observed policy singleton lacks its count.'}
        }else{
            if($null -ne $s.ReportedRecords){throw 'Unavailable policy source claims a known count.'}
            foreach($d in $defs.Values|Where-Object Inventory -CEQ $a.Id){if($values[$d.Id].State -cne $state.Value){throw 'Unavailable policy source supplies readings.'}}
        }
    }
    if($latest -ne (ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC)){throw 'Policy collection timestamp differs from sources.'}
    $expected=Get-WinSecPowerShellLoggingCandidateIntegrity $Snapshot -CancellationAction $CancellationAction
    foreach($a in Get-WinSecPowerShellLoggingCandidateAreas){if($summaries[$a.Id].Complete -cne $expected[$a.Id].Complete -or $summaries[$a.Id].Reason -cne $expected[$a.Id].Reason){throw 'Policy completion contradicts its sources.'}}
}
