# Isolated candidate acquisition. No production registration or work on import.
# Local identity and specific authorization remain the future coordinator's responsibility.
. (Join-Path $PSScriptRoot 'DefenderTechnicalSnapshot.ps1')

function Get-WinSecDefenderPreferenceQueryWorker {
    return {
        param([string]$SnapshotPath,[string]$DeviceId,[string]$ScanId)
        $ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
        $frame=[pscustomobject]@{SchemaVersion='WinSec.Defender.PreferenceQuery1.0';SourceId='Preferences';DeviceId=$DeviceId;ScanId=$ScanId;
            CollectedAtUTC='';State='ERROR';Reason='BOOTSTRAP_FAILED';RequestedProperties=@();Data=$null}
        $record=$null;$schema=$null
        try {
            . $SnapshotPath
            $frame.Reason='SCHEMA_UNAVAILABLE'
            $count=0
            # Metadata only, then a nonempty scalar projection. Never Get-MpPreference or SELECT *.
            Get-CimClass -Namespace 'root/Microsoft/Windows/Defender' -ClassName 'MSFT_MpPreference' -OperationTimeoutSec 5 -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null | ForEach-Object {
                $count++;if($count -gt 1){$frame.Reason='UNEXPECTED_CARDINALITY';throw 'Rejected schema cardinality.'};$schema=$_
            }
            if($count -ne 1){$frame.Reason='UNEXPECTED_CARDINALITY';throw 'Rejected schema cardinality.'}
            $frame.Reason='INVALID_SCHEMA'
            $frame.RequestedProperties=@(Get-WinSecDefenderPreferenceProjection $schema)
            if($frame.RequestedProperties.Count -eq 0){$frame.Reason='NO_REVIEWED_PROPERTIES';throw 'No reviewed projection.'}
            $frame.Reason='PROVIDER_UNAVAILABLE';$count=0
            Get-CimInstance -Namespace 'root/Microsoft/Windows/Defender' -ClassName 'MSFT_MpPreference' `
                -Property $frame.RequestedProperties -OperationTimeoutSec 5 -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null | ForEach-Object {
                $count++
                if($count -gt 1){$frame.Reason='UNEXPECTED_CARDINALITY';throw 'Rejected cardinality.'}
                $record=$_
            }
            if($count -ne 1){$frame.Reason='UNEXPECTED_CARDINALITY';throw 'Rejected cardinality.'}
            $frame.Reason='INVALID_SOURCE'
            Assert-WinSecDefenderCapturedCimSource $record Preferences
            $frame.Reason='NORMALIZATION_FAILED'
            $frame.Data=New-WinSecDefenderPreferenceReadings $record -RequestedProperties $frame.RequestedProperties
            $frame.State='OBSERVED';$frame.Reason='NONE'
        }catch{$frame.Data=$null;$frame.State='ERROR'}finally{
            if($record -is [Microsoft.Management.Infrastructure.CimInstance]){
                try{$null=[Microsoft.Management.Infrastructure.CimInstance].GetMethod('Dispose').Invoke($record,$null)}catch{}
            }
            if($schema -is [Microsoft.Management.Infrastructure.CimClass]){
                try{$null=[Microsoft.Management.Infrastructure.CimClass].GetMethod('Dispose').Invoke($schema,$null)}catch{}
            }
        }
        $frame.CollectedAtUTC=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
        return $frame
    }
}

function ConvertFrom-WinSecDefenderPreferenceQueryFrame {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Frame,[Parameter(Mandatory)][object]$Identity,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC)
    Assert-WinSecSnapshotIdentity $Identity
    if($Identity.CheckId -cne 'WSA-SYS-001'){throw 'Foreign Defender preference identity.'}
    if($Frame -isnot [Management.Automation.PSCustomObject]){throw 'Invalid Defender preference transport.'}
    $fields=@('SchemaVersion','SourceId','DeviceId','ScanId','CollectedAtUTC','State','Reason','RequestedProperties','Data')
    foreach($property in $Frame.PSObject.Properties){
        if($property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
            $property.Name -cnotin ($fields+@('PSComputerName','RunspaceId','PSShowComputerName'))){throw 'Invalid Defender preference transport.'}
    }
    foreach($name in $fields){if($null -eq $Frame.PSObject.Properties[$name]){throw 'Incomplete Defender preference transport.'}}
    foreach($name in @('SchemaVersion','SourceId','DeviceId','ScanId','CollectedAtUTC','State','Reason')){
        if($Frame.$name -isnot [string]){throw 'Invalid Defender preference header.'}
    }
    if($Frame.SchemaVersion -cne 'WinSec.Defender.PreferenceQuery1.0' -or $Frame.SourceId -cne 'Preferences' -or
        $Frame.DeviceId -cne $Identity.DeviceId -or $Frame.ScanId -cne $Identity.ScanId -or $Frame.State -cnotin @('OBSERVED','ERROR') -or
        $Frame.Reason -cnotin @('NONE','BOOTSTRAP_FAILED','SCHEMA_UNAVAILABLE','INVALID_SCHEMA','NO_REVIEWED_PROPERTIES','PROVIDER_UNAVAILABLE','UNEXPECTED_CARDINALITY','INVALID_SOURCE','NORMALIZATION_FAILED')){
        throw 'Foreign or invalid Defender preference transport.'
    }
    $start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    $collected=ConvertTo-WinSecSnapshotUtc $Frame.CollectedAtUTC
    if($start -gt $collected -or $collected -gt $end){throw 'Invalid Defender preference timeline.'}
    $data=$null;$definitions=@(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Preferences)
    $requested=$Frame.RequestedProperties
    if(($requested -isnot [array] -or $requested.Rank -ne 1) -and ($null -eq $requested -or $requested.GetType() -ne [Collections.ArrayList])){throw 'Invalid preference projection transport.'}
    if($requested.Count -gt $definitions.Count){throw 'Unreviewed preference projection transport.'}
    $names=@($definitions|ForEach-Object Property);$seen=@{};$requestedNames=@(foreach($name in $requested){
        if($name -isnot [string] -or $name -cnotin $names -or $seen.ContainsKey($name)){throw 'Unreviewed preference projection transport.'}
        $seen[$name]=$true;$name
    })
    $observed=0;$unknown=0;$errors=0;$unresolved=0
    if($Frame.State -ceq 'OBSERVED'){
        if($Frame.Reason -cne 'NONE' -or $requestedNames.Count -eq 0){throw 'Contradictory Defender preference state.'}
        Assert-WinSecSnapshotFields $Frame.Data @('ArtifactType','SchemaVersion','Readings')
        $carrier=$Frame.Data.Readings
        # CLIXML jobs deserialize arrays as ArrayList. Accept only this known transport or a rank-one array.
        if($carrier -is [Collections.ArrayList]){
            if($carrier.GetType() -ne [Collections.ArrayList]){throw 'Unreviewed Defender preference transport list.'}
        }elseif($carrier -isnot [array] -or $carrier.Rank -ne 1){throw 'Invalid Defender preference transport list.'}
        if($carrier.Count -ne $definitions.Count){throw 'Incomplete Defender preference transport list.'}
        $canonicalRows=if($carrier -is [Collections.ArrayList]){$carrier.ToArray()}else{$carrier}
        $canonical=[pscustomobject]@{ArtifactType=$Frame.Data.ArtifactType;SchemaVersion=$Frame.Data.SchemaVersion;Readings=@($canonicalRows)}
        Assert-WinSecDefenderPreferenceReadings $canonical
        $rows=@(foreach($reading in $canonical.Readings){$reading.PSObject.Copy()})
        $data=[pscustomobject]@{ArtifactType='WinSec.Defender.PreferenceReadings';SchemaVersion='1.0.0';Readings=$rows}
        for($i=0;$i -lt $rows.Count;$i++){
            if(-not $seen.ContainsKey($definitions[$i].Property) -and ($rows[$i].State -cne 'UNKNOWN' -or $rows[$i].Reason -cne 'PROVIDER_UNAVAILABLE')){throw 'Preference reading was not requested.'}
            if($rows[$i].State -ceq 'OBSERVED'){$observed++}else{$unknown++;if($definitions[$i].Required){$unresolved++}}
        }
    }else{
        if($null -ne $Frame.Data -or $Frame.Reason -ceq 'NONE'){throw 'Contradictory Defender preference failure.'}
        $errors=$definitions.Count;$unresolved=@($definitions|Where-Object Required).Count
    }
    [pscustomobject]@{ArtifactType='WinSec.Defender.PreferenceCapture';SchemaVersion='1.0.0';Identity=$Identity.PSObject.Copy();
        Source=[pscustomobject]@{SchemaVersion='WinSec.Defender.PreferenceSource1.0';Scope='SCALARS_ONLY';SourceId='Preferences';DeviceId=$Identity.DeviceId;ScanId=$Identity.ScanId;CollectedAtUTC=$Frame.CollectedAtUTC;State=$Frame.State;Data=$data};
        Provenance=[pscustomobject]@{Provider='CIM';Command='Get-CimInstance';ClassName='MSFT_MpPreference';
            Namespace='root/Microsoft/Windows/Defender';Properties=$requestedNames;ReviewedProperties=$names;RemoteRequested=$false;FallbackUsed=$false;
            QueryAttempted=($requestedNames.Count -gt 0)};
        Coverage=[pscustomobject]@{Expected=$definitions.Count;Observed=$observed;Unknown=$unknown;Errors=$errors;RequiredUnresolved=$unresolved;Complete=($observed -eq $definitions.Count)};
        Diagnostic=$Frame.Reason}
}

function Invoke-WinSecDefenderPreferenceCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback,
        [ValidateRange(1,15000)][int]$TimeoutMilliseconds=15000)
    Assert-WinSecSnapshotIdentity $Identity
    if($Identity.CheckId -cne 'WSA-SYS-001'){throw 'Foreign Defender preference identity.'}
    $owner=$Identity.PSObject.Copy()
    $cancel={
        if($CancellationAction){
            $answer=@(& $CancellationAction)
            if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid Defender preference cancellation.'}
            if($answer[0]){throw [OperationCanceledException]::new('Defender preference capture cancelled.')}
        }
    }
    $job=$null;$frame=$null;$count=0;$clock=[Diagnostics.Stopwatch]::StartNew()
    $start=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
    try {
        $null=& $cancel
        if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage='PREFERENCE_QUERY';CompletedSteps=0;TotalSteps=1})}
        $null=& $cancel
        try {
            $job=Start-Job -ScriptBlock (Get-WinSecDefenderPreferenceQueryWorker) `
                -ArgumentList (Join-Path $PSScriptRoot 'DefenderTechnicalSnapshot.ps1'),$owner.DeviceId,$owner.ScanId -ErrorAction Stop
        }catch{throw 'Defender preference worker could not start.'}
        if($job -isnot [Management.Automation.Job]){throw 'Invalid Defender preference worker.'}
        while($true){
            $null=& $cancel
            if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){throw [TimeoutException]::new('Defender preference capture timed out.')}
            if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage='PREFERENCE_QUERY';CompletedSteps=0;TotalSteps=1})}
            if($job.HasMoreData){
                try{Receive-Job -Job $job -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction Ignore | ForEach-Object {
                    $count++;if($count -gt 1){throw 'Invalid frame count.'};$frame=$_
                }}catch{throw 'Invalid Defender preference worker output.'}
            }
            if($job.State -cin @('Completed','Failed','Stopped','Blocked','Disconnected')){break}
            Start-Sleep -Milliseconds 50
        }
        if($job.HasMoreData){
            try{Receive-Job -Job $job -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction Ignore | ForEach-Object {
                $count++;if($count -gt 1){throw 'Invalid frame count.'};$frame=$_
            }}catch{throw 'Invalid Defender preference worker output.'}
        }
        $null=& $cancel
        if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){throw [TimeoutException]::new('Defender preference capture timed out.')}
        if($job.State -cne 'Completed' -or $count -ne 1){throw 'Defender preference worker did not complete.'}
        $end=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
        $result=ConvertFrom-WinSecDefenderPreferenceQueryFrame $frame $owner $start $end
        $null=& $cancel
        if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage='PREFERENCE_CAPTURED';CompletedSteps=1;TotalSteps=1})}
        $null=& $cancel
        if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){throw [TimeoutException]::new('Defender preference capture timed out.')}
        return $result
    }finally{
        if($job -is [Management.Automation.Job]){
            if($job.State -cnotin @('Completed','Failed','Stopped')){Stop-Job -Job $job -ErrorAction SilentlyContinue}
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
