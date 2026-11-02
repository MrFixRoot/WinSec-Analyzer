# Isolated candidate acquisition. No production registration or work on import.
# Local identity and specific authorization remain the future coordinator's responsibility.
. (Join-Path $PSScriptRoot 'DefenderTechnicalSnapshot.ps1')

function Get-WinSecDefenderStatusQueryWorker {
    return {
        param([string]$SnapshotPath,[string]$DeviceId,[string]$ScanId)
        $ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
        $frame=[pscustomobject]@{SchemaVersion='WinSec.Defender.StatusQuery1.0';SourceId='Status';DeviceId=$DeviceId;ScanId=$ScanId;
            CollectedAtUTC='';State='ERROR';Reason='BOOTSTRAP_FAILED';Data=$null}
        $record=$null
        try {
            . $SnapshotPath
            $frame.Reason='PROVIDER_UNAVAILABLE'
            $count=0
            # No remote session, preferences, detection history, nested job or CIM fallback.
            Get-MpComputerStatus -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null | ForEach-Object {
                $count++
                if($count -gt 1){$frame.Reason='UNEXPECTED_CARDINALITY';throw 'Rejected cardinality.'}
                $record=$_
            }
            if($count -ne 1){$frame.Reason='UNEXPECTED_CARDINALITY';throw 'Rejected cardinality.'}
            $frame.Reason='INVALID_SOURCE'
            Assert-WinSecDefenderCapturedCimSource $record Status
            $frame.Reason='NORMALIZATION_FAILED'
            $frame.Data=New-WinSecDefenderStatusReadings $record
            $frame.State='OBSERVED';$frame.Reason='NONE'
        }catch{$frame.Data=$null;$frame.State='ERROR'}finally{
            if($record -is [Microsoft.Management.Infrastructure.CimInstance]){
                try{$null=[Microsoft.Management.Infrastructure.CimInstance].GetMethod('Dispose').Invoke($record,$null)}catch{}
            }
        }
        $frame.CollectedAtUTC=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
        return $frame
    }
}

function ConvertFrom-WinSecDefenderStatusQueryFrame {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Frame,[Parameter(Mandatory)][object]$Identity,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC)
    Assert-WinSecSnapshotIdentity $Identity
    if($Identity.CheckId -cne 'WSA-SYS-001'){throw 'Foreign Defender status identity.'}
    if($Frame -isnot [Management.Automation.PSCustomObject]){throw 'Invalid Defender status transport.'}
    $fields=@('SchemaVersion','SourceId','DeviceId','ScanId','CollectedAtUTC','State','Reason','Data')
    foreach($property in $Frame.PSObject.Properties){
        if($property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
            $property.Name -cnotin ($fields+@('PSComputerName','RunspaceId','PSShowComputerName'))){throw 'Invalid Defender status transport.'}
    }
    foreach($name in $fields){if($null -eq $Frame.PSObject.Properties[$name]){throw 'Incomplete Defender status transport.'}}
    foreach($name in @('SchemaVersion','SourceId','DeviceId','ScanId','CollectedAtUTC','State','Reason')){
        if($Frame.$name -isnot [string]){throw 'Invalid Defender status header.'}
    }
    if($Frame.SchemaVersion -cne 'WinSec.Defender.StatusQuery1.0' -or $Frame.SourceId -cne 'Status' -or
        $Frame.DeviceId -cne $Identity.DeviceId -or $Frame.ScanId -cne $Identity.ScanId -or $Frame.State -cnotin @('OBSERVED','ERROR') -or
        $Frame.Reason -cnotin @('NONE','BOOTSTRAP_FAILED','PROVIDER_UNAVAILABLE','UNEXPECTED_CARDINALITY','INVALID_SOURCE','NORMALIZATION_FAILED')){
        throw 'Foreign or invalid Defender status transport.'
    }
    $start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    $collected=ConvertTo-WinSecSnapshotUtc $Frame.CollectedAtUTC
    if($start -gt $collected -or $collected -gt $end){throw 'Invalid Defender status timeline.'}
    $data=$null;$definitions=@(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Status)
    $observed=0;$unknown=0;$errors=0;$unresolved=0
    if($Frame.State -ceq 'OBSERVED'){
        if($Frame.Reason -cne 'NONE'){throw 'Contradictory Defender status state.'}
        Assert-WinSecSnapshotFields $Frame.Data @('ArtifactType','SchemaVersion','Readings')
        $carrier=$Frame.Data.Readings
        # CLIXML jobs deserialize arrays as ArrayList. Accept only this known transport or a rank-one array.
        if($carrier -is [Collections.ArrayList]){
            if($carrier.GetType() -ne [Collections.ArrayList]){throw 'Unreviewed Defender status transport list.'}
        }elseif($carrier -isnot [array] -or $carrier.Rank -ne 1){throw 'Invalid Defender status transport list.'}
        if($carrier.Count -ne $definitions.Count){throw 'Incomplete Defender status transport list.'}
        $canonicalRows=if($carrier -is [Collections.ArrayList]){$carrier.ToArray()}else{$carrier}
        $canonical=[pscustomobject]@{ArtifactType=$Frame.Data.ArtifactType;SchemaVersion=$Frame.Data.SchemaVersion;Readings=@($canonicalRows)}
        Assert-WinSecDefenderStatusReadings $canonical
        $rows=@(foreach($reading in $canonical.Readings){$reading.PSObject.Copy()})
        $data=[pscustomobject]@{ArtifactType='WinSec.Defender.StatusReadings';SchemaVersion='1.0.0';Readings=$rows}
        for($i=0;$i -lt $rows.Count;$i++){
            if($rows[$i].State -ceq 'OBSERVED'){$observed++}else{$unknown++;if($definitions[$i].Required){$unresolved++}}
        }
    }else{
        if($null -ne $Frame.Data -or $Frame.Reason -ceq 'NONE'){throw 'Contradictory Defender status failure.'}
        $errors=$definitions.Count;$unresolved=@($definitions|Where-Object Required).Count
    }
    [pscustomobject]@{ArtifactType='WinSec.Defender.StatusCapture';SchemaVersion='1.0.0';Identity=$Identity.PSObject.Copy();
        Source=[pscustomobject]@{SourceId='Status';DeviceId=$Identity.DeviceId;ScanId=$Identity.ScanId;CollectedAtUTC=$Frame.CollectedAtUTC;State=$Frame.State;Data=$data};
        Provenance=[pscustomobject]@{Provider='CMDLET';Command='Get-MpComputerStatus';ClassName='MSFT_MpComputerStatus';
            Namespace='root/Microsoft/Windows/Defender';Properties=@($definitions|ForEach-Object Property);RemoteRequested=$false;FallbackUsed=$false;
            QueryAttempted=($Frame.Reason -cne 'BOOTSTRAP_FAILED')};
        Coverage=[pscustomobject]@{Expected=$definitions.Count;Observed=$observed;Unknown=$unknown;Errors=$errors;RequiredUnresolved=$unresolved;Complete=($observed -eq $definitions.Count)};
        Diagnostic=$Frame.Reason}
}

function Invoke-WinSecDefenderStatusCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback,
        [ValidateRange(1,15000)][int]$TimeoutMilliseconds=15000)
    Assert-WinSecSnapshotIdentity $Identity
    if($Identity.CheckId -cne 'WSA-SYS-001'){throw 'Foreign Defender status identity.'}
    $owner=$Identity.PSObject.Copy()
    $cancel={
        if($CancellationAction){
            $answer=@(& $CancellationAction)
            if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid Defender status cancellation.'}
            if($answer[0]){throw [OperationCanceledException]::new('Defender status capture cancelled.')}
        }
    }
    $job=$null;$frame=$null;$count=0;$clock=[Diagnostics.Stopwatch]::StartNew()
    $start=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
    try {
        $null=& $cancel
        if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage='STATUS_QUERY';CompletedSteps=0;TotalSteps=1})}
        $null=& $cancel
        try {
            $job=Start-Job -ScriptBlock (Get-WinSecDefenderStatusQueryWorker) `
                -ArgumentList (Join-Path $PSScriptRoot 'DefenderTechnicalSnapshot.ps1'),$owner.DeviceId,$owner.ScanId -ErrorAction Stop
        }catch{throw 'Defender status worker could not start.'}
        if($job -isnot [Management.Automation.Job]){throw 'Invalid Defender status worker.'}
        while($true){
            $null=& $cancel
            if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){throw [TimeoutException]::new('Defender status capture timed out.')}
            if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage='STATUS_QUERY';CompletedSteps=0;TotalSteps=1})}
            if($job.HasMoreData){
                try{Receive-Job -Job $job -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction Ignore | ForEach-Object {
                    $count++;if($count -gt 1){throw 'Invalid frame count.'};$frame=$_
                }}catch{throw 'Invalid Defender status worker output.'}
            }
            if($job.State -cin @('Completed','Failed','Stopped','Blocked','Disconnected')){break}
            Start-Sleep -Milliseconds 50
        }
        if($job.HasMoreData){
            try{Receive-Job -Job $job -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction Ignore | ForEach-Object {
                $count++;if($count -gt 1){throw 'Invalid frame count.'};$frame=$_
            }}catch{throw 'Invalid Defender status worker output.'}
        }
        $null=& $cancel
        if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){throw [TimeoutException]::new('Defender status capture timed out.')}
        if($job.State -cne 'Completed' -or $count -ne 1){throw 'Defender status worker did not complete.'}
        $end=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
        $result=ConvertFrom-WinSecDefenderStatusQueryFrame $frame $owner $start $end
        $null=& $cancel
        if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage='STATUS_CAPTURED';CompletedSteps=1;TotalSteps=1})}
        $null=& $cancel
        if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){throw [TimeoutException]::new('Defender status capture timed out.')}
        return $result
    }finally{
        if($job -is [Management.Automation.Job]){
            if($job.State -cnotin @('Completed','Failed','Stopped')){Stop-Job -Job $job -ErrorAction SilentlyContinue}
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
