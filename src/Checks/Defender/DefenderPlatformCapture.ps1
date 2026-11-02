# Isolated candidate acquisition. Import declares functions only; production never imports this file.
# Call only inside a separately authorized local operation. Identity is supplied, not authenticated here.
. (Join-Path $PSScriptRoot 'DefenderTechnicalSnapshot.ps1')

function Get-WinSecDefenderPlatformQueryWorker {
    # Runs in an owned job. Only a bounded, normalized frame may cross the process boundary.
    return {
        param([string]$SnapshotPath,[string]$DeviceId,[string]$ScanId)
        $ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
        $frame=[pscustomobject]@{SchemaVersion='WinSec.Defender.PlatformQuery1.0';SourceId='Platform';DeviceId=$DeviceId;ScanId=$ScanId;
            CollectedAtUTC='';State='ERROR';Reason='PROVIDER_UNAVAILABLE';Data=$null}
        $record=$null
        try {
            . $SnapshotPath
            $count=0
            Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_OperatingSystem' `
                -Property Version,BuildNumber,OperatingSystemSKU,ProductType -OperationTimeoutSec 5 -ErrorAction Stop `
                3>$null 4>$null 5>$null 6>$null | ForEach-Object {
                $count++
                if($count -gt 1){$frame.Reason='UNEXPECTED_CARDINALITY';throw 'Rejected cardinality.'}
                $record=$_
            }
            if($count -ne 1){$frame.Reason='UNEXPECTED_CARDINALITY';throw 'Rejected cardinality.'}
            $frame.Reason='INVALID_SOURCE'
            Assert-WinSecDefenderCapturedCimSource $record Platform
            $data=[ordered]@{}
            $frame.Reason='INVALID_VALUE'
            foreach($field in @(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Platform)){
                $property=Get-WinSecDefenderCapturedProperty $record $field.Property
                if(-not $property.Exists -or -not $property.Safe){throw 'Rejected field.'}
                $value=ConvertTo-WinSecDefenderTechnicalValue $property.Value $field.Kind
                if(-not $value.Valid){throw 'Rejected value.'}
                $data[$field.Property]=$value.Value
            }
            $frame.Data=[pscustomobject]$data;$frame.State='OBSERVED';$frame.Reason='NONE'
        }catch{
            $frame.Data=$null;$frame.State='ERROR'
        }finally{
            if($record -is [Microsoft.Management.Infrastructure.CimInstance]){
                try{$null=[Microsoft.Management.Infrastructure.CimInstance].GetMethod('Dispose').Invoke($record,$null)}catch{}
            }
        }
        $frame.CollectedAtUTC=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
        return $frame
    }
}

function ConvertFrom-WinSecDefenderPlatformQueryFrame {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Frame,[Parameter(Mandatory)][object]$Identity,
        [Parameter(Mandatory)][string]$StartedAtUTC,[Parameter(Mandatory)][string]$CompletedAtUTC)
    Assert-WinSecSnapshotIdentity $Identity
    if($Identity.CheckId -cne 'WSA-SYS-001'){throw 'Foreign Defender capture identity.'}
    # Receive-Job may add these transport properties; none enters the capture or snapshot.
    if($Frame -isnot [Management.Automation.PSCustomObject]){throw 'Invalid Defender platform transport.'}
    $fields=@('SchemaVersion','SourceId','DeviceId','ScanId','CollectedAtUTC','State','Reason','Data')
    $transport=@('PSComputerName','RunspaceId','PSShowComputerName')
    foreach($property in $Frame.PSObject.Properties){
        if($property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or $property.Name -cnotin ($fields+$transport)){
            throw 'Invalid Defender platform transport.'
        }
    }
    foreach($name in $fields){if($null -eq $Frame.PSObject.Properties[$name]){throw 'Incomplete Defender platform transport.'}}
    foreach($name in @('SchemaVersion','SourceId','DeviceId','ScanId','CollectedAtUTC')){
        if($Frame.$name -isnot [string]){throw 'Invalid Defender platform transport header.'}
    }
    if($Frame.SchemaVersion -cne 'WinSec.Defender.PlatformQuery1.0' -or $Frame.SourceId -cne 'Platform' -or
        $Frame.DeviceId -cne $Identity.DeviceId -or $Frame.ScanId -cne $Identity.ScanId -or
        $Frame.State -isnot [string] -or $Frame.State -cnotin @('OBSERVED','ERROR') -or
        $Frame.Reason -isnot [string] -or $Frame.Reason -cnotin @('NONE','PROVIDER_UNAVAILABLE','UNEXPECTED_CARDINALITY','INVALID_SOURCE','INVALID_VALUE')){
        throw 'Foreign or invalid Defender platform transport.'
    }
    $start=ConvertTo-WinSecSnapshotUtc $StartedAtUTC;$end=ConvertTo-WinSecSnapshotUtc $CompletedAtUTC
    $collected=ConvertTo-WinSecSnapshotUtc $Frame.CollectedAtUTC
    if($start -gt $collected -or $collected -gt $end){throw 'Invalid Defender capture timeline.'}
    $data=$null
    if($Frame.State -ceq 'OBSERVED'){
        if($Frame.Reason -cne 'NONE'){throw 'Contradictory Defender capture state.'}
        Assert-WinSecSnapshotFields $Frame.Data @('Version','BuildNumber','OperatingSystemSKU','ProductType')
        $copy=[ordered]@{}
        foreach($field in @(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Platform)){
            # The worker already normalized these leaves. Reject objects/arrays/coercions before inspecting values.
            if(($field.Kind -ceq 'PlatformVersion' -and $Frame.Data.($field.Property) -isnot [string]) -or
                ($field.Kind -cne 'PlatformVersion' -and $Frame.Data.($field.Property) -isnot [uint32])){
                throw 'Invalid normalized Defender capture type.'
            }
            $value=ConvertTo-WinSecDefenderTechnicalValue $Frame.Data.($field.Property) $field.Kind
            if(-not $value.Valid -or $value.Value -cne $Frame.Data.($field.Property)){throw 'Invalid normalized Defender capture value.'}
            $copy[$field.Property]=$value.Value
        }
        $data=[pscustomobject]$copy
    }elseif($null -ne $Frame.Data -or $Frame.Reason -ceq 'NONE'){throw 'Contradictory Defender capture failure.'}
    [pscustomobject]@{ArtifactType='WinSec.Defender.PlatformCapture';SchemaVersion='1.0.0';Identity=$Identity.PSObject.Copy();
        Source=[pscustomobject]@{SourceId='Platform';DeviceId=$Identity.DeviceId;ScanId=$Identity.ScanId;
            CollectedAtUTC=$Frame.CollectedAtUTC;State=$Frame.State;Data=$data};
        Provenance=[pscustomobject]@{Provider='CIM';Command='Get-CimInstance';Namespace='root/cimv2';ClassName='Win32_OperatingSystem';
            Properties=@('Version','BuildNumber','OperatingSystemSKU','ProductType');RemoteRequested=$false};
        Diagnostic=$Frame.Reason}
}

function Invoke-WinSecDefenderPlatformCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback,
        [ValidateRange(1,15000)][int]$TimeoutMilliseconds=15000)
    Assert-WinSecSnapshotIdentity $Identity
    if($Identity.CheckId -cne 'WSA-SYS-001'){throw 'Foreign Defender capture identity.'}
    $owner=$Identity.PSObject.Copy()
    $cancel={
        if($CancellationAction){
            $answer=@(& $CancellationAction)
            if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid Defender capture cancellation.'}
            if($answer[0]){throw [OperationCanceledException]::new('Defender capture cancelled.')}
        }
    }
    $job=$null;$frame=$null;$count=0;$clock=[Diagnostics.Stopwatch]::StartNew()
    $start=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
    try {
        $null=& $cancel
        if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage='PLATFORM_QUERY';CompletedSteps=0;TotalSteps=1})}
        $null=& $cancel
        try {
            $job=Start-Job -ScriptBlock (Get-WinSecDefenderPlatformQueryWorker) `
                -ArgumentList (Join-Path $PSScriptRoot 'DefenderTechnicalSnapshot.ps1'),$owner.DeviceId,$owner.ScanId -ErrorAction Stop
        }catch{throw 'Defender capture worker could not start.'}
        if($job -isnot [Management.Automation.Job]){throw 'Invalid Defender capture worker.'}
        while($true){
            $null=& $cancel
            if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){throw [TimeoutException]::new('Defender platform capture timed out.')}
            if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage='PLATFORM_QUERY';CompletedSteps=0;TotalSteps=1})}
            if($job.HasMoreData){
                try {
                    Receive-Job -Job $job -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction Ignore | ForEach-Object {
                        $count++;if($count -gt 1){throw 'Invalid frame count.'};$frame=$_
                    }
                }catch{throw 'Invalid Defender capture worker output.'}
            }
            if($job.State -cin @('Completed','Failed','Stopped','Blocked','Disconnected')){break}
            Start-Sleep -Milliseconds 50
        }
        if($job.HasMoreData){
            try {
                Receive-Job -Job $job -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction Ignore | ForEach-Object {
                    $count++;if($count -gt 1){throw 'Invalid frame count.'};$frame=$_
                }
            }catch{throw 'Invalid Defender capture worker output.'}
        }
        $null=& $cancel
        if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){throw [TimeoutException]::new('Defender platform capture timed out.')}
        if($job.State -cne 'Completed' -or $count -ne 1){throw 'Defender capture worker did not complete.'}
        $end=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
        $result=ConvertFrom-WinSecDefenderPlatformQueryFrame $frame $owner $start $end
        $null=& $cancel
        if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage='PLATFORM_CAPTURED';CompletedSteps=1;TotalSteps=1})}
        $null=& $cancel
        return $result
    }finally{
        # Only the job created by this invocation is stopped/removed. Never enumerate or stop other jobs/services.
        if($job -is [Management.Automation.Job]){
            if($job.State -cnotin @('Completed','Failed','Stopped')){Stop-Job -Job $job -ErrorAction SilentlyContinue}
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
