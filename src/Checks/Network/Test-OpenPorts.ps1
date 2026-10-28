# WinSec Analyzer
# Archivo: src\Checks\Network\Test-OpenPorts.ps1
# Read local TCP listeners / UDP bindings only. Never connect, probe or resolve peers.
function Invoke-WinSecOpenPortsQuery {
    [CmdletBinding()]
    param([ValidateSet('Platform','TCP','UDP')][string]$Role,[scriptblock]$CancellationAction,[scriptblock]$Heartbeat)
    $namespace='root/StandardCimv2';$filter=$null;$limit=512
    if($Role -ceq 'Platform'){
        $namespace='root/cimv2';$class='Win32_OperatingSystem';$limit=1
        $properties=@('Caption','Version','BuildNumber','OperatingSystemSKU','ProductType')
    }else{
        $class=if($Role -ceq 'TCP'){'MSFT_NetTCPConnection'}else{'MSFT_NetUDPEndpoint'}
        $properties=@(Get-WinSecOpenPortsProperties $Role)
        if($Role -ceq 'TCP'){$filter='State = 2'}
    }
    $job=$null;$timer=[Diagnostics.Stopwatch]::StartNew();$items=New-Object 'Collections.Generic.List[object]'
    try {
        $job=Start-Job -ScriptBlock {
            param($ns,$cn,$props,$where,$maximum)
            $records=New-Object 'Collections.Generic.List[object]';$status='AVAILABLE'
            try {
                $available=$props
                if($ns -ceq 'root/StandardCimv2'){
                    $classes=@(Get-CimClass -Namespace $ns -ClassName $cn -OperationTimeoutSec 5 -ErrorAction Stop)
                    if($classes.Count -ne 1 -or $classes[0].CimClassName -ine $cn){throw 'PORTS_SCHEMA_INVALID'}
                    $available=@()
                    foreach($name in $props){
                        $found=@($classes[0].CimClassProperties|Where-Object {$_.Name -ieq $name})
                        if($found.Count -gt 1 -or ($found.Count -eq 0 -and $name -cin @('LocalAddress','LocalPort','State'))){throw 'PORTS_SCHEMA_INVALID'}
                        if($found.Count){$available+=$name}
                    }
                }
                $parameters=@{Namespace=$ns;ClassName=$cn;Property=$available;OperationTimeoutSec=5;ErrorAction='Stop'}
                if($where){$parameters.Filter=$where}
                Get-CimInstance @parameters|ForEach-Object {
                    if($records.Count -ge $maximum){throw 'PORTS_RECORD_LIMIT'}
                    $record=[ordered]@{}
                    foreach($name in $available){$record[$name]=$_.PSObject.Properties[$name].Value}
                    $records.Add([pscustomobject]$record)
                }
            }catch{
                $status=switch($_.Exception.Message){PORTS_RECORD_LIMIT {'RECORD_LIMIT'};PORTS_SCHEMA_INVALID {'SCHEMA_INVALID'};default {'QUERY_FAILED'}}
                $records.Clear()
            }
            [pscustomobject]@{Class=$cn;Status=$status;Records=@($records.ToArray())}
        } -ArgumentList $namespace,$class,$properties,$filter,$limit -ErrorAction Stop
        while($true){
            if($CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid endpoint cancellation.'};if($answer[0]){throw [OperationCanceledException]::new('Endpoint collection cancelled.')}}
            if($Heartbeat){$null=& $Heartbeat}
            if($job.HasMoreData){Receive-Job $job -ErrorAction Stop|ForEach-Object {$items.Add($_);if($items.Count -gt 1){throw 'Invalid endpoint query envelope.'}}}
            if($job.State -cin @('Completed','Failed','Stopped','Disconnected','Blocked')){break}
            if($timer.Elapsed.TotalSeconds -ge 30){throw 'Endpoint query timeout.'}
            Start-Sleep -Milliseconds 60
        }
        if($job.State -cne 'Completed'){throw 'Endpoint query failed.'}
        if($job.HasMoreData){Receive-Job $job -ErrorAction Stop|ForEach-Object {$items.Add($_)}}
        if($items.Count -ne 1 -or $items[0].Class -cne $class -or $items[0].Status -cne 'AVAILABLE' -or
            $items[0].Records -isnot [Collections.IList] -or $items[0].Records.Count -gt $limit){throw 'Endpoint query unavailable or exceeded limit.'}
        return $items[0].Records
    }finally{
        if($job -is [Management.Automation.Job]){
            if($job.State -cnotin @('Completed','Failed','Stopped')){Stop-Job $job -ErrorAction SilentlyContinue}
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
function Test-WinSecOpenPorts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DeviceId,[Parameter(Mandatory)][string]$ScanId,[string]$CheckId='WSA-NET-004',
        [scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    if($CheckId -cne 'WSA-NET-004' -or -not (Test-WinSecTargetIdentifier $DeviceId) -or -not (Test-WinSecTargetIdentifier $ScanId)){throw 'Invalid Open Ports identity.'}
    $issues=New-Object 'Collections.Generic.List[string]';$batches=New-Object 'Collections.Generic.List[object]'
    $e=[pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;CollectedAtUTC='';CollectionSuccessful=$false;CollectionComplete=$false;
        CoverageComplete=$false;UnknownFieldCount=0;CollectionIssues=@();Platform=[pscustomobject]@{BuildNumber=$null;OperatingSystemSKU=$null;ProductType=$null};
        Availability=[pscustomobject]@{TCP='UNKNOWN';UDP='UNKNOWN'};Counts=[pscustomobject]@{TCP=$null;UDP=$null};Batches=@()}
    $completed=0;$phase='PLATFORM';$successful=0
    $emit={if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage=$phase;CompletedSteps=[int]$completed;TotalSteps=[int]4})}}
    $cancel={if($CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid endpoint cancellation.'};if($answer[0]){throw [OperationCanceledException]::new('Endpoint collection cancelled.')}}}
    $null=& $cancel;$null=& $emit
    try {
        $p=@(Invoke-WinSecOpenPortsQuery Platform -CancellationAction $CancellationAction -Heartbeat $emit)
        if($p.Count -ne 1 -or [string]$p[0].BuildNumber -cnotmatch '\A[0-9]{5}\z' -or [int]$p[0].BuildNumber -lt 22000 -or
            $p[0].ProductType -ne 1 -or [string]$p[0].Caption -notmatch '\A(?:Microsoft )?Windows 11(?: .*)?\z' -or
            [string]$p[0].Version -cne ('10.0.'+$p[0].BuildNumber) -or $null -eq (ConvertTo-WinSecOpenPortsNumber $p[0].OperatingSystemSKU)){throw 'Unknown Windows client.'}
        $e.Platform=[pscustomobject]@{BuildNumber=[int]$p[0].BuildNumber;OperatingSystemSKU=[long]$p[0].OperatingSystemSKU;ProductType=1}
    }catch [OperationCanceledException]{throw}catch{$issues.Add('PLATFORM_UNAVAILABLE')}
    $completed++
    foreach($protocol in @('TCP','UDP')){
        $phase=$protocol;$null=& $cancel;$null=& $emit
        try {
            $raw=@(Invoke-WinSecOpenPortsQuery $protocol -CancellationAction $CancellationAction -Heartbeat $emit)
            if($raw.Count -gt 512){throw 'Endpoint inventory exceeds the reviewed limit.'}
            $normalized=@();$index=0
            foreach($record in $raw){$null=& $cancel;$index++;$normalized+=,(ConvertTo-WinSecOpenPortsEndpoint $record $protocol $index)}
            $count=Get-WinSecOpenPortsCounts $normalized
            $pending=@()
            for($offset=0;$offset -lt $normalized.Count;$offset+=64){
                $last=[math]::Min($normalized.Count-1,$offset+63)
                $json=ConvertTo-Json -InputObject ([ordered]@{SchemaVersion='1.0.0';Protocol=$protocol;Items=@($normalized[$offset..$last])}) -Compress -Depth 4
                $null=ConvertTo-WinSecOpenPortsBatch $json
                $pending+=,[pscustomobject]@{Protocol=$protocol;Json=$json}
            }
            foreach($batch in $pending){$batches.Add($batch)}
            $e.Counts.$protocol=$count;$e.Availability.$protocol='OBSERVED';$e.UnknownFieldCount+=$count.UnknownFields;$successful++
        }catch [OperationCanceledException]{throw}catch{$issues.Add($protocol+'_UNAVAILABLE')}
        $completed++
    }
    $phase='NORMALIZING';$null=& $cancel;$null=& $emit
    $e.Batches=@($batches.ToArray());$e.CollectionIssues=@($issues.ToArray());$e.CollectedAtUTC=[datetime]::UtcNow.ToString('o')
    $e.CollectionSuccessful=($successful -gt 0);$e.CollectionComplete=($issues.Count -eq 0);$e.CoverageComplete=($e.CollectionComplete -and $e.UnknownFieldCount -eq 0)
    $completed++;$null=& $emit
    [pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;SectionKey='NetworkSecurity';Status=if($e.CollectionComplete){'INFORMATIONAL'}else{'UNKNOWN'};Evidence=$e}
}
