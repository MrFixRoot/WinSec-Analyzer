# Local configuration only: no sockets, probes, DNS resolution or changes to Windows.
function Invoke-WinSecNetworkConfigurationQuery {
    [CmdletBinding()]
    param([string]$Role,[scriptblock]$CancellationAction,[scriptblock]$Heartbeat)
    $namespace='root/cimv2';$class='Win32_OperatingSystem';$limit=1;$required=@()
    $properties=@('Caption','Version','BuildNumber','OperatingSystemSKU','ProductType')
    if($Role -cnotin @('Platform','Registry')){
        $p=Get-WinSecNetworkConfigurationProvider $Role;$namespace=$p.Namespace;$class=$p.Class
        $properties=@($p.Fields.Name);$required=$p.Required;$limit=$p.Limit
    }
    $job=$null;$timer=[Diagnostics.Stopwatch]::StartNew();$items=New-Object 'Collections.Generic.List[object]'
    try {
        $job=Start-Job -ScriptBlock {
            param($roleName,$ns,$cn,$props,$requiredFields,$maximum)
            $records=New-Object 'Collections.Generic.List[object]';$status='AVAILABLE'
            try {
                if($roleName -ceq 'Registry'){
                    $base=$null;$key=$null
                    try {
                        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
                        $key=$base.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\DNSClient',$false)
                        $values=[ordered]@{}
                        foreach($name in @('EnableMulticast','DisableSmartNameResolution','DoHPolicy')){
                            $value=$null;$state='NOT_CONFIGURED'
                            if($key -and $name -in $key.GetValueNames()){
                                if($key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::DWord){throw 'NETWORK_POLICY_TYPE'}
                                $value=[long]$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                                if($value -lt 0 -or $value -gt $(if($name -ceq 'DoHPolicy'){3}else{1})){throw 'NETWORK_POLICY_RANGE'}
                                $state='CONFIGURED'
                            }
                            $values[$name]=[pscustomobject]@{State=$state;Value=$value}
                        }
                        $records.Add([pscustomobject]@{ReadState='READ';Values=[pscustomobject]$values})
                    }finally{if($key){$key.Dispose()};if($base){$base.Dispose()}}
                }else{
                    $available=$props
                    if($roleName -cne 'Platform'){
                        $classes=@(Get-CimClass -Namespace $ns -ClassName $cn -OperationTimeoutSec 5 -ErrorAction Stop)
                        if($classes.Count -ne 1 -or $classes[0].CimClassName -ine $cn){throw 'NETWORK_SCHEMA_INVALID'}
                        $available=@()
                        foreach($name in $props){
                            $found=@($classes[0].CimClassProperties|Where-Object Name -IEQ $name)
                            if($found.Count -gt 1 -or ($found.Count -eq 0 -and $name -cin $requiredFields)){throw 'NETWORK_SCHEMA_INVALID'}
                            if($found.Count){$available+=$name}
                        }
                        if(-not $available.Count){throw 'NETWORK_SCHEMA_INVALID'}
                    }
                    Get-CimInstance -Namespace $ns -ClassName $cn -Property $available -OperationTimeoutSec 5 -ErrorAction Stop|ForEach-Object {
                        if($records.Count -ge $maximum){throw 'NETWORK_RECORD_LIMIT'}
                        $r=[ordered]@{};foreach($name in $available){$r[$name]=$_.PSObject.Properties[$name].Value};$records.Add([pscustomobject]$r)
                    }
                }
            }catch{
                $status=switch($_.Exception.Message){NETWORK_RECORD_LIMIT {'RECORD_LIMIT'};NETWORK_SCHEMA_INVALID {'SCHEMA_INVALID'};default {'QUERY_FAILED'}};$records.Clear()
            }
            [pscustomobject]@{Role=$roleName;Status=$status;Records=@($records.ToArray())}
        } -ArgumentList $Role,$namespace,$class,$properties,$required,$limit -ErrorAction Stop
        while($true){
            if($CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid network cancellation.'};if($answer[0]){throw [OperationCanceledException]::new('Network collection cancelled.')}}
            if($Heartbeat){$null=& $Heartbeat}
            if($job.HasMoreData){Receive-Job $job -ErrorAction Stop|ForEach-Object {$items.Add($_);if($items.Count -gt 1){throw 'Invalid network query envelope.'}}}
            if($job.State -cin @('Completed','Failed','Stopped','Disconnected','Blocked')){break}
            if($timer.Elapsed.TotalSeconds -ge 30){throw 'NETWORK_TIMEOUT'};Start-Sleep -Milliseconds 60
        }
        if($job.State -cne 'Completed'){throw 'NETWORK_QUERY_FAILED'}
        if($job.HasMoreData){Receive-Job $job -ErrorAction Stop|ForEach-Object {$items.Add($_)}}
        if($items.Count -ne 1 -or $items[0].Role -cne $Role -or
            $items[0].Status -cnotin @('AVAILABLE','SCHEMA_INVALID','RECORD_LIMIT','QUERY_FAILED') -or
            $items[0].Records -isnot [Collections.IList] -or $items[0].Records.Count -gt $limit){throw 'NETWORK_INVALID_ENVELOPE'}
        if($items[0].Status -cne 'AVAILABLE'){throw ('NETWORK_'+$items[0].Status)}
        return $items[0].Records
    }finally{
        if($job -is [Management.Automation.Job]){
            if($job.State -cnotin @('Completed','Failed','Stopped')){Stop-Job $job -ErrorAction SilentlyContinue};Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
function Test-WinSecNetworkConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DeviceId,[Parameter(Mandatory)][string]$ScanId,[string]$CheckId='WSA-NET-005',
        [scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    if($CheckId -cne 'WSA-NET-005' -or -not (Test-WinSecTargetIdentifier $DeviceId) -or -not (Test-WinSecTargetIdentifier $ScanId)){throw 'Invalid Network Configuration identity.'}
    $providers=@(Get-WinSecNetworkConfigurationProviders);$issues=New-Object 'Collections.Generic.List[string]';$batches=New-Object 'Collections.Generic.List[object]'
    $diagnostics=New-Object 'Collections.Generic.List[string]';$diagnosticCodes=@(Get-WinSecNetworkConfigurationDiagnosticCodes)
    $e=[pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;CollectedAtUTC='';CollectionSuccessful=$false;CollectionComplete=$false;
        CoverageComplete=$false;UnknownFieldCount=0;CollectionIssues=@();ProviderDiagnostics=@();Platform=[pscustomobject]@{BuildNumber=$null;OperatingSystemSKU=$null;ProductType=$null};
        Availability=[pscustomobject]@{};Counts=[pscustomobject]@{};RegistryReadState='UNKNOWN';Registry=[pscustomobject]@{};Batches=@()}
    foreach($p in $providers){$e.Availability|Add-Member $p.Role UNKNOWN;$e.Counts|Add-Member $p.Role $null}
    foreach($p in Get-WinSecNetworkConfigurationRegistryDefinitions){$e.Registry|Add-Member $p.Name ([pscustomobject]@{State='UNKNOWN';Value=$null})}
    $completed=0;$total=$providers.Count+3;$phase='PLATFORM';$successful=0
    $emit={if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage=$phase;CompletedSteps=[int]$completed;TotalSteps=[int]$total})}}
    $cancel={if($CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid network cancellation.'};if($answer[0]){throw [OperationCanceledException]::new('Network collection cancelled.')}}}
    $null=& $cancel;$null=& $emit
    try {
        $p=@(Invoke-WinSecNetworkConfigurationQuery Platform -CancellationAction $CancellationAction -Heartbeat $emit)
        if($p.Count -ne 1 -or [string]$p[0].BuildNumber -cnotmatch '\A[0-9]{5}\z' -or [int]$p[0].BuildNumber -lt 22000 -or
            $p[0].ProductType -ne 1 -or [string]$p[0].Caption -notmatch '\A(?:Microsoft )?Windows 11(?: .*)?\z' -or
            [string]$p[0].Version -cne ('10.0.'+$p[0].BuildNumber) -or $null -eq (ConvertTo-WinSecNetworkConfigurationNumber $p[0].OperatingSystemSKU)){throw 'Unknown Windows network context.'}
        $e.Platform=[pscustomobject]@{BuildNumber=[int]$p[0].BuildNumber;OperatingSystemSKU=[long]$p[0].OperatingSystemSKU;ProductType=1}
    }catch [OperationCanceledException]{throw}catch{$issues.Add('PLATFORM_UNAVAILABLE')};$completed++
    foreach($provider in $providers){
        $role=$provider.Role;$phase=$role.ToUpperInvariant();$null=& $cancel;$null=& $emit
        $diagnosticStage='QUERY'
        try {
            $raw=@(Invoke-WinSecNetworkConfigurationQuery $role -CancellationAction $CancellationAction -Heartbeat $emit)
            $diagnosticStage='NORMALIZATION'
            if($raw.Count -gt $provider.Limit -or ($provider.Limit -eq 1 -and $raw.Count -ne 1)){throw 'Network provider inventory exceeds its reviewed cardinality.'}
            $records=@();$index=0
            foreach($record in $raw){$null=& $cancel;$index++;$records+=,(ConvertTo-WinSecNetworkConfigurationRecord $record $role $index)}
            $pending=@();$diagnosticStage='BATCH'
            for($offset=0;$offset -lt $records.Count;$offset+=16){
                $last=[math]::Min($records.Count-1,$offset+15)
                $json=ConvertTo-Json -InputObject ([ordered]@{SchemaVersion='1.0.0';Role=$role;Items=@($records[$offset..$last])}) -Compress -Depth 6
                $null=ConvertTo-WinSecNetworkConfigurationBatch $json;$pending+=,[pscustomobject]@{Role=$role;Json=$json}
            }
            foreach($batch in $pending){$batches.Add($batch)}
            $e.Counts.$role=$records.Count;$e.Availability.$role='OBSERVED';$e.UnknownFieldCount+=Get-WinSecNetworkConfigurationUnknownCount $records;$successful++
        }catch [OperationCanceledException]{throw}catch{
            $issues.Add($role.ToUpperInvariant()+'_UNAVAILABLE')
            $candidate=$role+':'+$diagnosticStage+':'+$_.Exception.Message
            if($candidate -cnotin $diagnosticCodes){$candidate=$role+':'+$diagnosticStage+':UNAVAILABLE'}
            $diagnostics.Add($candidate)
        };$completed++
    }
    $phase='DNSPOLICIES';$null=& $cancel;$null=& $emit
    try {
        $raw=@(Invoke-WinSecNetworkConfigurationQuery Registry -CancellationAction $CancellationAction -Heartbeat $emit)
        if($raw.Count -ne 1 -or $raw[0].ReadState -cne 'READ'){throw 'Invalid DNS policy response.'}
        $pending=[ordered]@{}
        foreach($p in Get-WinSecNetworkConfigurationRegistryDefinitions){
            $item=$raw[0].Values.($p.Name)
            if($null -eq $item -or $item.State -cnotin @('CONFIGURED','NOT_CONFIGURED') -or
                ($item.State -ceq 'NOT_CONFIGURED' -and $null -ne $item.Value) -or
                ($item.State -ceq 'CONFIGURED' -and $null -eq (ConvertTo-WinSecNetworkConfigurationNumber $item.Value $p.Maximum))){throw 'Invalid DNS machine policy.'}
            $pending[$p.Name]=[pscustomobject]@{State=$item.State;Value=$item.Value}
        }
        $e.Registry=[pscustomobject]$pending;$e.RegistryReadState='READ'
    }catch [OperationCanceledException]{throw}catch{$issues.Add('REGISTRY_UNAVAILABLE')};$completed++
    $phase='NORMALIZING';$null=& $cancel;$null=& $emit
    $e.Batches=@($batches.ToArray());$e.CollectionIssues=@($issues.ToArray());$e.ProviderDiagnostics=@($diagnostics.ToArray());$e.CollectedAtUTC=[datetime]::UtcNow.ToString('o')
    $e.CollectionSuccessful=($successful -gt 0);$e.CollectionComplete=($issues.Count -eq 0);$e.CoverageComplete=($e.CollectionComplete -and $e.UnknownFieldCount -eq 0)
    $completed++;$null=& $emit
    [pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;SectionKey='NetworkSecurity';Status=if($e.CollectionComplete){'INFORMATIONAL'}else{'UNKNOWN'};Evidence=$e}
}
