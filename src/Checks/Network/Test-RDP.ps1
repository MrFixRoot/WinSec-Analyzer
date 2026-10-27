# WinSec Analyzer
# Archivo: src\Checks\Network\Test-RDP.ps1
# Read-only local configuration. No connections, sessions, users or credentials.
function Invoke-WinSecRdpQuery {
    [CmdletBinding()]
    param([ValidateSet('Platform','Services','Global','General','Logon','Session','Redirection','Network','Permissions')][string]$Role,
        [scriptblock]$CancellationAction,[scriptblock]$Heartbeat,[ref]$Metadata,
        [ValidateSet('AllowDwm','PolicySourceAllowDwm')][string[]]$SkipFields=@())
    if($SkipFields.Count -and $Role -cne 'Redirection'){throw 'Unreviewed RDP property exclusion.'}
    $namespace='root/cimv2/TerminalServices';$filter=$null
    switch($Role){
        Platform {$namespace='root/cimv2';$class='Win32_OperatingSystem';$properties=@('Caption','Version','BuildNumber','OperatingSystemSKU','ProductType')}
        Services {$namespace='root/cimv2';$class='Win32_Service';$properties=@('Name','State','StartMode');$filter="Name = 'TermService' OR Name = 'UmRdpService' OR Name = 'SessionEnv'"}
        default {$d=@(Get-WinSecRdpClasses|Where-Object Id -CEQ $Role)[0];$class=$d.Class;$properties=@($d.Fields);if(-not $d.Singleton){$properties=@('TerminalName')+$properties}}
    }
    $properties=@($properties|Where-Object {$_ -cnotin $SkipFields})
    $job=$null;$timer=[Diagnostics.Stopwatch]::StartNew();$items=New-Object 'Collections.Generic.List[object]'
    try {
        $job=Start-Job -ScriptBlock {
            param($ns,$cn,$props,$where)
            $queryParameters=@{Namespace=$ns;ClassName=$cn;Property=$props;OperationTimeoutSec=5;ErrorAction='Stop'}
            if($where){$queryParameters.Filter=$where}
            if($ns -cne 'root/cimv2/TerminalServices'){Get-CimInstance @queryParameters;return}
            $missing=@();$records=New-Object 'Collections.Generic.List[object]';$status='AVAILABLE'
            try {
                $classes=@(Get-CimClass -Namespace $ns -ClassName $cn -OperationTimeoutSec 5 -ErrorAction Stop)
                if($classes.Count -ne 1 -or $classes[0].CimClassName -ine $cn){throw 'RDP_SCHEMA_IDENTITY_INVALID'}
                $available=@();$names=@{}
                foreach($name in $props){
                    $definition=@($classes[0].CimClassProperties|Where-Object {$_.Name -ieq $name})
                    if($definition.Count -gt 1){throw 'RDP_SCHEMA_IDENTITY_INVALID'}
                    if($definition.Count){$available+=$name;$names[$name]=$true}else{$missing+=$name}
                }
                if(($props -contains 'TerminalName' -and -not $names.ContainsKey('TerminalName')) -or $available.Count -eq 0){throw 'RDP_SCHEMA_IDENTITY_INVALID'}
                # No wildcard or newly discovered property may enter the query.
                $queryParameters.Property=$available
                Get-CimInstance @queryParameters|ForEach-Object {
                    if($records.Count -ge 64){throw 'RDP_RECORD_LIMIT'}
                    $record=[ordered]@{}
                    foreach($name in $available){$record[$name]=$_.PSObject.Properties[$name].Value}
                    $records.Add([pscustomobject]$record)
                }
            } catch {
                $status=switch($_.Exception.Message){RDP_RECORD_LIMIT {'RECORD_LIMIT'};RDP_SCHEMA_IDENTITY_INVALID {'SCHEMA_INVALID'};default {'QUERY_FAILED'}}
                if($status -ceq 'QUERY_FAILED'){
                    $native=$_.Exception.PSObject.Properties['NativeErrorCode']
                    if($null -ne $native){$status=switch([string]$native.Value){InvalidProperty {'INVALID_PROPERTY'};InvalidClass {'INVALID_CLASS'};AccessDenied {'ACCESS_DENIED'};NotSupported {'NOT_SUPPORTED'};default {'QUERY_FAILED'}}}
                }
                $records.Clear()
            }
            [pscustomobject]@{Class=$cn;Status=$status;UnsupportedFields=@($missing);Records=@($records.ToArray())}
        } -ArgumentList $namespace,$class,$properties,$filter -ErrorAction Stop
        while($true){
            if($CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid RDP cancellation.'};if($answer[0]){throw [OperationCanceledException]::new('RDP collection cancelled.')}}
            if($Heartbeat){$null=& $Heartbeat}
            if($job.HasMoreData){Receive-Job $job -ErrorAction Stop|ForEach-Object {if($items.Count -ge 64){throw 'RDP inventory exceeds the reviewed limit.'};$items.Add($_)}}
            if($job.State -cin @('Completed','Failed','Stopped','Disconnected','Blocked')){break}
            if($timer.Elapsed.TotalSeconds -ge 30){throw 'RDP query timeout.'}
            Start-Sleep -Milliseconds 60
        }
        if($job.State -cne 'Completed'){throw 'RDP query failed.'}
        if($job.HasMoreData){Receive-Job $job -ErrorAction Stop|ForEach-Object {if($items.Count -ge 64){throw 'RDP inventory exceeds the reviewed limit.'};$items.Add($_)}}
        if($namespace -ceq 'root/cimv2/TerminalServices'){
            if($items.Count -ne 1){throw 'Invalid RDP query envelope.'}
            $result=$items[0]
            if($result.Class -cne $class -or $result.Status -cnotin @('AVAILABLE','RECORD_LIMIT','SCHEMA_INVALID','QUERY_FAILED','INVALID_PROPERTY','INVALID_CLASS','ACCESS_DENIED','NOT_SUPPORTED') -or
                $result.UnsupportedFields -isnot [Collections.IList] -or @($result.UnsupportedFields|Where-Object {$_ -isnot [string] -or $_ -cnotin $properties -or $_ -ceq 'TerminalName'}).Count -or
                @($result.UnsupportedFields|Select-Object -Unique).Count -ne $result.UnsupportedFields.Count -or $result.Records -isnot [Collections.IList] -or $result.Records.Count -gt 64){throw 'Invalid RDP query envelope.'}
            if($Metadata){$Metadata.Value=@($result.UnsupportedFields)}
            if($result.Status -cne 'AVAILABLE'){
                $errorObject=[InvalidOperationException]::new('RDP configuration query failed.')
                $errorObject.Data['WinSecRdpQueryStatus']=$result.Status
                throw $errorObject
            }
            return $result.Records
        }
        return $items.ToArray()
    } finally {
        if($job -is [Management.Automation.Job]){
            if($job.State -cnotin @('Completed','Failed','Stopped')){Stop-Job $job -ErrorAction SilentlyContinue}
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
function Read-WinSecRdpRegistryValue {
    [CmdletBinding()]
    param([string]$Id)
    $defs=@(Get-WinSecRdpRegistryDefinitions|Where-Object Id -CEQ $Id)
    if($defs.Count -ne 1){throw 'Unreviewed RDP registry source.'}
    $d=$defs[0];$base=$null;$key=$null
    try {
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        $key=$base.OpenSubKey($d.Key,$false)
        if($null -eq $key -or $d.Name -notin @($key.GetValueNames())){return [pscustomobject]@{State='NOT_CONFIGURED';Value=$null}}
        if($key.GetValueKind($d.Name) -cne [Microsoft.Win32.RegistryValueKind]::DWord){throw 'Invalid RDP registry type.'}
        $raw=$key.GetValue($d.Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if($raw -isnot [int]){throw 'Invalid RDP DWORD.'}
        $value=[long][BitConverter]::ToUInt32([BitConverter]::GetBytes($raw),0)
        if($value -gt $d.Max -or ($Id -ceq 'ListenerPort' -and $value -lt 1)){throw 'Invalid RDP registry range.'}
        [pscustomobject]@{State='OBSERVED';Value=$value}
    } finally {if($key){$key.Dispose()};if($base){$base.Dispose()}}
}
function Test-WinSecRDP {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DeviceId,[Parameter(Mandatory)][string]$ScanId,[string]$CheckId='WSA-NET-003',
        [scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    if($CheckId -cne 'WSA-NET-003' -or -not (Test-WinSecTargetIdentifier $DeviceId) -or -not (Test-WinSecTargetIdentifier $ScanId)){throw 'Invalid RDP identity.'}
    $issues=New-Object 'Collections.Generic.List[string]';$classes=@(Get-WinSecRdpClasses);$registry=@(Get-WinSecRdpRegistryDefinitions)
    $e=[pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;CollectedAtUTC='';CollectionSuccessful=$false;CollectionComplete=$false;
        CollectionIssues=@();FieldDiagnostics=@();ProviderDiagnostics=@();UnknownFieldCount=0;RequiredUnknownFieldCount=0;InformationalUnknownFieldCount=0;
        NotApplicableFieldCount=0;CoverageComplete=$false;Platform=[pscustomobject]@{BuildNumber=$null;OperatingSystemSKU=$null;ProductType=$null};
        HostSupport='UNKNOWN';HostEnabled=$null;HostState='UNKNOWN';Services=[pscustomobject]@{};Registry=[pscustomobject]@{};Inventory=[pscustomobject]@{};Availability=[pscustomobject]@{}}
    $completed=0;$total=3+$classes.Count+$registry.Count;$phase='PLATFORM';$successful=0
    $emit={if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage=$phase;CompletedSteps=$completed;TotalSteps=$total})}}
    $cancel={if($CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid RDP cancellation.'};if($answer[0]){throw [OperationCanceledException]::new('RDP collection cancelled.')}}}
    $null=& $cancel;$null=& $emit
    try {
        $p=@(Invoke-WinSecRdpQuery Platform -CancellationAction $CancellationAction -Heartbeat $emit)
        if($p.Count -ne 1 -or [string]$p[0].BuildNumber -cnotmatch '\A[0-9]{5}\z' -or [int]$p[0].BuildNumber -lt 22000 -or
            $p[0].ProductType -ne 1 -or [string]$p[0].Caption -notmatch '\A(?:Microsoft )?Windows 11(?: .*)?\z' -or
            [string]$p[0].Version -cne ('10.0.'+$p[0].BuildNumber) -or $null -eq (ConvertTo-WinSecRdpNumber $p[0].OperatingSystemSKU)){throw 'Unknown Windows client.'}
        $e.Platform=[pscustomobject]@{BuildNumber=[int]$p[0].BuildNumber;OperatingSystemSKU=[long]$p[0].OperatingSystemSKU;ProductType=1};$successful++
        $e.HostSupport=Get-WinSecRdpHostSupport $e.Platform.BuildNumber $e.Platform.OperatingSystemSKU $e.Platform.ProductType
    } catch [OperationCanceledException]{throw} catch {$issues.Add('PLATFORM_UNAVAILABLE')}
    if($e.HostSupport -ceq 'UNKNOWN'){$issues.Add('HOST_EDITION_UNRESOLVED')}
    $completed++;$phase='SERVICES';$null=& $cancel;$null=& $emit
    try {
        $services=@(Invoke-WinSecRdpQuery Services -CancellationAction $CancellationAction -Heartbeat $emit)
        if($services.Count -ne 3){throw 'Missing RDP service.'}
        foreach($name in @('TermService','UmRdpService','SessionEnv')){
            $s=@($services|Where-Object {$_.Name -is [string] -and [string]::Equals($_.Name,$name,[StringComparison]::OrdinalIgnoreCase)})
            if($s.Count -ne 1 -or $s[0].State -cnotin @('Running','Stopped','Start Pending','Stop Pending','Continue Pending','Pause Pending','Paused') -or
                $s[0].StartMode -cnotin @('Auto','Manual','Disabled')){throw 'Invalid RDP service.'}
            $e.Services|Add-Member $name ([pscustomobject]@{State=$s[0].State.ToUpperInvariant().Replace(' ','_');StartMode=$s[0].StartMode.ToUpperInvariant()})
        };$successful++
    } catch [OperationCanceledException]{throw} catch {$issues.Add('SERVICES_UNAVAILABLE')}
    $completed++
    foreach($c in $classes){
        $phase=$c.Id.ToUpperInvariant();$null=& $cancel;$null=& $emit;$state='UNKNOWN';$json=$null
        if($e.HostSupport -ceq 'UNSUPPORTED_HOME'){$state='NOT_APPLICABLE'}
        else {
            try {
                $schemaMissing=@()
                $excluded=@(Get-WinSecRdpNotApplicableFields $c.Id $e.Platform)
                $raw=@(Invoke-WinSecRdpQuery $c.Id -CancellationAction $CancellationAction -Heartbeat $emit -Metadata ([ref]$schemaMissing) -SkipFields $excluded)
                if($raw.Count -lt 1 -or $raw.Count -gt 64 -or ($c.Singleton -and $raw.Count -ne 1)){throw 'Missing or excessive RDP listener configuration.'}
                $items=@();$seen=@{};$missing=0;$missingRequired=0;$missingInformational=0;$excludedCount=0
                $required=@(Get-WinSecRdpRequiredFields $c.Id)
                foreach($record in $raw){
                    $id='GLOBAL'
                    if(-not $c.Singleton){
                        $name=$record.TerminalName
                        if($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name) -or $name.Length -gt 256 -or $name -match '[\p{C}]'){throw 'Invalid RDP listener identity.'}
                        if($name -ieq 'RDP-Tcp'){$id='RDP_TCP'}else{$sha=[Security.Cryptography.SHA256]::Create();try{$id=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($name.ToUpperInvariant())))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
                    }
                    if($seen.ContainsKey($id)){throw 'Duplicate RDP listener identity.'};$seen[$id]=$true
                    $values=[ordered]@{}
                    foreach($field in $c.Fields){
                        if($field -cin $excluded){$values[$field]=$null;$excludedCount++;$e.FieldDiagnostics+=($c.Id+'.'+$field+':NOT_APPLICABLE');continue}
                        $property=$record.PSObject.Properties[$field];$rawValue=if($null -ne $property){$property.Value}else{$null}
                        $v=ConvertTo-WinSecRdpConfigurationValue $c.Id $field $rawValue
                        $values[$field]=$v
                        if($null -eq $v){
                            $missing++
                            if($field -cin $required){$missingRequired++}else{$missingInformational++}
                            $reason=if($field -cin $schemaMissing){'NOT_IN_PROVIDER_SCHEMA'}elseif($null -eq $property){'MISSING_PROPERTY'}elseif($null -eq $rawValue){'NULL_VALUE'}elseif($rawValue -is [bool]){'BOOLEAN_VALUE'}else{'INVALID_SCALAR'}
                            $e.FieldDiagnostics+=($c.Id+'.'+$field+':'+$reason)
                        }
                    }
                    $items+=[pscustomobject]@{Id=$id;Values=[pscustomobject]$values}
                }
                $json=ConvertTo-Json -InputObject ([pscustomobject]@{SchemaVersion='1.1.0';Class=$c.Id;NotApplicableFields=@($excluded);Items=@($items|Sort-Object Id)}) -Depth 8 -Compress
                $null=ConvertTo-WinSecRdpInventory $json;$state='OBSERVED';$successful++;$e.UnknownFieldCount+=$missing
                $e.RequiredUnknownFieldCount+=$missingRequired;$e.InformationalUnknownFieldCount+=$missingInformational;$e.NotApplicableFieldCount+=$excludedCount
                if($c.Id -ceq 'Global'){
                    $enabled=$items[0].Values.AllowTSConnections
                    if($e.HostSupport -ceq 'SUPPORTED' -and $null -ne $enabled -and $enabled -in @(0,1)){$e.HostEnabled=($enabled -eq 1);$e.HostState='OBSERVED'}
                    elseif($e.HostSupport -ceq 'SUPPORTED'){$issues.Add('CONFIGURATION_FIELDS_UNAVAILABLE')}
                }
            } catch [OperationCanceledException]{throw} catch {
                $json=$null;$issues.Add('PROVIDER_'+$c.Id.ToUpperInvariant()+'_UNAVAILABLE')
                $queryStatus=$_.Exception.Data['WinSecRdpQueryStatus']
                if($queryStatus -cnotin @('RECORD_LIMIT','SCHEMA_INVALID','INVALID_PROPERTY','INVALID_CLASS','ACCESS_DENIED','NOT_SUPPORTED')){$queryStatus='QUERY_FAILED'}
                $e.ProviderDiagnostics+=($c.Id+':'+$queryStatus)
            }
        }
        $e.Inventory|Add-Member $c.Id $json;$e.Availability|Add-Member $c.Id $state;$completed++
    }
    foreach($d in $registry){
        $phase='REGISTRY';$null=& $cancel;$null=& $emit
        try {
            $r=Read-WinSecRdpRegistryValue $d.Id
            if($r.State -cnotin @('OBSERVED','NOT_CONFIGURED') -or ($r.State -ceq 'NOT_CONFIGURED' -and $null -ne $r.Value)){throw 'Invalid RDP registry state.'}
            if($r.State -ceq 'OBSERVED'){
                $v=ConvertTo-WinSecRdpNumber $r.Value
                if($null -eq $v -or $v -gt $d.Max -or ($d.Id -ceq 'ListenerPort' -and $v -lt 1)){throw 'Invalid RDP registry value.'}
                $r=[pscustomobject]@{State='OBSERVED';Value=$v}
            }
            $e.Registry|Add-Member $d.Id ([pscustomobject]@{State=$r.State;Value=$r.Value})
        } catch {$e.Registry|Add-Member $d.Id ([pscustomobject]@{State='UNKNOWN';Value=$null});$issues.Add('REGISTRY_'+$d.Id.ToUpperInvariant()+'_UNAVAILABLE')}
        $completed++
    }
    # WMI is effective host configuration; never infer it from an absent policy.
    $policy=$e.Registry.Policy_fDenyTSConnections
    if($e.HostState -ceq 'OBSERVED' -and $policy.State -ceq 'OBSERVED' -and $e.HostEnabled -ne ($policy.Value -eq 0)){
        $e.HostEnabled=$null;$e.HostState='UNKNOWN';$issues.Add('HOST_STATE_CONFLICT')
    }
    if($e.HostSupport -ceq 'UNSUPPORTED_HOME'){$e.HostState='NOT_APPLICABLE';$e.HostEnabled=$null}
    if($e.RequiredUnknownFieldCount){$issues.Add('CONFIGURATION_FIELDS_UNAVAILABLE')}
    $phase='NORMALIZING';$null=& $cancel;$null=& $emit
    $e.CollectedAtUTC=[datetime]::UtcNow.ToString('o');$e.CollectionIssues=@($issues|Select-Object -Unique)
    $e.FieldDiagnostics=@($e.FieldDiagnostics|Sort-Object -Unique);$e.ProviderDiagnostics=@($e.ProviderDiagnostics|Sort-Object -Unique)
    $e.CollectionSuccessful=($successful -gt 0);$e.CollectionComplete=($issues.Count -eq 0)
    $e.CoverageComplete=($e.CollectionComplete -and $e.UnknownFieldCount -eq 0)
    $completed++;$null=& $emit
    [pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;SectionKey='NetworkSecurity';
        Status=if($e.CollectionComplete){'INFORMATIONAL'}else{'UNKNOWN'};Evidence=$e}
}
