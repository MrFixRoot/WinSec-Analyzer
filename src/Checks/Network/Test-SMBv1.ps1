# WinSec Analyzer
# Archivo: src\Checks\Network\Test-SMBv1.ps1
# Read-only local collection. Never connect to shares, probe ports or change SMB.
function Invoke-WinSecSmbQuery {
    [CmdletBinding()]
    param([ValidateSet('Server','Client')][string]$Role,[scriptblock]$CancellationAction,[scriptblock]$Heartbeat)
    $command=Get-Command -Name ('Get-Smb'+$Role+'Configuration') -CommandType Function,Cmdlet -ErrorAction Stop
    $job=$null;$timer=[Diagnostics.Stopwatch]::StartNew();$items=New-Object 'Collections.Generic.List[object]'
    try {
        $job=& $command -AsJob -ErrorAction Stop
        if($job -isnot [Management.Automation.Job]){throw 'SMB provider did not return an owned job.'}
        while($true) {
            if($CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid SMB cancellation.'};if($answer[0]){throw [OperationCanceledException]::new('SMB collection cancelled.')}}
            if($Heartbeat){$null=& $Heartbeat}
            if($job.HasMoreData){Receive-Job $job -ErrorAction Stop|ForEach-Object {if($items.Count -ge 1){throw 'Ambiguous SMB configuration.'};$items.Add($_)}}
            if($job.State -cin @('Completed','Failed','Stopped','Disconnected','Blocked')){break}
            if($timer.Elapsed.TotalSeconds -ge 30){throw 'SMB query timeout.'}
            Start-Sleep -Milliseconds 60
        }
        if($job.State -cne 'Completed'){throw 'SMB query failed.'}
        if($job.HasMoreData){Receive-Job $job -ErrorAction Stop|ForEach-Object {if($items.Count -ge 1){throw 'Ambiguous SMB configuration.'};$items.Add($_)}}
        if($items.Count -ne 1){throw 'Missing SMB configuration.'}
        return $items[0]
    } finally {
        if($job -is [Management.Automation.Job]){
            if($job.State -cnotin @('Completed','Failed','Stopped')){Stop-Job $job -ErrorAction SilentlyContinue}
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
function Read-WinSecSmbRegistryValue {
    [CmdletBinding()]
    param([string]$Id)
    $defs=@(Get-WinSecSmbRegistryDefinitions|Where-Object Id -CEQ $Id)
    if($defs.Count -ne 1){throw 'Unreviewed SMB registry source.'}
    $d=$defs[0];$base=$null;$key=$null
    try {
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        $key=$base.OpenSubKey($d.Key,$false)
        if($null -eq $key -or $d.Name -notin @($key.GetValueNames())){return [pscustomobject]@{State='NOT_CONFIGURED';Value=$null}}
        if($key.GetValueKind($d.Name).ToString() -cne $d.Kind){throw 'Invalid SMB registry type.'}
        $value=$key.GetValue($d.Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if($d.Kind -ceq 'MultiString'){
            if($value -isnot [string[]] -or $value.Count -gt 64){throw 'Invalid SMB dependency list.'}
            return [pscustomobject]@{State='OBSERVED';Value=($value -icontains 'MRxSMB10')}
        }
        # Registry DWORDs may be returned as signed Int32; do not reinterpret negatives.
        if($value -isnot [int] -or $value -lt 0 -or ($Id -like '*Start' -and $value -gt 4) -or
            ($Id -notlike '*Start' -and $value -gt 1)){throw 'Invalid SMB registry value.'}
        [pscustomobject]@{State='OBSERVED';Value=[long]$value}
    } finally {if($key){$key.Dispose()};if($base){$base.Dispose()}}
}
function Test-WinSecSMBv1 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DeviceId,[Parameter(Mandatory)][string]$ScanId,[string]$CheckId='WSA-NET-002',
        [scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    if($CheckId -cne 'WSA-NET-002' -or -not (Test-WinSecTargetIdentifier $DeviceId) -or -not (Test-WinSecTargetIdentifier $ScanId)){throw 'Invalid SMB identity.'}
    $issues=New-Object 'Collections.Generic.List[string]'
    $e=[pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;CollectedAtUTC='';CollectionSuccessful=$false;CollectionComplete=$false;
        CollectionIssues=@();Platform=[pscustomobject]@{BuildNumber=$null;OperatingSystemSKU=$null;ProductType=$null};
        Server=[pscustomobject]@{};Client=[pscustomobject]@{};Features=[pscustomobject]@{};Services=[pscustomobject]@{};
        Registry=[pscustomobject]@{};Availability=[pscustomobject]@{Server=[pscustomobject]@{};Client=[pscustomobject]@{}}}
    $completed=0;$total=14;$phase='PLATFORM';$successful=0
    $emit={if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage=$phase;CompletedSteps=$completed;TotalSteps=$total})}}
    $cancel={if($CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid SMB cancellation.'};if($answer[0]){throw [OperationCanceledException]::new('SMB collection cancelled.')}}}
    $null=& $cancel;$null=& $emit
    try {
        $p=@(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_OperatingSystem -Property Caption,Version,BuildNumber,OperatingSystemSKU,ProductType -OperationTimeoutSec 5 -ErrorAction Stop)
        if($p.Count -ne 1 -or [string]$p[0].BuildNumber -cnotmatch '\A[0-9]{5}\z' -or [int]$p[0].BuildNumber -lt 22000 -or
            [int]$p[0].ProductType -ne 1 -or [string]$p[0].Caption -notmatch '\A(?:Microsoft )?Windows 11(?: .*)?\z' -or
            [string]$p[0].Version -cne ('10.0.'+$p[0].BuildNumber)){throw 'Unknown Windows client.'}
        $e.Platform=[pscustomobject]@{BuildNumber=[int]$p[0].BuildNumber;OperatingSystemSKU=[int]$p[0].OperatingSystemSKU;ProductType=1};$successful++
    } catch {$issues.Add('PLATFORM_UNAVAILABLE')}
    $completed++
    foreach($role in @('Server','Client')) {
        $phase=$role.ToUpperInvariant();$null=& $cancel;$null=& $emit
        $raw=$null
        try {$raw=Invoke-WinSecSmbQuery $role -CancellationAction $CancellationAction -Heartbeat $emit;$successful++}
        catch [OperationCanceledException]{throw}
        catch {$issues.Add($phase+'_UNAVAILABLE')}
        foreach($f in Get-WinSecSmbConfigurationFields $role){
            $value=$null;$prop=if($null -ne $raw){$raw.PSObject.Properties[$f.Name]}else{$null}
            if($f.Name -like '*Count' -and $f.Name -cin @('NullSessionPipesCount','NullSessionSharesCount')){
                $prop=if($null -ne $raw){$raw.PSObject.Properties[($f.Name -replace 'Count$','')]}else{$null}
                if($null -ne $prop -and @($prop.Value).Count -le 10000){$value=@($prop.Value|Where-Object {$_ -is [string] -and $_.Length -gt 0}).Count}
            } elseif($null -ne $prop){$value=ConvertTo-WinSecSmbValue $prop.Value $f.Kind}
            $e.$role|Add-Member $f.Name $value
            if($f.Modern){$state=if($null -eq $prop -and $null -ne $raw -and $e.Platform.BuildNumber -cin @(22000,22621,22631)){'NOT_APPLICABLE'}else{'OBSERVED'};$e.Availability.$role|Add-Member $f.Name $state}
        }
        $required=if($role -ceq 'Server'){@('EnableSMB1Protocol','EnableSMB2Protocol','AuditSmb1Access','RequireSecuritySignature')}else{@('RequireSecuritySignature','EnableInsecureGuestLogons')}
        if(@($required|Where-Object {$null -eq $e.$role.$_}).Count){$issues.Add($phase+'_REQUIRED_FIELDS_UNAVAILABLE')}
        $completed++
    }
    $phase='FEATURES';$null=& $cancel;$null=& $emit
    $featureNames=@('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server','SMB1Protocol-Deprecation');$features=@()
    try {
        $features=@(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_OptionalFeature -Filter "Name LIKE 'SMB1Protocol%'" -Property Name,InstallState -OperationTimeoutSec 5 -ErrorAction Stop)
        if($features.Count -gt 4 -or @($features|Where-Object {$_.Name -isnot [string] -or $_.Name -cnotin $featureNames}).Count -or @($features.Name|Select-Object -Unique).Count -ne $features.Count){throw 'Invalid feature identities.'};$successful++
    } catch {$features=@();$issues.Add('FEATURES_UNAVAILABLE')}
    foreach($name in $featureNames){
        $found=@($features|Where-Object Name -CEQ $name);$state='UNKNOWN'
        if($found.Count -eq 1 -and $null -ne $found[0].InstallState -and $found[0].InstallState.GetType() -in @([uint32],[int],[long])){switch($found[0].InstallState){1 {$state='ENABLED'};2 {$state='DISABLED'};3 {$state='ABSENT'}}}
        if($state -ceq 'UNKNOWN'){$issues.Add('FEATURE_'+$name.Replace('-','_')+'_UNAVAILABLE')}
        $e.Features|Add-Member $name $state
    }
    $completed++;$phase='SERVICES';$null=& $cancel;$null=& $emit
    try {
        $services=@(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Filter "Name = 'LanmanServer' OR Name = 'LanmanWorkstation'" -Property Name,State,StartMode -OperationTimeoutSec 5 -ErrorAction Stop)
        if($services.Count -ne 2){throw 'Missing SMB service.'}
        foreach($name in @('LanmanServer','LanmanWorkstation')){
            $s=@($services|Where-Object {$_.Name -is [string] -and [string]::Equals($_.Name,$name,[StringComparison]::OrdinalIgnoreCase)})
            if($s.Count -ne 1 -or $s[0].State -cnotin @('Running','Stopped','Start Pending','Stop Pending','Continue Pending','Pause Pending','Paused') -or
                $s[0].StartMode -cnotin @('Auto','Manual','Disabled')){throw 'Invalid SMB service.'}
            $e.Services|Add-Member $name ([pscustomobject]@{State=$s[0].State.ToUpperInvariant().Replace(' ','_');StartMode=$s[0].StartMode.ToUpperInvariant()})
        };$successful++
    } catch {$issues.Add('SERVICES_UNAVAILABLE')}
    $completed++
    foreach($d in Get-WinSecSmbRegistryDefinitions){
        $phase='REGISTRY';$null=& $cancel;$null=& $emit
        try {
            $r=Read-WinSecSmbRegistryValue $d.Id
            if($r.State -cnotin @('OBSERVED','NOT_CONFIGURED') -or ($r.State -ceq 'NOT_CONFIGURED' -and $null -ne $r.Value)){throw 'Invalid registry state.'}
            if($r.State -ceq 'OBSERVED'){
                $v=ConvertTo-WinSecSmbValue $r.Value $(if($d.Kind -ceq 'MultiString'){'bool'}else{'number'})
                if($null -eq $v -or ($d.Kind -ceq 'DWord' -and (($d.Id -like '*Start' -and $v -gt 4) -or ($d.Id -notlike '*Start' -and $v -gt 1)))){throw 'Invalid registry value.'}
                $r=[pscustomobject]@{State='OBSERVED';Value=$v}
            }
            $e.Registry|Add-Member $d.Id ([pscustomobject]@{State=$r.State;Value=$r.Value})
        } catch {$e.Registry|Add-Member $d.Id ([pscustomobject]@{State='UNKNOWN';Value=$null});$issues.Add('REGISTRY_'+$d.Id.ToUpperInvariant()+'_UNAVAILABLE')}
        $completed++
    }
    $phase='NORMALIZING';$null=& $cancel;$null=& $emit
    $e.CollectedAtUTC=[datetime]::UtcNow.ToString('o');$e.CollectionIssues=@($issues|Select-Object -Unique)
    $e.CollectionSuccessful=($successful -gt 0);$e.CollectionComplete=($issues.Count -eq 0)
    $completed++;$null=& $emit
    [pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;SectionKey='NetworkSecurity';
        Status=if($e.CollectionComplete){'INFORMATIONAL'}else{'UNKNOWN'};Evidence=$e}
}
