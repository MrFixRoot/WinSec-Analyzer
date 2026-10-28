# Shared read-only IdentityAccess collector; function declarations only on import.
. (Join-Path $PSScriptRoot '../../Core/IdentityAccessTelemetry.ps1')
function Invoke-WinSecIdentityAccessQuery {
    [CmdletBinding()]
    param([ValidateSet('Platform','Administrators','Guest','Password','Lockout')][string]$Role,
        [scriptblock]$CancellationAction,[scriptblock]$Heartbeat)
    $job=$null;$timer=[Diagnostics.Stopwatch]::StartNew();$result=New-Object 'Collections.Generic.List[object]'
    try {
        $native=Join-Path $PSScriptRoot '../../Core/IdentityNativeReadOnly.ps1'
        $job=Start-Job -ScriptBlock {
            param($roleName,$nativePath)
            $records=@();$state='AVAILABLE'
            try {
                switch -CaseSensitive ($roleName) {
                    Platform {$records=@(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_OperatingSystem -Property Caption,Version,BuildNumber,OperatingSystemSKU,ProductType -OperationTimeoutSec 5 -ErrorAction Stop)}
                    Guest {
                        $fields=@('SID','Disabled','LocalAccount','Lockout','PasswordRequired','PasswordChangeable','PasswordExpires','AccountType','SIDType')
                        $records=@(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_UserAccount -Filter "LocalAccount = TRUE AND SID LIKE 'S-1-5-21-%-501'" -Property $fields -OperationTimeoutSec 5 -ErrorAction Stop)
                        if($records.Count -ne 1){throw 'GUEST_UNAVAILABLE'}
                    }
                    default {
                        . $nativePath
                        Add-Type -TypeDefinition (Get-WinSecIdentityNativeSource) -ErrorAction Stop
                        if($roleName -ceq 'Administrators'){
                            $groups=@(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Group -Filter "LocalAccount = TRUE AND SID = 'S-1-5-32-544'" -Property Name,SID,LocalAccount -OperationTimeoutSec 5 -ErrorAction Stop)
                            if($groups.Count -ne 1 -or $groups[0].SID -cne 'S-1-5-32-544' -or $groups[0].LocalAccount -ne $true){throw 'GROUP_UNAVAILABLE'}
                            $records=@([WinSec.IdentityNativeReadOnly]::Administrators($groups[0].Name)|ForEach-Object {[pscustomobject]@{SID=$_}})
                        }elseif($roleName -ceq 'Password'){
                            $p=[WinSec.IdentityNativeReadOnly]::Policy(0)
                            $records=@([pscustomobject]@{MinimumLength=$p[0];MaximumAgeSeconds=$p[1];MinimumAgeSeconds=$p[2];ForceLogoffSeconds=$p[3];HistoryLength=$p[4]})
                        }elseif($roleName -ceq 'Lockout'){
                            $p=[WinSec.IdentityNativeReadOnly]::Policy(3)
                            $records=@([pscustomobject]@{DurationSeconds=$p[0];ObservationWindowSeconds=$p[1];Threshold=$p[2]})
                        }else{throw 'UNREVIEWED_ROLE'}
                    }
                }
                $allowed=switch -CaseSensitive ($roleName){Platform {@('Caption','Version','BuildNumber','OperatingSystemSKU','ProductType')};Guest {$fields};Administrators {@('SID')};Password {@('MinimumLength','MaximumAgeSeconds','MinimumAgeSeconds','ForceLogoffSeconds','HistoryLength')};Lockout {@('DurationSeconds','ObservationWindowSeconds','Threshold')}}
                if($records.Count -gt $(if($roleName -ceq 'Administrators'){256}else{1})){throw 'RECORD_LIMIT'}
                $safe=@(foreach($record in $records){$data=[ordered]@{};foreach($field in $allowed){$data[$field]=$record.PSObject.Properties[$field].Value};[pscustomobject]$data})
            }catch{$state='UNAVAILABLE';$safe=@()}
            [pscustomobject]@{Role=$roleName;State=$state;Records=@($safe)}
        } -ArgumentList $Role,$native -ErrorAction Stop
        while($true){
            if($CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid identity cancellation.'};if($answer[0]){throw [OperationCanceledException]::new('Identity scan cancelled.')}}
            if($Heartbeat){$null=& $Heartbeat}
            if($job.HasMoreData){Receive-Job $job -ErrorAction Stop|ForEach-Object {$result.Add($_)}}
            if($result.Count -gt 1){throw 'Invalid identity query envelope.'}
            if($job.State -cin @('Completed','Failed','Stopped','Disconnected','Blocked')){break}
            if($timer.Elapsed.TotalSeconds -ge 30){throw 'Identity query timeout.'}
            Start-Sleep -Milliseconds 60
        }
        if($job.HasMoreData){Receive-Job $job -ErrorAction Stop|ForEach-Object {$result.Add($_)}}
        if($job.State -cne 'Completed' -or $result.Count -ne 1 -or $result[0].Role -cne $Role -or $result[0].State -cne 'AVAILABLE' -or $result[0].Records -isnot [Collections.IList]){throw 'Identity provider unavailable.'}
        return $result[0].Records
    }finally{
        if($job -is [Management.Automation.Job]){
            if($job.State -cnotin @('Completed','Failed','Stopped')){Stop-Job $job -ErrorAction SilentlyContinue}
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
function Invoke-WinSecIdentityAccessCollection {
    [CmdletBinding()]
    param([string]$DeviceId,[string]$ScanId,[string]$CheckId,[scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    $roles=@(Get-WinSecIdentityRoles $CheckId)
    if(-not (Test-WinSecTargetIdentifier $DeviceId) -or -not (Test-WinSecTargetIdentifier $ScanId)){throw 'Invalid identity collection identity.'}
    $e=[ordered]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;CollectedAtUTC='';CollectionSuccessful=$false;CollectionComplete=$false;CoverageComplete=$false;
        UnknownFieldCount=0;CollectionIssues=@();Platform=[pscustomobject]@{BuildNumber=$null;OperatingSystemSKU=$null;ProductType=$null};Availability=[ordered]@{}}
    $issues=New-Object 'Collections.Generic.List[string]';$completed=0;$phase='PLATFORM';$total=$roles.Count+2;$providers=0
    $cancel={if($CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid identity cancellation.'};if($answer[0]){throw [OperationCanceledException]::new('Identity scan cancelled.')}}}
    $emit={if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage=$phase;CompletedSteps=[int]$completed;TotalSteps=[int]$total})}}
    $null=& $cancel;$null=& $emit
    try {
        $p=@(Invoke-WinSecIdentityAccessQuery Platform -CancellationAction $CancellationAction -Heartbeat $emit)
        if($p.Count -ne 1 -or [string]$p[0].BuildNumber -cnotmatch '\A[0-9]{5}\z' -or [int]$p[0].BuildNumber -lt 22000 -or
            $p[0].ProductType -ne 1 -or [string]$p[0].Caption -notmatch '\A(?:Microsoft )?Windows 11(?: .*)?\z' -or
            [string]$p[0].Version -cne ('10.0.'+$p[0].BuildNumber) -or $null -eq (ConvertTo-WinSecIdentityNumber $p[0].OperatingSystemSKU)){throw 'Unknown Windows client.'}
        $e.Platform=[pscustomobject]@{BuildNumber=[int]$p[0].BuildNumber;OperatingSystemSKU=[long]$p[0].OperatingSystemSKU;ProductType=1}
    }catch [OperationCanceledException]{throw}catch{$issues.Add('PLATFORM_UNAVAILABLE')};$completed++
    foreach($role in $roles){
        $phase=$role.ToUpperInvariant();$null=& $cancel;$null=& $emit
        $e.Availability[$role]='UNKNOWN';$defaults=[ordered]@{}
        foreach($field in @(Get-WinSecIdentityFields $role)){$defaults[$field.Split('|')[0]]=$null};$e[$role]=[pscustomobject]$defaults
        try {
            $raw=@(Invoke-WinSecIdentityAccessQuery $role -CancellationAction $CancellationAction -Heartbeat $emit)
            $e[$role]=ConvertTo-WinSecIdentityRecord $role $raw
            foreach($field in $e[$role].PSObject.Properties){if($null -eq $field.Value){$e.UnknownFieldCount++}}
            $e.Availability[$role]='OBSERVED';$providers++
        }catch [OperationCanceledException]{throw}catch{$issues.Add($role.ToUpperInvariant()+'_UNAVAILABLE')}
        $completed++
    }
    if($CheckId -ceq 'WSA-IAM-003'){$e.UnknownFieldCount+=2} # Unsupported by these NetUserModalsGet levels; never invent defaults.
    $phase='NORMALIZING';$null=& $cancel;$null=& $emit
    $e.Availability=[pscustomobject]$e.Availability;$e.CollectionIssues=@($issues.ToArray());$e.CollectionSuccessful=($providers -gt 0)
    $e.CollectionComplete=($issues.Count -eq 0);$e.CoverageComplete=($e.CollectionComplete -and $e.UnknownFieldCount -eq 0);$e.CollectedAtUTC=[datetime]::UtcNow.ToString('o')
    $completed++;$null=& $emit
    [pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;SectionKey='IdentityAccess';Status=$(if($e.CollectionComplete){'INFORMATIONAL'}else{'UNKNOWN'});Evidence=[pscustomobject]$e}
}
