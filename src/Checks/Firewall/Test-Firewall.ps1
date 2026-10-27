# WinSec Analyzer
# Archivo: src\Checks\Firewall\Test-Firewall.ps1
# Read-only provider boundary; only owned CIM jobs may be stopped or removed.
function Invoke-WinSecFirewallQuery {
    [CmdletBinding()]
    param([string]$Command,[hashtable]$Arguments,[scriptblock]$CancellationAction,[scriptblock]$Heartbeat)
    $allowed=@('Get-NetFirewallProfile','Get-NetFirewallSetting','Get-NetFirewallRule','Get-NetFirewallPortFilter',
        'Get-NetFirewallAddressFilter','Get-NetFirewallApplicationFilter','Get-NetFirewallServiceFilter',
        'Get-NetFirewallInterfaceFilter','Get-NetFirewallInterfaceTypeFilter','Get-NetFirewallSecurityFilter',
        'Get-NetIPsecRule','Get-NetFirewallDynamicKeywordAddress','Get-NetFirewallHyperVVMCreator',
        'Get-NetFirewallHyperVVMSetting','Get-NetFirewallHyperVProfile','Get-NetFirewallHyperVRule')
    if($Command -cnotin $allowed -or @($Arguments.Keys|Where-Object {$_ -cnotin @('PolicyStore','All','TracePolicyStore')}).Count){throw 'Unreviewed Firewall query.'}
    if($Arguments.ContainsKey('PolicyStore') -and $Arguments.PolicyStore -cnotin @('ActiveStore','PersistentStore')){throw 'Only local stores are permitted.'}
    $commandInfo=Get-Command -Name $Command -CommandType Function,Cmdlet -ErrorAction Stop
    $job=$null;$timer=[Diagnostics.Stopwatch]::StartNew();$items=New-Object 'Collections.Generic.List[object]'
    try {
        $job=& $commandInfo @Arguments -AsJob -ErrorAction Stop
        if($job -isnot [Management.Automation.Job]){throw 'Firewall provider did not return an owned job.'}
        while($true) {
            if($null -ne $CancellationAction) {
                $answer=@(& $CancellationAction)
                if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid Firewall cancellation.'}
                if($answer[0]){throw [OperationCanceledException]::new('Firewall collection cancelled.')}
            }
            if($null -ne $Heartbeat){$null=& $Heartbeat}
            if($job.HasMoreData){Receive-Job -Job $job -ErrorAction Stop|ForEach-Object {if($items.Count -ge 10000){throw 'Inventory limit exceeded.'};$items.Add($_)}}
            if($job.State -cin @('Completed','Failed','Stopped','Disconnected','Blocked')){break}
            if($timer.Elapsed.TotalSeconds -ge 30){throw 'Firewall query timeout.'}
            Start-Sleep -Milliseconds 60
        }
        if($job.State -cne 'Completed'){throw 'Firewall query did not complete.'}
        if($job.HasMoreData){Receive-Job -Job $job -ErrorAction Stop|ForEach-Object {if($items.Count -ge 10000){throw 'Inventory limit exceeded.'};$items.Add($_)}}
        return ,$items.ToArray()
    } finally {
        if($job -is [Management.Automation.Job]) {
            if($job.State -cnotin @('Completed','Failed','Stopped')){Stop-Job -Job $job -ErrorAction SilentlyContinue}
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-WinSecFirewall {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DeviceId,[Parameter(Mandatory)][string]$ScanId,
        [string]$CheckId='WSA-NET-001',[scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    if($CheckId -cne 'WSA-NET-001' -or -not (Test-WinSecTargetIdentifier $DeviceId) -or -not (Test-WinSecTargetIdentifier $ScanId)){throw 'Invalid Firewall identity.'}
    $issues=New-Object 'Collections.Generic.List[string]';$batches=New-Object 'Collections.Generic.List[object]'
    $e=[pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;CollectedAtUTC='';CollectionSuccessful=$false;CollectionComplete=$false;
        CollectionIssues=@();Profiles=[pscustomobject]@{};Global=[pscustomobject]@{};Services=[pscustomobject]@{};
        Platform=[pscustomobject]@{BuildNumber=$null;OperatingSystemSKU=$null;ProductType=$null};Inventories=[pscustomobject]@{};Batches=@();HyperVState='UNKNOWN'}
    $steps=@(
        @{C='Get-NetFirewallProfile';S='ActiveStore';Key='ProfilesActive'},@{C='Get-NetFirewallProfile';S='PersistentStore';Key='ProfilesLocal'},
        @{C='Get-NetFirewallSetting';S='ActiveStore';Key='Global'},@{C='Get-NetFirewallRule';S='ActiveStore';Key='RulesActive'},
        @{C='Get-NetFirewallRule';S='PersistentStore';Key='RulesLocal'},@{C='Get-NetFirewallPortFilter';S='ActiveStore';Key='Port'},
        @{C='Get-NetFirewallAddressFilter';S='ActiveStore';Key='Address'},@{C='Get-NetFirewallApplicationFilter';S='ActiveStore';Key='Application'},
        @{C='Get-NetFirewallServiceFilter';S='ActiveStore';Key='Service'},@{C='Get-NetFirewallInterfaceFilter';S='ActiveStore';Key='Interface'},
        @{C='Get-NetFirewallInterfaceTypeFilter';S='ActiveStore';Key='InterfaceType'},@{C='Get-NetFirewallSecurityFilter';S='ActiveStore';Key='Security'},
        @{C='Get-NetIPsecRule';S='ActiveStore';Key='IPsec'},@{C='Get-NetFirewallDynamicKeywordAddress';S='ActiveStore';Key='DynamicKeywords'},
        @{C='Get-NetFirewallHyperVVMCreator';Key='HyperVCreators'},@{C='Get-NetFirewallHyperVVMSetting';S='ActiveStore';Key='HyperVSettings'},
        @{C='Get-NetFirewallHyperVProfile';S='ActiveStore';Key='HyperVProfiles'},@{C='Get-NetFirewallHyperVRule';S='ActiveStore';Key='HyperVRules'})
    foreach($kind in @('Port','Address','Application','Service','Interface','InterfaceType','Security')) {
        $steps+=@{C=('Get-NetFirewall'+$kind+'Filter');S='PersistentStore';Key=($kind+'Local')}
    }
    $completed=0;$total=$steps.Count+3;$phase='PLATFORM';$raw=@{};$failedKeys=@{}
    $emit={if($null -ne $ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Stage=$phase;CompletedSteps=$completed;TotalSteps=$total})}}
    $cancel={if($null -ne $CancellationAction){$v=@(& $CancellationAction);if($v.Count -ne 1 -or $v[0] -isnot [bool]){throw 'Invalid cancellation.'};if($v[0]){throw [OperationCanceledException]::new('Firewall collection cancelled.')}}}
    $null=& $cancel;$null=& $emit
    try {
        $p=@(Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption,Version,BuildNumber,OperatingSystemSKU,ProductType -OperationTimeoutSec 5 -ErrorAction Stop)
        if($p.Count -ne 1 -or [string]$p[0].BuildNumber -cnotmatch '\A[0-9]{5}\z' -or [int]$p[0].BuildNumber -lt 22000 -or
            [int]$p[0].ProductType -ne 1 -or [string]$p[0].Caption -notmatch '\A(?:Microsoft )?Windows 11(?: .*)?\z' -or
            [string]$p[0].Version -cne ('10.0.'+$p[0].BuildNumber)){throw 'Unknown Windows 11 client.'}
        $e.Platform=[pscustomobject]@{BuildNumber=[int]$p[0].BuildNumber;OperatingSystemSKU=[int]$p[0].OperatingSystemSKU;ProductType=1}
    } catch {$issues.Add('PLATFORM_UNAVAILABLE')}
    $completed++;$phase='SERVICES';$null=& $cancel;$null=& $emit
    foreach($name in @('MpsSvc','BFE')) {
        try {
            $s=@(Get-CimInstance -ClassName Win32_Service -Filter ("Name = '"+$name+"'") -Property Name,State,StartMode -OperationTimeoutSec 5 -ErrorAction Stop)
            if($s.Count -ne 1 -or $s[0].Name -cne $name){throw 'Ambiguous service.'}
            $e.Services|Add-Member $name ([pscustomobject]@{State=(ConvertTo-WinSecFirewallScalar $s[0].State);StartMode=(ConvertTo-WinSecFirewallScalar $s[0].StartMode)})
        } catch {$issues.Add('SERVICE_'+$name+'_UNAVAILABLE')}
        $null=& $cancel
    }
    $completed++
    foreach($step in $steps) {
        $phase=$step.Key.ToUpperInvariant();$null=& $cancel;$null=& $emit
        if($step.Key -like 'HyperV*' -and $e.Platform.BuildNumber -eq 22000) {
            $e.HyperVState='NOT_APPLICABLE';$raw[$step.Key]=@();$completed++;continue
        }
        $arguments=@{};if($step.S){$arguments.PolicyStore=$step.S}
        $arguments.All=$true
        if($step.C -ceq 'Get-NetFirewallRule'){$arguments.TracePolicyStore=$true}
        try {$raw[$step.Key]=@(Invoke-WinSecFirewallQuery -Command $step.C -Arguments $arguments -CancellationAction $CancellationAction -Heartbeat $emit)[0]}
        catch [OperationCanceledException] {throw}
        catch {$raw[$step.Key]=@();$failedKeys[$step.Key]=$true;$issues.Add($phase+'_UNAVAILABLE')}
        $completed++
    }
    $phase='NORMALIZING';$null=& $emit
    foreach($store in @('Active','Local')) {
        foreach($p in @($raw['Profiles'+$store])) {
            $name=[string](Get-WinSecFirewallValue $p Name)
            if($name -cnotin @('Domain','Private','Public')){$issues.Add('PROFILE_IDENTITY_INVALID');continue}
            $safe=[pscustomobject]@{}
            foreach($field in Get-WinSecFirewallProfileFields) {
                $v=if($field -ceq 'DisabledInterfaceAliasesCount'){
                    if($null -ne $p.PSObject.Properties['DisabledInterfaceAliases']){@((Get-WinSecFirewallValue $p DisabledInterfaceAliases)|Where-Object {$null -ne $_}).Count}else{$null}
                }else{ConvertTo-WinSecFirewallScalar (Get-WinSecFirewallValue $p $field)}
                $safe|Add-Member $field $v
            }
            $key=$store+$name
            if($null -eq $safe.Enabled -or $null -eq $safe.DefaultInboundAction -or $null -eq $safe.DefaultOutboundAction){$issues.Add('PROFILE_REQUIRED_FIELDS_UNAVAILABLE')}
            if($null -ne $e.Profiles.PSObject.Properties[$key]){throw 'Duplicate Firewall profile.'};$e.Profiles|Add-Member $key $safe
        }
    }
    if(@($raw.Global).Count -eq 1) {
        foreach($field in Get-WinSecFirewallGlobalFields) {
            $v=if($field -like '*Count'){
                $source=$field -replace 'Count$',''
                if($null -ne $raw.Global[0].PSObject.Properties[$source]){@((Get-WinSecFirewallValue $raw.Global[0] $source)|Where-Object {$null -ne $_}).Count}else{$null}
            }else{ConvertTo-WinSecFirewallScalar (Get-WinSecFirewallValue $raw.Global[0] $field)}
            $e.Global|Add-Member $field $v
        }
    }
    $indexes=@{}
    foreach($kind in @('Port','Address','Application','Service','Interface','InterfaceType','Security','PortLocal','AddressLocal','ApplicationLocal','ServiceLocal','InterfaceLocal','InterfaceTypeLocal','SecurityLocal')) {
        $index=@{};foreach($f in @($raw[$kind])) {
            $id=[string](Get-WinSecFirewallValue $f InstanceID)
            if(-not $id){$issues.Add($kind.ToUpperInvariant()+'_IDENTITY_INVALID');continue}
            if($index.ContainsKey($id)){$issues.Add($kind.ToUpperInvariant()+'_IDENTITY_INVALID');$index[$id]=$null;continue};$index[$id]=$f
        };$indexes[$kind]=$index
    }
    foreach($inventory in @(@{Key='RulesActive';Store='ACTIVE'},@{Key='RulesLocal';Store='LOCAL'},@{Key='IPsec';Store='IPSEC'},@{Key='HyperVRules';Store='HYPERV'})) {
        $rules=@($raw[$inventory.Key]);$seen=@{};$batch=New-Object 'Collections.Generic.List[object]'
        $e.Inventories|Add-Member ($inventory.Key+'Count') $(if($failedKeys.ContainsKey($inventory.Key)){$null}else{$rules.Count})
        foreach($r in $rules) {
            $null=& $cancel
            $name=[string](Get-WinSecFirewallValue $r Name);if(-not $name){$name=[string](Get-WinSecFirewallValue $r InstanceID)}
            if(-not $name -or $seen.ContainsKey($name)){throw 'Ambiguous Firewall rule identity.'};$seen[$name]=$true
            $safe=[ordered]@{Id=(Get-WinSecFirewallDigest ($inventory.Store+'|'+$name));Store=$inventory.Store}
            foreach($field in @('Enabled','Direction','Action','EdgeTraversalPolicy','PolicyStoreSourceType','PrimaryStatus')){$safe[$field]=ConvertTo-WinSecFirewallScalar (Get-WinSecFirewallValue $r $field)}
            $safe.Profile=ConvertTo-WinSecFirewallToken (Get-WinSecFirewallValue $r Profile) profiles
            $complete=$true
            foreach($spec in @(@{K='Port';F='Protocol';T='protocol'},@{K='Port';F='LocalPort';T='ports'},@{K='Port';F='RemotePort';T='ports'},
                @{K='Address';F='LocalAddress';T='addresses'},@{K='Address';F='RemoteAddress';T='addresses'},
                @{K='Application';F='Program';T='program'},@{K='Application';F='Package';T='identity'},@{K='Service';F='Service';T='service'},
                @{K='Interface';F='InterfaceAlias';T='interfaces'},@{K='InterfaceType';F='InterfaceType';T='interfaces'},
                @{K='Security';F='Authentication';T='identity'},@{K='Security';F='Encryption';T='identity'},@{K='Security';F='OverrideBlockRules';T='identity'},
                @{K='Security';F='LocalUser';T='identity'},@{K='Security';F='RemoteUser';T='identity'},@{K='Security';F='RemoteMachine';T='identity'})) {
                $f=if($inventory.Store -ceq 'ACTIVE'){$indexes[$spec.K][$name]}elseif($inventory.Store -ceq 'LOCAL'){$indexes[$spec.K+'Local'][$name]}else{$r}
                if($null -eq $f){$complete=$false}
                $safe[$spec.F]=ConvertTo-WinSecFirewallToken (Get-WinSecFirewallValue $f $spec.F) $spec.T
            }
            $safe.FilterState=if($complete){'COMPLETE'}else{'PARTIAL'}
            if(-not $complete){$issues.Add($inventory.Store+'_FILTER_ASSOCIATION_UNRESOLVED')}
            $batch.Add([pscustomobject]$safe)
            if($batch.Count -eq 64){$batches.Add([pscustomobject]@{Inventory=$inventory.Store;Json=(ConvertTo-Json -InputObject $batch.ToArray() -Depth 5 -Compress)});$batch.Clear()}
        }
        if($batch.Count){$batches.Add([pscustomobject]@{Inventory=$inventory.Store;Json=(ConvertTo-Json -InputObject $batch.ToArray() -Depth 5 -Compress)})}
    }
    foreach($meta in @(@{Key='DynamicKeywords';Kind='DYNAMIC'},@{Key='HyperVCreators';Kind='HVCREATOR'},@{Key='HyperVSettings';Kind='HVSETTING'},@{Key='HyperVProfiles';Kind='HVPROFILE'})) {
        $values=@($raw[$meta.Key]);$e.Inventories|Add-Member ($meta.Key+'Count') $(if($failedKeys.ContainsKey($meta.Key)){$null}else{$values.Count})
        $batch=New-Object 'Collections.Generic.List[object]';$seen=@{}
        foreach($item in $values) {
            $null=& $cancel
            $identity=$null
            foreach($field in @('InstanceID','Id','Name','VMCreatorId')){if(-not $identity){$identity=[string](Get-WinSecFirewallValue $item $field)}}
            if(-not $identity -or $seen.ContainsKey($identity)){throw 'Ambiguous Firewall metadata identity.'};$seen[$identity]=$true
            $safe=[ordered]@{}
            foreach($field in Get-WinSecFirewallMetadataFields) {
                $v=Get-WinSecFirewallValue $item $field
                $safe[$field]=if($null -eq $v){$null}elseif($field -cin @('Addresses','VMCreatorId','PolicyStoreSource')){ConvertTo-WinSecFirewallToken $v identity}else{ConvertTo-WinSecFirewallScalar $v}
            }
            $batch.Add([pscustomobject]@{Id=(Get-WinSecFirewallDigest ($meta.Kind+'|'+$identity));Kind=$meta.Kind;Values=[pscustomobject]$safe})
            if($batch.Count -eq 64){$batches.Add([pscustomobject]@{Inventory=$meta.Kind;Json=(ConvertTo-Json -InputObject $batch.ToArray() -Depth 5 -Compress)});$batch.Clear()}
        }
        if($batch.Count){$batches.Add([pscustomobject]@{Inventory=$meta.Kind;Json=(ConvertTo-Json -InputObject $batch.ToArray() -Depth 5 -Compress)})}
    }
    if($e.HyperVState -cne 'NOT_APPLICABLE'){$e.HyperVState=if($issues.Contains('HYPERVSETTINGS_UNAVAILABLE')){'UNKNOWN'}else{'OBSERVED'}}
    $e.Batches=$batches.ToArray();$e.CollectionSuccessful=(@($e.Profiles.PSObject.Properties).Count -gt 0)
    $e.CollectionComplete=($issues.Count -eq 0 -and @($e.Profiles.PSObject.Properties).Count -eq 6)
    $e.CollectionIssues=@($issues.ToArray()|Sort-Object -Unique);$e.CollectedAtUTC=[datetime]::UtcNow.ToString('o');$completed++;$null=& $cancel;$null=& $emit
    [pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$CheckId;SectionKey='NetworkSecurity';
        Status=if($e.CollectionComplete){'INFORMATIONAL'}elseif($e.CollectionSuccessful){'UNKNOWN'}else{'ERROR'};Evidence=$e;TimestampUTC=$e.CollectedAtUTC}
}
