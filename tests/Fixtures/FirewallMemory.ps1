# Synthetic providers only. Never query the host running these tests.
function Initialize-WinSecFirewallFixture {
    $script:FirewallBuild=22631;$script:FirewallFailure='';$script:FirewallCancel=$false
    $script:FirewallCalls=New-Object 'Collections.Generic.List[string]'
    $script:FirewallEvents=New-Object 'Collections.Generic.List[object]'
    $script:FirewallRuleCount=2
}
function Get-WinSecFirewallFixtureCim {
    param($ClassName,$Filter,$Property,$OperationTimeoutSec,$ErrorAction,$Namespace)
    switch($ClassName) {
        Win32_OperatingSystem {[pscustomobject]@{Caption='Microsoft Windows 11 Pro';Version=('10.0.'+$script:FirewallBuild);BuildNumber=[string]$script:FirewallBuild;OperatingSystemSKU=48;ProductType=1}}
        Win32_Service {[pscustomobject]@{Name=if($Filter.Contains('MpsSvc')){'MpsSvc'}else{'BFE'};State='Running';StartMode='Auto'}}
        default {throw 'Forbidden native provider.'}
    }
}
function Invoke-WinSecFirewallFixtureQuery {
    param($Command,$Arguments,$CancellationAction,$Heartbeat)
    $script:FirewallCalls.Add($Command+'|'+$Arguments.PolicyStore)
    if($CancellationAction -and (& $CancellationAction)){throw [OperationCanceledException]::new('Synthetic cancellation.')}
    if($Heartbeat){$null=& $Heartbeat}
    if($script:FirewallFailure -ceq $Command){throw 'PRIVATE-PROVIDER-ERROR'}
    $items=@()
    switch($Command) {
        Get-NetFirewallProfile {
            $items=@(foreach($name in @('Domain','Private','Public')) {
                $p=[ordered]@{Name=$name;DisabledInterfaceAliases=@()}
                foreach($field in Get-WinSecFirewallProfileFields){if($field -cne 'DisabledInterfaceAliasesCount'){$p[$field]=$true}}
                $p.Enabled=($name -cne 'Public');$p.DefaultInboundAction='Block';$p.DefaultOutboundAction='Allow';$p.LogBlocked=$false;$p.LogMaxSizeKilobytes=4096
                [pscustomobject]$p
            })
        }
        Get-NetFirewallSetting {$items=@([pscustomobject]@{CertValidationLevel=0;EnableStatefulFtp=$true;EnableStatefulPptp=$false})}
        Get-NetFirewallRule {
            $items=@(for($i=0;$i -lt $script:FirewallRuleCount;$i++){[pscustomobject]@{Name=('PRIVATE-RULE-'+$i);Enabled=$true;Direction='Inbound';
                Action=if($i%2){'Block'}else{'Allow'};Profile='Public';EdgeTraversalPolicy='Block';PolicyStoreSourceType='Local';PrimaryStatus='OK'}})
        }
        {$_ -clike 'Get-NetFirewall*Filter'} {
            $items=@(for($i=0;$i -lt $script:FirewallRuleCount;$i++){[pscustomobject]@{InstanceID=('PRIVATE-RULE-'+$i);Protocol='TCP';
                LocalPort='Any';RemotePort='Any';LocalAddress='Any';RemoteAddress='Any';Program='C:\Users\PRIVATE-PERSON\app.exe';
                Package='PRIVATE-PACKAGE';Service='Any';InterfaceAlias='Any';InterfaceType='Any';Authentication='NotRequired';Encryption='NotRequired';
                OverrideBlockRules=$false;LocalUser='Any';RemoteUser='Any';RemoteMachine='Any'}})
        }
        Get-NetFirewallHyperVVMSetting {$items=@([pscustomobject]@{Name='PRIVATE-VM';Enabled=$true;DefaultInboundAction='Block';DefaultOutboundAction='Allow';LoopbackEnabled=$true;AllowHostPolicyMerge=$true})}
        Get-NetFirewallHyperVProfile {$items=@([pscustomobject]@{Name='Public';Enabled=$true;DefaultInboundAction='Block'})}
        Get-NetFirewallHyperVVMCreator {$items=@([pscustomobject]@{VMCreatorId='PRIVATE-CREATOR';Name='PRIVATE-VM-NAME'})}
        Get-NetFirewallDynamicKeywordAddress {$items=@([pscustomobject]@{Id='PRIVATE-DYNAMIC';AutoResolve=$true;Addresses=@('10.1.2.3')})}
        Get-NetIPsecRule {}
        Get-NetFirewallHyperVRule {}
        default {throw 'Unexpected Firewall query.'}
    }
    return ,$items
}
function New-WinSecFirewallFixtureSession {
    param([string]$ScanId='firewall-fixture',[string]$ScopeType='CONTROL')
    $id='local:hw1-'+('b'*64);$start=[datetime]::UtcNow.AddMinutes(-1).ToString('o')
    $r=Test-WinSecFirewall -DeviceId $id -ScanId $ScanId -ProgressCallback {param($event);$script:FirewallEvents.Add($event)} -CancellationAction {return $script:FirewallCancel}
    $r|Add-Member ObservedStatus $r.Status
    $end=[datetime]::UtcNow.ToString('o')
    New-WinSecResultSession -DeviceId $id -ScanId $ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @('WSA-NET-001') -ControlResults @($r) `
        -StartedAtUTC $start -CompletedAtUTC $end -ExecutionStatus COMPLETED -ScopeType $ScopeType -ScopeKey $(if($ScopeType -ceq 'CONTROL'){'WSA-NET-001'}else{'NetworkSecurity'})
}
