# Synthetic network configuration only; never call Windows or open sockets.
function Initialize-WinSecNetworkConfigurationFixture {
    $script:NetworkCalls=New-Object 'Collections.Generic.List[string]';$script:NetworkEvents=New-Object 'Collections.Generic.List[object]'
    $script:NetworkFailure='';$script:NetworkCount=2;$script:NetworkOptionalMissing=$false;$script:NetworkInvalid=''
    $script:NetworkBuild=22631;$script:NetworkSku=48;$script:NetworkWarn=$true;$script:NetworkRegistryMissing=$false
    $script:NetworkLegacyNoInterface=$false;$script:NetworkLegacyIPEnabled=$false;$script:NetworkLegacyDuplicateIndex=$false
}
function Invoke-WinSecNetworkConfigurationFixtureQuery {
    param($Role,$CancellationAction,$Heartbeat)
    $script:NetworkCalls.Add($Role)
    if($CancellationAction -and (& $CancellationAction)){throw [OperationCanceledException]::new('Synthetic cancellation.')}
    if($Heartbeat){$null=& $Heartbeat};if($Role -ceq $script:NetworkFailure){throw 'PRIVATE-PROVIDER-TEXT'}
    if($Role -ceq 'Platform'){return [pscustomobject]@{Caption='Microsoft Windows 11';Version=('10.0.'+$script:NetworkBuild);BuildNumber=[string]$script:NetworkBuild;OperatingSystemSKU=$script:NetworkSku;ProductType=1}}
    if($Role -ceq 'Registry'){
        $values=[ordered]@{};foreach($p in Get-WinSecNetworkConfigurationRegistryDefinitions){
            $values[$p.Name]=[pscustomobject]@{State=$(if($script:NetworkRegistryMissing){'NOT_CONFIGURED'}else{'CONFIGURED'});Value=$(if($script:NetworkRegistryMissing){$null}elseif($script:NetworkWarn){[long]1}else{[long]0})}}
        return [pscustomobject]@{ReadState='READ';Values=[pscustomobject]$values}
    }
    $p=Get-WinSecNetworkConfigurationProvider $Role;$count=if($Role -ceq 'DNSGlobal'){1}else{$script:NetworkCount}
    for($i=0;$i -lt $count;$i++){
        $r=[ordered]@{}
        foreach($f in $p.Fields){$v=switch($f.Kind){b {$true};ip {'192.0.2.10'};prefix {'192.0.2.0/24'};ips {,@('192.0.2.53','192.0.2.54')};f {[uint16]2};default {[uint32]1}}
            if($f.Name -cin @('Index','InterfaceIndex')){$v=[uint32]($i+1)}
            if($Role -ceq 'Legacy' -and $script:NetworkLegacyNoInterface){
                if($f.Name -ceq 'InterfaceIndex'){$v=$null}
                if($f.Name -ceq 'IPEnabled'){$v=$script:NetworkLegacyIPEnabled}
            }
            if($Role -ceq 'Legacy' -and $script:NetworkLegacyDuplicateIndex -and $f.Name -ceq 'Index'){$v=[uint32]1}
            if($f.Name -ceq 'TcpipNetbiosOptions' -and -not $script:NetworkWarn){$v=[uint32]2}
            if($f.Name -ceq 'NetworkCategory' -and -not $script:NetworkWarn){$v=[uint32]0}
            if($script:NetworkOptionalMissing -and $f.Name -cnotin $p.Required -and -not ($Role -ceq 'Legacy' -and $f.Name -ceq 'InterfaceIndex')){$v=$null}
            if($f.Name -ceq $script:NetworkInvalid){$v='PRIVATE-BAD-VALUE'}
            $r[$f.Name]=$v
        }
        $r.Name='PRIVATE-ADAPTER';$r.MACAddress='PRIVATE-MAC';$r.SSID='PRIVATE-SSID';$r.DNSDomain='PRIVATE-DOMAIN';[pscustomobject]$r
    }
}
function New-WinSecNetworkConfigurationFixtureSession {
    param([string]$ScanId='network-fixture')
    $id='local:hw1-'+('b'*64);$start=[datetime]::UtcNow.AddMinutes(-1).ToString('o')
    $r=Test-WinSecNetworkConfiguration $id $ScanId -ProgressCallback {param($event);$script:NetworkEvents.Add($event)}
    $r|Add-Member ObservedStatus $r.Status
    New-WinSecResultSession -DeviceId $id -ScanId $ScanId -CatalogVersion '0.9.0' -ExpectedCheckIds @('WSA-NET-005') -ControlResults @($r) `
        -StartedAtUTC $start -CompletedAtUTC ([datetime]::UtcNow.ToString('o')) -ExecutionStatus $(if($r.Status -ceq 'UNKNOWN'){'COMPLETED_WITH_ERRORS'}else{'COMPLETED'}) -ScopeType CONTROL -ScopeKey WSA-NET-005
}
function New-WinSecNetworkConfigurationFixtureAnalysis {
    param([string]$ProjectRoot,[string]$Framework='nist-csf')
    $s=New-WinSecNetworkConfigurationFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-005 SYNTHETIC SYNTHETIC
    $source=[pscustomobject]@{CheckId='WSA-NET-005';ScanId=$s.ScanId;ScopeType=$s.ScopeType;ScopeKey=$s.ScopeKey;CompletedAtUTC=$s.CompletedAtUTC;
        Origin='LIVE';PublicResult=(ConvertTo-WinSecPublicScanResult $s);CatalogVersion=$s.CatalogVersion;ExpectedCheckIds=@($s.ExpectedCheckIds)}
    New-WinSecFrameworkAnalysis $ProjectRoot $s.DeviceId SYNTHETIC CONTROL WSA-NET-005 $Framework @($source) @($r)
}
