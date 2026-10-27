# Synthetic endpoint providers only. Never query Windows or open sockets.
function Initialize-WinSecOpenPortsFixture {
    $script:PortsCalls=New-Object 'Collections.Generic.List[string]';$script:PortsEvents=New-Object 'Collections.Generic.List[object]'
    $script:PortsFailure='';$script:PortsCount=3;$script:PortsBuild=22631;$script:PortsSku=48
    $script:PortsOptionalMissing=$false;$script:PortsInvalid='';$script:PortsLoopbackOnly=$false
}
function Invoke-WinSecOpenPortsFixtureQuery {
    param($Role,$CancellationAction,$Heartbeat)
    $script:PortsCalls.Add($Role)
    if($CancellationAction -and (& $CancellationAction)){throw [OperationCanceledException]::new('Synthetic cancellation.')}
    if($Heartbeat){$null=& $Heartbeat}
    if($Role -ceq $script:PortsFailure){throw 'PRIVATE-PROVIDER-ERROR'}
    if($Role -ceq 'Platform'){return [pscustomobject]@{Caption='Microsoft Windows 11';Version=('10.0.'+$script:PortsBuild);BuildNumber=[string]$script:PortsBuild;OperatingSystemSKU=$script:PortsSku;ProductType=1}}
    for($i=0;$i -lt $script:PortsCount;$i++){
        $r=[pscustomobject]@{LocalAddress=$(if($script:PortsLoopbackOnly){'127.0.0.1'}elseif($i%3 -eq 0){'0.0.0.0'}elseif($i%3 -eq 1){'::1'}else{'192.0.2.9'});
            LocalPort=([uint16](1000+$i));OwningProcess=[uint32]42;CreationTime=([datetime]'2026-10-20T12:00:00Z');
            State=[byte]2;AppliedSetting=[byte]0;OffloadState=[byte]0;RemoteAddress='PRIVATE-PEER';UserName='PRIVATE-USER';Path='PRIVATE-PATH'}
        if($script:PortsOptionalMissing){$r.OwningProcess=$null;$r.CreationTime=$null;$r.AppliedSetting=$null;$r.OffloadState=$null}
        switch($script:PortsInvalid){Port {$r.LocalPort=$null};State {$r.State=5};Address {$r.LocalAddress='PRIVATE-NOT-AN-IP'};default {}}
        $r
    }
}
function New-WinSecOpenPortsFixtureSession {
    param([string]$ScanId='ports-fixture')
    $id='local:hw1-'+('b'*64);$start=[datetime]::UtcNow.AddMinutes(-1).ToString('o')
    $r=Test-WinSecOpenPorts $id $ScanId -ProgressCallback {param($event);$script:PortsEvents.Add($event)}
    $r|Add-Member ObservedStatus $r.Status
    New-WinSecResultSession -DeviceId $id -ScanId $ScanId -CatalogVersion '0.9.0' -ExpectedCheckIds @('WSA-NET-004') -ControlResults @($r) `
        -StartedAtUTC $start -CompletedAtUTC ([datetime]::UtcNow.ToString('o')) -ExecutionStatus $(if($r.Status -ceq 'UNKNOWN'){'COMPLETED_WITH_ERRORS'}else{'COMPLETED'}) -ScopeType CONTROL -ScopeKey WSA-NET-004
}
function New-WinSecOpenPortsFixtureAnalysis {
    param([string]$ProjectRoot,[string]$Framework='nist-csf')
    $s=New-WinSecOpenPortsFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-004 SYNTHETIC SYNTHETIC
    $source=[pscustomobject]@{CheckId='WSA-NET-004';ScanId=$s.ScanId;ScopeType=$s.ScopeType;ScopeKey=$s.ScopeKey;CompletedAtUTC=$s.CompletedAtUTC;
        Origin='LIVE';PublicResult=(ConvertTo-WinSecPublicScanResult $s);CatalogVersion=$s.CatalogVersion;ExpectedCheckIds=@($s.ExpectedCheckIds)}
    New-WinSecFrameworkAnalysis $ProjectRoot $s.DeviceId SYNTHETIC CONTROL WSA-NET-004 $Framework @($source) @($r)
}
