# Synthetic RDP providers only. No Windows reads, remote connections or writes.
function Initialize-WinSecRdpFixture {
    $script:RdpCalls=New-Object 'Collections.Generic.List[string]';$script:RdpEvents=New-Object 'Collections.Generic.List[object]'
    $script:RdpBuild=22631;$script:RdpSku=48;$script:RdpFailure='';$script:RdpEnabled=$true;$script:RdpMissing=''
    $script:RdpListeners=2;$script:RdpDuplicate=$false;$script:RdpConflict=$false;$script:RdpSafe=$false;$script:RdpNativePolicy=$true
    $script:RdpSchemaMissing='';$script:RdpNullField='';$script:RdpBooleanField=''
    $script:RdpNullFields=@();$script:RdpListenerCounts=@{};$script:RdpInvalidField=''
}
function Invoke-WinSecRdpFixtureQuery {
    param($Role,$CancellationAction,$Heartbeat,[ref]$Metadata,[string[]]$SkipFields=@())
    $script:RdpCalls.Add($Role)
    if($CancellationAction -and (& $CancellationAction)){throw [OperationCanceledException]::new('Synthetic cancellation.')}
    if($Heartbeat){$null=& $Heartbeat}
    if($script:RdpFailure -ceq $Role){throw 'PRIVATE-RDP-PROVIDER'}
    switch($Role){
        Platform {return [pscustomobject]@{Caption='Microsoft Windows 11';Version=('10.0.'+$script:RdpBuild);BuildNumber=[string]$script:RdpBuild;OperatingSystemSKU=$script:RdpSku;ProductType=1}}
        Services {foreach($name in @('termservice','UMRDPSERVICE','SessionEnv')){[pscustomobject]@{Name=$name;State='Stopped';StartMode='Manual';PathName='PRIVATE-SERVICE'}};return}
    }
    $defs=@(Get-WinSecRdpClasses|Where-Object Id -CEQ $Role)
    if($defs.Count -ne 1){throw 'Unreviewed fixture provider.'};$d=$defs[0]
    if($Metadata){$Metadata.Value=@($d.Fields|Where-Object {$_ -ceq $script:RdpSchemaMissing})}
    $count=if($d.Singleton){1}else{$script:RdpListeners}
    if($script:RdpListenerCounts.ContainsKey($Role)){$count=$script:RdpListenerCounts[$Role]}
    for($i=0;$i -lt $count;$i++){
        $r=[pscustomobject]@{TerminalName=if($i -eq 0 -or $script:RdpDuplicate){'RDP-Tcp'}else{'PRIVATE-LISTENER-'+$i};Password='PRIVATE-PASSWORD';UserName='PRIVATE-USER';SSLCertificateSHA1Hash='PRIVATE-CERT';StringSecurityDescriptor='PRIVATE-ACL'}
        foreach($field in $d.Fields){
            if($field -ceq $script:RdpMissing -or $field -ceq $script:RdpSchemaMissing -or $field -cin $SkipFields){continue}
            $v=switch($field){AllowTSConnections {[long][int]$script:RdpEnabled};UserAuthenticationRequired {if($script:RdpSafe){[long]1}else{[long]0}};SecurityLayer {if($script:RdpSafe){[long]2}else{[long]0}};MinEncryptionLevel {if($script:RdpSafe){[long]3}else{[long]1}};default {[long]0}}
            if($field -ceq $script:RdpNullField -or $field -cin $script:RdpNullFields){$v=$null}
            if($field -ceq $script:RdpBooleanField){$v=$false}
            if($field -ceq $script:RdpInvalidField){$v=[long]9999}
            $r|Add-Member $field $v
        }
        $r
    }
}
function Read-WinSecRdpFixtureRegistry {
    param($Id)
    if(@(Get-WinSecRdpRegistryDefinitions|Where-Object Id -CEQ $Id).Count -ne 1){throw 'Unreviewed fixture registry source.'}
    $script:RdpCalls.Add('Registry.'+$Id)
    if($script:RdpFailure -ceq $Id){throw 'PRIVATE-REGISTRY'}
    if($script:RdpConflict -and $Id -ceq 'Policy_fDenyTSConnections'){return [pscustomobject]@{State='OBSERVED';Value=[long]1}}
    if(-not $script:RdpSafe -and $script:RdpNativePolicy -and $Id -ceq 'Policy_SecurityLayer'){return [pscustomobject]@{State='OBSERVED';Value=[long]0}}
    if(-not $script:RdpSafe -and $Id -ceq 'Policy_DisablePasswordSaving'){return [pscustomobject]@{State='OBSERVED';Value=[long]0}}
    if(-not $script:RdpSafe -and $Id -ceq 'Policy_AllowUnsignedFiles'){return [pscustomobject]@{State='OBSERVED';Value=[long]1}}
    [pscustomobject]@{State='NOT_CONFIGURED';Value=$null}
}
function New-WinSecRdpFixtureSession {
    param([string]$ScanId='rdp-fixture')
    $id='local:hw1-'+('b'*64);$start=[datetime]::UtcNow.AddMinutes(-1).ToString('o')
    $r=Test-WinSecRDP $id $ScanId -ProgressCallback {param($event);$script:RdpEvents.Add($event)}
    $r|Add-Member ObservedStatus $r.Status
    New-WinSecResultSession -DeviceId $id -ScanId $ScanId -CatalogVersion '0.9.0' -ExpectedCheckIds @('WSA-NET-003') -ControlResults @($r) `
        -StartedAtUTC $start -CompletedAtUTC ([datetime]::UtcNow.ToString('o')) -ExecutionStatus $(if($r.Status -ceq 'UNKNOWN'){'COMPLETED_WITH_ERRORS'}else{'COMPLETED'}) -ScopeType CONTROL -ScopeKey WSA-NET-003
}
function New-WinSecRdpFixtureAnalysis {
    param([string]$ProjectRoot,[string]$Framework='nist-csf')
    $s=New-WinSecRdpFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC
    $source=[pscustomobject]@{CheckId='WSA-NET-003';ScanId=$s.ScanId;ScopeType=$s.ScopeType;ScopeKey=$s.ScopeKey;CompletedAtUTC=$s.CompletedAtUTC;
        Origin='LIVE';PublicResult=(ConvertTo-WinSecPublicScanResult $s);CatalogVersion=$s.CatalogVersion;ExpectedCheckIds=@($s.ExpectedCheckIds)}
    New-WinSecFrameworkAnalysis $ProjectRoot $s.DeviceId SYNTHETIC CONTROL WSA-NET-003 $Framework @($source) @($r)
}
