# Synthetic SMB providers: no native Windows reads, connections or registry access.
function Initialize-WinSecSmbFixture {
    $script:SmbCalls=New-Object 'Collections.Generic.List[string]';$script:SmbEvents=New-Object 'Collections.Generic.List[object]'
    $script:SmbBuild=22631;$script:SmbFailure='';$script:SmbFeatureState=1;$script:SmbMissingFeature='';$script:SmbModernFields=$false
    $script:SmbServerEnabled=$true;$script:SmbDependency=$true;$script:SmbRegistryMissing=$false;$script:SmbBadScalar=$false
}
function Get-WinSecSmbFixtureCim {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
    if($Namespace -cne 'root/cimv2' -or $OperationTimeoutSec -ne 5){throw 'Forbidden SMB fixture query.'}
    $script:SmbCalls.Add($ClassName)
    if($script:SmbFailure -ceq $ClassName){throw 'PRIVATE-SMB-PROVIDER'}
    switch -CaseSensitive($ClassName) {
        Win32_OperatingSystem {
            if($Filter -or ($Property -join ',') -cne 'Caption,Version,BuildNumber,OperatingSystemSKU,ProductType'){throw 'Unexpected OS fields.'}
            [pscustomobject]@{Caption='Microsoft Windows 11 Pro';Version=('10.0.'+$script:SmbBuild);BuildNumber=[string]$script:SmbBuild;OperatingSystemSKU=48;ProductType=1}
        }
        Win32_OptionalFeature {
            if($Filter -cne "Name LIKE 'SMB1Protocol%'" -or ($Property -join ',') -cne 'Name,InstallState'){throw 'Unexpected feature fields.'}
            foreach($name in @('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server','SMB1Protocol-Deprecation')){
                if($name -cne $script:SmbMissingFeature){[pscustomobject]@{Name=$name;InstallState=[uint32]$script:SmbFeatureState;Caption='PRIVATE-FEATURE'}}
            }
        }
        Win32_Service {
            if($Filter -cne "Name = 'LanmanServer' OR Name = 'LanmanWorkstation'" -or ($Property -join ',') -cne 'Name,State,StartMode'){throw 'Unexpected service fields.'}
            foreach($name in @('lanmanserver','LANMANWORKSTATION')){[pscustomobject]@{Name=$name;State='Running';StartMode='Auto';PathName='PRIVATE-SERVICE'}}
        }
        default {throw 'Native CIM query prohibited.'}
    }
}
function Invoke-WinSecSmbFixtureQuery {
    param($Role,$CancellationAction,$Heartbeat)
    $script:SmbCalls.Add($Role)
    if($CancellationAction -and (& $CancellationAction)){throw [OperationCanceledException]::new('Synthetic cancellation.')}
    if($Heartbeat){$null=& $Heartbeat}
    if($script:SmbFailure -ceq $Role){throw 'PRIVATE-SMB-PROVIDER'}
    $raw=[pscustomobject]@{AnnounceComment='PRIVATE-SMB-COMMENT';PSComputerName='PRIVATE-PEER'}
    foreach($f in Get-WinSecSmbConfigurationFields $Role){
        if($f.Modern -and -not $script:SmbModernFields){continue}
        $v=switch($f.Kind){bool {$true};number {[uint32]5};smbCiphers {'AES_128_GCM, AES_256_GCM'};smbDialect {'SMB311'}}
        if($f.Name -ceq 'EnableSMB1Protocol'){$v=$script:SmbServerEnabled}
        if($f.Name -ceq 'RequireSecuritySignature' -and $script:SmbBadScalar){$v='PRIVATE-INVALID-BOOL'}
        if($f.Name -cin @('NullSessionPipesCount','NullSessionSharesCount')){$raw|Add-Member ($f.Name -replace 'Count$','') @('PRIVATE-SHARE');continue}
        $raw|Add-Member $f.Name $v
    }
    return $raw
}
function Read-WinSecSmbFixtureRegistry {
    param($Id)
    if(@(Get-WinSecSmbRegistryDefinitions|Where-Object Id -CEQ $Id).Count -ne 1){throw 'Unreviewed registry read.'}
    $script:SmbCalls.Add('Registry.'+$Id)
    if($script:SmbFailure -ceq $Id){throw 'PRIVATE-SMB-REGISTRY'}
    if($script:SmbRegistryMissing){return [pscustomobject]@{State='NOT_CONFIGURED';Value=$null}}
    [pscustomobject]@{State='OBSERVED';Value=if($Id -ceq 'ClientDependsOnSMB1'){$script:SmbDependency}elseif($Id -like '*Start'){[long]2}else{[long]1}}
}
function New-WinSecSmbFixtureSession {
    param([string]$ScanId='smb-fixture')
    $id='local:hw1-'+('b'*64);$start=[datetime]::UtcNow.AddMinutes(-1).ToString('o')
    $r=Test-WinSecSMBv1 $id $ScanId -ProgressCallback {param($event);$script:SmbEvents.Add($event)}
    $r|Add-Member ObservedStatus $r.Status
    New-WinSecResultSession -DeviceId $id -ScanId $ScanId -CatalogVersion '0.9.0' -ExpectedCheckIds @('WSA-NET-002') -ControlResults @($r) `
        -StartedAtUTC $start -CompletedAtUTC ([datetime]::UtcNow.ToString('o')) -ExecutionStatus $(if($r.Status -ceq 'UNKNOWN'){'COMPLETED_WITH_ERRORS'}else{'COMPLETED'}) -ScopeType CONTROL -ScopeKey WSA-NET-002
}
