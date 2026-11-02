# Synthetic local SAM providers only; no Windows queries or native API calls.
function Initialize-WinSecIdentityFixture {
    $script:IdentityCalls=New-Object 'Collections.Generic.List[string]';$script:IdentityEvents=New-Object 'Collections.Generic.List[object]'
    $script:IdentityFailure='';$script:IdentityMissing='';$script:IdentityMemberCount=2;$script:IdentityDuplicate=$false
    $script:IdentityGuestDisabled=$false;$script:IdentityGuestSid='S-1-5-21-11-22-33-501'
    $script:IdentityBuild=22631
    $script:IdentityMinimumLength=0;$script:IdentityLockoutThreshold=0
}
function Invoke-WinSecIdentityFixtureQuery {
    param($Role,$CancellationAction,$Heartbeat)
    $script:IdentityCalls.Add($Role)
    if($CancellationAction -and (& $CancellationAction)){throw [OperationCanceledException]::new('Synthetic cancellation.')}
    if($Heartbeat){$null=& $Heartbeat};if($Role -ceq $script:IdentityFailure){throw 'PRIVATE-PROVIDER-TEXT'}
    switch -CaseSensitive ($Role){
        Platform {return [pscustomobject]@{Caption='Microsoft Windows 11 Pro';Version=('10.0.'+$script:IdentityBuild);BuildNumber=[string]$script:IdentityBuild;OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}}
        Administrators {
            for($i=0;$i -lt $script:IdentityMemberCount;$i++){[pscustomobject]@{SID=('S-1-5-21-11-22-33-'+$(if($script:IdentityDuplicate){1000}else{1000+$i}));Name='PRIVATE-ACCOUNT';Domain='PRIVATE-DOMAIN'}}
            return
        }
        Guest {$data=[ordered]@{SID=$script:IdentityGuestSid;Disabled=$script:IdentityGuestDisabled;LocalAccount=$true;Lockout=$false;PasswordRequired=$false;PasswordChangeable=$true;PasswordExpires=$false;AccountType=[uint32]512;SIDType=[uint32]1;Name='PRIVATE-RENAMED-GUEST'} }
        Password {$data=[ordered]@{MinimumLength=[uint32]$script:IdentityMinimumLength;MaximumAgeSeconds=[uint32]4294967295;MinimumAgeSeconds=[uint32]0;ForceLogoffSeconds=[uint32]4294967295;HistoryLength=[uint32]0}}
        Lockout {$data=[ordered]@{DurationSeconds=[uint32]1800;ObservationWindowSeconds=[uint32]1800;Threshold=[uint32]$script:IdentityLockoutThreshold}}
    }
    if($script:IdentityMissing -and $data.Contains($script:IdentityMissing)){$data[$script:IdentityMissing]=$null}
    [pscustomobject]$data
}
function New-WinSecIdentityFixtureSession {
    param([string[]]$CheckIds=@('WSA-IAM-001','WSA-IAM-002','WSA-IAM-003'),[string]$ScanId='identity-fixture')
    $start=[datetime]::UtcNow.AddMinutes(-1).ToString('o');$records=@();$device='local:hw1-'+('b'*64)
    foreach($id in $CheckIds){
        $r=Invoke-WinSecIdentityAccessCollection $device $ScanId $id -ProgressCallback {param($event);$script:IdentityEvents.Add($event)}
        $r|Add-Member ObservedStatus $r.Status;$records+=,$r
    }
    $scope=if($CheckIds.Count -eq 1){'CONTROL'}else{'SECTION'};$key=if($CheckIds.Count -eq 1){$CheckIds[0]}else{'IdentityAccess'}
    New-WinSecResultSession -DeviceId $device -ScanId $ScanId -CatalogVersion 0.9.0 -ExpectedCheckIds $CheckIds -ControlResults $records -StartedAtUTC $start `
        -CompletedAtUTC ([datetime]::UtcNow.ToString('o')) -ExecutionStatus $(if(@($records|Where-Object Status -CEQ UNKNOWN).Count){'COMPLETED_WITH_ERRORS'}else{'COMPLETED'}) -ScopeType $scope -ScopeKey $key
}
function New-WinSecIdentityFixtureSource {
    param($Session,[string]$CheckId)
    [pscustomobject]@{CheckId=$CheckId;ScanId=$Session.ScanId;ScopeType=$Session.ScopeType;ScopeKey=$Session.ScopeKey;CompletedAtUTC=$Session.CompletedAtUTC;
        Origin='LIVE';PublicResult=(ConvertTo-WinSecPublicScanResult $Session);CatalogVersion=$Session.CatalogVersion;ExpectedCheckIds=@($Session.ExpectedCheckIds)}
}
