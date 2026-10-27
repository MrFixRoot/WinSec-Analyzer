# Only data; no Windows providers or real application storage.
function New-WinSecFrameworkWorkflowFixture {
    param([string]$CheckId='WSA-SYS-002',[string]$ScanId='framework-fixture')
    $id='local:hw1-'+('b'*64);$start=[datetime]::UtcNow.AddMinutes(-2).ToString('o');$end=[datetime]::UtcNow.AddMinutes(-1).ToString('o')
    $e=[pscustomobject]@{DeviceId=$id;ScanId=$ScanId;CheckId=$CheckId;CollectedAtUTC=$end;CollectionSuccessful=$true;CollectionComplete=$true;CollectionIssues=@()}
    switch($CheckId) {
        WSA-SYS-001 {
            $e|Add-Member DefenderStatus ([pscustomobject]@{AMRunningMode='Normal';AMServiceEnabled=$true;AntivirusEnabled=$false;RealTimeProtectionEnabled=$false;
                BehaviorMonitorEnabled=$true;IsTamperProtected=$false;DefenderSignaturesOutOfDate=$true})
            $e|Add-Member ConfigurationModes ([pscustomobject]@{Pua='DISABLED';Cloud='DISABLED';Tamper='DISABLED';AsrVulnerableDriver='AUDIT'})
            $e|Add-Member DefenderPreferences ([pscustomobject]@{PUAProtection=0;MAPSReporting=0;EnableNetworkProtection=2;EnableControlledFolderAccess=0;ExclusionPath=@('PRIVATE-EXCLUSION')})
            $e|Add-Member AttackSurfaceReduction ([pscustomobject]@{Available=$true;Complete=$true;ConfiguredRuleCount=1;
                Rules=@([pscustomobject]@{RuleId='56a863a9-875e-4185-98a7-b882c64b5ce5';Mode='AUDIT';RawAction='2';EffectiveEnforcementConfirmed=$false})})
            $e|Add-Member StatusSource 'Get-MpComputerStatus';$e|Add-Member PreferenceSource 'Get-MpPreference'
        }
        WSA-SYS-002 {$e|Add-Member SystemVolume ([pscustomobject]@{DriveLetter='C:';ProtectionStatus='OFF';ConversionStatus='FULLY_DECRYPTED';EncryptionPercentage=0;
            EncryptionMethod='NONE';LockStatus='UNLOCKED';RecoveryPassword='PRIVATE-RECOVERY'})}
        WSA-SYS-003 {
            $e|Add-Member Platform ([pscustomobject]@{Version='10.0.22631';BuildNumber='22631';OperatingSystemSKU=48;ProductType=1;State='OBSERVED'})
            $e|Add-Member UpdateService ([pscustomobject]@{State='STOPPED';StartMode='DISABLED'})
            $e|Add-Member RestartInformation ([pscustomobject]@{State='OBSERVED';Value=$true})
        }
    }
    $c=[pscustomobject]@{CheckId=$CheckId;DeviceId=$id;ScanId=$ScanId;SectionKey='SystemSecurity';Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';TimestampUTC=$end;Evidence=$e}
    $session=New-WinSecResultSession -DeviceId $id -ScanId $ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @($CheckId) -ControlResults @($c) `
        -StartedAtUTC $start -CompletedAtUTC $end -ExecutionStatus COMPLETED -ScopeType CONTROL -ScopeKey $CheckId
    $public=ConvertTo-WinSecPublicScanResult $session
    $report=New-WinSecTechnicalReport $session $CheckId SYNTHETIC SYNTHETIC
    [pscustomobject]@{Session=$session;Report=$report;Source=[pscustomobject]@{CheckId=$CheckId;ScanId=$ScanId;ScopeType='CONTROL';ScopeKey=$CheckId;
        CompletedAtUTC=$end;Origin='LIVE';PublicResult=$public;CatalogVersion=$session.CatalogVersion;ExpectedCheckIds=@($session.ExpectedCheckIds)}}
}
