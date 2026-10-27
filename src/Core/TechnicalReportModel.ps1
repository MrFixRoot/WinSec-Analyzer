# Versioned, allowlisted technical telemetry. No Windows queries or writes.
. (Join-Path $PSScriptRoot 'TechnicalControlRegistry.ps1')
. (Join-Path $PSScriptRoot 'FirewallTelemetry.ps1')
function Get-WinSecTechnicalField {
    param([AllowNull()][object]$Value,[string]$Path)
    foreach($name in $Path.Split('.')) {
        if($null -eq $Value){return [pscustomobject]@{Exists=$false;Value=$null}}
        if($Value -is [Collections.IDictionary]) {
            if(-not $Value.Contains($name)){return [pscustomobject]@{Exists=$false;Value=$null}}
            $Value=$Value[$name]
        } else {
            $p=$Value.PSObject.Properties[$name]
            if($null -eq $p){return [pscustomobject]@{Exists=$false;Value=$null}}
            if($p.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){throw 'Technical telemetry requires plain data.'}
            $Value=$p.Value
        }
    }
    [pscustomobject]@{Exists=$true;Value=$Value}
}

function Get-WinSecTechnicalDefinitions {
    param([ValidateSet('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003','WSA-NET-001')][string]$CheckId)
    if($CheckId -ceq 'WSA-NET-001'){return Get-WinSecFirewallTechnicalDefinitions}
    $spec=@(
        'CollectionSuccessful|Coleccion|bool|Collector|'
        'CollectionComplete|Coleccion|bool|Collector|'
        'CollectionIssueCount|Coleccion (mensajes libres excluidos)|number|Collector|'
    )
    switch($CheckId) {
        WSA-SYS-001 {
            $spec+='StatusSource|Fuentes consultadas|source|Collector|'
            $spec+='PreferenceSource|Fuentes consultadas|source|Collector|'
            foreach($name in @('AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled','BehaviorMonitorEnabled',
                'OnAccessProtectionEnabled','IoavProtectionEnabled','NISEnabled','IsTamperProtected','DefenderSignaturesOutOfDate','RebootRequired')) {
                $spec+='DefenderStatus.'+$name+'|Estado y proteccion|bool|Get-MpComputerStatus|'
            }
            $spec+='DefenderStatus.AMRunningMode|Estado y proteccion|runningMode|Get-MpComputerStatus|'
            foreach($name in @('AntivirusSignatureAge','NISSignatureAge','QuickScanAge','FullScanAge','ComputerState')) {
                $spec+='DefenderStatus.'+$name+'|Firmas y analisis|number|Get-MpComputerStatus|'
            }
            foreach($name in @('AntivirusSignatureLastUpdated','NISSignatureLastUpdated','QuickScanEndTime','FullScanEndTime')) {
                $spec+='DefenderStatus.'+$name+'|Firmas y analisis|date|Get-MpComputerStatus|'
            }
            foreach($name in @('AntivirusSignatureVersion','NISSignatureVersion','AMEngineVersion','AMProductVersion')) {
                $spec+='DefenderStatus.'+$name+'|Firmas y analisis|version|Get-MpComputerStatus|'
            }
            foreach($name in @('DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableIOAVProtection','DisableBlockAtFirstSeen',
                'DisableScriptScanning','DisableArchiveScanning','DisableEmailScanning','DisableRemovableDriveScanning',
                'DisableScanningNetworkFiles','DisableScanningMappedNetworkDrivesForFullScan','DisableCatchupQuickScan','DisableCatchupFullScan',
                'DisableIntrusionPreventionSystem','DisablePrivacyMode','CheckForSignaturesBeforeRunningScan','AllowNetworkProtectionOnWinServer',
                'AllowNetworkProtectionDownLevel','EnableFileHashComputation','DisableRdpParsing','DisableHttpParsing','DisableDnsOverTcpParsing',
                'DisableSshParsing','DisableTlsParsing')) {
                $spec+='DefenderPreferences.'+$name+'|Preferencias (Disable=true significa desactivado)|bool|Get-MpPreference|'
            }
            foreach($name in @('PUAProtection','MAPSReporting','SubmitSamplesConsent','CloudBlockLevel','ScanScheduleDay','ScanParameters',
                'EnableNetworkProtection','EnableControlledFolderAccess')) {
                $spec+='DefenderPreferences.'+$name+'|Modos configurados|mode|Get-MpPreference|'
            }
            foreach($name in @('CloudExtendedTimeout','SignatureUpdateInterval','ScanAvgCPULoadFactor')) {
                $spec+='DefenderPreferences.'+$name+'|Preferencias numericas|number|Get-MpPreference|'
            }
            foreach($name in @('Paths','Processes','Extensions','ASR','ControlledFolderAllowedApplications','ControlledFolderProtectedFolders')) {
                $spec+='ExclusionCounts.'+$name+'|Exclusiones (solo recuentos, sin rutas)|number|Get-MpPreference|'
            }
            $spec+='PreferenceCollectionSuccessful|Coleccion|bool|Collector|'
            foreach($name in @('Pua','Cloud','Tamper','AsrVulnerableDriver')) {
                $spec+='ConfigurationModes.'+$name+'|Interpretacion de modos (sin puntos adicionales)|mode|Collector|'
            }
            foreach($name in @('Available','Complete','UnlistedRulesAssessed')) {
                $spec+='AttackSurfaceReduction.'+$name+'|ASR: alcance del inventario|bool|Get-MpPreference|'
            }
            $spec+='AttackSurfaceReduction.ConfiguredRuleCount|ASR: alcance del inventario|number|Get-MpPreference|'
            foreach($name in @('BLOCK','AUDIT','WARN','DISABLED','NOT_CONFIGURED','UNKNOWN')) {
                $spec+='AttackSurfaceReduction.Modes.'+$name+'|ASR: recuentos por modo|number|Get-MpPreference|'
            }
        }
        WSA-SYS-002 {
            $spec+='StatusSource|Fuentes consultadas|source|Collector|'
            $spec+='Scope|Alcance de volumen|source|Collector|'
            foreach($item in @('DriveLetter|drive','ProtectionStatus|mode','ConversionStatus|mode','EncryptionPercentage|number',
                'EncryptionMethod|mode','LockStatus|mode')) {
                $pair=$item.Split('|');$spec+='SystemVolume.'+$pair[0]+'|BitLocker: solo unidad de Windows|'+$pair[1]+'|CIM:Win32_EncryptableVolume|'
            }
        }
        WSA-SYS-003 {
            foreach($item in @('Version|version','BuildNumber|number','OperatingSystemSKU|number','ProductType|number','State|mode')) {
                $p=$item.Split('|');$spec+='Platform.'+$p[0]+'|Windows observado|'+$p[1]+'|CIM:Win32_OperatingSystem|'
            }
            foreach($name in @('State','StartMode')){$spec+='UpdateService.'+$name+'|Servicio Windows Update|mode|CIM:Win32_Service|'}
            foreach($name in @('CurrentBuildNumber','UBR')) {
                $spec+='VersionRegistry.'+$name+'.Value|Build y revision instaladas|number|Registry64:CurrentVersion|VersionRegistry.'+$name+'.State'
            }
            $spec+='VersionRegistry.ReadState|Build y revision instaladas|mode|Registry64:CurrentVersion|'
            $spec+='RestartInformation.Value|Reinicio requerido por actualizaciones|bool|WUA:ISystemInformation.RebootRequired|RestartInformation.State'
            foreach($area in @(@{Name='AutomaticUpdates';Fields=@('NoAutoUpdate','AUOptions','UseWUServer')},
                @{Name='WindowsUpdate';Fields=@('DeferQualityUpdates','DeferQualityUpdatesPeriodInDays','SetDisableUXWUAccess',
                'DoNotConnectToWindowsUpdateInternetLocations','SetPolicyDrivenUpdateSourceForQualityUpdates',
                'ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates','SetComplianceDeadline',
                'SetComplianceDeadlineForQU','SetComplianceDeadlineForFU','SetEDURestart')})) {
                $prefix='PolicyRegistry.'+$area.Name
                $spec+=$prefix+'.ReadState|Politicas de registro: '+$area.Name+'|mode|Registry64:WindowsUpdate|'
                foreach($name in $area.Fields){$spec+=$prefix+'.'+$name+'.Value|Politicas de registro: '+$area.Name+'|number|Registry64:WindowsUpdate|'+$prefix+'.'+$name+'.State'}
            }
            foreach($name in @('AllowAutoUpdate','ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates',
                'IgnoreWindowsUpdateGroupPolicies','SetEDURestart')) {
                $p='AutomationPolicy.'+$name
                $spec+=$p+'.State|Politicas gestionadas: '+$name+'|mode|WINRT:NamedPolicy|'
                $spec+=$p+'.Kind|Politicas gestionadas: '+$name+'|mode|WINRT:NamedPolicy|'
                $spec+=$p+'.Managed|Politicas gestionadas: '+$name+'|bool|WINRT:NamedPolicy|'+$p+'.State'
                $spec+=$p+'.Value|Politicas gestionadas: '+$name+'|number|WINRT:NamedPolicy|'+$p+'.State'
            }
            foreach($name in @('EffectivePolicyVerified','UpdateSearchPerformed','ScoringEligible')){$spec+=$name+'|Limites de la recoleccion|bool|Collector|'}
        }
    }
    foreach($line in $spec){$p=$line.Split('|');[pscustomobject]@{Id=$p[0];Group=$p[1];Kind=$p[2];Source=$p[3];StatePath=$p[4]}}
}

function ConvertTo-WinSecTechnicalValue {
    param([AllowNull()][object]$Value,[string]$Kind)
    if($null -eq $Value){return $null}
    if($Value.GetType().IsEnum){$Value=[Convert]::ToInt64($Value)}
    switch($Kind) {
        firewallIssues {
            if($Value -isnot [string]){throw 'Invalid Firewall diagnostics.'}
            if($Value -ceq 'NONE'){return $Value}
            $codes=@($Value.Split(','));$allowed=@(Get-WinSecFirewallIssueCodes)
            if($codes.Count -le $allowed.Count -and @($codes|Where-Object {$_ -cnotin $allowed}).Count -eq 0 -and @($codes|Select-Object -Unique).Count -eq $codes.Count){return $Value}
        }
        firewallBatch {$null=ConvertTo-WinSecFirewallBatch $Value;return $Value}
        firewallMetadata {$null=ConvertTo-WinSecFirewallMetadataBatch $Value;return $Value}
        firewallScalar {
            if($Value -is [bool]){return $Value}
            if($Value -is [long] -or $Value -is [int]){return ConvertTo-WinSecTechnicalValue $Value number}
            $safe=ConvertTo-WinSecFirewallScalar $Value
            if($null -ne $safe){return $safe}
            if($Value -ceq 'OBSERVED' -or $Value -ceq 'NOT_APPLICABLE'){return $Value}
        }
        bool {if($Value -is [bool]){return $Value}}
        number {
            if($Value -is [string] -and $Value -cmatch '\A-?[0-9]{1,10}\z'){$Value=[long]$Value}
            if($Value.GetType() -in @([byte],[sbyte],[int16],[uint16],[int32],[uint32],[long],[uint64],[double],[decimal]) -and
                [double]$Value -ge -2147483648 -and [double]$Value -le 4294967295 -and [Math]::Floor([double]$Value) -eq [double]$Value){return [long]$Value}
        }
        date {
            if($Value -is [datetime]){return $Value.ToUniversalTime().ToString('o')}
            if($Value -is [datetimeoffset]){return $Value.UtcDateTime.ToString('o')}
            if($Value -is [string]){return (ConvertTo-WinSecResultUtc $Value 'TechnicalDate').UtcDateTime.ToString('o')}
        }
        version {if($Value -is [string] -and $Value -cmatch '\A[0-9]{1,10}(?:\.[0-9]{1,10}){0,4}\z'){return $Value}}
        drive {if($Value -is [string] -and $Value -cmatch '\A[A-Z]:\z'){return $Value}}
        source {if($Value -is [string] -and $Value -cin @('Get-MpComputerStatus','Get-MpPreference',
            'CIM:MSFT_MpComputerStatus','CIM:MSFT_MpPreference','CIM:Win32_EncryptableVolume','OS_VOLUME_ONLY','UNKNOWN')){return $Value}}
        runningMode {if($Value -is [string] -and $Value -cin @('Normal','Passive','EDR Block Mode','SxS Passive Mode')){return $Value}}
        mode {
            if($Value -is [ValueType] -or ($Value -is [string] -and $Value -cmatch '\A-?[0-9]{1,10}\z')) {
                return ConvertTo-WinSecTechnicalValue $Value number
            }
            if($Value -is [string] -and $Value -in @('UNKNOWN','OBSERVED','READ','CONFIGURED','NOT_CONFIGURED','NOT_APPLICABLE',
                'RUNNING','STOPPED','START_PENDING','STOP_PENDING','CONTINUE_PENDING','PAUSE_PENDING','PAUSED','AUTO','BOOT','SYSTEM','MANUAL','DISABLED','ON','OFF','UNLOCKED','LOCKED',
                'FULLY_DECRYPTED','FULLY_ENCRYPTED','ENCRYPTION_IN_PROGRESS','DECRYPTION_IN_PROGRESS','ENCRYPTION_PAUSED','DECRYPTION_PAUSED',
                'NONE','AES_128_WITH_DIFFUSER','AES_256_WITH_DIFFUSER','AES_128','AES_256','HARDWARE_ENCRYPTION','XTS_AES_128','XTS_AES_256',
                'BLOCK','AUDIT','AUDITMODE','WARN','ENABLED','BASIC','ADVANCED','HIGH','HIGHPLUS','ZEROTOLERANCE','DEFAULT','ALWAYSPROMPT',
                'BLOCKDISKMODIFICATIONONLY','AUDITDISKMODIFICATIONONLY','NOTCONFIGURED',
                'SENDSAFESAMPLES','NEVERSEND','SENDALLSAMPLES','LOW','MODERATE','NOT_EVALUATED','BOOLEAN','INT32','UINT32','INT64','EMPTY',
                'INVALID','BINARY','STRING')){return $Value}
        }
    }
    throw 'Invalid allowlisted technical value.'
}

function Get-WinSecTechnicalRowDefinition {
    param([string]$Id,[object[]]$Definitions)
    $found=@($Definitions|Where-Object Id -CEQ $Id)
    if($found.Count -eq 1){return $found[0]}
    if($Id -cmatch '\AInventory\.(ACTIVE|LOCAL|IPSEC|HYPERV)\.([0-9]{4})\z' -and @($Definitions|Where-Object Id -CEQ HyperVState).Count -eq 1) {
        return [pscustomobject]@{Id=$Id;Group=('Firewall rule inventory: '+$Matches[1]);Kind='firewallBatch';Source='NetSecurity:local';StatePath=''}
    }
    if($Id -cmatch '\AInventory\.(DYNAMIC|HVCREATOR|HVSETTING|HVPROFILE)\.([0-9]{4})\z' -and @($Definitions|Where-Object Id -CEQ HyperVState).Count -eq 1) {
        return [pscustomobject]@{Id=$Id;Group=('Firewall auxiliary inventory: '+$Matches[1]);Kind='firewallMetadata';Source='NetSecurity:local';StatePath=''}
    }
    if($Id -cmatch '\AAttackSurfaceReduction\.Rules\.([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\.(Mode|RawAction|EffectiveEnforcementConfirmed)\z' -and
        @($Definitions|Where-Object Id -CEQ 'AttackSurfaceReduction.Available').Count -eq 1) {
        return [pscustomobject]@{Id=$Id;Group='ASR: reglas individuales (no se asumen reglas ausentes)';
            Kind=if($Matches[2] -ceq 'EffectiveEnforcementConfirmed'){'bool'}else{'mode'};Source='Get-MpPreference';StatePath=''}
    }
    throw 'Unknown technical setting.'
}

function ConvertTo-WinSecTechnicalReport {
    param([Parameter(Mandatory)][object]$Report)
    $r=Copy-WinSecResultData $Report
    Assert-WinSecConfigurationFields $r @('SchemaVersion','CatalogVersion','DeviceId','ScanId','SectionKey','CheckId','ScopeType','ScopeKey',
        'DeviceName','Hostname','Profile','ObservedOSRelease','ObservedEdition','StartedAtUTC','CompletedAtUTC','CollectedAtUTC','GeneratedAtUTC','CollectorStatus','Rows')
    foreach($field in @('SchemaVersion','CatalogVersion','DeviceId','ScanId','SectionKey','CheckId','ScopeType','ScopeKey')) {
        if($r.$field -isnot [string]){throw 'Technical identities must be scalar text.'}
    }
    if($r.SchemaVersion -cne '1.0.0' -or $r.CatalogVersion -cne '1.0.0' -or
        $r.DeviceId -cnotmatch '\Alocal:hw1-[a-f0-9]{64}\z' -or -not (Test-WinSecTargetIdentifier $r.ScanId) -or
        $r.CheckId -isnot [string] -or $r.SectionKey -cne (Get-WinSecTechnicalControl $r.CheckId).SectionKey) {
        throw 'Invalid technical report identity.'
    }
    Assert-WinSecResultScope $r.ScopeType $r.ScopeKey
    if(($r.ScopeType -ceq 'SECTION' -and $r.ScopeKey -cne $r.SectionKey) -or
        ($r.ScopeType -ceq 'CONTROL' -and $r.ScopeKey -cne $r.CheckId)){throw 'Foreign technical scope.'}
    foreach($name in @('DeviceName','Hostname','Profile','ObservedOSRelease','ObservedEdition','CollectorStatus')) {
        if(-not (Test-WinSecResultText $r.$name)){throw 'Invalid technical header.'}
    }
    if($r.CollectorStatus -cnotin @('INFORMATIONAL','UNKNOWN','ERROR','NOT_EVALUATED','NOT_CHECKED','NOT_APPLICABLE')){throw 'Invalid technical collection status.'}
    foreach($name in @('StartedAtUTC','CompletedAtUTC','CollectedAtUTC','GeneratedAtUTC')) {
        if($r.$name -is [datetime]){$r.$name=$r.$name.ToUniversalTime().ToString('o')}
        $r.$name=(ConvertTo-WinSecResultUtc $r.$name $name).UtcDateTime.ToString('o')
    }
    if($r.StartedAtUTC -cgt $r.CollectedAtUTC -or $r.CollectedAtUTC -cgt $r.CompletedAtUTC -or $r.CompletedAtUTC -cgt $r.GeneratedAtUTC){throw 'Invalid technical report timeline.'}
    $defs=@(Get-WinSecTechnicalDefinitions $r.CheckId);$seen=@{}
    $limit=if($r.CheckId -ceq 'WSA-NET-001'){1000}else{600}
    if($r.Rows -isnot [array] -or $r.Rows.Count -gt $limit){throw 'Invalid technical reading count.'}
    foreach($row in $r.Rows) {
        Assert-WinSecConfigurationFields $row @('SettingId','Value','State','Reason')
        if($row.SettingId -isnot [string] -or $seen.ContainsKey($row.SettingId) -or $row.State -isnot [string] -or
            $row.State -cnotin @('OBSERVED','UNKNOWN','ERROR','NOT_COLLECTED','NOT_CONFIGURED','NOT_APPLICABLE') -or
            $row.Reason -isnot [string] -or $row.Reason -cnotin @('NONE','UNAVAILABLE','INVALID_VALUE','PROVIDER_ERROR')){throw 'Invalid technical reading.'}
        $d=Get-WinSecTechnicalRowDefinition $row.SettingId $defs
        if($row.State -ceq 'OBSERVED') {
            if($null -eq $row.Value -or $row.Reason -cne 'NONE'){throw 'Missing observed technical value.'}
            $row.Value=ConvertTo-WinSecTechnicalValue $row.Value $d.Kind
        } elseif($null -ne $row.Value -or $row.Reason -ceq 'NONE'){throw 'Unresolved telemetry cannot supply a value.'}
        $excluded=if($r.CheckId -ceq 'WSA-NET-001'){@('Inventories.HyperVRulesCount','Inventories.HyperVCreatorsCount','Inventories.HyperVSettingsCount','Inventories.HyperVProfilesCount')}else{@('AutomationPolicy.IgnoreWindowsUpdateGroupPolicies.Managed','AutomationPolicy.IgnoreWindowsUpdateGroupPolicies.Value')}
        if($row.State -ceq 'NOT_APPLICABLE' -and $row.SettingId -cnotin $excluded) {
            throw 'Unreviewed technical exclusion.'
        }
        $seen[$row.SettingId]=$true
    }
    if(@($defs|Where-Object {-not $seen.ContainsKey($_.Id)}).Count){throw 'Missing technical catalog readings.'}
    if($r.CheckId -ceq 'WSA-NET-001') {
        $identities=@{};$counts=@{}
        foreach($row in @($r.Rows|Where-Object {$_.SettingId -clike 'Inventory.*'})) {
            if($row.State -cne 'OBSERVED'){throw 'Firewall inventory cannot be silently omitted.'}
            $kind=$row.SettingId.Split('.')[1]
            $batch=if($kind -cin @('ACTIVE','LOCAL','IPSEC','HYPERV')){ConvertTo-WinSecFirewallBatch $row.Value}else{ConvertTo-WinSecFirewallMetadataBatch $row.Value}
            foreach($item in $batch) {
                if($identities.ContainsKey($kind+'|'+$item.Id)){throw 'Repeated Firewall inventory identity.'};$identities[$kind+'|'+$item.Id]=$true
                if($kind -cin @('ACTIVE','LOCAL','IPSEC','HYPERV') -and $item.Store -cne $kind){throw 'Foreign Firewall inventory store.'}
                if($kind -cnotin @('ACTIVE','LOCAL','IPSEC','HYPERV') -and $item.Kind -cne $kind){throw 'Foreign Firewall metadata kind.'}
                $counts[$kind]++
            }
        }
        $map=@{ACTIVE='RulesActive';LOCAL='RulesLocal';IPSEC='IPsec';HYPERV='HyperVRules';DYNAMIC='DynamicKeywords';HVCREATOR='HyperVCreators';HVSETTING='HyperVSettings';HVPROFILE='HyperVProfiles'}
        foreach($kind in $map.Keys) {
            $count=@($r.Rows|Where-Object SettingId -CEQ ('Inventories.'+$map[$kind]+'Count'))[0]
            if($count.State -ceq 'OBSERVED' -and [long]$count.Value -ne [long]$counts[$kind]){throw 'Incomplete Firewall inventory.'}
        }
    }
    if(@($r.Rows|Where-Object State -CEQ NOT_APPLICABLE).Count) {
        $build=@($r.Rows|Where-Object SettingId -CEQ Platform.BuildNumber)
        $type=@($r.Rows|Where-Object SettingId -CEQ Platform.ProductType)
        $platform=@($r.Rows|Where-Object SettingId -CEQ Platform.State)
        if($r.CheckId -ceq 'WSA-NET-001') {
            $hyper=@($r.Rows|Where-Object SettingId -CEQ HyperVState)
            if($build.Count -ne 1 -or $build[0].State -cne 'OBSERVED' -or $build[0].Value -ne 22000 -or $type.Count -ne 1 -or
                $type[0].State -cne 'OBSERVED' -or $type[0].Value -ne 1 -or $hyper.Count -ne 1 -or $hyper[0].Value -cne 'NOT_APPLICABLE'){throw 'Firewall exclusion lacks observed platform support.'}
        } elseif($r.CheckId -cne 'WSA-SYS-003' -or $build.Count -ne 1 -or $build[0].State -cne 'OBSERVED' -or
            $build[0].Value -notin @(22000,22621,22631) -or $type.Count -ne 1 -or $type[0].Value -ne 1 -or
            $platform.Count -ne 1 -or $platform[0].Value -cne 'OBSERVED'){throw 'Technical exclusion lacks observed platform support.'}
    }
    return $r
}

function New-WinSecTechnicalReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Session,[Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$DeviceName,[Parameter(Mandatory)][string]$Hostname,[AllowNull()][object]$Context)
    $Session=Copy-WinSecResultData $Session
    if(-not (Test-WinSecResultSession $Session)){throw 'Invalid technical source session.'}
    $records=@($Session.ControlResults|Where-Object CheckId -CEQ $CheckId)
    if($records.Count -ne 1 -or $records[0].Status -ceq 'NOT_SELECTED'){throw 'Technical control was not executed.'}
    $control=$records[0];$evidence=(Get-WinSecTechnicalField $control Evidence).Value
    if($null -ne $evidence) {
        foreach($name in @('DeviceId','ScanId','CheckId')){if((Get-WinSecTechnicalField $evidence $name).Value -cne $control.$name){throw 'Foreign technical evidence.'}}
    }
    $defs=@(Get-WinSecTechnicalDefinitions $CheckId);$rows=New-Object 'Collections.Generic.List[object]'
    $readings=@(foreach($d in $defs){[pscustomobject]@{Definition=$d;Reading=(Get-WinSecTechnicalField $evidence $d.Id)}})
    if($CheckId -ceq 'WSA-SYS-001') {
        $rules=(Get-WinSecTechnicalField $evidence 'AttackSurfaceReduction.Rules').Value
        if($null -ne $rules) {
            if($rules -isnot [array] -or $rules.Count -gt 128){throw 'Invalid technical ASR inventory.'}
            foreach($rule in $rules) {
                $id=(Get-WinSecTechnicalField $rule RuleId).Value
                if($id -isnot [string] -or $id -cnotmatch '\A[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\z'){throw 'Invalid technical ASR rule.'}
                foreach($field in @('Mode','RawAction','EffectiveEnforcementConfirmed')) {
                    $d=Get-WinSecTechnicalRowDefinition ('AttackSurfaceReduction.Rules.'+$id+'.'+$field) $defs
                    $readings+=[pscustomobject]@{Definition=$d;Reading=(Get-WinSecTechnicalField $rule $field)}
                }
            }
        }
    }
    if($CheckId -ceq 'WSA-NET-001') {
        $numbers=@{}
        foreach($batch in @((Get-WinSecTechnicalField $evidence Batches).Value)) {
            if($null -eq $batch){continue}
            $store=$batch.Inventory
            if($store -cnotin @('ACTIVE','LOCAL','IPSEC','HYPERV','DYNAMIC','HVCREATOR','HVSETTING','HVPROFILE')){throw 'Unreviewed Firewall inventory.'}
            if(-not $numbers.ContainsKey($store)){$numbers[$store]=0};$numbers[$store]++
            $d=Get-WinSecTechnicalRowDefinition ('Inventory.'+$store+'.'+('{0:D4}' -f $numbers[$store])) $defs
            $readings+=[pscustomobject]@{Definition=$d;Reading=[pscustomobject]@{Exists=$true;Value=$batch.Json}}
        }
    }
    foreach($entry in $readings) {
        $d=$entry.Definition;$reading=$entry.Reading;$value=$null
        if($d.Id -ceq 'CollectionIssueCount') {
            $issues=Get-WinSecTechnicalField $evidence CollectionIssues
            if($issues.Exists -and $issues.Value -is [array]){$reading=[pscustomobject]@{Exists=$true;Value=$issues.Value.Count}}
        }
        if($CheckId -ceq 'WSA-NET-001' -and $d.Id -ceq 'CollectionIssueCodes') {
            $issues=Get-WinSecTechnicalField $evidence CollectionIssues
            if($issues.Exists -and $issues.Value -is [array]){$reading=[pscustomobject]@{Exists=$true;Value=if($issues.Value.Count){$issues.Value -join ','}else{'NONE'}}}
        }
        $state=if($reading.Exists){'UNKNOWN'}else{'NOT_COLLECTED'};$reason='UNAVAILABLE'
        if($null -ne $reading.Value) {
            try {$value=ConvertTo-WinSecTechnicalValue $reading.Value $d.Kind;$state='OBSERVED';$reason='NONE'}
            catch {if($d.Kind -cin @('firewallBatch','firewallMetadata')){throw};$value=$null;$state='UNKNOWN';$reason='INVALID_VALUE'}
        }
        if($d.StatePath) {
            $sourceState=(Get-WinSecTechnicalField $evidence $d.StatePath).Value
            if($sourceState -cin @('NOT_CONFIGURED','NOT_APPLICABLE','UNKNOWN')) {
                $state=$sourceState;$value=$null;$reason='UNAVAILABLE'
            }
        }
        if($reading.Value -is [string] -and $reading.Value -ceq 'UNKNOWN'){$state='UNKNOWN';$value=$null;$reason='UNAVAILABLE'}
        if($CheckId -ceq 'WSA-NET-001' -and $d.Id -cin @('Inventories.HyperVRulesCount','Inventories.HyperVCreatorsCount','Inventories.HyperVSettingsCount','Inventories.HyperVProfilesCount') -and
            (Get-WinSecTechnicalField $evidence HyperVState).Value -ceq 'NOT_APPLICABLE'){$state='NOT_APPLICABLE';$value=$null;$reason='UNAVAILABLE'}
        $rows.Add([pscustomobject]@{SettingId=$d.Id;Value=$value;State=$state;Reason=$reason})
    }
    $collected=(Get-WinSecTechnicalField $evidence CollectedAtUTC).Value
    if($null -eq $collected){$collected=$control.TimestampUTC}
    $profile='UNRESOLVED';$release='UNRESOLVED';$edition='UNRESOLVED'
    if($null -ne $Context) {
        if($Context.DeviceId -cne $Session.DeviceId -or $Context.ScanId -cne $Session.ScanId){throw 'Foreign technical Windows context.'}
        $profile=$Context.Profile;$release=$Context.OSRelease;$edition=$Context.Edition
    }
    ConvertTo-WinSecTechnicalReport ([pscustomobject]@{SchemaVersion='1.0.0';CatalogVersion='1.0.0';DeviceId=$Session.DeviceId;
        ScanId=$Session.ScanId;SectionKey=(Get-WinSecTechnicalControl $CheckId).SectionKey;CheckId=$CheckId;ScopeType=$Session.ScopeType;ScopeKey=$Session.ScopeKey;
        DeviceName=$DeviceName;Hostname=$Hostname;Profile=$profile;ObservedOSRelease=$release;ObservedEdition=$edition;
        StartedAtUTC=$Session.StartedAtUTC;CompletedAtUTC=$Session.CompletedAtUTC;CollectedAtUTC=$collected;
        GeneratedAtUTC=[datetime]::UtcNow.ToString('o');CollectorStatus=$control.Status;Rows=$rows.ToArray()})
}
