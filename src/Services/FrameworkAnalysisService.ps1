# Analyze saved, normalized readings. Never query Windows, execute remediation or rate security.
. (Join-Path $PSScriptRoot '../Core/FrameworkMappingEngine.ps1')
. (Join-Path $PSScriptRoot 'FrameworkService.ps1')

function Test-WinSecAnalysisText {
    param([AllowNull()][object]$Value)
    return ($Value -is [string] -and -not [string]::IsNullOrWhiteSpace($Value) -and $Value.Length -le 4096 -and $Value -notmatch '[\p{C}\p{Zl}\p{Zp}]')
}

function Test-WinSecAnalysisReferenceUrl {
    param([string]$Url,[string]$FrameworkId)
    if($Url -match '[\s()<>{}\[\]"\\`]' ){return $false}
    $uri=$null
    if(-not [uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or $uri.Port -ne 443 -or $uri.UserInfo){return $false}
    $hosts=switch($FrameworkId){'nist-csf' {@('www.nist.gov','nvlpubs.nist.gov')};'cis-controls' {@('www.cisecurity.org','cas.docs.cisecurity.org')};'mitre-attack' {@('attack.mitre.org')}}
    return $uri.DnsSafeHost -cin @($hosts)
}

function Get-WinSecFrameworkAnalysisCatalog {
    param([string]$ProjectRoot,[ValidateSet('nist-csf','cis-controls','mitre-attack')][string]$FrameworkId)
    $path=Join-Path $ProjectRoot 'config/framework-analysis.json'
    Assert-WinSecDeviceRemovalPath $ProjectRoot $path
    if((Get-Item -LiteralPath $path).Length -gt 131072){throw 'Analysis catalog too large.'}
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $rules=ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath $path -Raw -Encoding UTF8)
    Assert-WinSecConfigurationFields $rules @('schemaVersion','catalogVersion','interpretation','rules','sources')
    if($rules.schemaVersion -cne '1.0.0' -or $rules.catalogVersion -cnotin @('1.1.0','1.2.0','1.3.0','1.4.0','1.5.0') -or
        $rules.interpretation -cne 'REVIEW_WARNINGS_NOT_COMPLIANCE' -or $rules.rules -isnot [array] -or $rules.rules.Count -gt 200){throw 'Invalid warning catalog.'}
    $seen=@{}
    foreach($rule in $rules.rules) {
        Assert-WinSecConfigurationFields $rule @('id','checkId','setting','condition','criterion','title','recommendation')
        foreach($field in @('id','checkId','setting','condition','criterion','title','recommendation')) {
            if(-not (Test-WinSecAnalysisText $rule.$field)){throw 'Unsafe warning rule.'}
        }
        if($seen.ContainsKey($rule.id) -or $rule.id -cnotmatch '\A[A-Z0-9-]{1,64}\z' -or
            $rule.checkId -cnotin @(Get-WinSecTechnicalControls|ForEach-Object CheckId) -or
            $rule.condition -cnotin @('TRUE','FALSE','ALLOW','STOPPED','NOT_BLOCK','DISABLED','OFF','NOT_ENCRYPTED','NOT_NORMAL','ENABLED','RDP_NLA_OFF','RDP_NATIVE','RDP_LOW_ENCRYPTION','ONE','ZERO','PORTS_REVIEW')){throw 'Invalid warning predicate.'}
        if($rule.condition -ceq 'PORTS_REVIEW' -and ($rule.checkId -cne 'WSA-NET-004' -or $rule.setting -cnotin @('Inventory.TCP.*','Inventory.UDP.*'))){throw 'Invalid endpoint review predicate.'}
        if($rule.condition -clike 'RDP_*' -and ($rule.checkId -cne 'WSA-NET-003' -or
            ($rule.condition -ceq 'RDP_NATIVE' -and $rule.setting -cne 'Registry.Policy_SecurityLayer.Value') -or
            ($rule.condition -cne 'RDP_NATIVE' -and $rule.setting -cne 'Inventory.General'))){throw 'Invalid contextual RDP predicate.'}
        if($rule.setting -cne 'AttackSurfaceReduction.Rules.*.Mode' -and $rule.condition -cne 'PORTS_REVIEW') {
            $null=Get-WinSecTechnicalRowDefinition $rule.setting @(Get-WinSecTechnicalDefinitions $rule.checkId)
        }
        $seen[$rule.id]=$true
    }
    if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $hash){throw 'Warning catalog changed.'}
    $definition=@(Get-WinSecFrameworkDefinitions|Where-Object Id -CEQ $FrameworkId)[0]
    $fp=Join-Path $ProjectRoot ('config/frameworks/'+$definition.FileName)
    Assert-WinSecDeviceRemovalPath $ProjectRoot $fp
    if((Get-Item -LiteralPath $fp).Length -gt 1048576){throw 'Framework too large.'}
    $fh=(Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash
    $framework=ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath $fp -Raw -Encoding UTF8)
    $null=Test-WinSecFrameworkDocument $framework $FrameworkId
    if($framework.enabled -cne $true -or (Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash -cne $fh){throw 'Framework changed or disabled.'}
    [pscustomobject]@{Rules=$rules;RuleHash=$hash;Framework=$framework;FrameworkHash=$fh}
}

function Test-WinSecFrameworkWarning {
    param($Value,[string]$Condition)
    switch($Condition) {
        ZERO {return ($Value -is [ValueType] -and $Value -isnot [bool] -and $Value -eq 0)}
        ONE {return ($Value -is [ValueType] -and $Value -isnot [bool] -and $Value -eq 1)}
        ENABLED {return ($Value -is [string] -and $Value -ceq 'ENABLED')}
        TRUE {return ($Value -is [bool] -and $Value)}
        ALLOW {return ($Value -ceq 'ALLOW')}
        STOPPED {return ($Value -ceq 'STOPPED')}
        FALSE {return ($Value -is [bool] -and -not $Value)}
        NOT_BLOCK {return ($Value -in @('DISABLED','AUDIT','AUDITMODE','WARN','NOT_CONFIGURED','NOTCONFIGURED') -or
            ($Value -is [ValueType] -and $Value -in @(0,2,3,4,5,6)))}
        DISABLED {return ($Value -in @('DISABLED',0))}
        OFF {return ($Value -ceq 'OFF')}
        NOT_ENCRYPTED {return ($Value -in @('FULLY_DECRYPTED','ENCRYPTION_IN_PROGRESS','DECRYPTION_IN_PROGRESS','ENCRYPTION_PAUSED','DECRYPTION_PAUSED'))}
        NOT_NORMAL {return ($Value -in @('Passive','EDR Block Mode','SxS Passive Mode'))}
    }
    return $false
}

function New-WinSecFrameworkAnalysis {
    [CmdletBinding()]
    param([string]$ProjectRoot,[string]$DeviceId,[string]$DeviceName,[string]$ScopeType,[string]$ScopeKey,
        [ValidateSet('nist-csf','cis-controls','mitre-attack')][string]$FrameworkId,
        [AllowEmptyCollection()][object[]]$Sources=@(),[AllowEmptyCollection()][object[]]$Reports=@(),
        [scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    Assert-WinSecResultScope $ScopeType $ScopeKey
    if($ScopeType -cnotin @('SECTION','CONTROL') -or -not (Test-WinSecDeviceDisplayName $DeviceName) -or
        $DeviceId -cnotmatch '\Alocal:hw1-[a-f0-9]{64}\z'){throw 'Invalid analysis scope or device.'}
    $catalog=Get-WinSecFrameworkAnalysisCatalog $ProjectRoot $FrameworkId
    $sourcesCopy=Copy-WinSecResultData $Sources;$reportsCopy=@($Reports|ForEach-Object {ConvertTo-WinSecTechnicalReport $_})
    $seen=@{};$manifest=@();$readings=@();$rows=New-Object 'Collections.Generic.List[object]'
    foreach($source in $sourcesCopy) {
        Assert-WinSecConfigurationFields $source @('CheckId','ScanId','ScopeType','ScopeKey','CompletedAtUTC','Origin','PublicResult','CatalogVersion','ExpectedCheckIds')
        Assert-WinSecResultScope $source.ScopeType $source.ScopeKey
        if($seen.ContainsKey($source.CheckId) -or $source.Origin -cnotin @('LIVE','RECORDS')){throw 'Duplicate or invalid analysis source.'}
        $seen[$source.CheckId]=$true
        $public=$source.PublicResult
        # Roundtrip through the existing immutable public contract, including old sessions.
        $record=[pscustomobject]@{SchemaVersion='1.0.0';DeviceId=$public.DeviceId;ScanId=$public.ScanId;CatalogVersion=$source.CatalogVersion;
            ScopeType=$public.ScopeType;ScopeKey=$public.ScopeKey;ExpectedCheckIds=$source.ExpectedCheckIds;PublicResult=$public;ContentSha256=''}
        $record.ContentSha256=Get-WinSecPublicHistoryDigest $record
        $public=(ConvertFrom-WinSecPublicHistoryRecord $record).PublicResult
        if($public.DeviceId -cne $DeviceId -or $public.ScanId -cne $source.ScanId -or
            $public.ScopeType -cne $source.ScopeType -or $public.ScopeKey -cne $source.ScopeKey -or
            $public.CompletedAtUTC -cne $source.CompletedAtUTC -or $source.CheckId -cnotin $source.ExpectedCheckIds -or
            ($ScopeType -ceq 'CONTROL' -and $source.CheckId -cne $ScopeKey) -or
            @($public.ControlResults|Where-Object {$_.CheckId -ceq $source.CheckId -and $_.SectionKey -ceq (Get-WinSecTechnicalControl $source.CheckId).SectionKey}).Count -ne 1 -or
            ($ScopeType -ceq 'SECTION' -and $ScopeKey -cne (Get-WinSecTechnicalControl $source.CheckId).SectionKey)){throw 'Foreign analysis source.'}
        $manifest+=,[pscustomobject]@{CheckId=$source.CheckId;ScanId=$source.ScanId;ScopeType=$source.ScopeType;ScopeKey=$source.ScopeKey;
            CompletedAtUTC=$source.CompletedAtUTC;Origin=$source.Origin}
        $matches=@($reportsCopy|Where-Object {$_.CheckId -ceq $source.CheckId -and $_.ScanId -ceq $source.ScanId})
        if($matches.Count -gt 1){throw 'Ambiguous technical source.'}
        if($matches.Count) {
            $r=$matches[0]
            if($r.DeviceId -cne $DeviceId -or $r.ScopeType -cne $source.ScopeType -or $r.ScopeKey -cne $source.ScopeKey -or
                $r.CompletedAtUTC -cne $source.CompletedAtUTC){throw 'Foreign technical source.'}
            foreach($reading in $r.Rows){$readings+=,[pscustomobject]@{CheckId=$source.CheckId;ScanId=$source.ScanId;Reading=$reading}}
        }
    }
    foreach($report in $reportsCopy) {
        if(@($sourcesCopy|Where-Object {$_.CheckId -ceq $report.CheckId -and $_.ScanId -ceq $report.ScanId}).Count -ne 1){throw 'Unrequested technical report.'}
    }
    if($reportsCopy.Count -gt $sourcesCopy.Count){throw 'Unrequested technical report.'}
    $id=[guid]::NewGuid().ToString('N');$done=0;$total=$readings.Count+$sourcesCopy.Count
    $emit={if($null -ne $ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{DeviceId=$DeviceId;AnalysisId=$id;Completed=$done;Total=$total})}}
    $cancel={if($null -ne $CancellationAction){$answer=@(& $CancellationAction);if($answer.Count -ne 1 -or $answer[0] -isnot [bool]){throw 'Invalid analysis cancellation.'};return $answer[0]};return $false}
    $add={param($check,$scan,$setting,$criterion,$kind,$title,$observed,$recommendation)
        $refs=@(Get-WinSecFrameworkMappings -CheckId $check -CriterionId $criterion -Platform Windows -Frameworks @($catalog.Framework))
        $rows.Add([pscustomobject]@{Id=('{0:D2}' -f ($rows.Count+1));CheckId=$check;ScanId=$scan;SettingId=$setting;
            CriterionId=$criterion;State='WARNING';Kind=$kind;Title=$title;Observed=$observed;Recommendation=$recommendation;
            References=@($refs|Select-Object FrameworkId,FrameworkName,FrameworkVersion,ReferenceId,ReferenceType,Title,Url,Description,Recommendation)})
    }
    $null=& $emit
    foreach($entry in $readings) {
        if(& $cancel){return $null}
        $reading=$entry.Reading
        if($entry.CheckId -ceq 'WSA-NET-001' -and $reading.SettingId -clike 'Inventory.*') {
            $definition=Get-WinSecTechnicalRowDefinition $reading.SettingId @(Get-WinSecTechnicalDefinitions $entry.CheckId)
            # Inspect every normalized record without calling a Windows provider.
            if($definition.Kind -ceq 'firewallBatch') {
                $rules=ConvertTo-WinSecFirewallBatch $reading.Value;$broad=0
                foreach($rule in $rules) {
                    if(& $cancel){return $null}
                    if($rule.Store -ceq 'ACTIVE' -and $rule.Enabled -ceq $true -and $rule.Direction -ceq 'INBOUND' -and
                        $rule.Action -ceq 'ALLOW' -and $rule.Profile -cmatch 'PUBLIC|ANY' -and
                        $rule.RemoteAddress -ceq 'ANY' -and $rule.LocalPort -ceq 'ANY'){$broad++}
                }
                if($broad) {
                    $null=& $add $entry.CheckId $entry.ScanId $reading.SettingId 'WSA-FW-REVIEW-004' 'CONFIGURATION_REVIEW' `
                        'Broad inbound public exceptions require review' ($broad.ToString()+' enabled rules in '+$reading.SettingId+'; inspect their complete records in the technical Markdown.') `
                        'Review every rule in this batch, blocking-rule precedence, interfaces, application restrictions and approved business exceptions. An allow rule alone does not prove that traffic can reach a service.'
                }
            }
        }
        foreach($rule in @($catalog.Rules.rules|Where-Object {$_.checkId -ceq $entry.CheckId -and $reading.SettingId -clike $_.setting})) {
            if($rule.condition -ceq 'PORTS_REVIEW'){
                if($reading.State -ceq 'OBSERVED'){
                    $review=@()
                    foreach($endpoint in (ConvertTo-WinSecOpenPortsBatch $reading.Value)){
                        if(& $cancel){return $null}
                        if($endpoint.BindingScope -cne 'LOOPBACK'){$review+=,$endpoint}
                    }
                    if($review.Count){
                        $ports=(@($review.Port|Sort-Object -Unique) -join ', ')
                        $null=& $add $entry.CheckId $entry.ScanId $reading.SettingId $rule.criterion 'CONFIGURATION_REVIEW' $rule.title `
                            ($review.Count.ToString()+' non-loopback bindings; ports '+$ports+'. See '+$reading.SettingId+' in the technical Markdown for every endpoint.') $rule.recommendation
                    }
                }
                continue
            }
            if($entry.CheckId -ceq 'WSA-NET-003' -and $rule.condition -clike 'RDP_*'){
                # Listener warnings need effective host permission from this exact saved scan.
                $hostRows=@($readings|Where-Object {$_.CheckId -ceq $entry.CheckId -and $_.ScanId -ceq $entry.ScanId -and $_.Reading.SettingId -ceq 'HostEnabled'})
                $supportRows=@($readings|Where-Object {$_.CheckId -ceq $entry.CheckId -and $_.ScanId -ceq $entry.ScanId -and $_.Reading.SettingId -ceq 'HostSupport'})
                if($reading.State -ceq 'OBSERVED' -and $hostRows.Count -eq 1 -and $hostRows[0].Reading.State -ceq 'OBSERVED' -and $hostRows[0].Reading.Value -ceq $true -and
                    $supportRows.Count -eq 1 -and $supportRows[0].Reading.Value -ceq 'SUPPORTED'){
                    # The WMI getter documentation and setter use different numeric labels.
                    # Never reinterpret that raw enum as a registry value. A configured
                    # native-only machine policy is independent, explicit evidence.
                    if($rule.condition -ceq 'RDP_NATIVE'){
                        if($reading.Value -eq 0){$null=& $add $entry.CheckId $entry.ScanId $reading.SettingId $rule.criterion 'CONFIGURATION_REVIEW' $rule.title 'Machine SecurityLayer policy=0 (native RDP)' $rule.recommendation}
                        continue
                    }
                    $nativePolicy=@($readings|Where-Object {$_.CheckId -ceq $entry.CheckId -and $_.ScanId -ceq $entry.ScanId -and $_.Reading.SettingId -ceq 'Registry.Policy_SecurityLayer.Value'})
                    if($rule.condition -ceq 'RDP_LOW_ENCRYPTION' -and ($nativePolicy.Count -ne 1 -or $nativePolicy[0].Reading.State -cne 'OBSERVED' -or $nativePolicy[0].Reading.Value -ne 0)){continue}
                    $batch=ConvertTo-WinSecRdpInventory $reading.Value
                    foreach($item in $batch.Items){
                        if(& $cancel){return $null}
                        $field=switch($rule.condition){RDP_NLA_OFF {'UserAuthenticationRequired'};RDP_LOW_ENCRYPTION {'MinEncryptionLevel'}}
                        $v=$item.Values.$field
                        $warn=($null -ne $v -and $(if($rule.condition -ceq 'RDP_LOW_ENCRYPTION'){$v -in @(1,2)}else{$v -eq 0}))
                        if($warn){$null=& $add $entry.CheckId $entry.ScanId $reading.SettingId $rule.criterion 'CONFIGURATION_REVIEW' $rule.title `
                            ('Listener '+$item.Id+'; '+$field+'='+$v) $rule.recommendation}
                    }
                }
                continue
            }
            if($reading.State -ceq 'OBSERVED' -and (Test-WinSecFrameworkWarning $reading.Value $rule.condition)) {
                $null=& $add $entry.CheckId $entry.ScanId $reading.SettingId $rule.criterion 'CONFIGURATION_REVIEW' $rule.title `
                    (ConvertTo-Json -InputObject $reading.Value -Compress) $rule.recommendation
            }
        }
        $done++;$null=& $emit
    }
    foreach($source in $sourcesCopy) {
        if(& $cancel){return $null}
        foreach($finding in @($source.PublicResult.Findings|Where-Object {$_.CheckId -ceq $source.CheckId -and $_.Kind -ceq 'CONFIGURATION_DEVIATION'})) {
            $g=$finding.Guidance
            if($null -eq $g -or $finding.EvaluationStatus -cne 'FAIL'){continue}
            if(@($rows|Where-Object {$_.CheckId -ceq $source.CheckId -and $_.CriterionId -ceq $g.CriterionId}).Count){continue}
            $null=& $add $source.CheckId $source.ScanId $g.CriterionId $g.CriterionId 'VERIFIED_DEVIATION' $g.CriterionTitle 'Deviation recorded at collection' $g.Recommendation
        }
        $done++;$null=& $emit
    }
    $unknown=@($readings|Where-Object {$_.Reading.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')}).Count
    # Inventories are typed containers: an observed container can still hold
    # unresolved informational readings. Count such containers as limited too.
    foreach($entry in @($readings|Where-Object {$_.CheckId -ceq 'WSA-NET-003' -and $_.Reading.SettingId -clike 'Inventory.*' -and $_.Reading.State -ceq 'OBSERVED'})){
        if(& $cancel){return $null}
        $batch=ConvertTo-WinSecRdpInventory $entry.Reading.Value
        $excluded=if($null -ne $batch.PSObject.Properties['NotApplicableFields']){@($batch.NotApplicableFields)}else{@()}
        $limited=$false
        foreach($item in $batch.Items){foreach($field in $item.Values.PSObject.Properties){if($null -eq $field.Value -and $field.Name -cnotin $excluded){$limited=$true}}}
        if($limited){$unknown++}
    }
    foreach($entry in @($readings|Where-Object {$_.CheckId -ceq 'WSA-NET-004' -and $_.Reading.SettingId -clike 'Inventory.*' -and $_.Reading.State -ceq 'OBSERVED'})){
        if(& $cancel){return $null}
        $endpoints=ConvertTo-WinSecOpenPortsBatch $entry.Reading.Value
        if((Get-WinSecOpenPortsCounts $endpoints).UnknownFields -gt 0){$unknown++}
    }
    $result=[pscustomobject]@{SchemaVersion='1.0.0';AnalysisId=$id;DeviceId=$DeviceId;DeviceName=$DeviceName;
        ScopeType=$ScopeType;ScopeKey=$ScopeKey;FrameworkId=$FrameworkId;FrameworkVersion=$catalog.Framework.frameworkVersion;
        FrameworkSha256=$catalog.FrameworkHash;RuleCatalogVersion=$catalog.Rules.catalogVersion;RuleCatalogSha256=$catalog.RuleHash;
        GeneratedAtUTC=[datetime]::UtcNow.ToString('o');Sources=$manifest;Rows=$rows.ToArray();
        ReadingCount=$readings.Count;UnknownReadingCount=$unknown;MissingTechnicalCheckIds=@($sourcesCopy|Where-Object {
            $check=$_.CheckId;@($reportsCopy|Where-Object CheckId -CEQ $check).Count -eq 0}|ForEach-Object CheckId);ContentSha256=''}
    $result.ContentSha256=Get-WinSecFrameworkAnalysisDigest $result
    return Assert-WinSecFrameworkAnalysis $result $DeviceId $ScopeType $ScopeKey
}

function Get-WinSecFrameworkAnalysisDigest {
    param($Analysis)
    $copy=Copy-WinSecResultData $Analysis;$copy.ContentSha256=''
    Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson $copy)
}

function Assert-WinSecFrameworkAnalysis {
    param($Analysis,[string]$DeviceId,[string]$ScopeType,[string]$ScopeKey)
    $a=Copy-WinSecResultData $Analysis
    Assert-WinSecConfigurationFields $a @('SchemaVersion','AnalysisId','DeviceId','DeviceName','ScopeType','ScopeKey','FrameworkId',
        'FrameworkVersion','FrameworkSha256','RuleCatalogVersion','RuleCatalogSha256','GeneratedAtUTC','Sources','Rows','ReadingCount',
        'UnknownReadingCount','MissingTechnicalCheckIds','ContentSha256')
    if($a.GeneratedAtUTC -is [datetime]){$a.GeneratedAtUTC=$a.GeneratedAtUTC.ToUniversalTime().ToString('o')}
    $null=ConvertTo-WinSecResultUtc $a.GeneratedAtUTC GeneratedAtUTC
    $sourceIds=@{}
    foreach($source in $a.Sources) {
        Assert-WinSecConfigurationFields $source @('CheckId','ScanId','ScopeType','ScopeKey','CompletedAtUTC','Origin')
        if($source.CompletedAtUTC -is [datetime]){$source.CompletedAtUTC=$source.CompletedAtUTC.ToUniversalTime().ToString('o')}
        $null=ConvertTo-WinSecResultUtc $source.CompletedAtUTC CompletedAtUTC
        Assert-WinSecResultScope $source.ScopeType $source.ScopeKey
        if($source.CheckId -isnot [string] -or $sourceIds.ContainsKey($source.CheckId) -or $source.Origin -cnotin @('LIVE','RECORDS') -or -not (Test-WinSecTargetIdentifier $source.ScanId) -or
            $source.CheckId -cnotin @(Get-WinSecTechnicalControls|ForEach-Object CheckId) -or
            ($ScopeType -ceq 'CONTROL' -and $source.CheckId -cne $ScopeKey) -or
            ($ScopeType -ceq 'SECTION' -and $ScopeKey -cne (Get-WinSecTechnicalControl $source.CheckId).SectionKey) -or
            ($source.ScopeType -ceq 'CONTROL' -and $source.ScopeKey -cne $source.CheckId) -or
            ($source.ScopeType -ceq 'SECTION' -and $source.ScopeKey -cne (Get-WinSecTechnicalControl $source.CheckId).SectionKey)){throw 'Invalid framework source manifest.'}
        $sourceIds[$source.CheckId]=$true
    }
    if($a.SchemaVersion -cne '1.0.0' -or $a.AnalysisId -isnot [string] -or $a.AnalysisId -cnotmatch '\A[a-f0-9]{32}\z' -or $a.DeviceId -isnot [string] -or
        $a.DeviceId -cne $DeviceId -or $a.ScopeType -cne $ScopeType -or $a.ScopeKey -cne $ScopeKey -or
        $a.ScopeType -cnotin @('SECTION','CONTROL') -or $a.FrameworkId -cnotin @('nist-csf','cis-controls','mitre-attack') -or $a.Sources -isnot [array] -or $a.Sources.Count -gt 14 -or
        $a.Rows -isnot [array] -or $a.Rows.Count -gt 2000 -or $a.MissingTechnicalCheckIds -isnot [array] -or
        -not (Test-WinSecDeviceDisplayName $a.DeviceName) -or $a.ContentSha256 -cne (Get-WinSecFrameworkAnalysisDigest $a)){throw 'Invalid or changed framework view.'}
    Assert-WinSecResultScope $a.ScopeType $a.ScopeKey
    foreach($field in @('FrameworkVersion','RuleCatalogVersion')){if(-not (Test-WinSecResultText $a.$field)){throw 'Invalid analysis version.'}}
    foreach($field in @('FrameworkSha256','RuleCatalogSha256','ContentSha256')){if($a.$field -isnot [string] -or $a.$field -cnotmatch '\A[A-F0-9]{64}\z'){throw 'Invalid analysis digest.'}}
    foreach($field in @('ReadingCount','UnknownReadingCount')) {
        if(($a.$field -isnot [int] -and $a.$field -isnot [long]) -or $a.$field -lt 0 -or $a.$field -gt 8400){throw 'Invalid analysis count.'}
    }
    if($a.UnknownReadingCount -gt $a.ReadingCount){throw 'Invalid analysis coverage.'}
    foreach($missing in $a.MissingTechnicalCheckIds){if($missing -isnot [string] -or -not $sourceIds.ContainsKey($missing)){throw 'Foreign missing snapshot.'}}
    $rowIds=@{}
    foreach($row in $a.Rows) {
        Assert-WinSecConfigurationFields $row @('Id','CheckId','ScanId','SettingId','CriterionId','State','Kind','Title','Observed','Recommendation','References')
        if(@($a.Sources|Where-Object {$_.CheckId -ceq $row.CheckId -and $_.ScanId -ceq $row.ScanId}).Count -ne 1 -or
            $row.Id -isnot [string] -or $rowIds.ContainsKey($row.Id) -or $row.Id -cnotmatch '\A[0-9]{2,4}\z' -or
            $row.State -cne 'WARNING' -or $row.Kind -cnotin @('CONFIGURATION_REVIEW','VERIFIED_DEVIATION') -or $row.References -isnot [array]){throw 'Mixed framework finding.'}
        $rowIds[$row.Id]=$true
        foreach($field in @('Id','CheckId','ScanId','SettingId','CriterionId','State','Kind','Title','Observed','Recommendation')) {
            if(-not (Test-WinSecAnalysisText $row.$field)){throw 'Unsafe framework finding.'}
        }
        foreach($ref in $row.References){
            Assert-WinSecConfigurationFields $ref @('FrameworkId','FrameworkName','FrameworkVersion','ReferenceId','ReferenceType','Title','Url','Description','Recommendation')
            if($ref.FrameworkId -cne $a.FrameworkId -or $ref.FrameworkVersion -cne $a.FrameworkVersion){throw 'Foreign framework reference.'}
            foreach($p in $ref.PSObject.Properties){if(-not (Test-WinSecAnalysisText $p.Value)){throw 'Unsafe framework reference.'}}
            if(-not (Test-WinSecAnalysisReferenceUrl $ref.Url $a.FrameworkId)){throw 'Unsafe framework URL.'}
        }
    }
    return $a
}
