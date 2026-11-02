# Versioned analysis of the reviewed 2.1 transport, not conversion into candidate 2.0 captures.
. (Join-Path $PSScriptRoot 'TechnicalFrameworkAnalysis.ps1')

function Read-WinSecProjectionFrameworkSource {
    param($Coordinator,$Source,[scriptblock]$CancellationAction)
    $device=$Source.PublicResult.DeviceId;$scan=$Source.ScanId;$check=$Source.CheckId
    $key=(Get-WinSecScanSessionKey $device $scan)+'|'+$check
    if(-not $Coordinator.TechnicalLocations.ContainsKey($key)){
        $report=Read-WinSecTechnicalReport $Coordinator.ProjectRoot $device $scan $check
        return [pscustomobject]@{Report=$report;Snapshot=$null}
    }
    $reference=$Coordinator.TechnicalLocations[$key]
    Assert-WinSecSnapshotFields $reference @('Identity','CollectedAtUTC','CatalogSha256');Assert-WinSecSnapshotIdentity $reference.Identity
    if($reference.Identity.DeviceId -cne $device -or $reference.Identity.ScanId -cne $scan -or $reference.Identity.CheckId -cne $check -or
        $reference.Identity.ScopeType -cne $Source.ScopeType -or $reference.Identity.ScopeKey -cne $Source.ScopeKey){throw 'Foreign projected analysis reference.'}
    $catalog=Get-WinSecProjectionCatalog $check
    if($reference.CatalogSha256 -cne (Get-WinSecSnapshotCatalogHash $catalog)){throw 'Changed projected analysis catalog.'}
    $pair=Read-WinSecTechnicalSnapshotPair $Coordinator.ProjectRoot $reference.Identity $reference.CollectedAtUTC $catalog $reference.CatalogSha256 -CancellationAction $CancellationAction
    if($pair.PublicationStatus -cne 'COMMITTED'){throw 'Projected analysis requires a committed pair.'}
    [pscustomobject]@{Report=(ConvertFrom-WinSecProjectionSnapshot $pair.Snapshot);Snapshot=$pair.Snapshot}
}

function Get-WinSecProjectedReadingReview {
    param($Catalog,[object[]]$Reports,[object[]]$Snapshots,[object[]]$Sources,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    $clock=[Diagnostics.Stopwatch]::StartNew();$ledger=New-Object 'Collections.Generic.List[object]';$manifest=New-Object 'Collections.Generic.List[object]'
    $Reports=@($Reports|ForEach-Object {ConvertTo-WinSecTechnicalReport $_});$Sources=Copy-WinSecResultData $Sources
    $Snapshots=Copy-WinSecTechnicalAnalysisData $Snapshots -CancellationAction $CancellationAction
    $eligible=@{};$rules=@();$completed=0;$total=0;$budget=@{Bytes=0}
    $additional=New-Object 'Collections.Generic.List[object]';$supplemental=New-Object 'Collections.Generic.List[object]'
    foreach($report in $Reports){$total+=$report.Rows.Count}
    $emit={if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Phase='Classifying saved readings';Completed=$completed;Total=$total})}}
    $null=& $emit
    foreach($rule in $Catalog.Rules.rules){
        $refs=@(Get-WinSecFrameworkMappings -CheckId $rule.checkId -CriterionId $rule.criterion -Platform Windows -Frameworks @($Catalog.Framework))
        if($refs.Count){$rules+=,$rule}
    }
    foreach($report in $Reports){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $r=ConvertTo-WinSecTechnicalReport $report;$source=@($Sources|Where-Object {$_.CheckId -ceq $r.CheckId -and $_.ScanId -ceq $r.ScanId})
        if($source.Count -ne 1 -or $source[0].PublicResult.DeviceId -cne $r.DeviceId -or $source[0].ScopeType -cne $r.ScopeType -or $source[0].ScopeKey -cne $r.ScopeKey -or $source[0].CompletedAtUTC -cne $r.CompletedAtUTC){throw 'Foreign projected reading report.'}
        $matches=@($Snapshots|Where-Object {$_.Identity.CheckId -ceq $r.CheckId -and $_.Identity.ScanId -ceq $r.ScanId})
        if($matches.Count -gt 1){throw 'Ambiguous projected snapshot.'}
        $identity=$null;$schema='LEGACY';$catalogId=$null;$catalogVersion=$null;$catalogHash=$null;$collector=$null;$snapshotHash=$null
        $platform=[pscustomobject]@{Version=$null;BuildNumber=$null;OperatingSystemSKU=$null;ProductType=$null}
        if($matches.Count){
            $s=$matches[0];$cat=Get-WinSecProjectionCatalog $r.CheckId;$hash=Get-WinSecSnapshotCatalogHash $cat
            Assert-WinSecTechnicalSnapshot $s $cat $hash $s.Identity -CancellationAction $CancellationAction
            if((Get-WinSecTechnicalAnalysisHash (ConvertFrom-WinSecProjectionSnapshot $s)) -cne (Get-WinSecTechnicalAnalysisHash $r)){throw 'Projected report contradicts its saved snapshot.'}
            $identity=$s.Identity;$schema=$s.SchemaVersion;$catalogId=$s.CatalogId;$catalogVersion=$s.CatalogVersion;$catalogHash=$hash;$collector=$s.CollectorVersion;$snapshotHash=Get-WinSecTechnicalAnalysisHash $s
            foreach($p in $platform.PSObject.Properties){$platform.($p.Name)=$s.Platform.($p.Name)}
        }else{
            foreach($p in $platform.PSObject.Properties){$row=@($r.Rows|Where-Object SettingId -CEQ ('Platform.'+$p.Name));if($row.Count -eq 1 -and $row[0].State -ceq 'OBSERVED'){$platform.($p.Name)=$row[0].Value}}
        }
        $known=($null -ne $platform.BuildNumber -and $platform.BuildNumber -ge 22000 -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1)
        # These existing reviewed projections never stored platform rows. Their generic
        # property semantics are version independent; retain warnings without inventing OS metadata.
        $valueSemantics=($r.CheckId -cin @('WSA-SYS-001','WSA-SYS-002'))
        $applicable=($known -or $valueSemantics)
        $basis=if($known){'OBSERVED_WINDOWS11_CONTEXT'}elseif($valueSemantics){'REVIEWED_VALUE_SEMANTICS'}else{'UNRESOLVED_CONTEXT'}
        $eligible[$r.CheckId]=$applicable
        $extraRule=$null;$extraReady=$false
        if($r.CheckId -ceq 'WSA-NET-002' -and $Catalog.Framework.frameworkId -ceq 'mitre-attack'){
            $extraRule=@((Get-WinSecTechnicalFrameworkRuleCatalog).Rules|Where-Object Id -CEQ 'TF-SMB-002')[0]
            $extraReady=$known;$warning=$true
            foreach($required in $extraRule.Required){
                $input=@($r.Rows|Where-Object SettingId -CEQ $required.FieldId)
                if($input.Count -ne 1 -or $input[0].State -cne 'OBSERVED' -or $input[0].Value -isnot [bool]){$extraReady=$false}
                elseif($input[0].Value -cne $required.Expected){$warning=$false}
            }
            $outcome=if(-not $extraReady){'UNRESOLVED_RULE'}elseif($warning){'WARNING'}else{'EVALUATED'}
            $supplemental.Add([pscustomobject]@{CheckId=$r.CheckId;ScanId=$r.ScanId;RuleId=$extraRule.Id;RuleVersion=$extraRule.Version;RuleSha256=(Get-WinSecTechnicalAnalysisHash $extraRule);
                ReferenceId='M1037';ReferenceVersion='1.2';Outcome=$outcome})
            if($extraReady -and $warning){
                $additional.Add([pscustomobject]@{Id='00';CheckId=$r.CheckId;ScanId=$r.ScanId;SettingId='Server.RequireSecuritySignature';CriterionId=$extraRule.Id;State='WARNING';Kind=$extraRule.ResultKind;
                    Title=$extraRule.Title;Observed='SMB2/3 enabled; required signing=false; global encryption=false. Per-share settings, traffic and relay feasibility were not observed.';
                    Recommendation=($extraRule.Recommendation+' Technical basis: '+$extraRule.TechnicalUrl);References=@([pscustomobject]@{
                        FrameworkId='mitre-attack';FrameworkName=$Catalog.Framework.name;FrameworkVersion=$Catalog.Framework.frameworkVersion;ReferenceId='M1037';ReferenceType='Mitigation';
                        Title='Filter Network Traffic (reviewed object v1.2)';Url=$extraRule.Relations[0].Url;Description=$extraRule.Relations[0].Context;Recommendation=$extraRule.Recommendation})})
            }
        }
        $firewallEligible=($r.CheckId -ceq 'WSA-NET-001' -and @(Get-WinSecFrameworkMappings -CheckId $r.CheckId -CriterionId 'WSA-FW-REVIEW-004' -Platform Windows -Frameworks @($Catalog.Framework)).Count -gt 0)
        $manifest.Add([pscustomobject]@{CheckId=$r.CheckId;ScanId=$r.ScanId;ScopeType=$r.ScopeType;ScopeKey=$r.ScopeKey;Origin=$source[0].Origin;
            Identity=$identity;SnapshotSchemaVersion=$schema;CatalogId=$catalogId;CatalogVersion=$catalogVersion;CatalogSha256=$catalogHash;CollectorVersion=$collector;SnapshotSha256=$snapshotHash;
            ReportSha256=(Get-WinSecTechnicalAnalysisHash $r);CollectedAtUTC=$r.CollectedAtUTC;CompletedAtUTC=$r.CompletedAtUTC;Platform=$platform;ApplicabilityBasis=$basis})
        $definitions=@(Get-WinSecTechnicalDefinitions $r.CheckId $r.CatalogVersion)
        foreach($row in $r.Rows){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $matched=@($rules|Where-Object {$_.checkId -ceq $r.CheckId -and $row.SettingId -clike $_.setting})
            $extraField=($null -ne $extraRule -and $row.SettingId -cin @($extraRule.Required.FieldId));$rowReady=$applicable
            if($extraField -and -not $extraReady){$rowReady=$false}
            $kind=(Get-WinSecTechnicalRowDefinition $row.SettingId $definitions).Kind
            $add={param([string]$record,[string]$field,[string]$state,[bool]$evaluative)
                Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
                $treatment=if($state -cne 'OBSERVED'){$state}elseif(-not $evaluative){'INFORMATIVE_NO_RULE'}elseif($rowReady){'EVALUATED'}else{'UNRESOLVED_RULE'}
                $entry=[pscustomobject]@{CheckId=$r.CheckId;ScanId=$r.ScanId;SettingId=$row.SettingId;RecordId=$record;Field=$field;State=$state;Treatment=$treatment}
                $budget.Bytes+=[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $entry -Compress))+192
                if($budget.Bytes -gt (Get-WinSecSnapshotSpecification).MaxDocumentBytes){throw 'Projected reading review memory budget exceeded.'}
                $ledger.Add($entry)
            }
            # Container metadata is informational. Typed native fields are classified separately below.
            $container=($kind -cin @('rdpInventory','portsBatch','networkBatch','firewallBatch','firewallMetadata','identityMembers'))
            $null=& $add 'Row' 'Value' $row.State (($matched.Count -gt 0 -or $extraField) -and -not $container)
            if(-not $container -or $row.State -cne 'OBSERVED'){$completed++;$null=& $emit;continue}
            $items=@();$excluded=@();$valuesProperty=$false
            switch($kind){
                rdpInventory {$b=ConvertTo-WinSecRdpInventory $row.Value;$items=@($b.Items);$excluded=@($b.NotApplicableFields);$valuesProperty=$true}
                networkBatch {$b=ConvertTo-WinSecNetworkConfigurationBatch $row.Value;$items=@($b.Items);$valuesProperty=$true}
                portsBatch {$items=ConvertTo-WinSecOpenPortsBatch $row.Value}
                firewallBatch {$items=ConvertTo-WinSecFirewallBatch $row.Value}
                firewallMetadata {$items=ConvertTo-WinSecFirewallMetadataBatch $row.Value;$valuesProperty=$true}
                identityMembers {$items=ConvertTo-WinSecIdentityMembers $row.Value}
            }
            $index=0
            foreach($item in $items){
                $values=if($valuesProperty){$item.Values}else{$item}
                foreach($p in $values.PSObject.Properties){
                    $state=if($null -eq $p.Value -and $p.Name -cin $excluded){'NOT_APPLICABLE'}elseif($null -eq $p.Value -or ($p.Value -is [string] -and $p.Value -ceq 'UNKNOWN')){'UNKNOWN'}else{'OBSERVED'}
                    $evaluative=$false
                    foreach($rule in $matched){
                        $fields=switch($rule.condition){PORTS_REVIEW {@('BindingScope','Port')};NETWORK_REVIEW {@('IPEnabled','TcpipNetbiosOptions','NetworkCategory')};RDP_NLA_OFF {@('UserAuthenticationRequired')};RDP_LOW_ENCRYPTION {@('MinEncryptionLevel')};default {@()}}
                        if($p.Name -cin $fields){$evaluative=$true}
                    }
                    if($kind -ceq 'firewallBatch' -and $p.Name -cin @('Store','Enabled','Direction','Action','Profile','RemoteAddress','LocalPort')){
                        $evaluative=$firewallEligible
                    }
                    $null=& $add ('Item'+$index) $p.Name $state $evaluative
                };$index++
            }
            $completed++;$null=& $emit
        }
    }
    foreach($s in $Snapshots){if(@($Reports|Where-Object {$_.CheckId -ceq $s.Identity.CheckId -and $_.ScanId -ceq $s.Identity.ScanId}).Count -ne 1){throw 'Unrequested projected analysis snapshot.'}}
    $counts=[ordered]@{};foreach($t in @('EVALUATED','INFORMATIVE_NO_RULE','UNRESOLVED_RULE','UNKNOWN','ERROR','NOT_COLLECTED','NOT_CONFIGURED','NOT_APPLICABLE')){$counts[$t]=@($ledger|Where-Object Treatment -CEQ $t).Count}
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    [pscustomobject]@{Ledger=$ledger.ToArray();Eligible=$eligible;AdditionalRows=$additional.ToArray();Summary=[pscustomobject]@{ArtifactType='WinSec.ProjectedReadingReview';SchemaVersion='1.0.0';EngineVersion='1.1.0';
        ReadingCount=$ledger.Count;Treatments=[pscustomobject]$counts;Sources=$manifest.ToArray();SupplementalRules=$supplemental.ToArray();LedgerSha256=(Get-WinSecTechnicalAnalysisHash $ledger.ToArray());Assessment='LIMITED_NOT_COMPLIANCE'}}
}

function New-WinSecProjectionFrameworkAnalysis {
    param([string]$ProjectRoot,[string]$DeviceId,[string]$DeviceName,[string]$ScopeType,[string]$ScopeKey,[string]$FrameworkId,
        [object[]]$Sources=@(),[object[]]$Reports=@(),[object[]]$Snapshots=@(),[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    $catalog=Get-WinSecFrameworkAnalysisCatalog $ProjectRoot $FrameworkId
    try{
        $review=Get-WinSecProjectedReadingReview $catalog $Reports $Snapshots $Sources -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
        $a=New-WinSecFrameworkAnalysis -ProjectRoot $ProjectRoot -DeviceId $DeviceId -DeviceName $DeviceName -ScopeType $ScopeType -ScopeKey $ScopeKey -FrameworkId $FrameworkId `
            -Sources $Sources -Reports $Reports -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback -MappedRulesOnly
        if($null -eq $a){return $null}
        $a.Rows=@($a.Rows|Where-Object {$review.Eligible.ContainsKey($_.CheckId) -and $review.Eligible[$_.CheckId]})
        $a.Rows+=@($review.AdditionalRows)
        for($i=0;$i -lt $a.Rows.Count;$i++){$a.Rows[$i].Id='{0:D2}' -f ($i+1)}
        $a.SchemaVersion='1.1.0';$a|Add-Member ReadingReview $review.Summary
        $a.ContentSha256=Get-WinSecFrameworkAnalysisDigest $a
        $a=Assert-WinSecFrameworkAnalysis $a $DeviceId $ScopeType $ScopeKey
        [pscustomobject]@{Analysis=$a;Ledger=$review.Ledger}
    }catch [OperationCanceledException]{return $null}
}

function Assert-WinSecProjectedReadingSummary {
    param($Summary,$Analysis)
    Assert-WinSecSnapshotFields $Summary @('ArtifactType','SchemaVersion','EngineVersion','ReadingCount','Treatments','Sources','SupplementalRules','LedgerSha256','Assessment')
    $types=@('EVALUATED','INFORMATIVE_NO_RULE','UNRESOLVED_RULE','UNKNOWN','ERROR','NOT_COLLECTED','NOT_CONFIGURED','NOT_APPLICABLE')
    Assert-WinSecSnapshotFields $Summary.Treatments $types;$total=0
    foreach($t in $types){if(-not(Test-WinSecSnapshotUInt $Summary.Treatments.$t)){throw 'Invalid projected coverage count.'};$total+=$Summary.Treatments.$t}
    if($Summary.ArtifactType -cne 'WinSec.ProjectedReadingReview' -or $Summary.SchemaVersion -cne '1.0.0' -or $Summary.EngineVersion -cne '1.1.0' -or $Summary.Assessment -cne 'LIMITED_NOT_COMPLIANCE' -or
        -not(Test-WinSecSnapshotUInt $Summary.ReadingCount) -or $Summary.ReadingCount -ne $total -or $Summary.LedgerSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or $Summary.Sources -isnot [array]){throw 'Invalid projected reading summary.'}
    $seen=@{}
    foreach($s in $Summary.Sources){
        Assert-WinSecSnapshotFields $s @('CheckId','ScanId','ScopeType','ScopeKey','Origin','Identity','SnapshotSchemaVersion','CatalogId','CatalogVersion','CatalogSha256','CollectorVersion','SnapshotSha256','ReportSha256','CollectedAtUTC','CompletedAtUTC','Platform','ApplicabilityBasis')
        $matches=@($Analysis.Sources|Where-Object {$_.CheckId -ceq $s.CheckId -and $_.ScanId -ceq $s.ScanId -and $_.ScopeType -ceq $s.ScopeType -and $_.ScopeKey -ceq $s.ScopeKey -and $_.Origin -ceq $s.Origin -and $_.CompletedAtUTC -ceq $s.CompletedAtUTC})
        if($matches.Count -ne 1 -or $seen.ContainsKey($s.CheckId) -or $s.ReportSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or $s.ScanId -ceq $Analysis.AnalysisId){throw 'Foreign projected source summary.'};$seen[$s.CheckId]=$true
        $null=ConvertTo-WinSecResultUtc $s.CollectedAtUTC CollectedAtUTC
        Assert-WinSecSnapshotFields $s.Platform @('Version','BuildNumber','OperatingSystemSKU','ProductType')
        foreach($p in @('BuildNumber','OperatingSystemSKU','ProductType')){if($null -ne $s.Platform.$p -and -not(Test-WinSecSnapshotUInt $s.Platform.$p)){throw 'Invalid projected platform.'}}
        if($null -ne $s.Platform.Version -and $s.Platform.Version -cne ('10.0.'+$s.Platform.BuildNumber)){throw 'Conflicting projected platform.'}
        $known=($null -ne $s.Platform.BuildNumber -and $s.Platform.BuildNumber -ge 22000 -and $null -ne $s.Platform.OperatingSystemSKU -and $s.Platform.ProductType -eq 1)
        $basis=if($known){'OBSERVED_WINDOWS11_CONTEXT'}elseif($s.CheckId -cin @('WSA-SYS-001','WSA-SYS-002')){'REVIEWED_VALUE_SEMANTICS'}else{'UNRESOLVED_CONTEXT'}
        if($s.ApplicabilityBasis -cne $basis){throw 'Invented projected applicability.'}
        if($s.SnapshotSchemaVersion -ceq '2.1.0'){
            Assert-WinSecSnapshotIdentity $s.Identity;$cat=Get-WinSecProjectionCatalog $s.CheckId
            if($s.Identity.DeviceId -cne $Analysis.DeviceId -or $s.Identity.CheckId -cne $s.CheckId -or $s.Identity.ScanId -cne $s.ScanId -or $s.Identity.ScopeType -cne $s.ScopeType -or $s.Identity.ScopeKey -cne $s.ScopeKey -or $s.Identity.SnapshotId -ceq $Analysis.AnalysisId -or
                $s.CatalogId -cne $cat.CatalogId -or $s.CatalogVersion -cne $cat.CatalogVersion -or $s.CatalogSha256 -cne (Get-WinSecSnapshotCatalogHash $cat) -or $s.CollectorVersion -cne '0.9.0' -or $s.SnapshotSha256 -cnotmatch '\A[A-F0-9]{64}\z'){throw 'Invalid projected source provenance.'}
        }elseif($s.SnapshotSchemaVersion -cne 'LEGACY' -or $null -ne $s.Identity -or $null -ne $s.SnapshotSha256 -or $null -ne $s.CatalogId -or $null -ne $s.CatalogVersion -or $null -ne $s.CatalogSha256 -or $null -ne $s.CollectorVersion){throw 'Invented legacy snapshot identity.'}
    }
    foreach($source in $Analysis.Sources){if($source.CheckId -cnotin $Analysis.MissingTechnicalCheckIds -and -not $seen.ContainsKey($source.CheckId)){throw 'Missing projected source provenance.'}}
    if($Summary.SupplementalRules -isnot [array] -or $Summary.SupplementalRules.Count -gt 1){throw 'Invalid supplemental rule declaration.'}
    foreach($rule in $Summary.SupplementalRules){
        Assert-WinSecSnapshotFields $rule @('CheckId','ScanId','RuleId','RuleVersion','RuleSha256','ReferenceId','ReferenceVersion','Outcome')
        $definition=@((Get-WinSecTechnicalFrameworkRuleCatalog).Rules|Where-Object Id -CEQ 'TF-SMB-002')[0]
        if($Analysis.FrameworkId -cne 'mitre-attack' -or $rule.CheckId -cne 'WSA-NET-002' -or @($Summary.Sources|Where-Object {$_.CheckId -ceq $rule.CheckId -and $_.ScanId -ceq $rule.ScanId}).Count -ne 1 -or
            $rule.RuleId -cne $definition.Id -or $rule.RuleVersion -cne $definition.Version -or $rule.RuleSha256 -cne (Get-WinSecTechnicalAnalysisHash $definition) -or $rule.ReferenceId -cne 'M1037' -or $rule.ReferenceVersion -cne '1.2' -or
            $rule.Outcome -cnotin @('WARNING','EVALUATED','UNRESOLVED_RULE')){throw 'Unreviewed supplemental rule.'}
        if(@($Analysis.Rows|Where-Object CriterionId -CEQ $definition.Id).Count -ne $(if($rule.Outcome -ceq 'WARNING'){1}else{0})){throw 'Supplemental result contradicts its declaration.'}
    }
}
