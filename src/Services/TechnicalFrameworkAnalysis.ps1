# Stage 10 candidate: explicit saved sources only. No registration into the production F/P workflow.
. (Join-Path $PSScriptRoot '../Core/TechnicalFrameworkRules.ps1')
. (Join-Path $PSScriptRoot 'TechnicalSnapshotStore.ps1')

function Get-WinSecTechnicalAnalysisAdapter {
    param([string]$CheckId)
    $spec=switch -CaseSensitive ($CheckId){
        'WSA-SYS-001' {'Defender/Defender|DefenderTechnical'}
        'WSA-SYS-002' {'BitLocker/BitLocker|BitLockerTechnical'}
        'WSA-SYS-003' {'System/WindowsUpdate|WindowsUpdateTechnical'}
        'WSA-NET-001' {'Firewall/Firewall|FirewallCandidate'}
        'WSA-NET-002' {'Network/Smb|SmbCandidate'}
        'WSA-NET-003' {'Network/Rdp|RdpCandidate'}
        'WSA-NET-004' {'Network/OpenPorts|OpenPortsCandidate'}
        'WSA-NET-005' {'Network/NetworkConfiguration|NetworkCandidate'}
        'WSA-IAM-001' {'Accounts/LocalAdmins|LocalAdminsCandidate'}
        'WSA-IAM-002' {'Accounts/Guest|GuestCandidate'}
        'WSA-IAM-003' {'Policies/PasswordPolicy|PasswordPolicyCandidate'}
        'WSA-LOG-001' {'System/PowerShellLogging|PowerShellLoggingCandidate'}
        'WSA-LOG-002' {'Policies/AuditPolicy|AuditPolicyCandidate'}
        'WSA-HRD-001' {'Services/WindowsServices|WindowsServicesCandidate'}
        default {throw 'Unsupported technical analysis control.'}
    }
    $parts=$spec.Split('|')
    [pscustomobject]@{Path=(Join-Path $PSScriptRoot ('../Checks/'+$parts[0]+'TechnicalStorage.ps1'));
        Catalog=('Get-WinSec'+$parts[1]+'Catalog');Validate=('Assert-WinSec'+$parts[1]+'Snapshot');Read=('Read-WinSec'+$parts[1]+'Pair')}
}

function Get-WinSecTechnicalAnalysisHash {
    param([object]$Value)
    Get-WinSecSnapshotByteHash ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 16 -Compress)))
}

function Copy-WinSecTechnicalAnalysisData {
    param([AllowNull()][object]$Value,[scriptblock]$CancellationAction)
    # Closed data types, no getters, bounded depth/memory and no fixed record-count truncation.
    $budget=@{Bytes=0;Nodes=0};$clock=[Diagnostics.Stopwatch]::StartNew()
    $walk={param($node,[int]$depth)
        $budget.Nodes++;$budget.Bytes+=64
        if($depth -gt 16 -or $budget.Bytes -gt 16777216){throw 'Technical analysis data budget exceeded.'}
        if($budget.Nodes % 128 -eq 0){Assert-WinSecSnapshotValidationBudget $clock $CancellationAction}
        if($null -eq $node){return $null}
        if($node -is [string] -or $node.GetType() -in @([bool],[byte],[int16],[uint16],[int],[uint32],[long],[uint64])){
            foreach($p in $node.PSObject.Properties){if($p.IsInstance -and $p.MemberType -ne [Management.Automation.PSMemberTypes]::Property){throw 'Extended analysis scalar is not ordinary data.'}}
            if($node -is [string]){$budget.Bytes+=[Text.Encoding]::UTF8.GetByteCount($node)};return ,$node
        }
        if($node -is [array]){
            if($node.Rank -ne 1 -or $node.GetLowerBound(0) -ne 0){throw 'Invalid technical analysis array.'}
            $a=New-Object 'Collections.Generic.List[object]';foreach($child in $node){$a.Add((& $walk $child ($depth+1)))};return ,$a.ToArray()
        }
        if($node.GetType() -ne [Management.Automation.PSCustomObject]){throw 'Technical analysis requires ordinary data.'}
        $values=[ordered]@{};foreach($p in $node.PSObject.Properties){
            if($p.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or $values.Contains($p.Name)){throw 'Unreviewed technical analysis member.'}
            $values[$p.Name]=& $walk $p.Value ($depth+1)
        };return ,([pscustomobject]$values)
    }
    $result=& $walk $Value 0
    if($budget.Bytes -gt 16777216){throw 'Technical analysis data budget exceeded.'}
    return ,$result
}

function Assert-WinSecTechnicalAnalysisSelection {
    param([object]$Selection)
    Assert-WinSecSnapshotFields $Selection @('DeviceId','ScopeType','ScopeKey')
    if($Selection.DeviceId -isnot [string] -or $Selection.DeviceId -cnotmatch '\Alocal:hw1-[a-f0-9]{64}\z' -or
        $Selection.ScopeType -cnotin @('CONTROL','SECTION') -or $Selection.ScopeKey -isnot [string]){throw 'Invalid technical analysis selection.'}
    $ids=@(foreach($i in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003','WSA-NET-001','WSA-NET-002','WSA-NET-003','WSA-NET-004','WSA-NET-005','WSA-IAM-001','WSA-IAM-002','WSA-IAM-003','WSA-LOG-001','WSA-LOG-002','WSA-HRD-001')){
        $c=Get-WinSecSnapshotControl $i
        if(($Selection.ScopeType -ceq 'CONTROL' -and $Selection.ScopeKey -ceq $i) -or ($Selection.ScopeType -ceq 'SECTION' -and $Selection.ScopeKey -ceq $c.SectionKey)){$i}
    })
    if(-not $ids.Count){throw 'Unknown technical analysis scope.'}
    return $ids
}

function Read-WinSecTechnicalAnalysisSources {
    [CmdletBinding()]param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Selection,
        [AllowEmptyCollection()][object[]]$References=@(),[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    $ids=@(Assert-WinSecTechnicalAnalysisSelection $Selection);$seen=@{};$output=New-Object 'Collections.Generic.List[object]'
    $clock=[Diagnostics.Stopwatch]::StartNew();$done=0;$bytes=0
    foreach($reference in $References){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        Assert-WinSecSnapshotFields $reference @('Identity','CollectedAtUTC','CatalogSha256','Origin')
        Assert-WinSecSnapshotIdentity $reference.Identity;$id=$reference.Identity.CheckId
        if($id -cnotin $ids -or $seen.ContainsKey($id) -or $reference.Identity.DeviceId -cne $Selection.DeviceId -or $reference.Origin -cnotin @('LIVE','RECORDS')){throw 'Foreign or duplicate technical analysis source.'}
        $seen[$id]=$true;$adapter=Get-WinSecTechnicalAnalysisAdapter $id
        . $adapter.Path
        $catalog=& $adapter.Catalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
        if($reference.CatalogSha256 -cne $hash){throw 'Unreviewed technical source catalog.'}
        $pair=& $adapter.Read -ProjectRoot $ProjectRoot -ExpectedIdentity $reference.Identity -CollectedAtUTC $reference.CollectedAtUTC -CancellationAction $CancellationAction
        if($pair.PublicationStatus -cne 'COMMITTED' -or $null -eq $pair.Snapshot){throw 'Technical analysis requires a committed pair.'}
        $bytes+=[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $pair.Snapshot -Depth 16 -Compress))
        if($bytes -gt (Get-WinSecSnapshotSpecification).MaxDocumentBytes){throw 'Selected technical source byte budget exceeded.'}
        $output.Add([pscustomobject]@{Identity=$reference.Identity;Origin=$reference.Origin;Snapshot=$pair.Snapshot;Catalog=$catalog;CatalogSha256=$hash})
        $done++;if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Phase='READ_SAVED_SOURCES';Completed=$done;Total=$References.Count})}
    }
    return $output.ToArray()
}

function New-WinSecTechnicalFrameworkView {
    [CmdletBinding()]param([Parameter(Mandatory)][object]$Selection,
        [Parameter(Mandatory)][ValidateSet('nist-csf','cis-controls','mitre-attack')][string]$FrameworkId,
        [AllowEmptyCollection()][object[]]$Sources=@(),[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    $Selection=Copy-WinSecTechnicalAnalysisData $Selection -CancellationAction $CancellationAction
    $ids=@(Assert-WinSecTechnicalAnalysisSelection $Selection);$rules=Get-WinSecTechnicalFrameworkRuleCatalog
    $framework=@($rules.Frameworks|Where-Object Id -CEQ $FrameworkId)[0];$clock=[Diagnostics.Stopwatch]::StartNew()
    $manifest=New-Object 'Collections.Generic.List[object]';$ledger=New-Object 'Collections.Generic.List[object]'
    $outcomes=New-Object 'Collections.Generic.List[object]';$findings=New-Object 'Collections.Generic.List[object]'
    $seen=@{};$retained=New-Object 'Collections.Generic.List[object]';$bytes=0;$total=0
    # Validate every selected source before producing any warnings. Never trust a caller-supplied catalog.
    foreach($source in $Sources){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        Assert-WinSecSnapshotFields $source @('Identity','Origin','Snapshot','Catalog','CatalogSha256');Assert-WinSecSnapshotIdentity $source.Identity
        $id=$source.Identity.CheckId
        if($id -cnotin $ids -or $source.Identity.DeviceId -cne $Selection.DeviceId -or $seen.ContainsKey($id) -or $source.Origin -cnotin @('LIVE','RECORDS')){throw 'Foreign or duplicate technical analysis source.'}
        $seen[$id]=$true;$adapter=Get-WinSecTechnicalAnalysisAdapter $id;. $adapter.Path
        $catalog=& $adapter.Catalog;$hash=Get-WinSecSnapshotCatalogHash $catalog
        Assert-WinSecSnapshotCatalog $source.Catalog
        if($source.CatalogSha256 -cne $hash -or (Get-WinSecSnapshotCatalogHash $source.Catalog) -cne $hash){throw 'Unreviewed technical analysis catalog.'}
        $null=& $adapter.Validate -Snapshot $source.Snapshot -ExpectedIdentity $source.Identity -CancellationAction $CancellationAction
        $json=ConvertTo-Json -InputObject $source.Snapshot -Depth 16 -Compress;$bytes+=[Text.Encoding]::UTF8.GetByteCount($json)
        if($bytes -gt (Get-WinSecSnapshotSpecification).MaxDocumentBytes){throw 'Technical analysis source byte budget exceeded.'}
        $snapshot=ConvertFrom-WinSecTechnicalSnapshotJson -Json $json -Catalog $catalog -CatalogSha256 $hash -ExpectedIdentity $source.Identity -CancellationAction $CancellationAction
        $retained.Add($snapshot);$total+=$snapshot.Collection.Observed+$snapshot.Collection.Unknown+$snapshot.Collection.Errors+$snapshot.Collection.NotCollected+$snapshot.Collection.NotConfigured+$snapshot.Collection.NotApplicable
        $manifest.Add([pscustomobject]@{Identity=$snapshot.Identity;Origin=$source.Origin;SnapshotSchemaVersion=$snapshot.SchemaVersion;CatalogId=$snapshot.CatalogId;
            CatalogVersion=$snapshot.CatalogVersion;CatalogSha256=$hash;CollectorVersion=$snapshot.CollectorVersion;SnapshotSha256=(Get-WinSecTechnicalAnalysisHash $snapshot);
            CollectedAtUTC=$snapshot.CollectedAtUTC;CompletedAtUTC=$snapshot.CompletedAtUTC;Platform=$snapshot.Platform;Collection=$snapshot.Collection;Inventories=$snapshot.Inventories})
    }
    $analysisId=[guid]::NewGuid().ToString('N');$done=0
    foreach($s in $retained){
        $active=@($rules.Rules|Where-Object {$_.CheckId -ceq $s.Identity.CheckId -and @($_.Relations|Where-Object FrameworkId -CEQ $FrameworkId).Count})
        $evaluated=@{};$unresolved=@{}
        foreach($rule in $active){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $entries=@($s.Batches|Where-Object InventoryId -CEQ $rule.InventoryId|ForEach-Object Records)
            $inventory=@($s.Inventories|Where-Object Id -CEQ $rule.InventoryId)[0]
            $state='NO_DATA';$matches=$true;$evidence=@()
            $platformKnown=($null -ne $s.Platform.BuildNumber -and $null -ne $s.Platform.OperatingSystemSKU -and $s.Platform.ProductType -eq $rule.ProductType -and $s.Platform.Version -ceq ('10.0.'+$s.Platform.BuildNumber) -and $s.Platform.BuildNumber -ge $rule.MinBuild)
            if(-not $platformKnown){$state='UNKNOWN_PLATFORM'}
            elseif($entries.Count -gt 1 -or ($null -ne $inventory.ReportedRecords -and $inventory.ReportedRecords -gt 1)){$state='AMBIGUOUS_RECORD'}
            elseif($entries.Count -eq 1){
                $state='EVALUATED'
                foreach($required in $rule.Required){
                    $r=@($entries[0].Readings|Where-Object FieldId -CEQ $required.FieldId)[0]
                    $evidence+=,[pscustomobject]@{InventoryId=$rule.InventoryId;RecordId=$entries[0].Id;FieldId=$required.FieldId;State=$r.State;Value=$r.Value}
                    if($r.State -cne 'OBSERVED' -or $r.Value -isnot [bool]){$state='UNRESOLVED_READING'}
                    elseif($r.Value -cne $required.Expected){$matches=$false}
                }
                if($state -ceq 'EVALUATED'){
                    foreach($required in $rule.Required){$evaluated[$rule.InventoryId+'|'+$entries[0].Id+'|'+$required.FieldId]=$true}
                    if($matches){$state='WARNING';$relation=@($rule.Relations|Where-Object FrameworkId -CEQ $FrameworkId)[0]
                        $findings.Add([pscustomobject]@{RuleId=$rule.Id;RuleVersion=$rule.Version;CheckId=$s.Identity.CheckId;ScanId=$s.Identity.ScanId;SnapshotId=$s.Identity.SnapshotId;
                            State='WARNING';Kind=$rule.ResultKind;Title=$rule.Title;Criterion=$rule.Criterion;TechnicalUrl=$rule.TechnicalUrl;TechnicalRevision=$rule.TechnicalRevision;
                            Recommendation=$rule.Recommendation;Relation=$relation;Evidence=$evidence})
                    }
                }
            }
            if($state -cnotin @('EVALUATED','WARNING')){foreach($entry in $entries){foreach($required in $rule.Required){$unresolved[$rule.InventoryId+'|'+$entry.Id+'|'+$required.FieldId]=$true}}}
            $outcomes.Add([pscustomobject]@{CheckId=$s.Identity.CheckId;ScanId=$s.Identity.ScanId;SnapshotId=$s.Identity.SnapshotId;RuleId=$rule.Id;State=$state})
        }
        foreach($batch in $s.Batches){foreach($record in $batch.Records){foreach($r in $record.Readings){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $key=$batch.InventoryId+'|'+$record.Id+'|'+$r.FieldId
            $treatment=if($r.State -cne 'OBSERVED'){$r.State}elseif($evaluated.ContainsKey($key)){'EVALUATED'}elseif($unresolved.ContainsKey($key)){'UNRESOLVED_RULE'}else{'INFORMATIVE_NO_RULE'}
            # Values are deliberately excluded: identifiable configuration remains in protected technical artifacts.
            $ledger.Add([pscustomobject]@{CheckId=$s.Identity.CheckId;ScanId=$s.Identity.ScanId;SnapshotId=$s.Identity.SnapshotId;InventoryId=$batch.InventoryId;RecordId=$record.Id;FieldId=$r.FieldId;State=$r.State;Reason=$r.Reason;Treatment=$treatment})
            $done++;if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Phase='ANALYZE_SAVED_READINGS';AnalysisId=$analysisId;Completed=$done;Total=$total})}
        }}}
    }
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    $counts=[ordered]@{};foreach($kind in @('EVALUATED','INFORMATIVE_NO_RULE','UNRESOLVED_RULE','UNKNOWN','ERROR','NOT_COLLECTED','NOT_CONFIGURED','NOT_APPLICABLE')){$counts[$kind]=@($ledger|Where-Object Treatment -CEQ $kind).Count}
    $view=[pscustomobject]@{ArtifactType='WinSec.TechnicalFrameworkView';SchemaVersion='1.0.0';EngineVersion='1.0.0';AnalysisId=$analysisId;GeneratedAtUTC=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture);
        Selection=[pscustomobject]@{DeviceId=$Selection.DeviceId;ScopeType=$Selection.ScopeType;ScopeKey=$Selection.ScopeKey};Framework=$framework;
        RuleCatalogVersion=$rules.CatalogVersion;RuleCatalogSha256=(Get-WinSecTechnicalAnalysisHash $rules);Sources=$manifest.ToArray();Readings=$ledger.ToArray();RuleOutcomes=$outcomes.ToArray();
        Findings=$findings.ToArray();Coverage=[pscustomobject]@{ReadingCount=$ledger.Count;Treatments=[pscustomobject]$counts;MissingCheckIds=@($ids|Where-Object {-not $seen.ContainsKey($_)});Assessment='LIMITED_NOT_COMPLIANCE'};ContentSha256=''}
    if(@($manifest|Where-Object {$_.Identity.ScanId -ceq $analysisId -or $_.Identity.SnapshotId -ceq $analysisId}).Count){throw 'Analysis identity collision.'}
    $view.ContentSha256=Get-WinSecTechnicalAnalysisHash $view
    if([Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $view -Depth 16 -Compress)) -gt (Get-WinSecSnapshotSpecification).MaxDocumentBytes){throw 'Technical analysis view byte budget exceeded.'}
    return Assert-WinSecTechnicalFrameworkView $view $Selection -CancellationAction $CancellationAction
}

function Assert-WinSecTechnicalFrameworkView {
    param([object]$View,[object]$Selection,[scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $View=Copy-WinSecTechnicalAnalysisData $View -CancellationAction $CancellationAction;$Selection=Copy-WinSecTechnicalAnalysisData $Selection -CancellationAction $CancellationAction
    $null=Assert-WinSecTechnicalAnalysisSelection $Selection
    Assert-WinSecSnapshotFields $View @('ArtifactType','SchemaVersion','EngineVersion','AnalysisId','GeneratedAtUTC','Selection','Framework','RuleCatalogVersion','RuleCatalogSha256','Sources','Readings','RuleOutcomes','Findings','Coverage','ContentSha256')
    if($View.ArtifactType -cne 'WinSec.TechnicalFrameworkView' -or $View.SchemaVersion -cne '1.0.0' -or $View.EngineVersion -cne '1.0.0' -or $View.AnalysisId -cnotmatch '\A[a-f0-9]{32}\z' -or
        (Get-WinSecTechnicalAnalysisHash $View.Selection) -cne (Get-WinSecTechnicalAnalysisHash $Selection)){throw 'Foreign technical framework view.'}
    # Validate frozen bytes before reuse. Digests protect accidental corruption, not malicious rewriting with fresh hashes.
    $json=ConvertTo-Json -InputObject $View -Depth 16 -Compress
    Assert-WinSecSnapshotJsonBudget $json
    $copy=$View;$hash=$copy.ContentSha256;$copy.ContentSha256=''
    if($hash -cne (Get-WinSecTechnicalAnalysisHash $copy)){throw 'Changed technical framework view.'}
    $rules=Get-WinSecTechnicalFrameworkRuleCatalog
    if($View.RuleCatalogVersion -cne $rules.CatalogVersion -or $View.RuleCatalogSha256 -cne (Get-WinSecTechnicalAnalysisHash $rules)){throw 'Stale technical framework rule catalog.'}
    $null=ConvertTo-WinSecSnapshotUtc $View.GeneratedAtUTC
    $framework=@($rules.Frameworks|Where-Object Id -CEQ $View.Framework.Id)
    if($framework.Count -ne 1 -or (Get-WinSecTechnicalAnalysisHash $framework[0]) -cne (Get-WinSecTechnicalAnalysisHash $View.Framework)){throw 'Unreviewed technical framework.'}
    foreach($name in @('Sources','Readings','RuleOutcomes','Findings')){if($View.$name -isnot [array]){throw 'Invalid technical view array.'}}
    $sourceIds=@{};$allowed=@(Assert-WinSecTechnicalAnalysisSelection $Selection);$catalogs=@{}
    foreach($source in $View.Sources){
        Assert-WinSecSnapshotFields $source @('Identity','Origin','SnapshotSchemaVersion','CatalogId','CatalogVersion','CatalogSha256','CollectorVersion','SnapshotSha256','CollectedAtUTC','CompletedAtUTC','Platform','Collection','Inventories')
        Assert-WinSecSnapshotIdentity $source.Identity;$check=$source.Identity.CheckId
        if($source.Identity.DeviceId -cne $Selection.DeviceId -or $check -cnotin $allowed -or $sourceIds.ContainsKey($check) -or $source.Origin -cnotin @('LIVE','RECORDS') -or
            $source.SnapshotSchemaVersion -cne '2.0.0' -or $source.SnapshotSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or $source.Identity.ScanId -ceq $View.AnalysisId -or $source.Identity.SnapshotId -ceq $View.AnalysisId){throw 'Foreign technical view source.'}
        $adapter=Get-WinSecTechnicalAnalysisAdapter $check;. $adapter.Path;$cat=& $adapter.Catalog
        if($source.CatalogId -cne $cat.CatalogId -or $source.CatalogVersion -cne $cat.CatalogVersion -or $source.CatalogSha256 -cne (Get-WinSecSnapshotCatalogHash $cat)){throw 'Unreviewed technical view source catalog.'}
        $collected=ConvertTo-WinSecSnapshotUtc $source.CollectedAtUTC;$completed=ConvertTo-WinSecSnapshotUtc $source.CompletedAtUTC
        if($completed -lt $collected -or $source.CollectorVersion -cnotmatch '\A[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\z'){throw 'Invalid technical view source provenance.'}
        Assert-WinSecSnapshotFields $source.Platform @('Version','OSRelease','Edition','BuildNumber','UBR','OperatingSystemSKU','ProductType')
        foreach($name in @('BuildNumber','UBR','OperatingSystemSKU','ProductType')){if($null -ne $source.Platform.$name -and -not(Test-WinSecSnapshotUInt $source.Platform.$name)){throw 'Invalid technical view platform.'}}
        foreach($name in @('Version','OSRelease','Edition')){if($null -ne $source.Platform.$name -and -not(Test-WinSecSnapshotToken ('V'+$source.Platform.$name))){throw 'Invalid technical view platform text.'}}
        if($null -ne $source.Platform.Version -and $source.Platform.Version -cne ('10.0.'+$source.Platform.BuildNumber)){throw 'Conflicting technical view platform.'}
        Assert-WinSecSnapshotFields $source.Collection @('Status','Coverage','RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')
        foreach($name in @('RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')){if(-not(Test-WinSecSnapshotUInt $source.Collection.$name)){throw 'Invalid technical source count.'}}
        if($source.Collection.Status -cnotin @('COMPLETE','PARTIAL') -or $source.Collection.Coverage -cnotin @('COMPLETE','LIMITED') -or $source.Inventories -isnot [array] -or $source.Inventories.Count -ne $cat.Inventories.Count){throw 'Invalid technical source coverage.'}
        $inventoryIds=@{}
        foreach($inventory in $source.Inventories){
            Assert-WinSecSnapshotFields $inventory @('Id','State','Complete','ReportedRecords','RetainedRecords','Reason')
            if($inventory.Id -cnotin @($cat.Inventories.Id) -or $inventoryIds.ContainsKey($inventory.Id) -or $inventory.State -cnotin @('OBSERVED','UNKNOWN','ERROR','NOT_COLLECTED','NOT_APPLICABLE') -or $inventory.Complete -isnot [bool] -or -not(Test-WinSecSnapshotUInt $inventory.RetainedRecords) -or
                ($null -ne $inventory.ReportedRecords -and (-not(Test-WinSecSnapshotUInt $inventory.ReportedRecords) -or $inventory.ReportedRecords -lt $inventory.RetainedRecords)) -or $inventory.Reason -cnotin (Get-WinSecSnapshotSpecification).Reasons){throw 'Invalid technical source inventory.'}
            $inventoryIds[$inventory.Id]=$true
        }
        $sourceIds[$check]=$source;$catalogs[$check]=$cat
    }
    $readingKeys=@{};$counts=[ordered]@{};foreach($kind in @('EVALUATED','INFORMATIVE_NO_RULE','UNRESOLVED_RULE','UNKNOWN','ERROR','NOT_COLLECTED','NOT_CONFIGURED','NOT_APPLICABLE')){$counts[$kind]=0}
    foreach($r in $View.Readings){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        Assert-WinSecSnapshotFields $r @('CheckId','ScanId','SnapshotId','InventoryId','RecordId','FieldId','State','Reason','Treatment')
        $source=$sourceIds[$r.CheckId];$cat=$catalogs[$r.CheckId];$key=$r.CheckId+'|'+$r.InventoryId+'|'+$r.RecordId+'|'+$r.FieldId
        if($null -eq $source -or $source.Identity.ScanId -cne $r.ScanId -or $source.Identity.SnapshotId -cne $r.SnapshotId -or $readingKeys.ContainsKey($key) -or -not(Test-WinSecSnapshotToken $r.RecordId) -or
            @($cat.Fields|Where-Object {$_.Id -ceq $r.FieldId -and $_.InventoryId -ceq $r.InventoryId}).Count -ne 1 -or -not $counts.Contains($r.Treatment) -or
            ($r.State -ceq 'OBSERVED' -and $r.Treatment -cnotin @('EVALUATED','INFORMATIVE_NO_RULE','UNRESOLVED_RULE')) -or
            ($r.State -cne 'OBSERVED' -and ($r.Treatment -cne $r.State -or $r.State -cnotin @('UNKNOWN','ERROR','NOT_COLLECTED','NOT_CONFIGURED','NOT_APPLICABLE')))){throw 'Invalid technical reading treatment.'}
        $readingKeys[$key]=$r;$counts[$r.Treatment]++
    }
    foreach($source in $View.Sources){
        $sourceReadings=@($View.Readings|Where-Object CheckId -CEQ $source.Identity.CheckId)
        foreach($pair in @(@('OBSERVED','Observed'),@('UNKNOWN','Unknown'),@('ERROR','Errors'),@('NOT_COLLECTED','NotCollected'),@('NOT_CONFIGURED','NotConfigured'),@('NOT_APPLICABLE','NotApplicable'))){
            if(@($sourceReadings|Where-Object State -CEQ $pair[0]).Count -ne $source.Collection.($pair[1])){throw 'Technical view lost source readings.'}
        }
    }
    $outcomeKeys=@{}
    foreach($outcome in $View.RuleOutcomes){
        Assert-WinSecSnapshotFields $outcome @('CheckId','ScanId','SnapshotId','RuleId','State')
        $source=$sourceIds[$outcome.CheckId];$rule=@($rules.Rules|Where-Object {$_.Id -ceq $outcome.RuleId -and $_.CheckId -ceq $outcome.CheckId -and @($_.Relations|Where-Object FrameworkId -CEQ $framework[0].Id).Count})
        $key=$outcome.CheckId+'|'+$outcome.RuleId
        if($null -eq $source -or $source.Identity.ScanId -cne $outcome.ScanId -or $source.Identity.SnapshotId -cne $outcome.SnapshotId -or $rule.Count -ne 1 -or $outcomeKeys.ContainsKey($key) -or
            $outcome.State -cnotin @('WARNING','EVALUATED','NO_DATA','UNKNOWN_PLATFORM','AMBIGUOUS_RECORD','UNRESOLVED_READING')){throw 'Invalid technical rule outcome.'}
        $outcomeKeys[$key]=$outcome
    }
    $findingKeys=@{}
    foreach($finding in $View.Findings){
        Assert-WinSecSnapshotFields $finding @('RuleId','RuleVersion','CheckId','ScanId','SnapshotId','State','Kind','Title','Criterion','TechnicalUrl','TechnicalRevision','Recommendation','Relation','Evidence')
        $rule=@($rules.Rules|Where-Object {$_.Id -ceq $finding.RuleId -and $_.CheckId -ceq $finding.CheckId})[0];$key=$finding.CheckId+'|'+$finding.RuleId;$outcome=$outcomeKeys[$key]
        if($null -eq $rule -or $null -eq $outcome -or $outcome.State -cne 'WARNING' -or $findingKeys.ContainsKey($key) -or $finding.State -cne 'WARNING' -or $finding.ScanId -cne $outcome.ScanId -or $finding.SnapshotId -cne $outcome.SnapshotId -or $finding.Evidence -isnot [array] -or $finding.Evidence.Count -ne $rule.Required.Count){throw 'Unsupported technical finding.'}
        foreach($pair in @(@('RuleVersion','Version'),@('Kind','ResultKind'),@('Title','Title'),@('Criterion','Criterion'),@('TechnicalUrl','TechnicalUrl'),@('TechnicalRevision','TechnicalRevision'),@('Recommendation','Recommendation'))){if($finding.($pair[0]) -cne $rule.($pair[1])){throw 'Changed technical finding description.'}}
        $relation=@($rule.Relations|Where-Object FrameworkId -CEQ $framework[0].Id)
        if($relation.Count -ne 1 -or (Get-WinSecTechnicalAnalysisHash $finding.Relation) -cne (Get-WinSecTechnicalAnalysisHash $relation[0])){throw 'Unreviewed technical finding relation.'}
        for($i=0;$i -lt $rule.Required.Count;$i++){
            $e=$finding.Evidence[$i];Assert-WinSecSnapshotFields $e @('InventoryId','RecordId','FieldId','State','Value')
            $r=$readingKeys[$finding.CheckId+'|'+$e.InventoryId+'|'+$e.RecordId+'|'+$e.FieldId]
            if($e.FieldId -cne $rule.Required[$i].FieldId -or $e.InventoryId -cne $rule.InventoryId -or $e.State -cne 'OBSERVED' -or $e.Value -isnot [bool] -or $e.Value -cne $rule.Required[$i].Expected -or $null -eq $r -or $r.Treatment -cne 'EVALUATED'){throw 'Unverified technical finding evidence.'}
        };$findingKeys[$key]=$true
    }
    if(@($View.RuleOutcomes|Where-Object State -CEQ WARNING).Count -ne $findingKeys.Count){throw 'Missing technical findings.'}
    Assert-WinSecSnapshotFields $View.Coverage @('ReadingCount','Treatments','MissingCheckIds','Assessment')
    if($View.Coverage.ReadingCount -ne $View.Readings.Count -or $View.Coverage.Assessment -cne 'LIMITED_NOT_COMPLIANCE' -or
        (Get-WinSecTechnicalAnalysisHash $View.Coverage.Treatments) -cne (Get-WinSecTechnicalAnalysisHash ([pscustomobject]$counts)) -or
        (Get-WinSecTechnicalAnalysisHash $View.Coverage.MissingCheckIds) -cne (Get-WinSecTechnicalAnalysisHash @($allowed|Where-Object {-not $sourceIds.ContainsKey($_)}))){throw 'False technical view coverage.'}
    $copy.ContentSha256=$hash;return $copy
}

function Update-WinSecTechnicalFrameworkCache {
    [CmdletBinding()]param([object]$PreviousView,[object]$Selection,
        [ValidateSet('nist-csf','cis-controls','mitre-attack')][string]$FrameworkId,[object[]]$Sources=@(),[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    # Publish only after successful analysis. A caller retains its old reference on cancellation or rejection.
    try{$view=New-WinSecTechnicalFrameworkView -Selection $Selection -FrameworkId $FrameworkId -Sources $Sources -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback}
    catch [OperationCanceledException]{return [pscustomobject]@{Status='CANCELLED';View=$PreviousView}}
    [pscustomobject]@{Status='ANALYZED';View=$view}
}
