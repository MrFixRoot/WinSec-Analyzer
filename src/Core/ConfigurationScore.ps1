# Versioned configuration scores and public criterion manifest. No Windows queries.
. (Join-Path $PSScriptRoot 'CriterionApplicability.ps1')
. (Join-Path $PSScriptRoot 'BitLockerCriterionPrerequisites.ps1')
. (Join-Path $PSScriptRoot 'WindowsUpdateCriterionEvidence.ps1')
. (Join-Path $PSScriptRoot 'CriterionWeight.ps1')
function Assert-WinSecConfigurationFields {
    param([object]$Value,[string[]]$Fields)
    if ($Value -isnot [pscustomobject] -or @($Value.PSObject.Properties).Count -ne $Fields.Count -or
        @($Value.PSObject.Properties|Where-Object {$_.Name -cnotin $Fields}).Count) { throw 'Invalid configuration assessment fields.' }
}

function Get-WinSecConfigurationScoringPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $path=Join-Path $ProjectRoot 'config/scoring.json'
    Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
    $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 1048576) { throw 'Invalid configuration scoring policy file.' }
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $root=ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath $path -Raw -Encoding UTF8)
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $hash) { throw 'Scoring policy changed while reading.' }
    $policy=Get-WinSecResultField $root 'configurationScoring'
    if ($null -eq $policy) { return $null }
    Assert-WinSecConfigurationFields $policy @('schemaVersion','enabled','methodologyId','methodologyVersion','controlMethod','sectionMethod','requireCompleteControl','requireCompleteSection','globalDeviceScore')
    foreach ($field in @('schemaVersion','methodologyId','methodologyVersion','controlMethod','sectionMethod')) {
        if ($policy.$field -isnot [string]) {throw 'Scoring policy metadata must be scalar text.'}
    }
    if ($policy.schemaVersion -cne '1.0.0' -or $policy.enabled -isnot [bool] -or
        $policy.methodologyId -cne 'WSA_CONTROL_CRITERIA_MEAN' -or $policy.methodologyVersion -cnotin @('1.0.0','1.1.0','1.2.0') -or
        ($policy.methodologyVersion -ceq '1.2.0' -and $policy.controlMethod -cne 'WEIGHTED_PASS_CRITERIA_FRACTION') -or
        ($policy.methodologyVersion -cne '1.2.0' -and $policy.controlMethod -cne 'PASS_CRITERIA_FRACTION') -or $policy.sectionMethod -cne 'EQUAL_CONTROL_MEAN' -or
        $policy.requireCompleteControl -isnot [bool] -or -not $policy.requireCompleteControl -or
        $policy.requireCompleteSection -isnot [bool] -or -not $policy.requireCompleteSection -or
        $policy.globalDeviceScore -isnot [bool] -or $policy.globalDeviceScore) { throw 'Unsupported configuration scoring methodology.' }
    [pscustomobject]@{Policy=$policy;Sha256=$hash}
}

function Get-WinSecConfigurationControlTotals {
    param([object]$Control,[string]$MethodologyVersion='1.0.0')
    if($MethodologyVersion -cnotin @('1.0.0','1.1.0','1.2.0')){throw 'Unsupported configuration scoring methodology.'}
    $criteria=@($Control.Criteria);$resolved=@($criteria|Where-Object {$_.Status -cin @('PASS','FAIL')}).Count
    $passed=@($criteria|Where-Object {$_.Status -ceq 'PASS'}).Count
    $applicable=@($criteria|Where-Object {$MethodologyVersion -ceq '1.0.0' -or $_.Status -cne 'NOT_APPLICABLE'}).Count
    $excluded=($MethodologyVersion -cne '1.0.0' -and $criteria.Count -gt 0 -and $applicable -eq 0 -and $Control.Permission -ceq 'APPROVED')
    $complete=($applicable -gt 0 -and $resolved -eq $applicable -and $Control.Permission -ceq 'APPROVED')
    $numerator=[long]$passed;$denominator=[long]$applicable
    if($MethodologyVersion -ceq '1.2.0') {
        $numerator=0L;$denominator=0L
        foreach($criterion in $criteria) {
            $weight=Get-WinSecCriterionWeight $criterion -Required
            if($criterion.Status -ceq 'NOT_APPLICABLE'){continue}
            $denominator+=$weight
            if($criterion.Status -ceq 'PASS'){$numerator+=$weight}
        }
    }
    [pscustomobject]@{
        Value=if ($complete) {[Math]::Round((100.0*$numerator/$denominator),2,[MidpointRounding]::AwayFromZero)} else {$null}
        Coverage=if ($applicable) {[Math]::Round((100.0*$resolved/$applicable),2,[MidpointRounding]::AwayFromZero)} else {$null}
        Status=if ($complete) {'COMPLETE'} elseif($excluded){'NOT_APPLICABLE'} else {'NOT_SCORED'}
        EvaluatedCriteria=$resolved;TotalCriteria=$criteria.Count
    }
}

function Get-WinSecConfigurationSectionTotals {
    param([object[]]$Controls,[string]$MethodologyVersion='1.0.0')
    if($MethodologyVersion -cnotin @('1.0.0','1.1.0','1.2.0')){throw 'Unsupported configuration scoring methodology.'}
    $recordedCount=$Controls.Count
    if($MethodologyVersion -cne '1.0.0'){$Controls=@($Controls|Where-Object {$_.Status -cne 'NOT_APPLICABLE'})}
    $complete=@($Controls|Where-Object {$_.Status -ceq 'COMPLETE'}).Count
    $sum=0.0
    foreach ($control in $Controls) {
        if ($control.Status -ceq 'COMPLETE') {
            $denominator=0L;$numerator=0L
            foreach($criterion in $control.Criteria) {
                $weight=if($MethodologyVersion -ceq '1.2.0'){Get-WinSecCriterionWeight $criterion -Required}else{1}
                if($MethodologyVersion -cne '1.0.0' -and $criterion.Status -ceq 'NOT_APPLICABLE'){continue}
                $denominator+=$weight
                if($criterion.Status -ceq 'PASS'){$numerator+=$weight}
            }
            if($denominator -eq 0){throw 'A complete control has no applicable criteria.'}
            $sum+=100.0*$numerator/$denominator
        }
    }
    [pscustomobject]@{
        Value=if ($Controls.Count -gt 0 -and $complete -eq $Controls.Count) {[Math]::Round(($sum/$Controls.Count),2,[MidpointRounding]::AwayFromZero)} else {$null}
        Coverage=if ($Controls.Count) {[Math]::Round((100.0*$complete/$Controls.Count),2,[MidpointRounding]::AwayFromZero)} else {$null}
        Status=if ($Controls.Count -gt 0 -and $complete -eq $Controls.Count) {'COMPLETE'} elseif($MethodologyVersion -cne '1.0.0' -and $recordedCount -gt 0 -and $Controls.Count -eq 0){'NOT_APPLICABLE'} else {'NOT_SCORED'}
        CompleteControls=$complete;TotalControls=$recordedCount
    }
}

function Assert-WinSecConfigurationTotals {
    param([object]$Actual,[object]$Expected)
    foreach ($p in $Expected.PSObject.Properties) {
        $value=$Actual.($p.Name)
        if ($null -eq $p.Value) { if ($null -ne $value) { throw 'Unexpected numeric configuration result.' }; continue }
        if ($p.Name -ceq 'Status') { if ($value -isnot [string] -or $value -cne $p.Value) { throw 'Inconsistent configuration state.' }; continue }
        if (($value -isnot [int] -and $value -isnot [long] -and $value -isnot [double] -and $value -isnot [decimal]) -or
            $value -ne $p.Value) { throw 'Configuration totals cannot be reproduced.' }
    }
}

function ConvertTo-WinSecPublicConfigurationAssessment {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Assessment,[Parameter(Mandatory)][object]$Owner)
    $copy=Copy-WinSecResultData $Assessment
    Assert-WinSecConfigurationFields $copy @('SchemaVersion','DeviceId','ScanId','ScopeType','ScopeKey','CatalogVersion','MethodologyId','MethodologyVersion','PolicySha256','Controls','Sections')
    foreach ($field in @('SchemaVersion','MethodologyId','MethodologyVersion')) {
        if ($copy.$field -isnot [string]) {throw 'Configuration methodology must be scalar text.'}
    }
    foreach ($name in @('DeviceId','ScanId','ScopeType','ScopeKey')) {
        if ($copy.$name -isnot [string] -or $copy.$name -cne (Get-WinSecResultField $Owner $name)) { throw 'Foreign configuration assessment.' }
    }
    Assert-WinSecResultScope $copy.ScopeType $copy.ScopeKey
    if ($copy.SchemaVersion -cne '1.0.0' -or $copy.MethodologyId -cne 'WSA_CONTROL_CRITERIA_MEAN' -or
        $copy.MethodologyVersion -cnotin @('1.0.0','1.1.0','1.2.0') -or $copy.PolicySha256 -isnot [string] -or $copy.PolicySha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        $copy.CatalogVersion -isnot [string] -or $copy.CatalogVersion -cne (Get-WinSecResultField $Owner 'CatalogVersion') -or
        $copy.Controls -isnot [array] -or $copy.Controls.Count -eq 0 -or $copy.Controls.Count -gt 128 -or $copy.Sections -isnot [array]) {
        throw 'Invalid configuration assessment metadata.'
    }
    $registry=Get-WinSecCheckRegistry -ProjectRoot ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')))
    $seen=@{};$sections=@{}
    foreach ($control in $copy.Controls) {
        Assert-WinSecConfigurationFields $control @('CheckId','SectionKey','Permission','Value','Coverage','Status','EvaluatedCriteria','TotalCriteria','Criteria')
        if (-not (Test-WinSecTargetIdentifier $control.CheckId) -or $seen.ContainsKey($control.CheckId) -or
            $control.SectionKey -isnot [string] -or $control.Permission -isnot [string] -or $control.Permission -cnotin @('APPROVED','EVALUATION_ONLY','UNAVAILABLE') -or
            $control.Criteria -isnot [array] -or $control.Criteria.Count -gt 128) { throw 'Invalid configuration control manifest.' }
        $definition=@($registry.Checks|Where-Object {$_.CheckId -ceq $control.CheckId -and $_.SectionKey -ceq $control.SectionKey})
        if ($definition.Count -ne 1 -or ($copy.ScopeType -ceq 'CONTROL' -and $copy.ScopeKey -cne $control.CheckId) -or
            ($copy.ScopeType -ceq 'SECTION' -and $copy.ScopeKey -cne $control.SectionKey)) { throw 'Configuration control is outside scope.' }
        $seen[$control.CheckId]=$true;$sections[$control.SectionKey]=$true;$ids=@{};$identity=$null
        foreach ($criterion in $control.Criteria) {
            $criterionFields=@('CriterionId','Title','Status','CatalogId','CatalogVersion','CatalogSha256','Profile','OSRelease','Edition','SourceFramework','SourceVersion','SourceControlId','SourceTitle','SourceUrl','Recommendation','VerifiedAtUTC')
            if($copy.MethodologyVersion -ceq '1.2.0'){$criterionFields+='Weight'}
            if($copy.MethodologyVersion -cne '1.0.0' -and $criterion.Status -ceq 'NOT_APPLICABLE'){$criterionFields+=@('ApplicabilityReason','ApplicabilitySourceUrl')}
            Assert-WinSecConfigurationFields $criterion $criterionFields
            if($copy.MethodologyVersion -ceq '1.2.0'){$criterion.Weight=Get-WinSecCriterionWeight $criterion -Required}
            if ($criterion.VerifiedAtUTC -is [datetime] -and $criterion.VerifiedAtUTC.Kind -eq [DateTimeKind]::Utc) {$criterion.VerifiedAtUTC=$criterion.VerifiedAtUTC.ToString('o')}
            foreach ($p in $criterion.PSObject.Properties) {
                if($p.Name -ceq 'Weight'){continue}
                $limit=if ($p.Name -ceq 'Recommendation') {4096} elseif ($p.Name -cin @('SourceUrl','ApplicabilitySourceUrl')) {1024} else {256}
                if ($p.Value -isnot [string] -or [string]::IsNullOrWhiteSpace($p.Value) -or $p.Value.Length -gt $limit -or $p.Value -match '[\p{C}]') { throw 'Invalid public criterion manifest field.' }
            }
            if (-not (Test-WinSecTargetIdentifier $criterion.CriterionId) -or $ids.ContainsKey($criterion.CriterionId) -or
                ($criterion.Status -cnotin @('PASS','FAIL','UNKNOWN','NOT_EVALUATED') -and
                 -not ($copy.MethodologyVersion -cne '1.0.0' -and $criterion.Status -ceq 'NOT_APPLICABLE')) -or
                $criterion.SourceFramework -cnotin @('LOCAL_POLICY','CIS Benchmarks') -or
                $criterion.SourceControlId -ceq 'NOT_ASSIGNED' -or
                $criterion.CatalogSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
                $criterion.Profile -cin @('*','UNRESOLVED','PENDING_SELECTION') -or
                $criterion.OSRelease -cin @('*','UNRESOLVED','PENDING_SELECTION') -or $criterion.Edition -cin @('*','UNRESOLVED','PENDING_SELECTION')) { throw 'Unverified public criterion manifest.' }
            $ids[$criterion.CriterionId]=$true
            $catalogIdentity=ConvertTo-Json -InputObject @($criterion.CatalogId,$criterion.CatalogVersion,$criterion.CatalogSha256,$criterion.Profile,$criterion.OSRelease,$criterion.Edition) -Compress
            if ($null -ne $identity -and $identity -cne $catalogIdentity) { throw 'Mixed criterion catalogs in one control.' };$identity=$catalogIdentity
            $date=ConvertTo-WinSecResultUtc $criterion.VerifiedAtUTC 'VerifiedAtUTC'
            if ($date -gt [DateTimeOffset]::UtcNow) { throw 'Future criterion review.' }
            $criterion.VerifiedAtUTC=$date.UtcDateTime.ToString('o')
            $uri=$null
            if (-not [Uri]::TryCreate($criterion.SourceUrl,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or
                $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'Unsafe criterion source URL.' }
            if($criterion.Status -ceq 'NOT_APPLICABLE') {
                $exclusion=[pscustomobject]@{NotApplicableTargets=@([pscustomobject]@{OSRelease=$criterion.OSRelease;Edition=$criterion.Edition;
                    Reason=$criterion.ApplicabilityReason;SourceUrl=$criterion.ApplicabilitySourceUrl})}
                $null=Get-WinSecCriterionPlatformExclusion $exclusion
            }
        }
        if($control.CheckId -ceq 'WSA-SYS-003') {
            foreach($criterion in @($control.Criteria|Where-Object Status -CEQ NOT_APPLICABLE)) {
                if($criterion.CriterionId -cne 'WSA-WUP-BASE-002' -or $criterion.CatalogVersion -cnotlike '1.2.0+*' -or
                    $criterion.ApplicabilityReason -cne 'PATCH_BASELINE_EXCLUDED_AFTER_SUPPORT' -or
                    $criterion.ApplicabilitySourceUrl -cne 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information' -or
                    @($control.Criteria|Where-Object {$_.CriterionId -ceq 'WSA-WUP-BASE-003' -and $_.Status -ceq 'FAIL'}).Count -ne 1) {
                    throw 'A Windows Update patch exclusion requires its recorded end-of-support criterion.'
                }
            }
        }
        Assert-WinSecConfigurationTotals $control (Get-WinSecConfigurationControlTotals $control $copy.MethodologyVersion)
    }
    # The entire recorded section/device set must be present, including disabled checks.
    $expected=@($registry.Checks|Where-Object {$_.Visible -eq $true -and
        ($copy.ScopeType -ceq 'DEVICE' -or ($copy.ScopeType -ceq 'SECTION' -and $_.SectionKey -ceq $copy.ScopeKey) -or
         ($copy.ScopeType -ceq 'CONTROL' -and $_.CheckId -ceq $copy.ScopeKey))})
    if ($expected.Count -ne $seen.Count -or @($expected|Where-Object {-not $seen.ContainsKey($_.CheckId)}).Count) { throw 'Incomplete configuration control set.' }
    $sectionSeen=@{}
    foreach ($section in $copy.Sections) {
        Assert-WinSecConfigurationFields $section @('SectionKey','Value','Coverage','Status','CompleteControls','TotalControls')
        if ($copy.ScopeType -ceq 'CONTROL' -or $section.SectionKey -isnot [string] -or -not $sections.ContainsKey($section.SectionKey) -or $sectionSeen.ContainsKey($section.SectionKey)) { throw 'Invalid configuration section.' }
        $sectionSeen[$section.SectionKey]=$true
        Assert-WinSecConfigurationTotals $section (Get-WinSecConfigurationSectionTotals @($copy.Controls|Where-Object {$_.SectionKey -ceq $section.SectionKey}) $copy.MethodologyVersion)
    }
    if (($copy.ScopeType -ceq 'CONTROL' -and $copy.Sections.Count) -or
        ($copy.ScopeType -cne 'CONTROL' -and $sectionSeen.Count -ne $sections.Count)) { throw 'Incomplete configuration section set.' }
    return $copy
}

function New-WinSecConfigurationAssessment {
    [CmdletBinding()]
    param([object]$Audit,[object]$Assessment,[object]$Context,[object]$Registry,
        [System.Collections.IDictionary]$Catalogs,[object]$PolicySnapshot,[string]$ScopeType,[string]$ScopeKey,[string]$ProjectRoot)
    $data=Copy-WinSecResultData ([pscustomobject]@{Audit=$Audit;Assessment=$Assessment;Context=$Context;Registry=$Registry;Catalogs=$Catalogs;PolicySnapshot=$PolicySnapshot})
    $Audit=$data.Audit;$Assessment=$data.Assessment;$Context=$data.Context;$Registry=$data.Registry;$Catalogs=$data.Catalogs;$PolicySnapshot=$data.PolicySnapshot
    if ($null -eq $PolicySnapshot -or -not $PolicySnapshot.Policy.enabled -or $null -eq $Context -or
        $Context.Profile -cin @('UNRESOLVED','PENDING_SELECTION') -or [string]::IsNullOrWhiteSpace($Context.Profile)) { return $null }
    foreach ($field in @('DeviceId','ScanId')) {
        if ($Audit.$field -isnot [string] -or $Context.$field -isnot [string] -or $Audit.$field -cne $Context.$field) {throw 'Foreign configuration context.'}
    }
    foreach ($collector in $Audit.ControlResults) {
        if ($collector.DeviceId -isnot [string] -or $collector.ScanId -isnot [string] -or
            $collector.DeviceId -cne $Audit.DeviceId -or $collector.ScanId -cne $Audit.ScanId) {throw 'Foreign configuration collector.'}
    }
    $controls=New-Object 'System.Collections.Generic.List[object]';$hasApproved=$false
    $expected=@($Registry.Checks|Where-Object {$_.Visible -eq $true -and ($ScopeType -ceq 'DEVICE' -or
        ($ScopeType -ceq 'SECTION' -and $_.SectionKey -ceq $ScopeKey) -or ($ScopeType -ceq 'CONTROL' -and $_.CheckId -ceq $ScopeKey))})
    foreach ($definition in $expected) {
        $control=[pscustomobject]@{CheckId=$definition.CheckId;SectionKey=$definition.SectionKey;Permission='UNAVAILABLE';Value=$null;
            Coverage=$null;Status='NOT_SCORED';EvaluatedCriteria=0;TotalCriteria=0;Criteria=@()}
        $snapshot=if ($Catalogs.Contains($definition.CheckId)) {$Catalogs[$definition.CheckId]} else {$null}
        $collector=@($Audit.ControlResults|Where-Object {$_.CheckId -ceq $definition.CheckId -and $_.Status -cne 'NOT_SELECTED'})
        if ($collector.Count -gt 1) {throw 'Duplicate configuration collector.'}
        if ($null -ne $snapshot -and (Test-WinSecCriteriaCatalog $snapshot.Catalog).ReadyForEvaluation) {
            $hasApproved=$true;$eligible=$false;$evaluated=$null
            if ($collector.Count -eq 1) {
                $selection=Get-WinSecApplicableCriteria -Catalog $snapshot.Catalog -TargetContext $Context -ControlResult $collector[0] `
                    -ProjectRoot $ProjectRoot -DependencyEvidence (Resolve-WinSecAssessmentDependencies $collector[0])
                $eligible=($selection.Status -ceq 'READY' -and $selection.ScoringEligible -ceq $true)
                $original=@($Assessment.CriteriaSelections|Where-Object {$_.CheckId -ceq $definition.CheckId})
                $eligible=($eligible -and $original.Count -eq 1 -and $original[0].Status -ceq 'READY' -and
                    $original[0].CatalogSha256 -ceq $snapshot.Sha256)
                if ($eligible) {
                    $evaluated=Invoke-WinSecControlEvaluation -ControlResult $collector[0] -Criteria $selection.EligibleCriteria -TargetContext $Context
                    $prior=@($Assessment.EvaluationResults|Where-Object {$_.CheckId -ceq $definition.CheckId})
                    if ($prior.Count -ne 1 -or $prior[0].Status -cne $evaluated.Status -or
                        @($prior[0].Evaluations).Count -ne @($evaluated.Evaluations).Count) { throw 'Configuration evaluation changed before scoring.' }
                    foreach ($item in $evaluated.Evaluations) {
                        $match=@($prior[0].Evaluations|Where-Object {$_.CriterionId -ceq $item.CriterionId -and $_.Status -ceq $item.Status})
                        if ($match.Count -ne 1) { throw 'Configuration criterion cannot be reproduced.' }
                    }
                    $control.Permission='APPROVED'
                }
            }
            foreach ($rule in @($snapshot.Catalog.Criteria)) {
                $items=@(if ($null -ne $evaluated) {$evaluated.Evaluations|Where-Object {$_.CriterionId -ceq $rule.CriterionId}})
                $allowedStatuses=@('PASS','FAIL','UNKNOWN','NOT_EVALUATED')
                if($PolicySnapshot.Policy.methodologyVersion -cne '1.0.0'){$allowedStatuses+='NOT_APPLICABLE'}
                $status=if ($items.Count -eq 1 -and $items[0].Status -cin $allowedStatuses) {$items[0].Status} else {'NOT_EVALUATED'}
                $control.Criteria+=@([pscustomobject]@{CriterionId=$rule.CriterionId;Title=$rule.Name;Status=$status;CatalogId=$snapshot.Catalog.CatalogId;
                    CatalogVersion=$snapshot.Catalog.CatalogVersion;CatalogSha256=$snapshot.Sha256;Profile=$rule.Applicability.Profile;
                    OSRelease=$rule.Applicability.OSRelease;Edition=$rule.Applicability.Edition;SourceFramework=$rule.Source.Framework;
                    SourceVersion=$rule.Source.Version;SourceControlId=$rule.Source.ControlId;SourceTitle=$rule.Source.Title;SourceUrl=$rule.Source.Url;
                    Recommendation=$rule.Recommendation;VerifiedAtUTC=([DateTimeOffset]::Parse($rule.Verification.ReviewedAtUTC)).UtcDateTime.ToString('o')})
                $weight=Get-WinSecCriterionWeight $rule
                if($PolicySnapshot.Policy.methodologyVersion -ceq '1.2.0'){$control.Criteria[-1]|Add-Member Weight $weight}
                elseif($weight -ne 1){throw 'Weighted criteria require methodology 1.2.0.'}
                if($status -ceq 'NOT_APPLICABLE') {
                    $exclusion=Get-WinSecCriterionPlatformExclusion $rule $Context
                    if($null -eq $exclusion -and $definition.CheckId -ceq 'WSA-SYS-003' -and $collector.Count -eq 1) {
                        $exclusion=Get-WinSecWindowsUpdateCriterionExclusion -Criterion $rule -Evidence $collector[0].Evidence `
                            -TargetContext $Context -DeviceId $Audit.DeviceId -ScanId $Audit.ScanId
                    }
                    if($null -eq $exclusion){throw 'Unverified platform exclusion cannot be scored.'}
                    $control.Criteria[-1]|Add-Member ApplicabilityReason $exclusion.Reason
                    $control.Criteria[-1]|Add-Member ApplicabilitySourceUrl $exclusion.SourceUrl
                }
            }
        }
        $totals=Get-WinSecConfigurationControlTotals $control $PolicySnapshot.Policy.methodologyVersion
        foreach ($p in $totals.PSObject.Properties) {$control.($p.Name)=$p.Value}
        $controls.Add($control)
    }
    if (-not $hasApproved) { return $null }
    $sections=@(if ($ScopeType -cne 'CONTROL') {foreach ($key in @($controls.SectionKey|Sort-Object -Unique)) {
        $totals=Get-WinSecConfigurationSectionTotals @($controls|Where-Object {$_.SectionKey -ceq $key}) $PolicySnapshot.Policy.methodologyVersion
        [pscustomobject]@{SectionKey=$key;Value=$totals.Value;Coverage=$totals.Coverage;Status=$totals.Status;CompleteControls=$totals.CompleteControls;TotalControls=$totals.TotalControls}
    }})
    $summary=[pscustomobject]@{SchemaVersion='1.0.0';DeviceId=$Audit.DeviceId;ScanId=$Audit.ScanId;ScopeType=$ScopeType;ScopeKey=$ScopeKey;
        CatalogVersion=[string]$Audit.CatalogVersion;MethodologyId=$PolicySnapshot.Policy.methodologyId;
        MethodologyVersion=$PolicySnapshot.Policy.methodologyVersion;PolicySha256=$PolicySnapshot.Sha256;Controls=@($controls.ToArray());Sections=$sections}
    ConvertTo-WinSecPublicConfigurationAssessment $summary $summary
}

function Get-WinSecConfigurationScoreText {
    param([AllowNull()][object]$Assessment,[string]$ScopeType,[string]$ScopeKey)
    if ($null -eq $Assessment) { return 'NOT_SCORED' }
    $copy=ConvertTo-WinSecPublicConfigurationAssessment $Assessment $Assessment
    $items=@(if ($ScopeType -ceq 'CONTROL') {$copy.Controls|Where-Object {$_.CheckId -ceq $ScopeKey}}
        elseif ($ScopeType -ceq 'SECTION') {$copy.Sections|Where-Object {$_.SectionKey -ceq $ScopeKey}})
    if($items.Count -eq 1 -and $items[0].Status -ceq 'NOT_APPLICABLE'){return 'NOT_APPLICABLE'}
    if ($items.Count -ne 1 -or $null -eq $items[0].Value) { return 'NOT_SCORED' }
    return ('{0:0.##}/100' -f $items[0].Value)
}

function Get-WinSecConfigurationRows {
    [CmdletBinding()]
    param([AllowNull()][object]$Assessment,[string]$ScopeType,[string]$ScopeKey)
    if($null -eq $Assessment){return}
    $copy=ConvertTo-WinSecPublicConfigurationAssessment $Assessment $Assessment
    if($ScopeType -cnotin @('SECTION','CONTROL')){throw 'Invalid configuration table scope.'}
    foreach($control in $copy.Controls) {
        if(($ScopeType -ceq 'SECTION' -and $control.SectionKey -cne $ScopeKey) -or
            ($ScopeType -ceq 'CONTROL' -and $control.CheckId -cne $ScopeKey)){continue}
        foreach($criterion in $control.Criteria) {
            [pscustomobject]@{Id=$criterion.CriterionId;FindingId=$criterion.CriterionId;CriterionId=$criterion.CriterionId;
                Finding=$criterion.Title;Description=if($criterion.Status -ceq 'NOT_APPLICABLE'){$criterion.ApplicabilityReason}else{('Recorded criterion: '+$criterion.CriterionId+'; catalog '+$criterion.CatalogVersion)};
                ConfigurationState=$criterion.Status;Kind='CRITERION_RESULT';EvaluationStatus=$criterion.Status;
                ConfigurationPercent=if($criterion.Status -ceq 'PASS'){'100%'}elseif($criterion.Status -ceq 'FAIL'){'0%'}elseif($criterion.Status -ceq 'NOT_APPLICABLE'){'EXCLUDED'}else{'NOT_SCORED'};
                Severity='UNASSIGNED';Priority='UNASSIGNED';Evidence='';
                Recommendation=if($criterion.Status -ceq 'FAIL'){$criterion.Recommendation}else{'No confirmed deviation for this criterion. This is a configuration assessment, not an enforcement test.'};
                Reference=$criterion.SourceUrl;FrameworkReferences=@();CheckId=$control.CheckId;SectionKey=$control.SectionKey;
                DeviceId=$copy.DeviceId;ScanId=$copy.ScanId;CatalogVersion=$criterion.CatalogVersion}
        }
    }
}

function Assert-WinSecConfigurationViewContext {
    param([AllowNull()][object]$Assessment,[object]$NavigationState,[string]$ScanId)
    if ($null -eq $Assessment) { return }
    $copy=ConvertTo-WinSecPublicConfigurationAssessment $Assessment $Assessment
    if ($null -eq $NavigationState -or $NavigationState.SelectedDeviceId -isnot [string] -or
        $NavigationState.SelectedDeviceId -cne $copy.DeviceId -or $ScanId -cne $copy.ScanId) { throw 'Foreign configuration display context.' }
}

function Assert-WinSecConfigurationProvenance {
    param([object]$Session,[object]$Assessment)
    foreach ($control in $Assessment.Controls) {
        foreach ($criterion in $control.Criteria) {
            $findings=@($Session.Findings|Where-Object {$_.CheckId -ceq $control.CheckId -and $null -ne $_.Guidance -and $_.Guidance.CriterionId -ceq $criterion.CriterionId})
            if ($criterion.Status -ceq 'FAIL' -and $control.Permission -ceq 'APPROVED' -and $findings.Count -ne 1) { throw 'A scored deviation has no original finding.' }
            foreach ($finding in $findings) {
                if ($criterion.Status -cne 'FAIL' -or $finding.Guidance.CatalogSha256 -cne $criterion.CatalogSha256 -or
                    $finding.Guidance.CriterionTitle -cne $criterion.Title -or $finding.Guidance.Recommendation -cne $criterion.Recommendation -or
                    $finding.Guidance.ReferenceId -cne $criterion.SourceControlId -or $finding.Guidance.ReferenceUrl -cne $criterion.SourceUrl) { throw 'Finding and criterion manifest disagree.' }
            }
            if (@($Session.EvaluationResults).Count -eq 0 -and @($Session.CriteriaSelections).Count -eq 0) { continue } # Public history: arithmetic/integrity, never raw re-evaluation.
            if ($control.Permission -cne 'APPROVED') { continue }
            $selections=@($Session.CriteriaSelections|Where-Object {$_.CheckId -ceq $control.CheckId})
            $collectors=@($Session.ControlResults|Where-Object {$_.CheckId -ceq $control.CheckId})
            if ($selections.Count -ne 1 -or $collectors.Count -ne 1 -or $selections[0].Status -cne 'READY' -or
                $selections[0].CatalogSha256 -cne $criterion.CatalogSha256 -or @($selections[0].EligibleCriteria).Count -ne $control.TotalCriteria) { throw 'Missing original configuration selection.' }
            $rules=@($selections[0].EligibleCriteria|Where-Object {$_.CriterionId -ceq $criterion.CriterionId})
            if ($rules.Count -ne 1 -or $rules[0].Name -cne $criterion.Title -or $rules[0].Recommendation -cne $criterion.Recommendation -or
                $rules[0].Source.ControlId -cne $criterion.SourceControlId -or $rules[0].Source.Url -cne $criterion.SourceUrl -or
                $rules[0].Source.Framework -cne $criterion.SourceFramework -or $rules[0].Source.Version -cne $criterion.SourceVersion -or
                $rules[0].Source.Title -cne $criterion.SourceTitle -or $rules[0].Applicability.Profile -cne $criterion.Profile -or
                $rules[0].Applicability.OSRelease -cne $criterion.OSRelease -or $rules[0].Applicability.Edition -cne $criterion.Edition) { throw 'Configuration policy snapshot differs.' }
            if($Assessment.MethodologyVersion -ceq '1.2.0' -and
                (Get-WinSecCriterionWeight $rules[0]) -ne $criterion.Weight){throw 'Configuration criterion weight differs from its approved source.'}
            if($control.CheckId -ceq 'WSA-SYS-002' -and $criterion.CriterionId -clike 'WSA-BLK-BASE-*') {
                Assert-WinSecBitLockerScoredCollection -ControlResult $collectors[0]
            }
            if($control.CheckId -ceq 'WSA-SYS-003') {
                Assert-WinSecWindowsUpdateScoredCollection -ControlResult $collectors[0] -Session $Session
            }
            $context=[pscustomobject]@{DeviceId=$Session.DeviceId;ScanId=$Session.ScanId;OSFamily='Windows';OSRelease=$criterion.OSRelease;Edition=$criterion.Edition;Profile=$criterion.Profile}
            $result=Invoke-WinSecCriterionEvaluation -Criterion $rules[0] -Evidence $collectors[0].Evidence -TargetContext $context `
                -CheckId $control.CheckId -DeviceId $Session.DeviceId -ScanId $Session.ScanId
            if ($result.Status -cne $criterion.Status) { throw 'Configuration result cannot be independently reproduced.' }
            if($criterion.Status -ceq 'NOT_APPLICABLE') {
                $exclusion=Get-WinSecCriterionPlatformExclusion $rules[0] $context
                if($null -eq $exclusion -and $control.CheckId -ceq 'WSA-SYS-003') {
                    $exclusion=Get-WinSecWindowsUpdateCriterionExclusion -Criterion $rules[0] -Evidence $collectors[0].Evidence `
                        -TargetContext $context -DeviceId $Session.DeviceId -ScanId $Session.ScanId
                }
                if($null -eq $exclusion -or $criterion.ApplicabilityReason -cne $exclusion.Reason -or
                    $criterion.ApplicabilitySourceUrl -cne $exclusion.SourceUrl){throw 'Platform exclusion differs from the approved criterion.'}
            }
        }
    }
}
