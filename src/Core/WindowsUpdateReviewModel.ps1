# Public diagnostic snapshots. No raw policy values, provider messages or Windows I/O.
# These observations explain the three existing criteria; they add no score or finding.
function Get-WinSecWindowsUpdateReviewDescription {
    param([string]$CriterionId,[string]$State,[string]$Reason)
    $common=@(
        'UNKNOWN|COLLECTION_UNVERIFIED|Local collection could not be verified.'
        'UNKNOWN|PLATFORM_UNVERIFIED|Observed Windows and the selected profile could not be matched.'
        'UNKNOWN|CATALOG_NOT_YET_VALID|The collection predates the reviewed reference window.'
        'UNKNOWN|CATALOG_EXPIRED|The reviewed reference had expired at collection time.'
    )
    $rules=switch -CaseSensitive ($CriterionId) {
        WSA-WUP-BASE-001 {@(
            'UNKNOWN|PLATFORM_OR_SERVICE_UNVERIFIED|Windows or update service configuration could not be verified.'
            'NOT_AUTOMATIC|UPDATE_SERVICE_DISABLED|The Windows Update service is configured as disabled.'
            'UNKNOWN|POLICY_SOURCES_UNVERIFIED|Required local policy sources could not be verified.'
            'UNKNOWN|POLICY_PROVIDER_EDITION_UNVERIFIED|Effective automation policy is not yet verified for this Windows edition.'
            'UNKNOWN|DEADLINE_POLICY_INVALID|A deadline policy has an invalid or unsupported value.'
            'UNKNOWN|OVERRIDE_POLICY_REQUIRES_REVIEW|A policy modifier requires an individual applicability review.'
            'UNKNOWN|GROUP_POLICY_OVERRIDE_PLATFORM_UNVERIFIED|Policy precedence is unverified for this Windows build and revision.'
            'UNKNOWN|DEADLINE_POLICY_REQUIRES_REVIEW|An active or unresolved Group Policy deadline requires review.'
            'UNKNOWN|MDM_EQUIVALENT_POLICY_UNVERIFIED|Ignored Group Policies have no verified equivalent managed policy.'
            'UNKNOWN|GROUP_POLICY_MODE_UNREVIEWED|The configured automatic update mode has not been reviewed.'
            'UNKNOWN|GROUP_POLICY_MODE_UNRESOLVED|The automatic update policy combination could not be resolved.'
            'UNKNOWN|PARTIAL_DEADLINE_COVERAGE|Managed deadlines do not resolve automation for both update types.'
            'UNKNOWN|GROUP_POLICY_MDM_CONFLICT|Group Policy and managed policy disagree; precedence remains unresolved.'
            'AUTOMATIC|MANAGED_DEADLINES_RESOLVED|Reviewed managed deadlines resolve automatic installation for both update types.'
            'AUTOMATIC,NOT_AUTOMATIC|MANAGED_POLICY_RESOLVED|The reviewed managed automation policy was resolved.'
            'AUTOMATIC,NOT_AUTOMATIC|GROUP_POLICY_RESOLVED|The reviewed local automatic update policy was resolved.'
            'AUTOMATIC|OBSERVED_UNMANAGED_DEFAULT|The local policy provider reports the reviewed automatic default.'
            'UNKNOWN|UNMANAGED_DEFAULT_UNRESOLVED|The unmanaged default could not be resolved.'
        )}
        WSA-WUP-BASE-002 {@(
            'NOT_APPLICABLE|PATCH_BASELINE_EXCLUDED_AFTER_SUPPORT|Excluded from the score because verified security support has ended. Remaining weights are normalized; this does not establish patch currency.'
            'UNKNOWN|PATCH_APPLICABILITY_UNVERIFIED|A security baseline cannot be resolved until security support is verified.'
            'UNKNOWN|NO_REVIEWED_SECURITY_BASELINE|No reviewed cumulative OS security baseline is available.'
            'UNKNOWN|REVISION_UNVERIFIED|The installed cumulative OS revision could not be verified.'
            'UNKNOWN|NEWER_REVISION_NOT_REVIEWED|The installed revision is newer than the reviewed baseline; it requires review.'
            'UNKNOWN|DEADLINE_OR_PRIOR_BASELINE_UNVERIFIED|The deadline boundary or previous security baseline is unresolved.'
            'MISSING|REVIEWED_BASELINE_OVERDUE|The installed OS revision is below the reviewed security baseline after the seven-day deadline.'
            'UNKNOWN|UPDATE_COMPLETION_UNVERIFIED|Update completion is unverified because restart state is pending or unknown.'
            'MET|REVIEWED_OS_BASELINE_COMPLETED|The reviewed cumulative OS revision matches and no restart is pending.'
        )}
        WSA-WUP-BASE-003 {@(
            'UNKNOWN|SUPPORT_DATE_BOUNDARY|The security support end-date boundary requires review.'
            'OUT_OF_SUPPORT|SECURITY_SUPPORT_ENDED|The reviewed security support period for this Windows edition and release has ended.'
            'SUPPORTED|WITHIN_REVIEWED_SUPPORT_PERIOD|This Windows edition and release are within the reviewed security support period.'
        )}
        default {throw 'Unknown Windows Update review criterion.'}
    }
    foreach($rule in @($common)+@($rules)) {
        $parts=$rule.Split('|')
        if($parts[1] -ceq $Reason -and $State -cin $parts[0].Split(',')){return $parts[2]}
    }
    throw 'Unknown or inconsistent Windows Update review state.'
}

function Get-WinSecWindowsUpdateReviewId {
    param([string]$DeviceId,[string]$ScanId,[string]$CriterionId)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json @($DeviceId,$ScanId,$CriterionId) -Compress))
        'wup-review-'+[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()
    } finally {$sha.Dispose()}
}

function ConvertTo-WinSecWindowsUpdateReviewItem {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Item,[Parameter(Mandatory)][object]$Owner)
    $copy=Copy-WinSecResultData $Item
    Assert-WinSecConfigurationFields $copy @('ReviewId','CheckId','DeviceId','ScanId','Type','Status','WindowsUpdateSetting')
    $s=$copy.WindowsUpdateSetting
    Assert-WinSecConfigurationFields $s @('SchemaVersion','CriterionId','State','Reason','ReferenceVersion','ReferenceSha256',
        'ReferenceAsOfUTC','ReferenceValidUntilUTC','EvaluatedAtUTC')
    foreach($field in @('ReviewId','CheckId','DeviceId','ScanId','Type','Status')) {
        if($copy.$field -isnot [string]){throw 'Invalid Windows Update review identity type.'}
    }
    if($copy.CheckId -cne 'WSA-SYS-003' -or $copy.DeviceId -cne $Owner.DeviceId -or $copy.ScanId -cne $Owner.ScanId -or
        $copy.DeviceId -cnotmatch '\Alocal:hw1-[a-f0-9]{64}\z' -or $copy.ScanId -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z' -or
        $copy.Type -cne 'REVIEW_ONLY'){throw 'Invalid Windows Update review identity.'}
    foreach($field in @('SchemaVersion','CriterionId','State','Reason','ReferenceVersion','ReferenceSha256')) {
        if($s.$field -isnot [string] -or $s.$field.Length -gt 128){throw 'Invalid Windows Update review value type.'}
    }
    $null=Get-WinSecWindowsUpdateReviewDescription $s.CriterionId $s.State $s.Reason
    $status=if($s.State -ceq 'UNKNOWN'){'UNKNOWN'}else{'OBSERVED'}
    if($s.SchemaVersion -cne '1.0.0' -or $copy.Status -cne $status -or
        $s.ReferenceVersion -cnotmatch '\A20[0-9]{2}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]{0,3}\z' -or
        $s.ReferenceSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        $copy.ReviewId -cne (Get-WinSecWindowsUpdateReviewId $copy.DeviceId $copy.ScanId $s.CriterionId)) {
        throw 'Invalid Windows Update review state or source.'
    }
    foreach($field in @('ReferenceAsOfUTC','ReferenceValidUntilUTC','EvaluatedAtUTC')) {
        $s.$field=(ConvertTo-WinSecWindowsUpdateReferenceUtc $s.$field).ToString('o')
    }
    $asOf=ConvertTo-WinSecWindowsUpdateReferenceUtc $s.ReferenceAsOfUTC
    $until=ConvertTo-WinSecWindowsUpdateReferenceUtc $s.ReferenceValidUntilUTC
    $at=ConvertTo-WinSecWindowsUpdateReferenceUtc $s.EvaluatedAtUTC
    if($until -le $asOf -or ($until-$asOf).TotalDays -gt 7 -or
        ($at -lt $asOf -and $s.Reason -cne 'CATALOG_NOT_YET_VALID') -or
        ($at -ge $until -and $s.Reason -cne 'CATALOG_EXPIRED') -or
        ($at -ge $asOf -and $at -lt $until -and $s.Reason -cin @('CATALOG_NOT_YET_VALID','CATALOG_EXPIRED'))) {
        throw 'Inconsistent Windows Update review reference window.'
    }
    foreach($field in @('StartedAtUTC','CompletedAtUTC')) {
        $bound=Get-WinSecResultField $Owner $field
        if($null -ne $bound -and $bound -cne '') {
            $time=ConvertTo-WinSecWindowsUpdateReferenceUtc $bound
            if(($field -ceq 'StartedAtUTC' -and $at -lt $time) -or
                ($field -ceq 'CompletedAtUTC' -and $at -gt $time)){throw 'Windows Update review time is outside its session.'}
        }
    }
    $assessment=Get-WinSecResultField $Owner 'ConfigurationAssessment'
    if($null -ne $assessment) {
        $criteria=@(foreach($control in $assessment.Controls|Where-Object CheckId -CEQ 'WSA-SYS-003') {
            $control.Criteria|Where-Object CriterionId -CEQ $s.CriterionId
        })
        $expected=if($s.State -ceq 'UNKNOWN'){'UNKNOWN'}elseif($s.State -ceq 'NOT_APPLICABLE'){'NOT_APPLICABLE'}elseif($s.State -cin @('AUTOMATIC','MET','SUPPORTED')){'PASS'}else{'FAIL'}
        if($criteria.Count -ne 1 -or $criteria[0].Status -cne $expected){throw 'Windows Update review contradicts its recorded criterion.'}
    }
    return $copy
}

function New-WinSecWindowsUpdateReviewItems {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$ControlResult,[AllowNull()][object]$Selection)
    $control=Copy-WinSecResultData $ControlResult
    if($control.CheckId -cne 'WSA-SYS-003' -or $control.Status -cne 'INFORMATIONAL' -or $null -eq $Selection){return}
    $selectionCopy=Copy-WinSecResultData $Selection
    if($selectionCopy.CheckId -cne $control.CheckId -or $selectionCopy.DeviceId -cne $control.DeviceId -or
        $selectionCopy.ScanId -cne $control.ScanId){throw 'Foreign Windows Update review selection.'}
    if($selectionCopy.Status -cne 'READY'){return}
    $dependencies=Resolve-WinSecWindowsUpdateDependencies $control
    if(-not $dependencies['windows-update-local-evidence']){return}
    $items=New-Object 'System.Collections.Generic.List[object]'
    foreach($id in @('WSA-WUP-BASE-001','WSA-WUP-BASE-002','WSA-WUP-BASE-003')) {
        $rule=@($selectionCopy.EligibleCriteria|Where-Object CriterionId -CEQ $id)
        if($rule.Count -ne 1 -or -not (Test-WinSecCriteriaApprovalReady $rule[0])){throw 'Missing approved Windows Update review criterion.'}
        $context=[pscustomobject]@{DeviceId=$control.DeviceId;ScanId=$control.ScanId;OSFamily=$rule[0].Applicability.OSFamily;
            OSRelease=$rule[0].Applicability.OSRelease;Edition=$rule[0].Applicability.Edition;Profile=$rule[0].Applicability.Profile}
        $review=Get-WinSecWindowsUpdateCriterionReview $rule[0] $control.Evidence $context $control.DeviceId $control.ScanId
        $topic=switch($id){WSA-WUP-BASE-001 {'Automation'};WSA-WUP-BASE-002 {'SecurityBaseline'};WSA-WUP-BASE-003 {'SecuritySupport'}}
        $reference=$rule[0].WindowsUpdateReference
        $item=[pscustomobject]@{ReviewId=(Get-WinSecWindowsUpdateReviewId $control.DeviceId $control.ScanId $id);
            CheckId='WSA-SYS-003';DeviceId=$control.DeviceId;ScanId=$control.ScanId;Type='REVIEW_ONLY';
            Status=if($review.$topic.State -ceq 'UNKNOWN'){'UNKNOWN'}else{'OBSERVED'};
            WindowsUpdateSetting=[pscustomobject]@{SchemaVersion='1.0.0';CriterionId=$id;State=$review.$topic.State;Reason=$review.$topic.Reason;
                ReferenceVersion=$reference.Catalog.CatalogVersion;ReferenceSha256=$reference.Sha256;
                ReferenceAsOfUTC=$reference.Catalog.AsOfUTC;ReferenceValidUntilUTC=$reference.Catalog.ValidUntilUTC;
                EvaluatedAtUTC=$control.Evidence.CollectedAtUTC}}
        $items.Add((ConvertTo-WinSecWindowsUpdateReviewItem $item $control))
    }
    return $items.ToArray()
}

function ConvertTo-WinSecWindowsUpdateReviewRows {
    [CmdletBinding()]
    param([object[]]$ReviewItems=@())
    foreach($review in $ReviewItems) {
        $safe=ConvertTo-WinSecWindowsUpdateReviewItem $review $review
        $s=$safe.WindowsUpdateSetting
        $name=switch($s.CriterionId){WSA-WUP-BASE-001 {'Automatic updates'};WSA-WUP-BASE-002 {'Cumulative OS security baseline'};WSA-WUP-BASE-003 {'Windows security support'}}
        $description=Get-WinSecWindowsUpdateReviewDescription $s.CriterionId $s.State $s.Reason
        [pscustomobject]@{Id=$safe.ReviewId;FindingId=$safe.ReviewId;CriterionId=$s.CriterionId;
            Finding=($name+': '+$s.State+' - '+$description);Description=($s.Reason+'; reference '+$s.ReferenceVersion+'; evaluated '+$s.EvaluatedAtUTC);
            ConfigurationState='REVIEW_ONLY';Kind='REVIEW_ONLY';EvaluationStatus='NOT_EVALUATED';ConfigurationPercent='N/A';
            Severity='UNASSIGNED';Priority='UNASSIGNED';Evidence='';Recommendation='Diagnostic context for the recorded criterion; no additional score or confirmed deviation. Review unresolved sources manually.';
            Reference='';FrameworkReferences=@();CheckId=$safe.CheckId;SectionKey='SystemSecurity';DeviceId=$safe.DeviceId;ScanId=$safe.ScanId}
    }
}
