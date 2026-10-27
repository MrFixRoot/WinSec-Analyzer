# Pure, reproducible criterion inputs. Never trust caller-supplied verdicts.
. (Join-Path $PSScriptRoot 'WindowsUpdateAutomation.ps1')
. (Join-Path $PSScriptRoot 'CriterionWeight.ps1')

function Get-WinSecWindowsUpdateReferenceFingerprint {
    param([Parameter(Mandatory)][object]$Catalog)
    Assert-WinSecWindowsUpdateReferenceCatalog $Catalog
    # Closed reference schema contains strings, integers, arrays and NoteProperties.
    # Compact serialization is stable for this ASCII-only schema in 5.1 and 7.
    $canonical=[ordered]@{}
    foreach($property in $Catalog.PSObject.Properties) {
        $canonical[$property.Name]=if($property.Name -cin @('AsOfUTC','ValidUntilUTC')) {
            (ConvertTo-WinSecWindowsUpdateReferenceUtc $property.Value).ToString('o')
        } else {$property.Value}
    }
    $json=ConvertTo-Json $canonical -Depth 16 -Compress
    $sha=[Security.Cryptography.SHA256]::Create()
    try {[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))).Replace('-','')}
    finally {$sha.Dispose()}
}

function Resolve-WinSecWindowsUpdateDependencies {
    param([object]$ControlResult,[System.Collections.IDictionary]$DeclaredDependencies)
    $dependencies=if($null -eq $DeclaredDependencies){@{}}else{Copy-WinSecResultData $DeclaredDependencies}
    $key='windows-update-local-evidence'
    $allowed=(-not $dependencies.Contains($key) -or ($dependencies[$key] -is [bool] -and $dependencies[$key]))
    $dependencies[$key]=$false
    $evidence=Get-WinSecWindowsUpdateReferenceValue $ControlResult 'Evidence'
    if($evidence -isnot [pscustomobject] -or @($evidence.PSObject.Properties|Where-Object {$_.MemberType -ne 'NoteProperty'}).Count) {
        throw 'Windows Update evidence must contain data properties only.'
    }
    foreach($field in @('CheckId','DeviceId','ScanId')) {
        $expected=Get-WinSecWindowsUpdateReferenceValue $ControlResult $field
        $actual=Get-WinSecWindowsUpdateReferenceValue $evidence $field
        $pattern=switch($field){CheckId {'\AWSA-SYS-003\z'};DeviceId {'\Alocal:hw1-[a-f0-9]{64}\z'};ScanId {'\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z'}}
        if($expected -isnot [string] -or $expected -cnotmatch $pattern -or $actual -isnot [string] -or $actual -cne $expected) {
            throw 'Invalid or foreign Windows Update criterion identity.'
        }
    }
    $observed=Get-WinSecWindowsUpdateReferenceValue $ControlResult 'ObservedStatus'
    if($ControlResult.Status -isnot [string] -or $ControlResult.Status -cne 'INFORMATIONAL' -or
        $ControlResult.SectionKey -isnot [string] -or $ControlResult.SectionKey -cne 'SystemSecurity' -or
        ($null -ne $observed -and ($observed -isnot [string] -or $observed -cne 'INFORMATIONAL')) -or
        $evidence.CollectionSuccessful -isnot [bool] -or -not $evidence.CollectionSuccessful -or
        $evidence.Scope -isnot [string] -or $evidence.Scope -cne 'LOCAL_CONFIGURATION_ONLY' -or
        $evidence.SchemaVersion -isnot [string] -or $evidence.SchemaVersion -cnotin @('1.1.0','1.2.0','1.3.0')) {return ,$dependencies}
    $null=ConvertTo-WinSecWindowsUpdateReferenceUtc $evidence.CollectedAtUTC
    $dependencies[$key]=[bool]$allowed
    return ,$dependencies
}

function Get-WinSecWindowsUpdateCriterionReview {
    [CmdletBinding()]
    param([object]$Criterion,[object]$Evidence,[object]$TargetContext,[string]$DeviceId,[string]$ScanId)
    $id=Get-WinSecWindowsUpdateReferenceValue $Criterion 'CriterionId'
    $index=[array]::IndexOf(@('WSA-WUP-BASE-001','WSA-WUP-BASE-002','WSA-WUP-BASE-003'),$id)
    $paths=@('WindowsUpdate.Automation','WindowsUpdate.SecurityBaseline','WindowsUpdate.SecuritySupport')
    $weights=@(15,35,50)
    if($index -lt 0 -or $Criterion.CheckId -cne 'WSA-SYS-003' -or $Criterion.EvidencePath -cne $paths[$index] -or
        $Criterion.Operator -cne 'Equals' -or $Criterion.ExpectedValue -isnot [bool] -or -not $Criterion.ExpectedValue -or
        (Get-WinSecCriterionWeight $Criterion) -ne $weights[$index]) {throw 'Invalid Windows Update criterion contract.'}
    $reference=Get-WinSecWindowsUpdateReferenceValue $Criterion 'WindowsUpdateReference'
    Assert-WinSecWindowsUpdateReferenceFields $reference @('Catalog','Sha256','ContentSha256')
    if($reference.Sha256 -isnot [string] -or $reference.Sha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        $reference.ContentSha256 -isnot [string] -or
        $reference.ContentSha256 -cne (Get-WinSecWindowsUpdateReferenceFingerprint $reference.Catalog)) {
        throw 'Windows Update reference snapshot changed.'
    }
    $control=[pscustomobject]@{CheckId='WSA-SYS-003';DeviceId=$DeviceId;ScanId=$ScanId;SectionKey='SystemSecurity'
        Status='INFORMATIONAL';Evidence=$Evidence}
    $dependencies=Resolve-WinSecWindowsUpdateDependencies $control
    $view=[pscustomobject]@{}
    foreach($topic in @('Automation','SecurityBaseline','SecuritySupport')) {
        $view|Add-Member -NotePropertyName $topic -NotePropertyValue ([pscustomobject]@{State='UNKNOWN';Reason='COLLECTION_UNVERIFIED'})
    }
    if(-not $dependencies['windows-update-local-evidence']){return $view}
    $platform=ConvertTo-WinSecWindowsUpdateServicingPlatform $reference.Catalog $control
    # A selected profile does not prove the observed Windows build or SKU.
    if($platform.State -cne 'OBSERVED' -or $TargetContext.OSFamily -cne 'Windows' -or
        $TargetContext.OSRelease -cne ('Windows 11 '+$platform.Version) -or
        $TargetContext.Edition -cne ('SKU:'+$platform.OperatingSystemSKU) -or
        $TargetContext.DeviceId -cne $DeviceId -or $TargetContext.ScanId -cne $ScanId) {
        foreach($topic in @('Automation','SecurityBaseline','SecuritySupport')) {$view.$topic.Reason='PLATFORM_UNVERIFIED'}
        return $view
    }
    $review=Get-WinSecWindowsUpdateServicingReference $reference.Catalog $platform $Evidence.CollectedAtUTC
    if($review.SecuritySupport.Reason -cin @('CATALOG_NOT_YET_VALID','CATALOG_EXPIRED')) {
        foreach($topic in @('Automation','SecurityBaseline','SecuritySupport')) {$view.$topic.Reason=$review.SecuritySupport.Reason}
        return $view
    }
    $view.Automation=Get-WinSecWindowsUpdateAutomationReview $reference.Catalog $control
    $view.SecurityBaseline=[pscustomobject]@{State=$review.SecurityBaseline.State;Reason=$review.SecurityBaseline.Reason}
    $view.SecuritySupport=[pscustomobject]@{State=$review.SecuritySupport.State;Reason=$review.SecuritySupport.Reason}
    if($Criterion.Source.Version -clike '1.2.0+*' -and $review.SecuritySupport.State -ceq 'OUT_OF_SUPPORT') {
        $view.SecurityBaseline=[pscustomobject]@{State='NOT_APPLICABLE';Reason='PATCH_BASELINE_EXCLUDED_AFTER_SUPPORT'}
    }
    return $view
}

function Get-WinSecWindowsUpdateCriterionExclusion {
    [CmdletBinding()]
    param([object]$Criterion,[object]$Evidence,[object]$TargetContext,[string]$DeviceId,[string]$ScanId)
    if($Criterion.CheckId -cne 'WSA-SYS-003' -or $Criterion.CriterionId -cne 'WSA-WUP-BASE-002'){return}
    $review=Get-WinSecWindowsUpdateCriterionReview @PSBoundParameters
    if($review.SecurityBaseline.State -ceq 'NOT_APPLICABLE') {
        [pscustomobject]@{Reason='PATCH_BASELINE_EXCLUDED_AFTER_SUPPORT';
            SourceUrl='https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information'}
    }
}

function Get-WinSecWindowsUpdateCriterionEvidence {
    [CmdletBinding()]
    param([object]$Criterion,[object]$Evidence,[object]$TargetContext,[string]$DeviceId,[string]$ScanId)
    $review=Get-WinSecWindowsUpdateCriterionReview @PSBoundParameters
    $view=[pscustomobject]@{WindowsUpdate=[pscustomobject]@{Automation=$null;SecurityBaseline=$null;SecuritySupport=$null}}
    if($review.Automation.State -cin @('AUTOMATIC','NOT_AUTOMATIC')){$view.WindowsUpdate.Automation=($review.Automation.State -ceq 'AUTOMATIC')}
    if($review.SecurityBaseline.State -cin @('MET','MISSING')){$view.WindowsUpdate.SecurityBaseline=($review.SecurityBaseline.State -ceq 'MET')}
    if($review.SecuritySupport.State -cin @('SUPPORTED','OUT_OF_SUPPORT')){$view.WindowsUpdate.SecuritySupport=($review.SecuritySupport.State -ceq 'SUPPORTED')}
    return $view
}

function Assert-WinSecWindowsUpdateScoredCollection {
    param([object]$ControlResult,[object]$Session)
    $dependencies=Resolve-WinSecWindowsUpdateDependencies $ControlResult
    if(-not $dependencies['windows-update-local-evidence']){throw 'Windows Update verdict has no valid local collection.'}
    $at=ConvertTo-WinSecWindowsUpdateReferenceUtc $ControlResult.Evidence.CollectedAtUTC
    $start=ConvertTo-WinSecWindowsUpdateReferenceUtc $Session.StartedAtUTC
    $end=ConvertTo-WinSecWindowsUpdateReferenceUtc $Session.CompletedAtUTC
    if($at -lt $start -or $at -gt $end){throw 'Windows Update collection time is outside its scan session.'}
}
