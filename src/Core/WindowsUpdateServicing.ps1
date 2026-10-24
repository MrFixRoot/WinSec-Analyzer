# Pure reference validation/comparison; no Windows queries, I/O or score publication.
# A cumulative OS baseline is not a search for every applicable security update.

function Assert-WinSecWindowsUpdateReferenceFields {
    param([object]$InputObject,[string[]]$Fields)
    if($InputObject -isnot [pscustomobject] -or @($InputObject.PSObject.Properties).Count -ne $Fields.Count) {
        throw 'Invalid Windows Update reference fields.'
    }
    foreach($property in $InputObject.PSObject.Properties) {
        if($property.MemberType -ne 'NoteProperty' -or $property.Name -cnotin $Fields) {
            throw 'Invalid Windows Update reference property.'
        }
    }
}

function ConvertTo-WinSecWindowsUpdateReferenceDate {
    param([object]$Value)
    $date=[datetime]::MinValue
    if($Value -isnot [string] -or $Value -cnotmatch '\A20[0-9]{2}-[0-9]{2}-[0-9]{2}\z' -or
        -not [datetime]::TryParseExact($Value,'yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None,[ref]$date)) {
        throw 'Invalid Windows Update reference date.'
    }
    return [datetime]::SpecifyKind($date,[DateTimeKind]::Utc)
}

function ConvertTo-WinSecWindowsUpdateReferenceUtc {
    param([object]$Value)
    if($Value -is [datetime]) {
        if($Value.Kind -ne [DateTimeKind]::Utc){throw 'Windows Update reference time must be UTC.'}
        return $Value
    }
    $date=[datetime]::MinValue
    if($Value -isnot [string] -or $Value -cnotmatch '\A20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,7})?Z\z' -or
        -not [datetime]::TryParse($Value,[Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal),[ref]$date)) {
        throw 'Invalid Windows Update reference UTC time.'
    }
    return $date
}

function Test-WinSecWindowsUpdateReferenceInteger {
    param([object]$Value,[long]$Maximum=4294967295)
    return (($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or
        $Value -is [uint16] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [sbyte]) -and
        $Value -ge 0 -and $Value -le $Maximum)
}

function Assert-WinSecWindowsUpdateReferenceCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Catalog)
    Assert-WinSecWindowsUpdateReferenceFields $Catalog @('SchemaVersion','CatalogVersion','Status','Scope','AsOfUTC',
        'ValidUntilUTC','PatchDeadlineDays','SourceUrl','EditionGroups','Releases')
    $releaseSource='https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information'
    if($Catalog.SchemaVersion -isnot [string] -or $Catalog.SchemaVersion -cne '1.0.0' -or
        $Catalog.Status -isnot [string] -or $Catalog.Status -cne 'REVIEWED_REFERENCE_DATA' -or
        $Catalog.Scope -isnot [string] -or $Catalog.Scope -cne 'WINDOWS_OS_CUMULATIVE_SECURITY_BASELINE' -or
        $Catalog.SourceUrl -isnot [string] -or $Catalog.SourceUrl -cne $releaseSource -or
        -not (Test-WinSecWindowsUpdateReferenceInteger $Catalog.PatchDeadlineDays) -or $Catalog.PatchDeadlineDays -ne 7) {
        throw 'Invalid Windows Update reference header.'
    }
    $asOf=ConvertTo-WinSecWindowsUpdateReferenceUtc $Catalog.AsOfUTC
    $until=ConvertTo-WinSecWindowsUpdateReferenceUtc $Catalog.ValidUntilUTC
    if($asOf.TimeOfDay.Ticks -ne 0 -or $until -le $asOf -or $until -gt $asOf.AddDays(7) -or
        $Catalog.CatalogVersion -isnot [string] -or $Catalog.CatalogVersion -cnotmatch '\A20[0-9]{2}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]{0,3}\z' -or
        -not $Catalog.CatalogVersion.StartsWith($asOf.ToString('yyyy.MM.dd',[Globalization.CultureInfo]::InvariantCulture)+'.',[StringComparison]::Ordinal)) {
        throw 'Invalid Windows Update reference validity.'
    }
    $knownGroups=@{
        HOME_PRO=@('GAC','48,49,98,99,100,101,161,162,164,165','windows-11-home-and-pro')
        ENTERPRISE_EDUCATION=@('GAC','4,27,121,122','windows-11-enterprise-and-education')
        ENTERPRISE_LTSC=@('LTSC','125,126','windows-11-enterprise-ltsc-2024')
        IOT_ENTERPRISE_LTSC=@('LTSC','191','windows-11-iot-enterprise-ltsc-2024')
    }
    if($Catalog.EditionGroups -isnot [array] -or $Catalog.EditionGroups.Count -ne 4){throw 'Invalid Windows edition groups.'}
    $groups=@{}
    foreach($group in $Catalog.EditionGroups) {
        Assert-WinSecWindowsUpdateReferenceFields $group @('Key','Channel','Skus','SourceUrl')
        if($group.Key -isnot [string] -or $group.Key -cnotin @($knownGroups.Keys) -or $groups.ContainsKey($group.Key)) {
            throw 'Invalid or duplicate Windows edition group.'
        }
        $expected=$knownGroups[$group.Key]
        if($group.Channel -isnot [string] -or $group.Channel -cne $expected[0] -or
            $group.Skus -isnot [array] -or $group.Skus.Count -eq 0 -or
            $group.SourceUrl -isnot [string] -or $group.SourceUrl -cne ('https://learn.microsoft.com/en-us/lifecycle/products/'+$expected[2])) {
            throw 'Unreviewed Windows edition group.'
        }
        foreach($sku in $group.Skus) {
            if(-not (Test-WinSecWindowsUpdateReferenceInteger $sku 65535)){throw 'Invalid Windows SKU.'}
        }
        if(($group.Skus -join ',') -cne $expected[1]){throw 'Unreviewed Windows SKU mapping.'}
        $groups[$group.Key]=$group
    }
    $knownReleases=@{'21H2'=22000;'22H2'=22621;'23H2'=22631;'24H2'=26100;'25H2'=26200;'26H1'=28000;'26H2'=26300}
    if($Catalog.Releases -isnot [array] -or $Catalog.Releases.Count -ne 7){throw 'Invalid Windows release list.'}
    $seen=@{}
    foreach($release in $Catalog.Releases) {
        Assert-WinSecWindowsUpdateReferenceFields $release @('Release','Build','AvailableOn','Support','SecurityBaseline')
        if($release.Release -isnot [string] -or $release.Release -cnotin @($knownReleases.Keys) -or $seen.ContainsKey($release.Release) -or
            -not (Test-WinSecWindowsUpdateReferenceInteger $release.Build 99999) -or $release.Build -ne $knownReleases[$release.Release]) {
            throw 'Invalid or duplicate Windows release/build.'
        }
        $seen[$release.Release]=$true
        $available=ConvertTo-WinSecWindowsUpdateReferenceDate $release.AvailableOn
        if($available -gt $asOf){throw 'Windows reference release is not yet available.'}
        $expectedCount=if($release.Release -ceq '24H2'){4}else{2}
        if($release.Support -isnot [array] -or $release.Support.Count -ne $expectedCount){throw 'Invalid Windows support list.'}
        $seenSupport=@{}
        foreach($support in $release.Support) {
            Assert-WinSecWindowsUpdateReferenceFields $support @('EditionGroup','SupportEndsOn')
            if($support.EditionGroup -isnot [string] -or $support.EditionGroup -cnotin @($groups.Keys) -or
                $seenSupport.ContainsKey($support.EditionGroup) -or
                ($groups[$support.EditionGroup].Channel -ceq 'LTSC' -and $release.Release -cne '24H2')) {
                throw 'Invalid or duplicate Windows support context.'
            }
            $seenSupport[$support.EditionGroup]=$true
            if((ConvertTo-WinSecWindowsUpdateReferenceDate $support.SupportEndsOn) -le $available){throw 'Invalid Windows support interval.'}
        }
        if($null -ne $release.SecurityBaseline) {
            $baseline=$release.SecurityBaseline
            Assert-WinSecWindowsUpdateReferenceFields $baseline @('Kb','Revision','PublishedOn','SourceUrl')
            if($baseline.Kb -isnot [string] -or $baseline.Kb -cnotmatch '\AKB[1-9][0-9]{6}\z' -or
                -not (Test-WinSecWindowsUpdateReferenceInteger $baseline.Revision) -or $baseline.Revision -eq 0 -or
                $baseline.SourceUrl -isnot [string] -or $baseline.SourceUrl -cne ('https://support.microsoft.com/help/'+$baseline.Kb.Substring(2))) {
                throw 'Invalid Windows security baseline.'
            }
            $published=ConvertTo-WinSecWindowsUpdateReferenceDate $baseline.PublishedOn
            if($published -lt $available -or $published -gt $asOf){throw 'Invalid security publication date.'}
        }
    }
}

function Get-WinSecWindowsUpdateServicingReference {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Catalog,[AllowNull()][object]$Platform,
        [Parameter(Mandatory)][object]$EvaluatedAtUTC)
    Assert-WinSecWindowsUpdateReferenceCatalog $Catalog
    $at=ConvertTo-WinSecWindowsUpdateReferenceUtc $EvaluatedAtUTC
    $asOf=ConvertTo-WinSecWindowsUpdateReferenceUtc $Catalog.AsOfUTC
    $until=ConvertTo-WinSecWindowsUpdateReferenceUtc $Catalog.ValidUntilUTC
    $result=[pscustomobject]@{
        SchemaVersion='1.0.0';Scope=$Catalog.Scope;CatalogVersion=$Catalog.CatalogVersion
        CatalogAsOfUTC=$asOf.ToString('o');EvaluatedAtUTC=$at.ToString('o')
        SecuritySupport=[pscustomobject]@{State='UNKNOWN';Reason='PLATFORM_UNVERIFIED';SupportEndsOn=$null;SourceUrl=$null}
        SecurityBaseline=[pscustomobject]@{State='UNKNOWN';Reason='PLATFORM_UNVERIFIED';Kb=$null;RequiredRevision=$null;PublishedOn=$null;SourceUrl=$null}
    }
    if($at -lt $asOf -or $at -ge $until) {
        $reason=if($at -lt $asOf){'CATALOG_NOT_YET_VALID'}else{'CATALOG_EXPIRED'}
        $result.SecuritySupport.Reason=$reason;$result.SecurityBaseline.Reason=$reason;return $result
    }
    try {
        Assert-WinSecWindowsUpdateReferenceFields $Platform @('State','Version','BuildNumber','OperatingSystemSKU','ProductType',
            'Release','Channel','Revision','RevisionState','RestartState')
    } catch {return $result}
    if($Platform.State -isnot [string] -or $Platform.State -cne 'OBSERVED' -or
        $Platform.Version -isnot [string] -or $Platform.BuildNumber -isnot [string] -or
        $Platform.BuildNumber -cnotmatch '\A[1-9][0-9]{4}\z' -or $Platform.Version -cne ('10.0.'+$Platform.BuildNumber) -or
        -not (Test-WinSecWindowsUpdateReferenceInteger $Platform.OperatingSystemSKU 65535) -or
        -not (Test-WinSecWindowsUpdateReferenceInteger $Platform.ProductType 3) -or $Platform.ProductType -ne 1 -or
        $Platform.Release -isnot [string] -or $Platform.Channel -isnot [string]) {return $result}
    $releases=@($Catalog.Releases | Where-Object {$_.Build -eq [long]$Platform.BuildNumber -and $_.Release -ceq $Platform.Release})
    $groups=@($Catalog.EditionGroups | Where-Object {$_.Skus -contains $Platform.OperatingSystemSKU -and $_.Channel -ceq $Platform.Channel})
    if($releases.Count -ne 1 -or $groups.Count -ne 1){return $result}
    $release=$releases[0];$group=$groups[0]
    $support=@($release.Support | Where-Object {$_.EditionGroup -ceq $group.Key})
    if($support.Count -ne 1){return $result}
    $end=ConvertTo-WinSecWindowsUpdateReferenceDate $support[0].SupportEndsOn
    $result.SecuritySupport.SupportEndsOn=$support[0].SupportEndsOn;$result.SecuritySupport.SourceUrl=$group.SourceUrl
    # Microsoft dates are calendar dates (lifecycle pages use Pacific time).
    # Do not invent a UTC expiry instant or resolve conflicting boundary dates.
    if($at.Date -ge $end -and $at.Date -le $end.AddDays(1)) {
        $result.SecuritySupport.Reason='SUPPORT_DATE_BOUNDARY'
    } elseif($at.Date -gt $end.AddDays(1)) {
        $result.SecuritySupport.State='OUT_OF_SUPPORT';$result.SecuritySupport.Reason='SECURITY_SUPPORT_ENDED'
    } else {
        $result.SecuritySupport.State='SUPPORTED';$result.SecuritySupport.Reason='WITHIN_REVIEWED_SUPPORT_PERIOD'
    }
    $result.SecurityBaseline.Reason='PATCH_APPLICABILITY_UNVERIFIED'
    if($result.SecuritySupport.State -cne 'SUPPORTED'){return $result}
    $baseline=$release.SecurityBaseline
    if($null -eq $baseline){$result.SecurityBaseline.Reason='NO_REVIEWED_SECURITY_BASELINE';return $result}
    $result.SecurityBaseline.Kb=$baseline.Kb;$result.SecurityBaseline.RequiredRevision=$baseline.Revision
    $result.SecurityBaseline.PublishedOn=$baseline.PublishedOn;$result.SecurityBaseline.SourceUrl=$baseline.SourceUrl
    if($Platform.RevisionState -isnot [string] -or $Platform.RevisionState -cne 'OBSERVED' -or
        -not (Test-WinSecWindowsUpdateReferenceInteger $Platform.Revision)) {
        $result.SecurityBaseline.Reason='REVISION_UNVERIFIED';return $result
    }
    if($Platform.Revision -gt $baseline.Revision) {
        $result.SecurityBaseline.Reason='NEWER_REVISION_NOT_REVIEWED';return $result
    }
    if($Platform.Revision -lt $baseline.Revision) {
        $published=ConvertTo-WinSecWindowsUpdateReferenceDate $baseline.PublishedOn
        if($at.Date -le $published.AddDays($Catalog.PatchDeadlineDays)) {
            $result.SecurityBaseline.Reason='DEADLINE_OR_PRIOR_BASELINE_UNVERIFIED'
        } else {
            $result.SecurityBaseline.State='MISSING';$result.SecurityBaseline.Reason='REVIEWED_BASELINE_OVERDUE'
        }
        return $result
    }
    if($Platform.RestartState -isnot [string] -or $Platform.RestartState -cne 'NOT_PENDING') {
        $result.SecurityBaseline.Reason='UPDATE_COMPLETION_UNVERIFIED';return $result
    }
    $result.SecurityBaseline.State='MET';$result.SecurityBaseline.Reason='REVIEWED_OS_BASELINE_COMPLETED'
    return $result
}
