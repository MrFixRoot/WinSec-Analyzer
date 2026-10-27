# Definitions only. The caller must already hold explicit native-operation consent.
# This helper reads no Windows provider and writes no files.
function Test-WinSecNativeFrameworkViews {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$Session,[string]$CheckId,[string]$DeviceName)
    if($null -ne $Session.ConfigurationAssessment){throw 'Native framework review cannot publish a rating.'}
    $record=New-WinSecPublicHistoryRecord $Session
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    $public=ConvertTo-WinSecPublicScanResult $Session
    if((Get-WinSecPublicHistoryJson $restored.PublicResult) -cne (Get-WinSecPublicHistoryJson $public)) {
        throw 'Native public history roundtrip mismatch.'
    }
    $technical=New-WinSecTechnicalReport $Session $CheckId $DeviceName $DeviceName
    $source=[pscustomobject]@{CheckId=$CheckId;ScanId=$Session.ScanId;ScopeType=$Session.ScopeType;ScopeKey=$Session.ScopeKey;
        CompletedAtUTC=$Session.CompletedAtUTC;Origin='LIVE';PublicResult=$restored.PublicResult;
        CatalogVersion=$Session.CatalogVersion;ExpectedCheckIds=@($Session.ExpectedCheckIds)}
    $count=0
    foreach($framework in @('nist-csf','cis-controls','mitre-attack')) {
        $view=New-WinSecFrameworkAnalysis -ProjectRoot $ProjectRoot -DeviceId $Session.DeviceId -DeviceName $DeviceName `
            -ScopeType CONTROL -ScopeKey $CheckId -FrameworkId $framework -Sources @($source) -Reports @($technical)
        $markdown=New-WinSecFrameworkMarkdown $view
        if(-not $markdown -or $view.DeviceId -cne $Session.DeviceId -or $view.Sources[0].ScanId -cne $Session.ScanId) {
            throw 'Invalid native framework view identity.'
        }
        $count++
    }
    [pscustomobject]@{PublicHistoryRoundtripValidated=$true;InMemoryReports=$count;ReadingCount=$technical.Rows.Count;
        CriterionCount=(@($Session.CriteriaSelections|Where-Object CheckId -CEQ $CheckId)[0]).CatalogCriteriaCount;
        InformationalObservations=@($public.ReviewItems|Where-Object {$null -ne $_.BitLockerSetting}).Count}
}
