# Prepared reviewed readings only; never accesses Windows or application history.
function New-WinSecFrozenFindingsFixture {
    param([string]$ProjectRoot,[string[]]$Ids=@('WSA-SYS-002'),[string]$Framework='nist-csf',[switch]$Legacy,[switch]$Missing)
    $fixtures=@(foreach($id in $Ids){New-WinSecFrameworkWorkflowFixture $id ('export-'+$id)})
    $scope=if($Ids.Count -eq 1){'CONTROL'}else{'SECTION'};$key=if($Ids.Count -eq 1){$Ids[0]}else{'SystemSecurity'}
    $params=@{ProjectRoot=$ProjectRoot;DeviceId=$fixtures[0].Session.DeviceId;DeviceName='SYNTHETIC';ScopeType=$scope;ScopeKey=$key;FrameworkId=$Framework;Sources=@($fixtures.Source)}
    if(-not $Missing){$params.Reports=@($fixtures.Report)}
    if($Legacy){return New-WinSecFrameworkAnalysis @params}
    if(-not $Missing){$params.Snapshots=@($fixtures.Report|ForEach-Object {(New-WinSecProjectionSnapshot $_).Snapshot})}
    (New-WinSecProjectionFrameworkAnalysis @params).Analysis
}
function New-WinSecFrozenFindingsTestArtifact {
    param($Analysis,[string]$Time=([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')))
    $body=New-WinSecFrozenFindingsMarkdown $Analysis $Time
    $meta=[pscustomobject]@{SchemaVersion='2.0.0';DeviceId=$Analysis.DeviceId;AnalysisId=$Analysis.AnalysisId;FrameworkId=$Analysis.FrameworkId;
        ScopeType=$Analysis.ScopeType;ScopeKey=$Analysis.ScopeKey;ExportedAtUTC=$Time;AnalysisSha256=$Analysis.ContentSha256;ContentSha256=(Get-WinSecReportTextHash $body)}
    "<!-- WinSec framework findings`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
}
