# In-memory I/O boundary for legacy technical/history integration tests.
# Production normalization, rendering, digests and artifact readers remain real.
# Paired storage and filesystem publication are covered by their own suites.
. (Join-Path $PSScriptRoot '../../src/CLI/FrameworkWorkflow.ps1')
. (Join-Path $PSScriptRoot '../../src/UI/Screens/FrameworkFindings.ps1')
function Reset-WinSecFrameworkMemory {
    $script:technicalMemory=@{}
    $script:frameworkExports=New-Object 'Collections.Generic.List[object]'
}
function Write-WinSecTechnicalArtifact {
    param($ProjectRoot,$Report)
    $r=ConvertTo-WinSecTechnicalReport $Report
    $key=(Get-WinSecScanSessionKey $r.DeviceId $r.ScanId)+'|'+$r.CheckId
    if($script:technicalMemory.ContainsKey($key)){throw 'Immutable technical fixture conflict.'}
    $body=ConvertTo-WinSecTechnicalMarkdown $r
    $meta=[pscustomobject]@{SchemaVersion='2.0.0';DeviceId=$r.DeviceId;ScanId=$r.ScanId;CheckId=$r.CheckId;
        ScopeType=$r.ScopeType;ScopeKey=$r.ScopeKey;ContentSha256=(Get-WinSecReportTextHash $body)}
    $text="<!-- WinSec technical report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $null=ConvertFrom-WinSecTechnicalArtifact $text $r.DeviceId -IncludeReport
    $script:technicalMemory[$key]=$text
    [pscustomobject]@{DeviceId=$r.DeviceId;ScanId=$r.ScanId;CheckId=$r.CheckId;RelativePath='synthetic/technical.md'}
}
function Read-WinSecTechnicalReport {
    param($ProjectRoot,$DeviceId,$ScanId,$CheckId)
    $key=(Get-WinSecScanSessionKey $DeviceId $ScanId)+'|'+$CheckId
    if(-not $script:technicalMemory.ContainsKey($key)){return $null}
    $saved=ConvertFrom-WinSecTechnicalArtifact $script:technicalMemory[$key] $DeviceId -IncludeReport
    if($saved.ScanId -cne $ScanId -or $saved.CheckId -cne $CheckId){throw 'Foreign technical fixture.'}
    $saved
}
function Export-WinSecFrameworkAnalysis {
    param($ProjectRoot,$Analysis,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    $a=Assert-WinSecFrameworkAnalysis $Analysis $Analysis.DeviceId $Analysis.ScopeType $Analysis.ScopeKey
    if($CancellationAction -and (& $CancellationAction)){throw [OperationCanceledException]::new()}
    $utc=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)
    $body=New-WinSecFrozenFindingsMarkdown $a $utc
    $meta=[pscustomobject]@{SchemaVersion='2.0.0';DeviceId=$a.DeviceId;AnalysisId=$a.AnalysisId;FrameworkId=$a.FrameworkId;
        ScopeType=$a.ScopeType;ScopeKey=$a.ScopeKey;ExportedAtUTC=$utc;AnalysisSha256=$a.ContentSha256;
        ContentSha256=(Get-WinSecReportTextHash $body)}
    $text="<!-- WinSec framework findings`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $verified=ConvertFrom-WinSecFrozenFindingsArtifact $text $a.DeviceId
    $script:frameworkExports.Add([pscustomobject]@{Markdown=$text;Analysis=$verified.Analysis;Metadata=$verified.Metadata})
    [pscustomobject]@{RelativePath='synthetic/findings.md';AnalysisId=$a.AnalysisId}
}
function Open-WinSecFrameworkMemoryView {
    param($State,$Context,[string]$FrameworkId='nist-csf')
    function Show-WinSecExportFrameworkSelection {
        param($Selection,[switch]$ForFindings)
        [pscustomobject]@{Confirmed=$true;FrameworkId=$FrameworkId}
    }
    if(-not (Invoke-WinSecCLIFrameworkFindings $State $Context)){throw 'Synthetic framework selection cancelled.'}
    $Context.FrameworkFindings
}
function Add-WinSecFrameworkMemoryPublic {
    param($Context,$Public)
    $key='{0}:{1}{2}:{3}' -f $Public.DeviceId.Length,$Public.DeviceId,$Public.ScanId.Length,$Public.ScanId
    $Context.PublicScans[$key]=$Public
    $Context.ActiveScanByScope[(Get-WinSecCLIScopeKey $Public.DeviceId $Public.ScopeType $Public.ScopeKey)]=$Public.ScanId
}
