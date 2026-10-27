[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkWorkflowMemory.ps1')
function Get-CimInstance {throw 'Forbidden native query.'}
function Get-MpComputerStatus {throw 'Forbidden native query.'}
function Get-MpPreference {throw 'Forbidden native query.'}
$script:passed=0;$script:failed=0
function Assert-Framework {param([bool]$Value);if(-not $Value){throw 'Framework assertion failed.'}}
function Reject-Framework {param([scriptblock]$Action);$rejected=$false;try{$null=& $Action}catch{$rejected=$true};Assert-Framework $rejected}
function Test-Framework {param($Name,[scriptblock]$Action);try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
function New-Analysis {
    param([string]$Framework='nist-csf')
    $script:fixtures=@(foreach($id in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')){New-WinSecFrameworkWorkflowFixture $id ('fixture-'+$id)})
    New-WinSecFrameworkAnalysis -ProjectRoot $root -DeviceId $fixtures[0].Session.DeviceId -DeviceName SYNTHETIC -ScopeType SECTION -ScopeKey SystemSecurity `
        -FrameworkId $Framework -Sources @($fixtures.Source) -Reports @($fixtures.Report)
}
foreach($framework in @('nist-csf','cis-controls','mitre-attack')) {
    Test-Framework ('All three controls are reviewed against only '+$framework+' without ratings') {
        $a=New-Analysis $framework
        Assert-Framework ($a.Rows.Count -ge 10 -and $a.Sources.Count -eq 3 -and $a.ReadingCount -ge 148 -and
            @($a.Rows|Where-Object {$_.References.Count -eq 0}).Count -eq 0 -and
            @($a.Rows.References|Where-Object FrameworkId -CNE $framework).Count -eq 0)
        $md=New-WinSecFrameworkMarkdown $a
        Assert-Framework ($md -notmatch 'NOT_SCORED|/100|PRIVATE-|"Evidence"|ConfigurationPercent|Score' -and $md.Contains('Source scans'))
    }
}
Test-Framework 'Real progress visits every stored reading and source once' {
    $f=New-WinSecFrameworkWorkflowFixture;$script:events=New-Object 'Collections.Generic.List[object]'
    $a=New-WinSecFrameworkAnalysis $root $f.Session.DeviceId SYNTHETIC CONTROL WSA-SYS-002 nist-csf @($f.Source) @($f.Report) `
        -ProgressCallback {param($event);$script:events.Add($event)}
    Assert-Framework ($events[0].Completed -eq 0 -and $events[-1].Completed -eq $events[-1].Total -and $events.Count -eq ($f.Report.Rows.Count+2))
}
Test-Framework 'Cancellation returns no replacement analysis or report' {
    $f=New-WinSecFrameworkWorkflowFixture
    $a=New-WinSecFrameworkAnalysis $root $f.Session.DeviceId SYNTHETIC CONTROL WSA-SYS-002 nist-csf @($f.Source) @($f.Report) -CancellationAction {$true}
    Assert-Framework ($null -eq $a)
}
Test-Framework 'Cancellation after several readings stops progress before completion' {
    $f=New-WinSecFrameworkWorkflowFixture;$script:reviewed=0;$script:planned=0
    $a=New-WinSecFrameworkAnalysis $root $f.Session.DeviceId SYNTHETIC CONTROL WSA-SYS-002 nist-csf @($f.Source) @($f.Report) `
        -ProgressCallback {param($event);$script:reviewed=$event.Completed;$script:planned=$event.Total} `
        -CancellationAction {return ($script:reviewed -ge 4)}
    Assert-Framework ($null -eq $a -and $script:reviewed -eq 4 -and $script:reviewed -lt $script:planned)
}
Test-Framework 'Unknown and informational readings cannot invent configuration failures' {
    $f=New-WinSecFrameworkWorkflowFixture
    foreach($row in $f.Report.Rows){if($row.SettingId -like 'SystemVolume.*'){$row.Value=$null;$row.State='UNKNOWN';$row.Reason='UNAVAILABLE'}}
    $a=New-WinSecFrameworkAnalysis $root $f.Session.DeviceId SYNTHETIC CONTROL WSA-SYS-002 nist-csf @($f.Source) @($f.Report)
    Assert-Framework ($a.Rows.Count -eq 0 -and $a.UnknownReadingCount -ge 6)
}
Test-Framework 'Missing old technical files report incomplete coverage without rescanning' {
    $f=New-WinSecFrameworkWorkflowFixture
    $a=New-WinSecFrameworkAnalysis $root $f.Session.DeviceId SYNTHETIC CONTROL WSA-SYS-002 nist-csf @($f.Source) @()
    Assert-Framework ($a.MissingTechnicalCheckIds.Count -eq 1 -and $a.ReadingCount -eq 0 -and $a.Rows.Count -eq 0)
}
foreach($fault in @('Device','Scan','Scope','Duplicate','UnexpectedControl')) {
    Test-Framework ('Foreign or ambiguous technical input is rejected: '+$fault) {
        $f=New-WinSecFrameworkWorkflowFixture
        switch($fault){Device {$f.Report.DeviceId='local:hw1-'+('c'*64)};Scan {$f.Report.ScanId='foreign'};
            Scope {$f.Report.ScopeType='SECTION';$f.Report.ScopeKey='SystemSecurity'};Duplicate {};
            UnexpectedControl {$f.Source.CheckId='WSA-SYS-001'}}
        $reports=if($fault -ceq 'Duplicate'){@($f.Report,$f.Report)}else{@($f.Report)}
        Reject-Framework {New-WinSecFrameworkAnalysis $root $f.Session.DeviceId SYNTHETIC CONTROL WSA-SYS-002 nist-csf @($f.Source) $reports}
    }
}
Test-Framework 'Changed views and mixed frameworks cannot be exported as the selected view' {
    $a=New-Analysis;$a.Rows[0].Title='Changed'
    Reject-Framework {Assert-WinSecFrameworkAnalysis $a $a.DeviceId SECTION SystemSecurity}
    $a=New-Analysis;$a.Rows[0].References[0].FrameworkId='mitre-attack';$a.ContentSha256=Get-WinSecFrameworkAnalysisDigest $a
    Reject-Framework {Assert-WinSecFrameworkAnalysis $a $a.DeviceId SECTION SystemSecurity}
}
Test-Framework 'Framework report ownership and content are checked before device deletion' {
    $a=New-Analysis;$body=New-WinSecFrameworkMarkdown $a
    $m=@{SchemaVersion='1.0.0';DeviceId=$a.DeviceId;AnalysisId=$a.AnalysisId;FrameworkId=$a.FrameworkId;ContentSha256=(Get-WinSecReportTextHash $body)}
    $text="<!-- WinSec framework findings`n"+(ConvertTo-Json $m -Compress)+"`n-->`n"+$body
    $meta=ConvertFrom-WinSecMarkdownArtifact $text $a.DeviceId
    Assert-Framework ($meta.AnalysisId -ceq $a.AnalysisId)
    Reject-Framework {ConvertFrom-WinSecMarkdownArtifact ($text+'changed') $a.DeviceId}
    Reject-Framework {ConvertFrom-WinSecMarkdownArtifact $text ('local:hw1-'+('c'*64))}
}
Test-Framework 'Export rejects a foreign or injected reference URL even with a recomputed digest' {
    foreach($url in @('https://example.org/unreviewed','https://attack.mitre.org/techniques/T1562/001/','https://www.nist.gov/) [injected](https://example.org)')) {
        $a=New-Analysis;$a.Rows[0].References[0].Url=$url;$a.ContentSha256=Get-WinSecFrameworkAnalysisDigest $a
        Reject-Framework {New-WinSecFrameworkMarkdown $a}
    }
}
Write-Host ('Framework analysis: '+$script:passed+' passed; '+$script:failed+' failed.')
if($script:failed){throw 'Framework analysis tests failed.'}
