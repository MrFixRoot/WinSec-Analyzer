[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Checks/Network/Test-OpenPorts.ps1')
. (Join-Path $root 'tests/Fixtures/OpenPortsMemory.ps1')
function Get-CimInstance {throw 'Unmocked Windows query prohibited.'}
Set-Alias Invoke-WinSecOpenPortsQuery Invoke-WinSecOpenPortsFixtureQuery -Scope Script
$passed=0;$failed=0
function Assert-Ports {param([bool]$Value);if(-not $Value){throw 'Open Ports assertion failed.'}}
function Reject-Ports {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-Ports $caught}
function Test-Ports {param($Name,[scriptblock]$Action);Initialize-WinSecOpenPortsFixture;try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
Test-Ports 'TCP UDP IPv4 IPv6 and binding scopes are normalized without private provider properties' {
    $s=New-WinSecOpenPortsFixtureSession;$e=$s.ControlResults[0].Evidence
    Assert-Ports ($e.CollectionComplete -and $e.CoverageComplete -and $e.Counts.TCP.Total -eq 3 -and $e.Counts.UDP.Total -eq 3 -and $PortsCalls.Count -eq 3)
    $r=New-WinSecTechnicalReport $s WSA-NET-004 SYNTHETIC SYNTHETIC;$md=ConvertTo-WinSecTechnicalMarkdown $r
    Assert-Ports ($md.Contains('TCP-000001') -and $md.Contains('UDP-000003') -and $md.Contains('IPv6') -and $md.Contains('LOOPBACK') -and
        $md -notmatch 'PRIVATE-|192\.0\.2\.9|NOT_SCORED|/100' -and $md.Contains('sha256:'))
}
Test-Ports 'An observed empty inventory is complete and is not a failed provider' {
    $script:PortsCount=0;$s=New-WinSecOpenPortsFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-004 SYNTHETIC SYNTHETIC
    Assert-Ports ($s.ExecutionStatus -ceq 'COMPLETED' -and @($r.Rows|Where-Object SettingId -CLIKE Inventory.*).Count -eq 0)
}
Test-Ports 'Optional nulls stay unknown while successful execution and limited coverage remain separate' {
    $script:PortsOptionalMissing=$true;$s=New-WinSecOpenPortsFixtureSession;$e=$s.ControlResults[0].Evidence
    $r=New-WinSecTechnicalReport $s WSA-NET-004 SYNTHETIC SYNTHETIC
    Assert-Ports ($e.CollectionComplete -and -not $e.CoverageComplete -and $e.UnknownFieldCount -eq 18 -and (ConvertTo-WinSecTechnicalMarkdown $r).Contains('UNKNOWN'))
}
Test-Ports 'Framework review reports limited coverage when endpoint metadata is unknown' {
    $script:PortsOptionalMissing=$true;$a=New-WinSecOpenPortsFixtureAnalysis $root
    Assert-Ports ($a.UnknownReadingCount -eq 2 -and $a.Rows.Count -eq 2)
}
Test-Ports 'Historical Network Security versions do not acquire newly reviewed adapters' {
    $a=New-WinSecFrameworkAnalysis $root ('local:hw1-'+('b'*64)) SYNTHETIC SECTION NetworkSecurity nist-csf @() @()
    foreach($version in @('1.3.0','1.4.0')){
        $a.RuleCatalogVersion=$version;$a.ContentSha256=Get-WinSecFrameworkAnalysisDigest $a;$body=New-WinSecFrameworkMarkdown $a
        Assert-Ports ($body.Contains('Open Ports and Network Configuration remain pending.') -and -not $body.Contains('WSA-NET-004'))
    }
}
foreach($failure in @('TCP','UDP','Platform')){Test-Ports ('Provider failure remains partial without fabricated zero counts: '+$failure) {
    $script:PortsFailure=$failure;$s=New-WinSecOpenPortsFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-004 SYNTHETIC SYNTHETIC
    Assert-Ports ($s.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS' -and -not $s.ControlResults[0].Evidence.CollectionComplete -and (ConvertTo-WinSecTechnicalMarkdown $r) -notmatch 'PRIVATE-')
}}
foreach($bad in @('Port','State','Address')){Test-Ports ('Required invalid data cannot produce complete or truncated inventory: '+$bad) {
    $script:PortsInvalid=$bad;$s=New-WinSecOpenPortsFixtureSession;$e=$s.ControlResults[0].Evidence
    $null=New-WinSecTechnicalReport $s WSA-NET-004 SYNTHETIC SYNTHETIC
    Assert-Ports (-not $e.CollectionComplete -and $e.Availability.TCP -ceq 'UNKNOWN' -and $null -eq $e.Counts.TCP)
}}
Test-Ports 'Cancellation before and during collection publishes no completed result' {
    Reject-Ports {Test-WinSecOpenPorts ('local:hw1-'+('b'*64)) cancelled -CancellationAction {$true}}
    Reject-Ports {Test-WinSecOpenPorts ('local:hw1-'+('b'*64)) cancelled -CancellationAction {$PortsCalls.Count -ge 2}}
}
Test-Ports 'More than 512 endpoints rejects the provider rather than silently truncating' {
    $script:PortsCount=513;$s=New-WinSecOpenPortsFixtureSession
    Assert-Ports (-not $s.ControlResults[0].Evidence.CollectionComplete -and $s.ControlResults[0].Evidence.Batches.Count -eq 0)
}
Test-Ports 'The maximum inventory fits the existing Markdown budget without losing any endpoint' {
    $script:PortsCount=512;$s=New-WinSecOpenPortsFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-004 SYNTHETIC SYNTHETIC
    $body=ConvertTo-WinSecTechnicalMarkdown $r
    $meta=[ordered]@{SchemaVersion='2.0.0';DeviceId=$r.DeviceId;ScanId=$r.ScanId;CheckId=$r.CheckId;ScopeType=$r.ScopeType;ScopeKey=$r.ScopeKey;ContentSha256=(Get-WinSecReportTextHash $body)}
    $artifact="<!-- WinSec technical report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $null=ConvertFrom-WinSecTechnicalMarkdownArtifact $artifact $r.DeviceId
    Assert-Ports ($s.ControlResults[0].Evidence.Counts.TCP.Total -eq 512 -and $s.ControlResults[0].Evidence.Counts.UDP.Total -eq 512 -and
        @($r.Rows|Where-Object SettingId -CLIKE Inventory.*).Count -eq 16 -and [Text.Encoding]::UTF8.GetByteCount($artifact) -le 1048576)
}
foreach($framework in @('nist-csf','cis-controls','mitre-attack')){Test-Ports ('Every saved non-loopback batch has contextual references, never an exposure verdict: '+$framework) {
    $a=New-WinSecOpenPortsFixtureAnalysis $root $framework;$md=New-WinSecFrameworkMarkdown $a
    Assert-Ports ($a.Rows.Count -eq 2 -and @($a.Rows|Where-Object {$_.References.Count -eq 0}).Count -eq 0 -and $PortsCalls.Count -eq 3 -and $md -notmatch 'PRIVATE-')
}}
Test-Ports 'Loopback-only endpoints are retained without fictitious network exposure warnings' {
    $script:PortsLoopbackOnly=$true;$a=New-WinSecOpenPortsFixtureAnalysis $root
    Assert-Ports ($a.Rows.Count -eq 0 -and $a.ReadingCount -gt 0)
}
Test-Ports 'Stored counts, scope, protocol and duplicate IDs cannot be manipulated' {
    $r=New-WinSecTechnicalReport (New-WinSecOpenPortsFixtureSession) WSA-NET-004 SYNTHETIC SYNTHETIC
    $copy=Copy-WinSecResultData $r;@($copy.Rows|Where-Object SettingId -CEQ Counts.TCP.Total)[0].Value=0;Reject-Ports {ConvertTo-WinSecTechnicalReport $copy}
    $copy=Copy-WinSecResultData $r;$copy.ScopeKey='WSA-NET-003';Reject-Ports {ConvertTo-WinSecTechnicalReport $copy}
    $row=@($r.Rows|Where-Object SettingId -CEQ Inventory.TCP.0001)[0];$items=ConvertTo-WinSecOpenPortsBatch $row.Value
    $items[1].Id=$items[0].Id;Reject-Ports {ConvertTo-WinSecOpenPortsBatch (ConvertTo-Json -InputObject @{SchemaVersion='1.0.0';Protocol='TCP';Items=$items} -Compress)}
}
Test-Ports 'Windows context uses the common collection schema without authorizing production' {
    $plan=Get-WinSecAssessmentProfilePlan $root @('WSA-NET-004') WSA-W11-23H2-PRO-DEF-BASE
    $check=Get-WinSecRegisteredCheck (Get-WinSecCheckRegistry $root) WSA-NET-004
    Assert-Ports ($plan.Preview.Policies[0].CatalogId -ceq 'WSA-PORTS-COLLECTION' -and -not $check.ExecutionEnabled)
}
Write-Host ('Open Ports: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'Open Ports tests failed.'}
