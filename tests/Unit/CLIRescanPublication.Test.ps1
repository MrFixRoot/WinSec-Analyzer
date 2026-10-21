# WinSec Analyzer - CLI scan publication/ownership contract.
# All dependencies below are synthetic. No scans, startup or persistence.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $projectRoot 'src/CLI/Invoke-WinSecCLI.ps1')
$script:passed=0
$script:failed=0
$script:privateMarker='SYNTHETIC-PRIVATE-PUBLICATION'
function Assert-WinSecPublication {
    param([bool]$Condition)
    if (-not $Condition) {throw 'CLI publication contract assertion failed.'}
}
function Test-WinSecPublication {
    param([string]$Name,[scriptblock]$Action)
    try {$null=& $Action; $script:passed++; Write-Host "[PASS] $Name"}
    catch {$script:failed++; Write-Host "[FAIL] $Name"; Write-Host $_.Exception.Message}
}
function New-WinSecLocalTarget {
    [pscustomobject]@{DeviceId='local:PUBLICATION';Mode='LOCAL';Enabled=$true}
}
function Resolve-WinSecScanTarget {
    param($Coordinator,$DeviceId)
    if ($DeviceId -cne 'local:PUBLICATION') {throw 'Synthetic target rejected.'}
    New-WinSecLocalTarget
}
function Invoke-WinSecCoordinatedScan {
    [CmdletBinding()]
    param($Coordinator,$DeviceId,[scriptblock]$ConfirmAction,[switch]$PersistEvidence)
    Assert-WinSecPublication ($null -ne $ConfirmAction -and -not $PersistEvidence)
    $script:scanCalls++
    return $script:sourceResult
}
function New-WinSecPublicationFixture {
    $deviceId='local:PUBLICATION'; $scanId='publication-1'
    $script:scanCalls=0
    $script:sourceResult=[pscustomobject]@{
        DeviceId=$deviceId;ScanId=$scanId;PublicProjection=$true;ContainsRawEvidence=$false
        ScoringEligible=$false;OverallScore=$null;OverallStatus='NOT_SCORED';ExecutionStatus='COMPLETED'
        SectionResults=@([pscustomobject]@{
            DeviceId=$deviceId;ScanId=$scanId;Key='SystemSecurity';Score=$null;Status='NOT_SCORED'
            Metadata=@{Items=@('original')}
        })
        ControlResults=@([pscustomobject]@{
            DeviceId=$deviceId;ScanId=$scanId;CheckId='WSA-SYS-001';Status='INFORMATIONAL'
            Metadata=@{Items=@('original')}
        })
        Findings=@([pscustomobject]@{
            DeviceId=$deviceId;ScanId=$scanId;CheckId='WSA-SYS-001';FindingId='finding-1'
            Metadata=@{Items=@('original')}
        })
    }
    $key='{0}:{1}{2}:{3}' -f $deviceId.Length,$deviceId,$scanId.Length,$scanId
    [pscustomobject]@{
        State=[pscustomobject]@{SelectedDeviceId=$deviceId;Screen='MainMenu'}
        Context=[pscustomobject]@{
            ScanCoordinator=[pscustomobject]@{ScoringEnabled=$false;RemoteExecution=$false;AutomaticEvidencePersistence=$false}
            Devices=@((New-WinSecLocalTarget));PublicScans=@{};ActiveScanByDevice=@{};LastScanMessage='previous-message'
        }
        Key=$key
    }
}
function Assert-WinSecPublicationRejected {
    param($Fixture)
    $before=ConvertTo-Json -InputObject $Fixture -Depth 20 -Compress
    $published=New-Object 'System.Collections.Generic.List[object]'
    $caught=$null
    try {
        Invoke-WinSecCLILocalRescan -State $Fixture.State -Context $Fixture.Context |
            ForEach-Object {$published.Add($_)}
    }
    catch {$caught=$_}
    Assert-WinSecPublication ($null -ne $caught -and $published.Count -eq 0)
    Assert-WinSecPublication ($caught.Exception.Message -notlike ('*'+$script:privateMarker+'*'))
    Assert-WinSecPublication ($before -ceq (ConvertTo-Json -InputObject $Fixture -Depth 20 -Compress))
}
foreach ($collection in @('SectionResults','ControlResults','Findings')) {
    Test-WinSecPublication ("Response mutation preserves cached and producer records: $collection") {
        $fixture=New-WinSecPublicationFixture
        $response=Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
        $response.$collection[0].ScanId='changed'
        $response.$collection[0].Metadata.Items[0]='changed'
        $cached=$fixture.Context.PublicScans[$fixture.Key]
        Assert-WinSecPublication ($cached.$collection[0].ScanId -ceq 'publication-1' -and
            $cached.$collection[0].Metadata.Items[0] -ceq 'original' -and
            $script:sourceResult.$collection[0].Metadata.Items[0] -ceq 'original')
    }
    Test-WinSecPublication ("Producer mutation preserves cache and response: $collection") {
        $fixture=New-WinSecPublicationFixture
        $response=Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
        $script:sourceResult.$collection[0].ScanId='changed'
        $script:sourceResult.$collection[0].Metadata.Items[0]='changed'
        Assert-WinSecPublication ($response.$collection[0].ScanId -ceq 'publication-1' -and
            $fixture.Context.PublicScans[$fixture.Key].$collection[0].Metadata.Items[0] -ceq 'original')
    }
    foreach ($field in @('Evidence','RawEvidence','OriginalResult','ObservedValue','ExpectedValue')) {
        Test-WinSecPublication ("Private nested data cannot be published: $collection/$field") {
            $fixture=New-WinSecPublicationFixture
            $script:sourceResult.$collection[0].Metadata=@{Keys='decoy';Values=@(@{$field=$script:privateMarker})}
            Assert-WinSecPublicationRejected $fixture
        }
    }
    foreach ($field in @('DeviceId','ScanId')) {
        Test-WinSecPublication ("Foreign nested identity cannot be published: $collection/$field") {
            $fixture=New-WinSecPublicationFixture
            $script:sourceResult.$collection[0].$field='foreign'
            Assert-WinSecPublicationRejected $fixture
        }
    }
}
foreach ($field in @('PublicProjection','ContainsRawEvidence','ScoringEligible')) {
    Test-WinSecPublication ("Coerced root flag rejected before publication: $field") {
        $fixture=New-WinSecPublicationFixture
        $script:sourceResult.$field=if ($field -eq 'PublicProjection') {1} else {0}
        Assert-WinSecPublicationRejected $fixture
    }
}
foreach ($field in @('Score','ScoringPolicy','ScoringEligible')) {
    Test-WinSecPublication ("Nested scoring rejected before publication: $field") {
        $fixture=New-WinSecPublicationFixture
        $script:sourceResult.Findings[0].Metadata=@{$field=1}
        Assert-WinSecPublicationRejected $fixture
    }
}
Test-WinSecPublication 'Structured ScanId is not coerced into a session key' {
    $fixture=New-WinSecPublicationFixture
    $script:sourceResult.ScanId=@('publication-1')
    Assert-WinSecPublicationRejected $fixture
}
foreach ($location in @('ROOT','CONTROL')) {
    Test-WinSecPublication ("Calculated input properties are not executed: $location") {
        $fixture=New-WinSecPublicationFixture
        $script:getterCalls=0
        $record=if ($location -eq 'ROOT') {$script:sourceResult} else {$script:sourceResult.ControlResults[0]}
        $record | Add-Member -MemberType ScriptProperty -Name Title -Value {$script:getterCalls++;$script:privateMarker}
        Assert-WinSecPublicationRejected $fixture
        Assert-WinSecPublication ($script:getterCalls -eq 0)
    }
}
foreach ($kind in @('CYCLE','EXCESSIVE')) {
    Test-WinSecPublication ("Unsafe input graph is not published: $kind") {
        $fixture=New-WinSecPublicationFixture
        if ($kind -eq 'CYCLE') {$script:sourceResult.Findings[0].Metadata=$script:sourceResult}
        else {$script:sourceResult.Findings[0].Metadata=New-Object 'object[]' 10001}
        Assert-WinSecPublicationRejected $fixture
    }
}
Test-WinSecPublication 'Duplicate session keys preserve previous results and active selection' {
    $fixture=New-WinSecPublicationFixture
    $first=Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
    $script:sourceResult.ControlResults[0].Status='ERROR'
    Assert-WinSecPublicationRejected $fixture
    Assert-WinSecPublication ($fixture.Context.PublicScans[$fixture.Key].ControlResults[0].Status -ceq 'INFORMATIONAL')
}
Test-WinSecPublication 'A new scan preserves previous sessions and other devices' {
    $fixture=New-WinSecPublicationFixture
    $fixture.Context.PublicScans['previous-session']=[pscustomobject]@{Marker='previous'}
    $fixture.Context.ActiveScanByDevice['local:OTHER']='other-scan'
    $response=Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
    Assert-WinSecPublication ($fixture.Context.PublicScans.Count -eq 2 -and $script:scanCalls -eq 1 -and
        $fixture.Context.PublicScans['previous-session'].Marker -ceq 'previous' -and
        $fixture.Context.ActiveScanByDevice['local:OTHER'] -ceq 'other-scan' -and
        $fixture.Context.ActiveScanByDevice['local:PUBLICATION'] -ceq $response.ScanId)
}
Test-WinSecPublication 'Cancellation preserves the existing public and navigation state' {
    $fixture=New-WinSecPublicationFixture
    $fixture.Context.PublicScans['previous-session']=[pscustomobject]@{Marker='previous'}
    $fixture.Context.ActiveScanByDevice['local:PUBLICATION']='previous-scan'
    $script:sourceResult=$null
    $before=ConvertTo-Json -InputObject $fixture -Depth 20 -Compress
    $response=Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
    Assert-WinSecPublication ($null -eq $response -and
        $before -ceq (ConvertTo-Json -InputObject $fixture -Depth 20 -Compress))
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if ($script:failed -gt 0) {throw "$script:failed CLI publication test(s) failed."}
