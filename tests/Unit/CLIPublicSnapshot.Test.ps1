# WinSec Analyzer - CLI public input isolation/privacy regressions.
# Synthetic data only; no application startup, scans or persistence.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $projectRoot 'src/CLI/Invoke-WinSecCLI.ps1')
$script:passed = 0
$script:failed = 0
$script:privateMarker = 'SYNTHETIC-PRIVATE-CLI-SNAPSHOT'
function Assert-WinSecPublicSnapshot {
    param([bool]$Condition)
    if (-not $Condition) { throw 'Public input isolation/privacy assertion failed.' }
}
function Test-WinSecPublicSnapshot {
    param([string]$Name, [scriptblock]$Action)
    try { $null = & $Action; $script:passed++; Write-Host "[PASS] $Name" }
    catch { $script:failed++; Write-Host "[FAIL] $Name"; Write-Host $_.Exception.Message }
}
function New-WinSecPublicSnapshotFixture {
    $deviceId = 'local:PUBLIC-SNAPSHOT'
    $scanId = 'public-snapshot-1'
    $result = [pscustomobject]@{
        DeviceId=$deviceId; ScanId=$scanId; PublicProjection=$true; ContainsRawEvidence=$false
        ScoringEligible=$false; OverallScore=$null; OverallStatus='NOT_SCORED'
        SectionResults=@([pscustomobject]@{
            DeviceId=$deviceId; ScanId=$scanId; Key='SystemSecurity'; Score=$null
            Name='System Security'; Status='NOT_SCORED'
        })
        ControlResults=@([pscustomobject]@{
            DeviceId=$deviceId; ScanId=$scanId; CheckId='WSA-SYS-001'
            SectionKey='SystemSecurity'; Status='NOT_EVALUATED'
        })
        Findings=@([pscustomobject]@{
            DeviceId=$deviceId; ScanId=$scanId; CheckId='WSA-SYS-001'
            FindingId='finding-1'; Kind='EVALUATION_PENDING'
        })
    }
    $key = '{0}:{1}{2}:{3}' -f $deviceId.Length,$deviceId,$scanId.Length,$scanId
    [pscustomobject]@{
        State=[pscustomobject]@{SelectedDeviceId=$deviceId}
        Context=[pscustomobject]@{
            PublicScans=@{$key=$result}; ActiveScanByDevice=@{$deviceId=$scanId}
        }
        Result=$result; Key=$key
    }
}
function Assert-WinSecPublicSnapshotRejected {
    param([object]$Fixture)
    $published = New-Object 'System.Collections.Generic.List[object]'
    $caught = $null
    try {
        Get-WinSecCLIActiveAssessment -State $Fixture.State -Context $Fixture.Context |
            ForEach-Object { $published.Add($_) }
    }
    catch { $caught = $_ }
    Assert-WinSecPublicSnapshot ($null -ne $caught -and $published.Count -eq 0)
    Assert-WinSecPublicSnapshot ($caught.Exception.Message -notlike ('*'+$script:privateMarker+'*'))
}

foreach ($collection in @('SectionResults','ControlResults','Findings')) {
    Test-WinSecPublicSnapshot ("Screen mutation preserves cached records: $collection") {
        $fixture = New-WinSecPublicSnapshotFixture
        $fixture.Result.$collection[0] | Add-Member -NotePropertyName Metadata `
            -NotePropertyValue @{ Items=@([pscustomobject]@{Value='original'}) }
        $view = Get-WinSecCLIActiveAssessment -State $fixture.State -Context $fixture.Context
        $view.$collection[0].ScanId = 'changed'
        $view.$collection[0].Metadata.Items[0].Value = 'changed'
        $again = Get-WinSecCLIActiveAssessment -State $fixture.State -Context $fixture.Context
        Assert-WinSecPublicSnapshot ($again.$collection[0].ScanId -ceq 'public-snapshot-1' -and
            $again.$collection[0].Metadata.Items[0].Value -ceq 'original' -and
            -not [object]::ReferenceEquals($view.$collection[0],$fixture.Result.$collection[0]))
    }
    foreach ($field in @('Evidence','RawEvidence','OriginalResult','ObservedValue','ExpectedValue')) {
        Test-WinSecPublicSnapshot ("Nested private field rejected: $collection/$field") {
            $fixture = New-WinSecPublicSnapshotFixture
            $fixture.Result.$collection[0] | Add-Member -NotePropertyName Metadata `
                -NotePropertyValue @{Keys='decoy'; Values=@(@{$field=$script:privateMarker})}
            Assert-WinSecPublicSnapshotRejected $fixture
        }
    }
    Test-WinSecPublicSnapshot ("Dictionary records cannot hide evidence: $collection") {
        $fixture = New-WinSecPublicSnapshotFixture
        $dictionary = @{}
        foreach ($property in $fixture.Result.$collection[0].PSObject.Properties) {
            $dictionary[$property.Name] = $property.Value
        }
        $dictionary['Evidence'] = $null
        $fixture.Result.$collection = @($dictionary)
        Assert-WinSecPublicSnapshotRejected $fixture
    }
}
foreach ($field in @('Score','OverallScore','ScoreValue','ScoreResult','ScoringPolicy','ScoringEnabled','ScoringEligible')) {
    Test-WinSecPublicSnapshot ("Nested scoring rejected: $field") {
        $fixture = New-WinSecPublicSnapshotFixture
        $fixture.Result.Findings[0] | Add-Member -NotePropertyName Metadata -NotePropertyValue @{$field=1}
        Assert-WinSecPublicSnapshotRejected $fixture
    }
}
foreach ($field in @('PublicProjection','ContainsRawEvidence','ScoringEligible')) {
    Test-WinSecPublicSnapshot ("Numeric flag rejected: $field") {
        $fixture = New-WinSecPublicSnapshotFixture
        $fixture.Result.$field = if ($field -eq 'PublicProjection') {1} else {0}
        Assert-WinSecPublicSnapshotRejected $fixture
    }
}
foreach ($field in @('Score','ScoringEnabled','ScoringEligible')) {
    Test-WinSecPublicSnapshot ("Nested metadata retains array types before validation: $field") {
        $fixture = New-WinSecPublicSnapshotFixture
        $metadata = @{}
        $metadata[$field] = if ($field -eq 'Score') { ,@() } else { ,@($false) }
        $fixture.Result.Findings[0] | Add-Member -NotePropertyName Metadata -NotePropertyValue $metadata
        Assert-WinSecPublicSnapshotRejected $fixture
    }
}
Test-WinSecPublicSnapshot 'Active ScanId cannot be coerced from an array' {
    $fixture = New-WinSecPublicSnapshotFixture
    $fixture.Context.ActiveScanByDevice[$fixture.State.SelectedDeviceId] = @('public-snapshot-1')
    Assert-WinSecPublicSnapshotRejected $fixture
}
foreach ($location in @('ROOT','CONTROL','UNUSED_COLLECTION')) {
    Test-WinSecPublicSnapshot ("Calculated properties rejected without execution: $location") {
        $fixture = New-WinSecPublicSnapshotFixture
        $script:getterCalls = 0
        $record = switch ($location) {
            'ROOT' {$fixture.Result}
            'CONTROL' {$fixture.Result.ControlResults[0]}
            'UNUSED_COLLECTION' {
                $item = [pscustomobject]@{ReviewId='review-1'}
                $fixture.Result | Add-Member -NotePropertyName ReviewItems -NotePropertyValue @($item)
                $item
            }
        }
        $record | Add-Member -MemberType ScriptProperty -Name Title -Value {
            $script:getterCalls++; $script:privateMarker
        }
        Assert-WinSecPublicSnapshotRejected $fixture
        Assert-WinSecPublicSnapshot ($script:getterCalls -eq 0)
    }
}
foreach ($location in @('ROOT','RECORD','ARRAY')) {
    Test-WinSecPublicSnapshot ("Cycles rejected: $location") {
        $fixture = New-WinSecPublicSnapshotFixture
        $value = switch ($location) {
            'ROOT' {$fixture.Result}
            'RECORD' {
                $record=$fixture.Result.ControlResults[0]
                $record | Add-Member -NotePropertyName Back -NotePropertyValue $record
                $record
            }
            'ARRAY' {$array=New-Object 'object[]' 1; $array[0]=$array; ,$array}
        }
        $fixture.Result | Add-Member -NotePropertyName Metadata -NotePropertyValue $value
        Assert-WinSecPublicSnapshotRejected $fixture
    }
}
Test-WinSecPublicSnapshot 'Excessive graphs rejected without partial output' {
    $fixture = New-WinSecPublicSnapshotFixture
    $fixture.Result.Findings[0] | Add-Member -NotePropertyName Metadata -NotePropertyValue (New-Object 'object[]' 10001)
    Assert-WinSecPublicSnapshotRejected $fixture
}
Test-WinSecPublicSnapshot 'Excessive depth rejected without partial output' {
    $fixture = New-WinSecPublicSnapshotFixture
    $node = @{}
    for ($index=0;$index -lt 66;$index++) {$node=@{Next=$node}}
    $fixture.Result | Add-Member -NotePropertyName Metadata -NotePropertyValue $node
    Assert-WinSecPublicSnapshotRejected $fixture
}
Test-WinSecPublicSnapshot 'Unused public collections cannot hide raw data' {
    $fixture = New-WinSecPublicSnapshotFixture
    $fixture.Result | Add-Member -NotePropertyName ReviewItems -NotePropertyValue @(@{RawEvidence=$script:privateMarker})
    Assert-WinSecPublicSnapshotRejected $fixture
}
Test-WinSecPublicSnapshot 'Unselected devices are not copied or inspected' {
    $fixture = New-WinSecPublicSnapshotFixture
    $other = [pscustomobject]@{Metadata=$null}; $other.Metadata=$other
    $fixture.Context.PublicScans['unselected'] = $other
    $result = Get-WinSecCLIActiveAssessment -State $fixture.State -Context $fixture.Context
    Assert-WinSecPublicSnapshot ($result.ScanId -ceq 'public-snapshot-1')
}
Test-WinSecPublicSnapshot 'Safe dictionary projections remain supported and detached' {
    $fixture = New-WinSecPublicSnapshotFixture
    $control = @{}
    foreach ($property in $fixture.Result.ControlResults[0].PSObject.Properties) {
        $control[$property.Name] = $property.Value
    }
    $control['Metadata'] = @{Keys='public';Values=@('original');ScoringEnabled=$false;Score=$null}
    $fixture.Result.ControlResults = @($control)
    $projection = @{}
    foreach ($property in $fixture.Result.PSObject.Properties) {$projection[$property.Name]=$property.Value}
    $fixture.Context.PublicScans[$fixture.Key] = $projection
    $view = Get-WinSecCLIActiveAssessment -State $fixture.State -Context $fixture.Context
    $view.ControlResults[0].Metadata['Values'][0] = 'changed'
    Assert-WinSecPublicSnapshot ($view.OverallStatus -ceq 'NOT_SCORED' -and
        $control.Metadata['Values'][0] -ceq 'original' -and
        $view.ControlResults[0].Metadata.Keys -ceq 'public')
}
Test-WinSecPublicSnapshot 'Rejection preserves cache and navigation' {
    $fixture = New-WinSecPublicSnapshotFixture
    $fixture.Result.ControlResults[0] | Add-Member -NotePropertyName Metadata -NotePropertyValue @{Evidence=$null}
    $before = ConvertTo-Json -InputObject $fixture -Depth 15 -Compress
    Assert-WinSecPublicSnapshotRejected $fixture
    Assert-WinSecPublicSnapshot ($before -ceq (ConvertTo-Json -InputObject $fixture -Depth 15 -Compress))
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if ($script:failed -gt 0) {throw "$script:failed CLI public snapshot test(s) failed."}
