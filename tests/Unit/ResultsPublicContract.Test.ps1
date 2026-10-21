# WinSec Analyzer - public control display contract. Read-only catalog fixtures.
# No startup, scans, Windows queries, evidence storage or configuration changes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/UI/Components/Table.ps1')
. (Join-Path $root 'src/UI/Screens/Results.ps1')
$catalog=Get-Content -LiteralPath (Join-Path $root 'config/checks.json') -Raw|ConvertFrom-Json
$script:passed=0; $script:failed=0
function Assert-WinSecControls {param([bool]$Condition);if(-not $Condition){throw 'Control display assertion failed.'}}
function Test-WinSecControls {
    param([string]$Name,[scriptblock]$Action)
    try {$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch {$script:failed++;Write-Host "[FAIL] $Name";Write-Host $_.Exception.Message}
}
function Assert-WinSecControlsRejected {
    param([object[]]$Records)
    $caught=$null;$published=New-Object 'System.Collections.Generic.List[object]'
    try {Get-WinSecSectionControls -SectionKey SystemSecurity -ControlResults $Records|ForEach-Object{$published.Add($_)}}
    catch {$caught=$_}
    Assert-WinSecControls ($null -ne $caught -and $published.Count -eq 0 -and
        $caught.Exception.Message -notlike '*SYNTHETIC-CONTROL-PRIVATE*')
}
foreach($check in $catalog.checks) {
    Test-WinSecControls ('Catalog control identity is available before scanning: '+$check.checkId) {
        $rows=@(Get-WinSecSectionControls -SectionKey $check.sectionKey)
        $match=@($rows|Where-Object{$_.CheckId -ceq $check.checkId})
        $expected=if($check.implementationStatus -ceq 'PLANNED'){'PLANNED'}else{'PENDING'}
        Assert-WinSecControls ($match.Count -eq 1 -and $match[0].Key -ceq $check.controlKey -and
            $match[0].Name -ceq $check.name -and $match[0].Status -ceq $expected -and
            $match[0].Score -ceq 'NOT_SCORED' -and $match[0].CheckFile -ceq $check.execution.script)
    }
    Test-WinSecControls ('Public CheckId preserves NOT_SELECTED: '+$check.checkId) {
        $rows=@(Get-WinSecSectionControls -SectionKey $check.sectionKey -ControlResults @(
            [pscustomobject]@{CheckId=$check.checkId;SectionKey=$check.sectionKey;Status='NOT_SELECTED';ObservedStatus='NOT_SELECTED'}
        ))
        $match=@($rows|Where-Object{$_.CheckId -ceq $check.checkId})
        Assert-WinSecControls ($match.Count -eq 1 -and $match[0].Status -ceq 'NOT_SELECTED' -and $match[0].Score -ceq 'NOT_SCORED')
    }
}
foreach($status in @('PASS','FAIL','ERROR','UNKNOWN','NOT_EVALUATED','PENDING','NOT_CHECKED','NOT_APPLICABLE','NOT_SELECTED','MANUAL','INFORMATIONAL')) {
    Test-WinSecControls ("Public status is preserved without inference or score: $status") {
        $rows=@(Get-WinSecSectionControls -SectionKey SystemSecurity -ControlResults @(
            @{CheckId='WSA-SYS-001';SectionKey='SystemSecurity';Status=$status;ObservedStatus='ERROR'}
        ))
        Assert-WinSecControls ($rows[0].Status -ceq $status -and $rows[0].ObservedStatus -ceq 'ERROR' -and $rows[0].Score -ceq 'NOT_SCORED')
    }
}
foreach($identity in @('Key','ControlKey','Name')) {
    Test-WinSecControls ("Legacy identity remains available: $identity") {
        $value=if($identity -eq 'Name'){'Windows Defender'}else{'Defender'}
        $rows=@(Get-WinSecSectionControls -SectionKey SystemSecurity -ControlResults @(@{$identity=$value;Status='NOT_EVALUATED'}))
        Assert-WinSecControls ($rows[0].CheckId -ceq 'WSA-SYS-001' -and $rows[0].Status -ceq 'NOT_EVALUATED')
    }
}
foreach($value in @(0,100,'90/100','--/100',$false,@{Value='SYNTHETIC-CONTROL-PRIVATE'})) {
    Test-WinSecControls ('Caller score cannot authorize scoring: '+$value.GetType().Name) {
        Assert-WinSecControlsRejected @(@{CheckId='WSA-SYS-001';Key='Defender';Score=$value})
    }
}
foreach($record in @(
    @{CheckId='invalid'},@{CheckId=@('WSA-SYS-001')},@{CheckId=123},
    @{CheckId='WSA-SYS-001';SectionKey='NetworkSecurity'},
    @{CheckId='WSA-SYS-001';Key='BitLocker'},
    @{CheckId='WSA-SYS-001';ControlKey='BitLocker'},
    @{Key='Defender';ControlKey='BitLocker'},
    @{Key='invalid'},@{Name='invalid'},@{Status='UNKNOWN'},
    @{CheckId='WSA-SYS-001';Status='SYNTHETIC-CONTROL-PRIVATE'},
    @{CheckId='WSA-SYS-001';Status=@('ERROR')},
    @{CheckId='WSA-SYS-001';ObservedStatus=@('ERROR')},
    @{CheckId='WSA-SYS-001';ObservedStatus='SYNTHETIC-CONTROL-PRIVATE'}
)) {
    Test-WinSecControls 'Invalid control data rejects without partial rows' {Assert-WinSecControlsRejected @($record)}
}
Test-WinSecControls 'Duplicate CheckId rejects instead of picking the first record' {
    Assert-WinSecControlsRejected @(@{CheckId='WSA-SYS-001';Status='UNKNOWN'},@{CheckId='WSA-SYS-001';Status='ERROR'})
}
Test-WinSecControls 'Duplicate legacy/public aliases reject as the same control' {
    Assert-WinSecControlsRejected @(@{Key='Defender';Status='UNKNOWN'},@{CheckId='WSA-SYS-001';Status='ERROR'})
}
foreach($field in @('CheckId','Key','Name','SectionKey','Status','ObservedStatus','Score')) {
    Test-WinSecControls ("Calculated field rejected without executing getter: $field") {
        $script:getterCalls=0
        $record=[pscustomobject]@{CheckId='WSA-SYS-001';Key='Defender';SectionKey='SystemSecurity';Status='UNKNOWN';Name='Windows Defender';Score=$null;ObservedStatus=$null}
        $record.PSObject.Properties.Remove($field)
        $record|Add-Member -MemberType ScriptProperty -Name $field -Value {$script:getterCalls++;'SYNTHETIC-CONTROL-PRIVATE'}
        Assert-WinSecControlsRejected @($record)
        Assert-WinSecControls ($script:getterCalls -eq 0)
    }
}
Test-WinSecControls 'Another section cannot update selected control rows' {
    $rows=@(Get-WinSecSectionControls -SectionKey SystemSecurity -ControlResults @(@{CheckId='WSA-NET-001';SectionKey='NetworkSecurity';Status='ERROR'}))
    Assert-WinSecControls ($rows.Count -eq 3 -and @($rows|Where-Object{$_.Status -cne 'PENDING'}).Count -eq 0)
}
Test-WinSecControls 'Caller metadata is neither rendered nor shared and input is preserved' {
    $record=[pscustomobject]@{CheckId='WSA-SYS-001';Name='SYNTHETIC-CONTROL-PRIVATE';Status='INFORMATIONAL';Metadata=@{Value='original'}}
    $before=ConvertTo-Json -InputObject $record -Depth 5 -Compress
    $rows=@(Get-WinSecSectionControls -SectionKey SystemSecurity -ControlResults @($record))
    Assert-WinSecControls ($rows[0].Name -ceq 'Windows Defender' -and $rows[0].Status -ceq 'INFORMATIONAL' -and
        (ConvertTo-Json -InputObject $rows -Compress) -notlike '*SYNTHETIC-CONTROL-PRIVATE*' -and
        $null -eq $rows[0].PSObject.Properties['Metadata'])
    $rows[0].Status='ERROR'
    Assert-WinSecControls ($before -ceq (ConvertTo-Json -InputObject $record -Depth 5 -Compress))
}
Test-WinSecControls 'Catalog load failure rejects without exposing its diagnostic value' {
    function Get-WinSecCheckRegistry {param($ProjectRoot);throw 'SYNTHETIC-CONTROL-PRIVATE'}
    Assert-WinSecControlsRejected @()
}
Test-WinSecControls 'Catalog visibility filters display without authorizing or running checks' {
    . (Join-Path $root 'src/Core/CheckRegistry.ps1')
    $script:displayRegistryFixture=Get-WinSecCheckRegistry -ProjectRoot $root
    $hidden=@($script:displayRegistryFixture.Checks|Where-Object{$_.CheckId -ceq 'WSA-SYS-002'})
    $hidden[0].Visible=$false
    function Get-WinSecCheckRegistry {param($ProjectRoot);$script:displayRegistryFixture}
    $rows=@(Get-WinSecSectionControls -SectionKey SystemSecurity -ControlResults @(@{CheckId='WSA-SYS-002';Status='NOT_SELECTED'}))
    Assert-WinSecControls ($rows.Count -eq 2 -and @($rows|Where-Object{$_.CheckId -ceq 'WSA-SYS-002'}).Count -eq 0 -and
        @($script:displayRegistryFixture.Checks|Where-Object{$_.ExecutionEnabled}).Count -eq 0)
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if($script:failed -gt 0){throw "$script:failed public control display test(s) failed."}
