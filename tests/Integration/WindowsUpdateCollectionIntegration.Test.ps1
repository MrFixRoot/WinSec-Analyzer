# Collector -> audit adapter -> ResultModel -> public history, entirely in memory.
# Production Windows Update stays disabled; no permission or catalog fixture overrides.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Checks/System/Test-WindowsUpdate.ps1')
. (Join-Path $root 'tests/Fixtures/WindowsUpdateMemory.ps1')
function Save-WinSecPublicHistory {throw 'Unexpected native history write.'}
function Save-WinSecEvidence {throw 'Unexpected native evidence write.'}
$script:passed=0;$script:failed=0
$catalogPath=Join-Path $root 'config/checks.json';$scoringPath=Join-Path $root 'config/scoring.json'
$catalogHash=(Get-FileHash $catalogPath -Algorithm SHA256).Hash;$scoringHash=(Get-FileHash $scoringPath -Algorithm SHA256).Hash
$registry=Get-WinSecCheckRegistry -ProjectRoot $root
$check=Get-WinSecRegisteredCheck -Registry $registry -CheckId WSA-SYS-003
function Assert-WinSecWUIntegration {param([bool]$Value);if(-not $Value){throw 'Windows Update integration assertion failed.'}}
function Test-WinSecWUIntegration {
    param([string]$Name,[scriptblock]$Action)
    Reset-WinSecWindowsUpdateFixture
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
function New-WinSecWUFixtureSession {
    $raw=Test-WinSecWindowsUpdate -DeviceId $script:WU.DeviceId -ScanId wu-integration-1 -CheckId WSA-SYS-003
    $record=ConvertTo-WinSecAuditRecord -RawResult $raw -Check $check -DeviceId $raw.DeviceId -ScanId $raw.ScanId
    New-WinSecResultSession -DeviceId $raw.DeviceId -ScanId $raw.ScanId -StartedAtUTC $raw.TimestampUTC `
        -CompletedAtUTC ([datetime]::UtcNow.ToString('o')) -ExecutionStatus COMPLETED -ExpectedCheckIds @('WSA-SYS-003') `
        -ControlResults @($record) -ScopeType CONTROL -ScopeKey WSA-SYS-003 -CatalogVersion $registry.CatalogVersion
}
Test-WinSecWUIntegration 'Production catalog retains pending validation and refuses implementation execution' {
    Assert-WinSecWUIntegration ($check.ImplementationStatus -ceq 'PENDING_VALIDATION' -and -not $check.ExecutionEnabled -and
        -not $check.ExecutionReady -and $check.FunctionName -ceq 'Test-WinSecWindowsUpdate')
    $caught=$false;try{$null=Get-WinSecAuditImplementation -Check $check}catch{$caught=$true}
    Assert-WinSecWUIntegration ($caught -and $script:WU.IdentityReads -eq 0 -and $script:WU.CimReads -eq 0 -and $script:WU.KeyReads -eq 0)
}
Test-WinSecWUIntegration 'Coordinator cannot start or publish the disabled control even when confirmation accepts' {
    $coordinator=New-WinSecScanCoordinator;$target=New-WinSecLocalTarget
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $coordinator.PublicHistoryEnabled=$false
    $caught=$false
    try{$null=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -DeviceId $target.DeviceId -ScanId wu-disabled `
        -ScopeType CONTROL -ScopeKey WSA-SYS-003 -ConfirmAction {$true}}
    catch{$caught=$true}
    Assert-WinSecWUIntegration ($caught -and $coordinator.Sessions.Count -eq 0 -and $script:WU.CimReads -eq 0 -and $script:WU.KeyReads -eq 0)
}
Test-WinSecWUIntegration 'Audit adapter and result model preserve identity but project no raw Windows Update evidence or score' {
    $session=New-WinSecWUFixtureSession;$public=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecWUIntegration ($session.ControlResults[0].Evidence.PolicyRegistry.AutomaticUpdates.AUOptions.Value -eq 4 -and
        $public.ScopeType -ceq 'CONTROL' -and $public.ScopeKey -ceq 'WSA-SYS-003' -and $public.DeviceId -ceq $script:WU.DeviceId -and
        $public.ControlResults.Count -eq 1 -and $public.ControlResults[0].ObservedStatus -ceq 'INFORMATIONAL' -and
        $null -eq $public.OverallScore -and $public.Findings.Count -eq 0 -and $public.ReviewItems.Count -eq 0 -and
        (ConvertTo-Json $public -Depth 32) -notmatch 'PRIVATE-WU|"Evidence"|PolicyRegistry|AUOptions|StartMode')
}
Test-WinSecWUIntegration 'Canonical public history roundtrip keeps only the existing safe contract and never recollects' {
    $session=New-WinSecWUFixtureSession;$expected=ConvertTo-WinSecPublicScanResult $session
    $before=$script:WU.CimReads+$script:WU.KeyReads
    $record=New-WinSecPublicHistoryRecord $session
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    Assert-WinSecWUIntegration ((Get-WinSecPublicHistoryJson $expected) -ceq (Get-WinSecPublicHistoryJson $restored.PublicResult) -and
        $before -eq ($script:WU.CimReads+$script:WU.KeyReads) -and $null -eq $restored.PublicResult.OverallScore)
}
Test-WinSecWUIntegration 'The session owns its input; changing provider fixture values cannot change a public snapshot' {
    $session=New-WinSecWUFixtureSession;$before=Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult $session)
    $script:WU.Values.AutomaticUpdates.NoAutoUpdate=1;$script:WU.Services[0].StartMode='Disabled'
    Assert-WinSecWUIntegration ($session.ControlResults[0].Evidence.PolicyRegistry.AutomaticUpdates.NoAutoUpdate.Value -eq 0 -and
        (Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult $session)) -ceq $before)
}
foreach($fault in @('Device','Scan','Check','Section')) {
    Test-WinSecWUIntegration ('Audit adapter rejects foreign collector identity: '+$fault) {
        $raw=Test-WinSecWindowsUpdate -DeviceId $script:WU.DeviceId -ScanId wu-integration-1 -CheckId WSA-SYS-003
        switch($fault){Device {$raw.DeviceId='local:other'};Scan {$raw.ScanId='other'};Check {$raw.CheckId='WSA-SYS-001'};Section {$raw.SectionKey='NetworkSecurity'}}
        $caught=$false;try{$null=ConvertTo-WinSecAuditRecord -RawResult $raw -Check $check -DeviceId $script:WU.DeviceId -ScanId wu-integration-1}catch{$caught=$true}
        Assert-WinSecWUIntegration $caught
    }
}
Test-WinSecWUIntegration 'Partial collection is not a configuration failure or a fake finding' {
    $script:WU.FailClasses=@('Win32_Service');$session=New-WinSecWUFixtureSession;$public=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecWUIntegration ($session.ControlResults[0].Evidence.CollectionIssues -ccontains 'UPDATE_SERVICE_QUERY_FAILED' -and
        $public.ControlResults[0].ObservedStatus -ceq 'INFORMATIONAL' -and $public.Findings.Count -eq 0 -and $null -eq $public.OverallScore)
}
Test-WinSecWUIntegration 'Catalog and scoring files are unchanged after all synthetic operations' {
    Assert-WinSecWUIntegration ((Get-FileHash $catalogPath -Algorithm SHA256).Hash -ceq $catalogHash -and
        (Get-FileHash $scoringPath -Algorithm SHA256).Hash -ceq $scoringHash)
}
[Console]::WriteLine(('Windows Update collection integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Windows Update collection integration failed.'}
