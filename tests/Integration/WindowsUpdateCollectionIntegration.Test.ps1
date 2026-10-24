# Collector -> audit adapter -> ResultModel -> public history, entirely in memory.
# Production Windows Update stays disabled; no permission or catalog fixture overrides.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Services/WindowsUpdateReferenceService.ps1')
. (Join-Path $root 'src/Core/WindowsUpdateAutomation.ps1')
. (Join-Path $root 'src/Checks/System/Test-WindowsUpdate.ps1')
. (Join-Path $root 'tests/Fixtures/WindowsUpdateMemory.ps1')
function Save-WinSecPublicHistory {throw 'Unexpected native history write.'}
function Save-WinSecEvidence {throw 'Unexpected native evidence write.'}
$script:passed=0;$script:failed=0
$catalogPath=Join-Path $root 'config/checks.json';$scoringPath=Join-Path $root 'config/scoring.json'
$catalogHash=(Get-FileHash $catalogPath -Algorithm SHA256).Hash;$scoringHash=(Get-FileHash $scoringPath -Algorithm SHA256).Hash
$registry=Get-WinSecCheckRegistry -ProjectRoot $root
$check=Get-WinSecRegisteredCheck -Registry $registry -CheckId WSA-SYS-003
$servicingCatalog=(Get-WinSecWindowsUpdateReferenceCatalog $root).Catalog
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
    Assert-WinSecWUIntegration ($caught -and $script:WU.IdentityReads -eq 0 -and $script:WU.CimReads -eq 0 -and $script:WU.KeyReads -eq 0 -and
        $script:WU.VersionReads -eq 0 -and $script:WU.RebootReads -eq 0 -and $script:WU.NamedPolicyReads -eq 0)
}
Test-WinSecWUIntegration 'Coordinator cannot start or publish the disabled control even when confirmation accepts' {
    $coordinator=New-WinSecScanCoordinator;$target=New-WinSecLocalTarget
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $coordinator.PublicHistoryEnabled=$false
    $caught=$false
    try{$null=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -DeviceId $target.DeviceId -ScanId wu-disabled `
        -ScopeType CONTROL -ScopeKey WSA-SYS-003 -ConfirmAction {$true}}
    catch{$caught=$true}
    Assert-WinSecWUIntegration ($caught -and $coordinator.Sessions.Count -eq 0 -and $script:WU.CimReads -eq 0 -and $script:WU.KeyReads -eq 0 -and
        $script:WU.VersionReads -eq 0 -and $script:WU.RebootReads -eq 0 -and $script:WU.NamedPolicyReads -eq 0)
}
Test-WinSecWUIntegration 'Audit adapter and result model preserve identity but project no raw Windows Update evidence or score' {
    $session=New-WinSecWUFixtureSession;$public=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecWUIntegration ($session.ControlResults[0].Evidence.PolicyRegistry.AutomaticUpdates.AUOptions.Value -eq 4 -and
        $public.ScopeType -ceq 'CONTROL' -and $public.ScopeKey -ceq 'WSA-SYS-003' -and $public.DeviceId -ceq $script:WU.DeviceId -and
        $public.ControlResults.Count -eq 1 -and $public.ControlResults[0].ObservedStatus -ceq 'INFORMATIONAL' -and
        $null -eq $public.OverallScore -and $public.Findings.Count -eq 0 -and $public.ReviewItems.Count -eq 0 -and
        (ConvertTo-Json $public -Depth 32) -notmatch 'PRIVATE-WU|"Evidence"|PolicyRegistry|AUOptions|StartMode|VersionRegistry|RestartInformation|CurrentBuildNumber|"UBR"|AutomationPolicy|NamedPolicy|SetEDURestart')
}
Test-WinSecWUIntegration 'Canonical public history roundtrip keeps only the existing safe contract and never recollects' {
    $session=New-WinSecWUFixtureSession;$expected=ConvertTo-WinSecPublicScanResult $session
    $before=$script:WU.CimReads+$script:WU.KeyReads+$script:WU.VersionReads+$script:WU.RebootReads+$script:WU.NamedPolicyReads
    $record=New-WinSecPublicHistoryRecord $session
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    Assert-WinSecWUIntegration ((Get-WinSecPublicHistoryJson $expected) -ceq (Get-WinSecPublicHistoryJson $restored.PublicResult) -and
        $before -eq ($script:WU.CimReads+$script:WU.KeyReads+$script:WU.VersionReads+$script:WU.RebootReads+$script:WU.NamedPolicyReads) -and $null -eq $restored.PublicResult.OverallScore -and
        (Get-WinSecPublicHistoryJson $record) -notmatch 'VersionRegistry|RestartInformation|CurrentBuildNumber|"UBR"|AutomationPolicy|NamedPolicy')
}
Test-WinSecWUIntegration 'The session owns its input; changing provider fixture values cannot change a public snapshot' {
    $session=New-WinSecWUFixtureSession;$before=Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult $session)
    $script:WU.Values.AutomaticUpdates.NoAutoUpdate=1;$script:WU.Services[0].StartMode='Disabled'
    $script:WU.VersionValues.UBR=0;$script:WU.RebootValue=$true
    $script:WU.NamedPolicies.AllowAutoUpdate.Value=5
    Assert-WinSecWUIntegration ($session.ControlResults[0].Evidence.PolicyRegistry.AutomaticUpdates.NoAutoUpdate.Value -eq 0 -and
        $session.ControlResults[0].Evidence.VersionRegistry.UBR.Value -eq 9711 -and
        $session.ControlResults[0].Evidence.AutomationPolicy.AllowAutoUpdate.Value -eq 2 -and
        -not $session.ControlResults[0].Evidence.RestartInformation.Value -and
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
Test-WinSecWUIntegration 'Collected and adapted telemetry reaches the pure servicing comparison without a second provider query' {
    $script:WU.Systems[0].OperatingSystemSKU=[uint32]4
    $session=New-WinSecWUFixtureSession;$control=$session.ControlResults[0]
    $before=$script:WU.CimReads+$script:WU.KeyReads+$script:WU.VersionReads+$script:WU.RebootReads+$script:WU.NamedPolicyReads
    $p=ConvertTo-WinSecWindowsUpdateServicingPlatform $servicingCatalog $control
    $review=Get-WinSecWindowsUpdateServicingReference $servicingCatalog $p '2026-10-24T12:00:00Z'
    Assert-WinSecWUIntegration ($p.Release -ceq '24H2' -and $p.Channel -ceq 'GAC' -and $p.Revision -eq 9711 -and
        $p.RestartState -ceq 'NOT_PENDING' -and $review.SecuritySupport.State -ceq 'SUPPORTED' -and $review.SecurityBaseline.State -ceq 'MET' -and
        $before -eq ($script:WU.CimReads+$script:WU.KeyReads+$script:WU.VersionReads+$script:WU.RebootReads+$script:WU.NamedPolicyReads) -and
        $null -eq $session.ConfigurationAssessment -and $session.Findings.Count -eq 0)
}
foreach($fault in @('RebootPending','RebootUnavailable','RevisionUnreadable','BuildConflict')) {
    Test-WinSecWUIntegration ('Real collector boundaries preserve unresolved servicing facts: '+$fault) {
        $script:WU.Systems[0].OperatingSystemSKU=[uint32]4
        switch($fault) {
            RebootPending {$script:WU.RebootValue=$true};RebootUnavailable {$script:WU.RebootFails=$true}
            RevisionUnreadable {$script:WU.FailValues=@('Version.UBR')}
            BuildConflict {$script:WU.VersionValues.CurrentBuildNumber='26200'}
        }
        $session=New-WinSecWUFixtureSession
        $p=ConvertTo-WinSecWindowsUpdateServicingPlatform $servicingCatalog $session.ControlResults[0]
        $review=Get-WinSecWindowsUpdateServicingReference $servicingCatalog $p '2026-10-24T12:00:00Z'
        Assert-WinSecWUIntegration ($review.SecurityBaseline.State -ceq 'UNKNOWN' -and $session.Findings.Count -eq 0 -and
            $null -eq $session.ConfigurationAssessment -and
            (Get-WinSecPublicHistoryJson (New-WinSecPublicHistoryRecord $session)) -notmatch 'PRIVATE-WU|VersionRegistry|RestartInformation|CurrentBuildNumber|"UBR"')
        if($fault -ceq 'BuildConflict'){Assert-WinSecWUIntegration ($review.SecuritySupport.State -ceq 'UNKNOWN')}
        else {Assert-WinSecWUIntegration ($review.SecuritySupport.State -ceq 'SUPPORTED')}
    }
}
foreach($case in @('Automatic','Manual','Conflict','Unavailable','Deadline','Override','Default')) {
    Test-WinSecWUIntegration ('Collector and audit adapter preserve safe automation interpretation: '+$case) {
        switch($case) {
            Manual {$script:WU.Values.AutomaticUpdates.AUOptions=3}
            Conflict {$script:WU.NamedPolicies.AllowAutoUpdate.Managed=$true;$script:WU.NamedPolicies.AllowAutoUpdate.Value=0}
            Unavailable {$script:WU.NamedPolicyFailures=@('AllowAutoUpdate')}
            Deadline {$script:WU.NamedPolicies.ConfigureDeadlineForQualityUpdates.Managed=$true}
            Override {$script:WU.NamedPolicies.IgnoreWindowsUpdateGroupPolicies.Managed=$true;$script:WU.NamedPolicies.IgnoreWindowsUpdateGroupPolicies.Value=1}
            Default {$script:WU.MissingKeys=@('AutomaticUpdates','WindowsUpdate')}
        }
        $session=New-WinSecWUFixtureSession;$before=$script:WU.NamedPolicyReads
        $review=Get-WinSecWindowsUpdateAutomationReview $servicingCatalog $session.ControlResults[0]
        $expected=switch($case){Manual {'NOT_AUTOMATIC'};{$_ -in @('Automatic','Default')} {'AUTOMATIC'};default {'UNKNOWN'}}
        Assert-WinSecWUIntegration ($review.State -ceq $expected -and $script:WU.NamedPolicyReads -eq $before -and $before -eq 5 -and
            $session.Findings.Count -eq 0 -and $null -eq $session.ConfigurationAssessment -and
            (Get-WinSecPublicHistoryJson (New-WinSecPublicHistoryRecord $session)) -notmatch 'AutomationPolicy|NamedPolicy|PRIVATE-WU')
    }
}
Test-WinSecWUIntegration 'Catalog and scoring files are unchanged after all synthetic operations' {
    Assert-WinSecWUIntegration ((Get-FileHash $catalogPath -Algorithm SHA256).Hash -ceq $catalogHash -and
        (Get-FileHash $scoringPath -Algorithm SHA256).Hash -ceq $scoringHash)
}
[Console]::WriteLine(('Windows Update collection integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Windows Update collection integration failed.'}
