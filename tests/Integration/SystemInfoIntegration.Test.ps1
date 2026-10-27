# Real coordinator, Defender, applicability, evaluation and public-history contracts.
# Only Windows queries, catalog approval and storage boundaries are synthetic.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$script:catalog=Get-WinSecCheckRegistry -ProjectRoot $root
$script:draft=Get-WinSecAssessmentCatalog $root WSA-SYS-001
$script:assessment=(Get-Command Invoke-WinSecScanAssessment).ScriptBlock
$enabled=@($script:catalog.Checks|Where-Object ExecutionEnabled)
if($enabled.Count -ne 6 -or (($enabled.CheckId | Sort-Object) -join '|') -cne 'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -or
    @($enabled | Where-Object {-not $_.ExecutionReady -or $_.ImplementationStatus -cne 'VALIDATED'}).Count -ne 0){
    throw 'Only validated System Security, Firewall, SMBv1 and Remote Desktop controls may be enabled in production.'
}
$script:passed=0; $script:failed=0
function Assert-WinSecSystemInfoIntegration {param([bool]$Value);if(-not $Value){throw 'SystemInfo integration assertion failed.'}}
function Get-CimInstance {
    [CmdletBinding()]
    param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    if ($Namespace -ceq 'root/cimv2' -and $ClassName -ceq 'Win32_ComputerSystemProduct') {
        return [pscustomobject]@{UUID=$script:uuid}
    }
    if ($Namespace -ceq 'root/cimv2' -and $ClassName -ceq 'Win32_OperatingSystem') {
        $script:osReads++; $script:events.Add('OS')
        if ($script:osError) { throw 'PRIVATE-CONTEXT-PROVIDER-ERROR' }
        return $script:os
    }
    throw 'Unexpected synthetic CIM query.'
}
function Get-MpComputerStatus {
    [CmdletBinding()]param()
    $script:defenderReads++; $script:events.Add('DEFENDER')
    if ($script:cancelDuringCollection) { $script:cancel=$true }
    if ($script:changeHardware) { $script:uuid='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }
    [pscustomobject]@{AMRunningMode='Normal';AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$false}
}
function Get-MpPreference {
    [CmdletBinding()]param()
    [pscustomobject]@{PUAProtection=1;ExclusionPath=@('C:\PRIVATE-CONTEXT-EXCLUSION');
        AttackSurfaceReductionRules_Ids=@();AttackSurfaceReductionRules_Actions=@()}
}
function Import-WinSecDeviceInventory {
    param($ProjectRoot)
    [pscustomobject]@{schemaVersion='1.2.0';targets=@(New-WinSecLocalTarget);removedDeviceHashes=@()}
}
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $copy=Copy-WinSecResultData $script:catalog
    foreach($item in $copy.Checks){$item.ExecutionEnabled=$false;$item.ExecutionReady=$false}
    if ($script:ready) {
        $check=$copy.Checks|Where-Object CheckId -CEQ WSA-SYS-001
        $check.ExecutionEnabled=$true; $check.ExecutionReady=$true
        $check.ImplementationStatus='VALIDATED'; $check.RegistryStatus='READY'
    }
    $copy
}
function Get-WinSecAssessmentCatalog {
    param($ProjectRoot,$CheckId)
    if ($CheckId -ceq 'WSA-SYS-001') { Copy-WinSecResultData $script:policy }
}
function Invoke-WinSecScanAssessment {
    param($AuditResult,$ProjectRoot,$TargetContext,$DependencyEvidence,$CatalogSnapshots)
    $script:receivedContext=Copy-WinSecResultData $TargetContext
    & $script:assessment @PSBoundParameters
}
function Save-WinSecPublicHistory {
    param($ProjectRoot,$Session)
    if ($script:writeError) { throw 'PRIVATE-CONTEXT-WRITE-ERROR' }
    $script:stored.Add((Get-WinSecPublicHistoryJson (New-WinSecPublicHistoryRecord $Session)))
}
function Invoke-WinSecSystemInfoIntegrationScan {
    param([string]$ScanId='context-scan-1',[string]$ScopeType='CONTROL',[string]$ScopeKey='WSA-SYS-001')
    Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -DeviceId $script:device -ScanId $ScanId `
        -ScopeType $ScopeType -ScopeKey $ScopeKey -ConfirmAction {$script:events.Add('CONFIRMED');$true} `
        -CancellationAction {$script:cancel} -ProgressCallback {param($p);$script:events.Add($p.Phase)}
}
function Test-WinSecSystemInfoIntegration {
    param([string]$Name,[scriptblock]$Action)
    $script:uuid='12345678-1234-4567-89ab-123456789abc'
    $script:ready=$true; $script:osError=$false; $script:writeError=$false; $script:cancel=$false
    $script:changeHardware=$false; $script:cancelDuringCollection=$false
    $script:osReads=0; $script:defenderReads=0; $script:receivedContext=$null
    $script:events=New-Object 'System.Collections.Generic.List[string]'
    $script:stored=New-Object 'System.Collections.Generic.List[string]'
    $script:os=[pscustomobject]@{Caption='Microsoft Windows 11 Pro';Version='10.0.26100';BuildNumber='26100';
        OperatingSystemSKU=[uint32]48;ProductType=[uint32]1;RegisteredUser='PRIVATE-CONTEXT-USER'}
    $policy=Copy-WinSecResultData $script:draft.Catalog
    $policy.CatalogId='SYNTHETIC-CONTEXT';$policy.CatalogVersion='test-1';$policy.Status='APPROVED'
    $policy.ScoringEnabled=$false;$policy|Add-Member -NotePropertyName EvaluationEnabled -NotePropertyValue $true
    $rule=Copy-WinSecResultData $policy.Criteria[2];$rule.Approved=$true
    $rule.Source=[pscustomobject]@{Framework='LOCAL_POLICY';Version='test-1';ControlId='SYNTHETIC-CONTEXT-RT';
        Title='SYNTHETIC context policy';Url='https://example.invalid/synthetic-context'}
    $rule.Verification=[pscustomobject]@{Status='VERIFIED';ReviewedBy='SYNTHETIC';ReviewedAtUTC='2026-10-16T00:00:00Z'}
    $rule.Applicability=[pscustomobject]@{OSFamily='Windows';OSRelease='Windows 11 10.0.26100';Edition='SKU:48';Profile='SYNTHETIC'}
    $policy.Criteria=@($rule);$policy.ReviewOnly=@()
    $script:policy=[pscustomobject]@{Catalog=$policy;Sha256=('C'*64)}
    $script:coordinator=New-WinSecScanCoordinator
    $target=New-WinSecLocalTarget; $script:device=$target.DeviceId
    $script:coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $script:coordinator.AssessmentEnabled=$true; $script:coordinator.PublicHistoryEnabled=$true
    try { $null=& $Action; $script:passed++; Write-Host ('[PASS] '+$Name) }
    catch { $script:failed++; Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message); Write-Host $_.ScriptStackTrace }
}
Test-WinSecSystemInfoIntegration 'Initialization never queries OS or Defender' {
    Assert-WinSecSystemInfoIntegration ($script:osReads -eq 0 -and $script:defenderReads -eq 0)
}
Test-WinSecSystemInfoIntegration 'Confirmed scan obtains local context during finalization without inventing a profile' {
    $p=Invoke-WinSecSystemInfoIntegrationScan
    Assert-WinSecSystemInfoIntegration (($script:events -join ',') -ceq 'CONFIRMED,READING,DEFENDER,CHECK_COMPLETED,FINALIZING,OS,COMPLETED')
    Assert-WinSecSystemInfoIntegration ($script:receivedContext.OSRelease -ceq 'Windows 11 10.0.26100' -and
        $script:receivedContext.Edition -ceq 'SKU:48' -and $script:receivedContext.Profile -ceq 'UNRESOLVED' -and
        $script:receivedContext.DeviceId -ceq $script:device -and $script:receivedContext.ScanId -ceq $p.ScanId)
    Assert-WinSecSystemInfoIntegration ($script:osReads -eq 1 -and $p.Findings[0].Kind -ceq 'CATALOG_NOT_READY' -and
        $p.OverallStatus -ceq 'NOT_SCORED' -and @($p.Findings|Where-Object Kind -EQ CONFIGURATION_DEVIATION).Count -eq 0)
}
Test-WinSecSystemInfoIntegration 'Device, section and control scopes retain independent public history' {
    $null=Invoke-WinSecSystemInfoIntegrationScan -ScanId 'context-device' -ScopeType DEVICE -ScopeKey ALL
    $null=Invoke-WinSecSystemInfoIntegrationScan -ScanId 'context-section' -ScopeType SECTION -ScopeKey SystemSecurity
    $null=Invoke-WinSecSystemInfoIntegrationScan -ScanId 'context-control'
    Assert-WinSecSystemInfoIntegration ($script:osReads -eq 3 -and $script:stored.Count -eq 3 -and $script:coordinator.Sessions.Count -eq 3)
    foreach ($json in $script:stored) {
        $record=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $json)
        Assert-WinSecSystemInfoIntegration ($record.Record.DeviceId -ceq $script:device -and
            $json -notmatch 'PRIVATE-CONTEXT|RegisteredUser|OperatingSystemSKU|DefenderStatus|UNRESOLVED')
    }
}
Test-WinSecSystemInfoIntegration 'Confirmation cancellation does not query OS or Defender' {
    $p=Invoke-WinSecCoordinatedScan $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction {$false}
    Assert-WinSecSystemInfoIntegration ($null -eq $p -and $script:osReads -eq 0 -and
        $script:defenderReads -eq 0 -and $script:coordinator.Sessions.Count -eq 0)
}
Test-WinSecSystemInfoIntegration 'Esc after the collector skips context and preserves previous history' {
    $previous=Invoke-WinSecSystemInfoIntegrationScan
    $script:cancelDuringCollection=$true
    $next=Invoke-WinSecSystemInfoIntegrationScan -ScanId 'context-cancelled'
    Assert-WinSecSystemInfoIntegration ($null -eq $next -and $script:osReads -eq 1 -and
        $script:stored.Count -eq 1 -and $script:coordinator.Sessions.Count -eq 1 -and $null -ne $previous)
}
Test-WinSecSystemInfoIntegration 'Disabled checks do not trigger context collection' {
    $script:ready=$false
    $message=''
    try { $null=Invoke-WinSecSystemInfoIntegrationScan -ScopeType DEVICE -ScopeKey ALL } catch { $message=$_.Exception.Message }
    Assert-WinSecSystemInfoIntegration ($message -like 'NO_EXECUTABLE_CHECKS:*' -and
        $script:osReads -eq 0 -and $script:defenderReads -eq 0 -and $script:stored.Count -eq 0)
    $caught=$false
    try { $null=Invoke-WinSecSystemInfoIntegrationScan -ScanId 'disabled-control' } catch { $caught=$true }
    Assert-WinSecSystemInfoIntegration ($caught -and $script:osReads -eq 0 -and $script:defenderReads -eq 0)
}
Test-WinSecSystemInfoIntegration 'Independent consumers with assessment disabled do not query OS' {
    $script:coordinator.AssessmentEnabled=$false; $p=Invoke-WinSecSystemInfoIntegrationScan
    Assert-WinSecSystemInfoIntegration ($script:osReads -eq 0 -and $null -eq $script:receivedContext -and
        $p.OverallStatus -ceq 'NOT_SCORED')
}
Test-WinSecSystemInfoIntegration 'CIM failure leaves applicability unresolved and exports no provider exception' {
    $script:osError=$true; $p=Invoke-WinSecSystemInfoIntegrationScan
    Assert-WinSecSystemInfoIntegration ($script:receivedContext.OSRelease -ceq 'UNRESOLVED' -and
        $p.Findings[0].Kind -ceq 'CATALOG_NOT_READY' -and ($script:stored -join '|') -notmatch 'PRIVATE-CONTEXT')
}
Test-WinSecSystemInfoIntegration 'Hardware change aborts context collection and publication' {
    $script:changeHardware=$true; $caught=$false
    try { $null=Invoke-WinSecSystemInfoIntegrationScan } catch { $caught=$true }
    Assert-WinSecSystemInfoIntegration ($caught -and $script:osReads -eq 0 -and
        $script:stored.Count -eq 0 -and $script:coordinator.Sessions.Count -eq 0)
}
Test-WinSecSystemInfoIntegration 'Explicit bound context is preserved without a second OS query' {
    $context=[pscustomobject]@{DeviceId=$script:device;ScanId='explicit-context';OSFamily='Windows';
        OSRelease='Windows 11 10.0.26100';Edition='SKU:48';Profile='SYNTHETIC'}
    $p=Invoke-WinSecCoordinatedScan $script:coordinator -DeviceId $script:device -ScanId 'explicit-context' `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction {$true} -TargetContext $context `
        -DependencyEvidence @{'WSA-SYS-001'=@{'active-antivirus-mode'=$true}}
    Assert-WinSecSystemInfoIntegration ($script:osReads -eq 0 -and $p.Findings[0].Kind -ceq 'CONFIGURATION_DEVIATION' -and
        $p.Findings[0].Guidance.Profile -ceq 'SYNTHETIC' -and $p.OverallStatus -ceq 'NOT_SCORED')
}
Test-WinSecSystemInfoIntegration 'Failed storage never publishes the newly collected context or session' {
    $previous=Invoke-WinSecSystemInfoIntegrationScan
    $before=Get-WinSecPublicHistoryJson (Get-WinSecCoordinatorPublicResult -Coordinator $script:coordinator -DeviceId $script:device -ScanId $previous.ScanId)
    $script:writeError=$true; $caught=$false
    try { $null=Invoke-WinSecSystemInfoIntegrationScan -ScanId 'failed-context-save' } catch { $caught=$true }
    $retained=Get-WinSecCoordinatorPublicResult -Coordinator $script:coordinator -DeviceId $script:device -ScanId $previous.ScanId
    $missing=Get-WinSecCoordinatorPublicResult -Coordinator $script:coordinator -DeviceId $script:device -ScanId 'failed-context-save'
    Assert-WinSecSystemInfoIntegration ($caught -and $script:coordinator.Sessions.Count -eq 1 -and $script:stored.Count -eq 1 -and
        $null -eq $missing -and (Get-WinSecPublicHistoryJson $retained) -ceq $before)
}
Write-Host ('SystemInfo integration: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if ($script:failed) { throw 'SystemInfo integration failed.' }
