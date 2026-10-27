# Approval planning only, with synthetic hardware. Never execute a Rdp provider.
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'tests/Fixtures/RdpNativeValidationSupport.ps1')
function Get-WinSecRdpRequestHardware {'local:hw1-'+('b'*64)}
Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecRdpRequestHardware -Scope Script
function Get-CimInstance {throw 'PlanOnly must not query Windows.'}


function Invoke-WinSecRdpQuery {throw 'Request planning must not query Rdp.'}
function Assert-Request {param([bool]$Value);if(-not $Value){throw 'Rdp request assertion failed.'}}
$savedHostname=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-FW-REQUEST'
try {
    $validator=Join-Path $root 'tests/Integration/Invoke-RdpNativeValidation.ps1'
    $plan=(& $validator -PlanOnly -OperationId ('a'*32)) -join "`n" | ConvertFrom-Json
    Assert-Request ($plan.Request.DeviceId -ceq ('local:hw1-'+('b'*64)) -and $plan.Request.ScopeKey -ceq 'WSA-NET-003' -and
        $plan.Request.ReadOnly -ceq $true -and -not $plan.Request.PersistReports -and -not $plan.Request.PersistPublicHistory -and
        $plan.RequestHash -cmatch '\A[A-F0-9]{64}\z' -and $plan.Request.DependencyCount -gt 50)
    Write-Host '[PASS] PlanOnly binds synthetic identity, scope, runtime and frozen sources without collection'
    $caught=$false
    try{$null=& $validator -OperationId ('a'*32) -ApprovedRequestHash ('0'*64)}catch{$caught=$_.Exception.Message -ceq 'Rdp request changed or was not approved.'}
    Assert-Request $caught
    Write-Host '[PASS] An unapproved or stale hash is rejected before Rdp execution'
    $control=[pscustomobject]@{ObservedStatus='ERROR';Evidence=$null}
    $issues=@(Get-WinSecRdpNativeDiagnostics $control)
    Assert-Request ($issues.Count -eq 1 -and $issues[0] -ceq 'COLLECTOR_EVIDENCE_UNAVAILABLE')
    Write-Host '[PASS] Failed collection without evidence produces an explicit safe diagnostic'
    $control.ObservedStatus='INFORMATIONAL';$control.Evidence=[pscustomobject]@{CollectionIssues=@()}
    Assert-Request (@(Get-WinSecRdpNativeDiagnostics $control).Count -eq 0)
    $control.Evidence.CollectionIssues=@(Get-WinSecRdpIssueCodes)
    Assert-Request (@(Get-WinSecRdpNativeDiagnostics $control).Count -eq $control.Evidence.CollectionIssues.Count)
    Write-Host '[PASS] Empty and complete closed diagnostic catalogs remain valid'
    foreach($bad in @(@('UNREVIEWED_CODE'),@('PRIVATE-PROVIDER-ERROR'),@($null),$null,'PROFILESLOCAL_UNAVAILABLE')) {
        $control.Evidence.CollectionIssues=$bad;$caught=$false
        try{$null=Get-WinSecRdpNativeDiagnostics $control}catch{$caught=$true}
        Assert-Request $caught
    }
    Write-Host '[PASS] Unknown codes, raw text, null entries and malformed lists remain rejected'
    $control.Evidence|Add-Member FieldDiagnostics @('Permissions.DenyAdminPermissionForCustomization:BOOLEAN_VALUE')
    $control.Evidence|Add-Member ProviderDiagnostics @('Redirection:INVALID_PROPERTY')
    Assert-Request (@(Get-WinSecRdpNativeDetailDiagnostics $control Field).Count -eq 1 -and @(Get-WinSecRdpNativeDetailDiagnostics $control Provider).Count -eq 1)
    foreach($bad in @(@('General.Password:NULL_VALUE'),@('PRIVATE-ERROR'),@($null),$null,'General.SecurityLayer:NULL_VALUE')){
        $control.Evidence.FieldDiagnostics=$bad;$caught=$false
        try{$null=Get-WinSecRdpNativeDetailDiagnostics $control Field}catch{$caught=$true};Assert-Request $caught
    }
    Write-Host '[PASS] Detail diagnostics accept only reviewed fields and closed reasons without values'
    . (Join-Path $root 'tests/Fixtures/RdpMemory.ps1')
    Initialize-WinSecRdpFixture
    Set-Alias Invoke-WinSecRdpQuery Invoke-WinSecRdpFixtureQuery -Scope Script
    Set-Alias Read-WinSecRdpRegistryValue Read-WinSecRdpFixtureRegistry -Scope Script
    # Same test scope keeps synthetic provider aliases visible to declarations
    # loaded by the validator; no production provider may be reached.
    $result=(. $validator -OperationId ('a'*32) -ApprovedRequestHash $plan.RequestHash) -join "`n" | ConvertFrom-Json
    Assert-Request ($result.ExecutionStatus -ceq 'COMPLETED' -and $result.CollectionComplete -and $result.CollectionValidated -and
        $result.CollectionIssues.Count -eq 0 -and $result.TechnicalMarkdownValidated -and $result.PublicHistoryRoundtripValidated -and
        $result.HostSupport -ceq 'SUPPORTED' -and $result.UnknownFieldCount -eq 0 -and $result.UnavailableFields.Count -eq 0 -and
        $result.FieldDiagnostics.Count -eq 0 -and $result.ProviderDiagnostics.Count -eq 0 -and
        $result.InMemoryFrameworkReports -eq 3 -and -not $result.ReportsPersisted -and -not $result.WindowsChanges -and
        $script:RdpCalls.Count -eq (9+@(Get-WinSecRdpRegistryDefinitions).Count))
    Write-Host '[PASS] Exact approval runs the full validator with synthetic providers and no persistence'
} finally {$env:COMPUTERNAME=$savedHostname}
Write-Host 'Rdp request: 7 passed; 0 failed.'
