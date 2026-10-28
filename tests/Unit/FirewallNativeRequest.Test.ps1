# Approval planning only, with synthetic hardware. Never execute a Firewall provider.
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'tests/Fixtures/FirewallNativeValidationSupport.ps1')
function Get-WinSecFirewallRequestHardware {'local:hw1-'+('b'*64)}
Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecFirewallRequestHardware -Scope Script
function Get-CimInstance {throw 'PlanOnly must not query Windows.'}
function Get-NetFirewallProfile {throw 'Request planning must not query Firewall.'}
function Invoke-WinSecFirewallQuery {throw 'Request planning must not query Firewall.'}
function Assert-Request {param([bool]$Value);if(-not $Value){throw 'Firewall request assertion failed.'}}
$savedHostname=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-FW-REQUEST'
try {
    $validator=Join-Path $root 'tests/Integration/Invoke-FirewallNativeValidation.ps1'
    $plan=(& $validator -PlanOnly -OperationId ('a'*32)) -join "`n" | ConvertFrom-Json
    Assert-Request ($plan.Request.DeviceId -ceq ('local:hw1-'+('b'*64)) -and $plan.Request.ScopeKey -ceq 'WSA-NET-001' -and
        $plan.Request.ReadOnly -ceq $true -and -not $plan.Request.PersistReports -and -not $plan.Request.PersistPublicHistory -and
        $plan.RequestHash -cmatch '\A[A-F0-9]{64}\z' -and $plan.Request.DependencyCount -gt 50)
    Write-Host '[PASS] PlanOnly binds synthetic identity, scope, runtime and frozen sources without collection'
    $caught=$false
    try{$null=& $validator -OperationId ('a'*32) -ApprovedRequestHash ('0'*64)}catch{$caught=$_.Exception.Message -ceq 'Firewall request changed or was not approved.'}
    Assert-Request $caught
    Write-Host '[PASS] An unapproved or stale hash is rejected before Firewall execution'
    $control=[pscustomobject]@{ObservedStatus='ERROR';Evidence=$null}
    $issues=@(Get-WinSecFirewallNativeDiagnostics $control)
    Assert-Request ($issues.Count -eq 1 -and $issues[0] -ceq 'COLLECTOR_EVIDENCE_UNAVAILABLE')
    Write-Host '[PASS] Failed collection without evidence produces an explicit safe diagnostic'
    $control.ObservedStatus='INFORMATIONAL';$control.Evidence=[pscustomobject]@{CollectionIssues=@()}
    Assert-Request (@(Get-WinSecFirewallNativeDiagnostics $control).Count -eq 0)
    $control.Evidence.CollectionIssues=@(Get-WinSecFirewallIssueCodes)
    Assert-Request (@(Get-WinSecFirewallNativeDiagnostics $control).Count -eq $control.Evidence.CollectionIssues.Count)
    Write-Host '[PASS] Empty and complete closed diagnostic catalogs remain valid'
    foreach($bad in @(@('UNREVIEWED_CODE'),@('PRIVATE-PROVIDER-ERROR'),@($null),$null,'PROFILESLOCAL_UNAVAILABLE')) {
        $control.Evidence.CollectionIssues=$bad;$caught=$false
        try{$null=Get-WinSecFirewallNativeDiagnostics $control}catch{$caught=$true}
        Assert-Request $caught
    }
    Write-Host '[PASS] Unknown codes, raw text, null entries and malformed lists remain rejected'
} finally {$env:COMPUTERNAME=$savedHostname}
Write-Host 'Firewall request: 5 passed; 0 failed.'
