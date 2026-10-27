# Approval planning only, with synthetic hardware. Never execute a Firewall provider.
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
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
} finally {$env:COMPUTERNAME=$savedHostname}
Write-Host 'Firewall request: 2 passed; 0 failed.'
