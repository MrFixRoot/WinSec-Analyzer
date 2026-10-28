# The full validator runs against synthetic hardware/providers, never native sockets.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'tests/Fixtures/NetworkConfigurationNativeValidationSupport.ps1')
. (Join-Path $root 'tests/Fixtures/NetworkConfigurationMemory.ps1')
function Get-WinSecNetworkRequestHardware {'local:hw1-'+('b'*64)}
Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecNetworkRequestHardware -Scope Script
function Get-CimInstance {throw 'Native provider prohibited in request tests.'}
function Assert-NetworkRequest {param([bool]$Value);if(-not $Value){throw 'Endpoint request assertion failed.'}}
$saved=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-NETWORK';Initialize-WinSecNetworkConfigurationFixture
Set-Alias Invoke-WinSecNetworkConfigurationQuery Invoke-WinSecNetworkConfigurationFixtureQuery -Scope Script
try {
    $validator=Join-Path $root 'tests/Integration/Invoke-NetworkConfigurationNativeValidation.ps1'
    $plan=(& $validator -PlanOnly -OperationId ('a'*32)) -join "`n"|ConvertFrom-Json
    Assert-NetworkRequest ($plan.Request.ScopeKey -ceq 'WSA-NET-005' -and $plan.Request.ReadOnly -and $plan.Request.PersistReports -ceq $false -and $NetworkCalls.Count -eq 0)
    Write-Host '[PASS] Planning binds sources and identity without collecting endpoints'
    $caught=$false;try{$null=& $validator -OperationId ('a'*32) -ApprovedRequestHash ('0'*64)}catch{$caught=$_.Exception.Message -ceq 'NetworkConfiguration request changed or was not approved.'}
    Assert-NetworkRequest ($caught -and $NetworkCalls.Count -eq 0)
    Write-Host '[PASS] An unapproved hash cannot reach a provider'
    # Keep the synthetic provider's script variables in the same test scope.
    $r=(. $validator -OperationId ('a'*32) -ApprovedRequestHash $plan.RequestHash) -join "`n"|ConvertFrom-Json
    Assert-NetworkRequest ($r.ExecutionStatus -ceq 'COMPLETED' -and $r.InventoryCounts.Adapter -eq 2 -and $r.InventoryCounts.DNSGlobal -eq 1 -and
        $r.TechnicalMarkdownValidated -and $r.PublicHistoryRoundtripValidated -and $r.InMemoryFrameworkReports -eq 3 -and
        -not $r.ReportsPersisted -and -not $r.PublicHistoryPersisted -and -not $r.WindowsChanges -and $NetworkCalls.Count -eq 11)
    Write-Host '[PASS] Exact synthetic approval exercises the complete in-memory workflow'
    $caught=$false;try{Get-WinSecNetworkConfigurationNativeDiagnostics ([pscustomobject]@{Evidence=[pscustomobject]@{CollectionIssues=@('PRIVATE-ERROR')}})}catch{$caught=$true}
    Assert-NetworkRequest $caught
    Write-Host '[PASS] Only closed diagnostic identifiers can leave the validator'
    Assert-NetworkRequest ($r.ProviderDiagnostics -is [array] -and $r.ProviderDiagnostics.Count -eq 0)
    Write-Host '[PASS] A complete native workflow has no fabricated provider diagnostics'
    $script:NetworkInvalid='IPEnabled';$script:NetworkCalls.Clear()
    $plan=(& $validator -PlanOnly -OperationId ('b'*32)) -join "`n"|ConvertFrom-Json
    $partial=(. $validator -OperationId ('b'*32) -ApprovedRequestHash $plan.RequestHash) -join "`n"|ConvertFrom-Json
    Assert-NetworkRequest ($partial.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS' -and -not $partial.CollectionComplete -and
        $partial.ProviderDiagnostics.Count -eq 1 -and $partial.ProviderDiagnostics[0] -ceq 'Legacy:NORMALIZATION:NETWORK_REQUIRED_FIELD_IPEnabled' -and
        $null -eq $partial.InventoryCounts.Legacy -and $partial.InMemoryFrameworkReports -eq 3 -and -not $partial.ReportsPersisted)
    Write-Host '[PASS] Partial Legacy collection stays partial and emits only its reviewed field code'
    foreach($codes in @(@('Legacy:QUERY:PRIVATE-ERROR'),@('Legacy:NORMALIZATION:NETWORK_REQUIRED_FIELD_Password'),@('Legacy:QUERY:UNAVAILABLE','Legacy:QUERY:UNAVAILABLE'),@('Adapter:QUERY:UNAVAILABLE'))){
        $caught=$false
        try{$null=Get-WinSecNetworkConfigurationNativeProviderDiagnostics ([pscustomobject]@{Evidence=[pscustomobject]@{
            ProviderDiagnostics=$codes;Availability=[pscustomobject]@{Legacy='UNKNOWN';Adapter='OBSERVED'};CollectionIssues=@('LEGACY_UNAVAILABLE')}})}catch{$caught=$true}
        Assert-NetworkRequest $caught
    }
    Write-Host '[PASS] Private text, unreviewed fields, duplicate roles and contradictory diagnostics are rejected'
}finally{$env:COMPUTERNAME=$saved}
Write-Host 'Network Configuration native request: 7 passed; 0 failed.'
