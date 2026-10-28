# The full validator runs against synthetic hardware/providers, never native sockets.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'tests/Fixtures/OpenPortsNativeValidationSupport.ps1')
. (Join-Path $root 'tests/Fixtures/OpenPortsMemory.ps1')
function Get-WinSecPortsRequestHardware {'local:hw1-'+('b'*64)}
Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecPortsRequestHardware -Scope Script
function Get-CimInstance {throw 'Native provider prohibited in request tests.'}
function Assert-PortsRequest {param([bool]$Value);if(-not $Value){throw 'Endpoint request assertion failed.'}}
$saved=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-PORTS';Initialize-WinSecOpenPortsFixture
Set-Alias Invoke-WinSecOpenPortsQuery Invoke-WinSecOpenPortsFixtureQuery -Scope Script
try {
    $validator=Join-Path $root 'tests/Integration/Invoke-OpenPortsNativeValidation.ps1'
    $plan=(& $validator -PlanOnly -OperationId ('a'*32)) -join "`n"|ConvertFrom-Json
    Assert-PortsRequest ($plan.Request.ScopeKey -ceq 'WSA-NET-004' -and $plan.Request.ReadOnly -and $plan.Request.PersistReports -ceq $false -and $PortsCalls.Count -eq 0)
    Write-Host '[PASS] Planning binds sources and identity without collecting endpoints'
    $caught=$false;try{$null=& $validator -OperationId ('a'*32) -ApprovedRequestHash ('0'*64)}catch{$caught=$_.Exception.Message -ceq 'OpenPorts request changed or was not approved.'}
    Assert-PortsRequest ($caught -and $PortsCalls.Count -eq 0)
    Write-Host '[PASS] An unapproved hash cannot reach a provider'
    # Keep the synthetic provider's script variables in the same test scope.
    $r=(. $validator -OperationId ('a'*32) -ApprovedRequestHash $plan.RequestHash) -join "`n"|ConvertFrom-Json
    Assert-PortsRequest ($r.ExecutionStatus -ceq 'COMPLETED' -and $r.TcpEndpointCount -eq 3 -and $r.UdpEndpointCount -eq 3 -and
        $r.TechnicalMarkdownValidated -and $r.PublicHistoryRoundtripValidated -and $r.InMemoryFrameworkReports -eq 3 -and
        -not $r.ReportsPersisted -and -not $r.PublicHistoryPersisted -and -not $r.WindowsChanges -and $PortsCalls.Count -eq 3)
    Write-Host '[PASS] Exact synthetic approval exercises the complete in-memory workflow'
    $caught=$false;try{Get-WinSecOpenPortsNativeDiagnostics ([pscustomobject]@{Evidence=[pscustomobject]@{CollectionIssues=@('PRIVATE-ERROR')}})}catch{$caught=$true}
    Assert-PortsRequest $caught
    Write-Host '[PASS] Only closed diagnostic identifiers can leave the validator'
}finally{$env:COMPUTERNAME=$saved}
Write-Host 'Open Ports native request: 4 passed; 0 failed.'
