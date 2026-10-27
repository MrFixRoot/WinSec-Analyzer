# Approval planning only, with synthetic hardware. Never execute a Smb provider.
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'tests/Fixtures/SmbNativeValidationSupport.ps1')
function Get-WinSecSmbRequestHardware {'local:hw1-'+('b'*64)}
Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecSmbRequestHardware -Scope Script
function Get-CimInstance {throw 'PlanOnly must not query Windows.'}
function Get-SmbServerConfiguration {throw 'Request planning must not query SMB.'}
function Get-SmbClientConfiguration {throw 'Request planning must not query SMB.'}
function Invoke-WinSecSmbQuery {throw 'Request planning must not query Smb.'}
function Assert-Request {param([bool]$Value);if(-not $Value){throw 'Smb request assertion failed.'}}
$savedHostname=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-FW-REQUEST'
try {
    $validator=Join-Path $root 'tests/Integration/Invoke-SmbNativeValidation.ps1'
    $plan=(& $validator -PlanOnly -OperationId ('a'*32)) -join "`n" | ConvertFrom-Json
    Assert-Request ($plan.Request.DeviceId -ceq ('local:hw1-'+('b'*64)) -and $plan.Request.ScopeKey -ceq 'WSA-NET-002' -and
        $plan.Request.ReadOnly -ceq $true -and -not $plan.Request.PersistReports -and -not $plan.Request.PersistPublicHistory -and
        $plan.RequestHash -cmatch '\A[A-F0-9]{64}\z' -and $plan.Request.DependencyCount -gt 50)
    Write-Host '[PASS] PlanOnly binds synthetic identity, scope, runtime and frozen sources without collection'
    $caught=$false
    try{$null=& $validator -OperationId ('a'*32) -ApprovedRequestHash ('0'*64)}catch{$caught=$_.Exception.Message -ceq 'Smb request changed or was not approved.'}
    Assert-Request $caught
    Write-Host '[PASS] An unapproved or stale hash is rejected before Smb execution'
    $control=[pscustomobject]@{ObservedStatus='ERROR';Evidence=$null}
    $issues=@(Get-WinSecSmbNativeDiagnostics $control)
    Assert-Request ($issues.Count -eq 1 -and $issues[0] -ceq 'COLLECTOR_EVIDENCE_UNAVAILABLE')
    Write-Host '[PASS] Failed collection without evidence produces an explicit safe diagnostic'
    $control.ObservedStatus='INFORMATIONAL';$control.Evidence=[pscustomobject]@{CollectionIssues=@()}
    Assert-Request (@(Get-WinSecSmbNativeDiagnostics $control).Count -eq 0)
    $control.Evidence.CollectionIssues=@(Get-WinSecSmbIssueCodes)
    Assert-Request (@(Get-WinSecSmbNativeDiagnostics $control).Count -eq $control.Evidence.CollectionIssues.Count)
    Write-Host '[PASS] Empty and complete closed diagnostic catalogs remain valid'
    foreach($bad in @(@('UNREVIEWED_CODE'),@('PRIVATE-PROVIDER-ERROR'),@($null),$null,'PROFILESLOCAL_UNAVAILABLE')) {
        $control.Evidence.CollectionIssues=$bad;$caught=$false
        try{$null=Get-WinSecSmbNativeDiagnostics $control}catch{$caught=$true}
        Assert-Request $caught
    }
    Write-Host '[PASS] Unknown codes, raw text, null entries and malformed lists remain rejected'
    . (Join-Path $root 'tests/Fixtures/SmbMemory.ps1')
    Initialize-WinSecSmbFixture
    Set-Alias Get-CimInstance Get-WinSecSmbFixtureCim -Scope Script
    Set-Alias Invoke-WinSecSmbQuery Invoke-WinSecSmbFixtureQuery -Scope Script
    Set-Alias Read-WinSecSmbRegistryValue Read-WinSecSmbFixtureRegistry -Scope Script
    # Same test scope keeps synthetic provider aliases visible to declarations
    # loaded by the validator; no production provider may be reached.
    $result=(. $validator -OperationId ('a'*32) -ApprovedRequestHash $plan.RequestHash) -join "`n" | ConvertFrom-Json
    Assert-Request ($result.ExecutionStatus -ceq 'COMPLETED' -and $result.CollectionComplete -and $result.CollectionValidated -and
        $result.CollectionIssues.Count -eq 0 -and $result.TechnicalMarkdownValidated -and $result.PublicHistoryRoundtripValidated -and
        $result.InMemoryFrameworkReports -eq 3 -and -not $result.ReportsPersisted -and -not $result.WindowsChanges -and
        $script:SmbCalls.Count -eq 13)
    Write-Host '[PASS] Exact approval runs the full validator with synthetic providers and no persistence'
} finally {$env:COMPUTERNAME=$savedHostname}
Write-Host 'Smb request: 6 passed; 0 failed.'
