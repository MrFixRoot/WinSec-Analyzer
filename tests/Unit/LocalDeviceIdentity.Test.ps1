# Synthetic firmware only. No Windows audits or hardware identifiers are read.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/TargetRegistry.ps1')
. (Join-Path $root 'src/Core/AuditEngine.ps1')
$script:passed = 0
$script:failed = 0
$script:uuid = '12345678-1234-4567-89ab-123456789abc'
$script:products = $null
$script:providerFails = $false
$script:registryCalls = 0
function Get-CimInstance {
    [CmdletBinding()]
    param($Namespace, $ClassName, $Property, $OperationTimeoutSec)
    if ($Namespace -cne 'root/cimv2' -or $ClassName -cne 'Win32_ComputerSystemProduct' -or
        $Property -cne 'UUID' -or $OperationTimeoutSec -ne 5) { throw 'Unexpected identity query.' }
    if ($script:providerFails) { throw 'SENSITIVE-PROVIDER-DETAIL' }
    if ($null -ne $script:products) { return $script:products }
    return [pscustomobject]@{UUID=$script:uuid}
}
function Get-WinSecCheckRegistry { $script:registryCalls++; throw 'No collector registry may be reached.' }
function Assert-WinSecIdentity { param([bool]$Condition) if (-not $Condition) { throw 'Identity assertion failed.' } }
function Test-WinSecIdentityCase {
    param([string]$Name, [scriptblock]$Action)
    try { $null = & $Action; $script:passed++; Write-Host "[PASS] $Name" }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}
Test-WinSecIdentityCase 'Hardware identity is deterministic, versioned and does not expose the UUID' {
    $first = Get-WinSecLocalHardwareDeviceId
    Assert-WinSecIdentity ($first -cmatch '^local:hw1-[a-f0-9]{64}$' -and $first -ceq (Get-WinSecLocalHardwareDeviceId))
    Assert-WinSecIdentity (-not $first.Contains($script:uuid))
    $script:uuid = $script:uuid.ToUpperInvariant()
    Assert-WinSecIdentity ($first -ceq (Get-WinSecLocalHardwareDeviceId))
}
Test-WinSecIdentityCase 'Renaming or changing Windows installation metadata preserves DeviceId' {
    $savedName = $env:COMPUTERNAME
    try {
        $env:COMPUTERNAME = 'BEFORE-FIXTURE'; $first = New-WinSecLocalTarget
        $env:COMPUTERNAME = 'AFTER-FIXTURE'; $second = New-WinSecLocalTarget
        Assert-WinSecIdentity ($first.DeviceId -ceq $second.DeviceId -and $first.Hostname -cne $second.Hostname)
        Assert-WinSecIdentity ($second.Id -ceq $second.DeviceId -and $null -eq $second.Score)
    }
    finally { $env:COMPUTERNAME = $savedName }
}
Test-WinSecIdentityCase 'Different firmware creates a different device even with the same hostname' {
    $first = Get-WinSecLocalHardwareDeviceId
    $script:uuid = '87654321-4321-4567-89ab-cba987654321'
    Assert-WinSecIdentity ($first -cne (Get-WinSecLocalHardwareDeviceId))
}
foreach ($invalid in @('', 'not-a-guid', '00000000-0000-0000-0000-000000000000',
    'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF', '12345678-1234-4567-89ab-123456789abc ', 123, @('a','b'))) {
    $script:uuid = $invalid
    Test-WinSecIdentityCase 'Invalid firmware is rejected without hostname fallback or leaked details' {
        $caught = $false
        try { $null = New-WinSecLocalTarget } catch {
            $caught = $_.Exception.Message -ceq 'Unable to establish a valid local hardware identity.'
        }
        Assert-WinSecIdentity $caught
    }
}
Test-WinSecIdentityCase 'Ambiguous products are rejected' {
    $script:products = @([pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'},
        [pscustomobject]@{UUID='87654321-4321-4567-89ab-cba987654321'})
    $caught = $false
    try { $null = Get-WinSecLocalHardwareDeviceId } catch { $caught = $true }
    $script:products = $null
    Assert-WinSecIdentity $caught
}
Test-WinSecIdentityCase 'Provider failure is generic and does not reach checks' {
    $script:providerFails = $true
    $caught = $false
    try { $null = Invoke-WinSecAudit -SkipScoring } catch {
        $caught = $_.Exception.Message -ceq 'Unable to establish a valid local hardware identity.'
    }
    $script:providerFails = $false
    Assert-WinSecIdentity ($caught -and $script:registryCalls -eq 0)
}
Test-WinSecIdentityCase 'AuditEngine rejects a hostname identity before resolving any checks' {
    $script:uuid = '12345678-1234-4567-89ab-123456789abc'
    $caught = $false
    try { $null = Invoke-WinSecAudit -DeviceId ('local:' + $env:COMPUTERNAME) -SkipScoring }
    catch { $caught = $_.Exception.Message -match 'Only the current Windows device' }
    Assert-WinSecIdentity ($caught -and $script:registryCalls -eq 0)
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if ($script:failed -gt 0) { throw 'Local identity unit tests failed.' }
